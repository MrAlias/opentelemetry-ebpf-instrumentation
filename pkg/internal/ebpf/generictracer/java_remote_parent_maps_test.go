// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer_test

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"
	"go.opentelemetry.io/obi/pkg/internal/javabridge"
)

func TestJavaRemoteParentSharedMapSpecsAreCompatible(t *testing.T) {
	genericSpec, err := generictracer.LoadBpf()
	require.NoError(t, err)
	tpSpec, err := tpinjector.LoadBpf()
	require.NoError(t, err)
	goSpec, err := gotracer.LoadBpf()
	require.NoError(t, err)
	bridgeSpec, err := tpinjector.LoadBpfJavaRemoteParentMaps()
	require.NoError(t, err)
	primarySpec, err := tpinjector.LoadBpfJavaRemoteParent()
	require.NoError(t, err)

	for _, enabled := range []bool{true, false} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		t.Run(name, func(t *testing.T) {
			specs := map[string]*ebpf.CollectionSpec{
				"generic": genericSpec.Copy(),
				"tp":      tpSpec.Copy(),
				"go":      goSpec.Copy(),
				"bridge":  bridgeSpec.Copy(),
				"primary": primarySpec.Copy(),
			}
			for _, spec := range specs {
				if !enabled {
					javabridge.MinimizeDisabledMaps(spec)
				}
			}
			for _, loader := range []string{"generic", "bridge", "primary"} {
				cursor := specs[loader].Maps["java_remote_parent_receive_cursors"]
				require.NotNil(t, cursor, loader)
				require.Equal(t, ebpf.LRUHash, cursor.Type, loader)
				require.Equal(t, uint32(8), cursor.KeySize, loader)
				require.Equal(t, uint32(56), cursor.ValueSize, loader)
				require.Zero(t, cursor.Flags, loader)
				require.Equal(t, ebpfconvenience.PinInternal, cursor.Pinning, loader)
				if enabled {
					require.Greater(t, cursor.MaxEntries, uint32(1), loader)
				} else {
					require.Equal(t, uint32(1), cursor.MaxEntries, loader)
				}
			}
			for _, loader := range []string{"tp", "go"} {
				require.NotContains(t, specs[loader].Maps, "java_remote_parent_receive_cursors")
			}
			for loader, spec := range specs {
				for _, mapName := range []string{
					"java_remote_parent_connections",
					"java_remote_parent_cookie_connections",
				} {
					shared := spec.Maps[mapName]
					require.NotNil(t, shared, loader+" "+mapName)
					require.Equal(t, uint32(56), shared.ValueSize, loader+" "+mapName)
				}
			}
			for loader, spec := range specs {
				if loader == "generic" {
					continue
				}
				assertSharedMapSpecs(t, specs["generic"], spec)
			}
			for loader, spec := range specs {
				writeArgs := spec.Maps["active_ssl_write_args"]
				if writeArgs == nil {
					continue
				}
				require.Equal(t, ebpf.LRUHash, writeArgs.Type, loader)
				require.Equal(t, uint32(16), writeArgs.KeySize, loader)
				require.Equal(t, uint32(64), writeArgs.ValueSize, loader)
			}
		})
	}
}

func TestJavaRemoteParentGetsockoptRouterSpec(t *testing.T) {
	const (
		handlerMapName = "javabridge_getsockopt_handlers"
		routerName     = "obi_java_remote_parent_getsockopt"
	)
	targetNames := []string{
		"obi_java_remote_parent_getsockopt_direct_take",
		"obi_java_remote_parent_getsockopt_direct_discard",
		"obi_java_remote_parent_getsockopt_task_take",
		"obi_java_remote_parent_getsockopt_task_discard",
		"obi_java_remote_parent_getsockopt_health",
	}
	wantContents := []ebpf.MapKV{
		{Key: uint32(0), Value: targetNames[0]},
		{Key: uint32(1), Value: targetNames[1]},
		{Key: uint32(2), Value: targetNames[2]},
		{Key: uint32(3), Value: targetNames[3]},
		{Key: uint32(4), Value: targetNames[4]},
	}

	spec, err := tpinjector.LoadBpfJavaRemoteParent()
	require.NoError(t, err)

	handlers := spec.Maps[handlerMapName]
	require.NotNil(t, handlers)
	require.Equal(t, ebpf.ProgramArray, handlers.Type)
	require.Equal(t, uint32(4), handlers.KeySize)
	require.Equal(t, uint32(4), handlers.ValueSize)
	require.Equal(t, uint32(len(wantContents)), handlers.MaxEntries)
	require.Zero(t, handlers.Flags)
	require.Equal(t, ebpf.PinNone, handlers.Pinning)
	require.Equal(t, wantContents, handlers.Contents)

	for _, scale := range []struct {
		name   string
		factor int
	}{
		{name: "scale_down", factor: -3},
		{name: "scale_up", factor: 3},
	} {
		t.Run(scale.name, func(t *testing.T) {
			scaledSpec := spec.Copy()
			ebpfconvenience.SetupMapSizes(scaledSpec, scale.factor)
			scaledHandlers := scaledSpec.Maps[handlerMapName]
			require.NotNil(t, scaledHandlers)
			assertMapSpecEqual(t, handlerMapName, handlers, scaledHandlers)
			require.Equal(t, wantContents, scaledHandlers.Contents)
		})
	}

	for _, programName := range append([]string{routerName}, targetNames...) {
		program := spec.Programs[programName]
		require.NotNil(t, program, programName)
		require.Equal(t, ebpf.CGroupSockopt, program.Type, programName)
		require.Equal(t, ebpf.AttachCGroupGetsockopt, program.AttachType, programName)
		require.Equal(t, "cgroup/getsockopt", program.SectionName, programName)
	}

	router := spec.Programs[routerName]
	rawInstructionCount := router.Instructions.Size() / asm.InstructionSize
	require.LessOrEqual(t, rawInstructionCount, uint64(64))
	functionCalls := 0
	tailCalls := 0
	handlerMapReferences := 0
	tailCallSlots := make([]int64, 0, len(targetNames))
	for index := range router.Instructions {
		instruction := &router.Instructions[index]
		if instruction.IsFunctionCall() {
			functionCalls++
		}
		if instruction.IsBuiltinCall() && instruction.Constant == int64(asm.FnTailCall) {
			tailCalls++
			require.Positive(t, index)
			slot := &router.Instructions[index-1]
			require.Equal(t, asm.Mov.Op(asm.ImmSource), slot.OpCode)
			require.Equal(t, asm.R3, slot.Dst)
			tailCallSlots = append(tailCallSlots, slot.Constant)
		}
		if instruction.Reference() == handlerMapName {
			handlerMapReferences++
		}
	}
	require.Zero(t, functionCalls)
	require.Equal(t, len(targetNames), tailCalls)
	require.Equal(t, len(targetNames), handlerMapReferences)
	require.ElementsMatch(t, []int64{0, 1, 2, 3, 4}, tailCallSlots)

	for _, targetName := range targetNames {
		tailCalls := 0
		for index := range spec.Programs[targetName].Instructions {
			instruction := &spec.Programs[targetName].Instructions[index]
			if instruction.IsBuiltinCall() && instruction.Constant == int64(asm.FnTailCall) {
				tailCalls++
			}
		}
		require.Zero(t, tailCalls, targetName)
	}
}

func TestBPFProgramsStayWithinVerifierMapLimit(t *testing.T) {
	const verifierMapLimit = 64

	loaders := []struct {
		name string
		load func() (*ebpf.CollectionSpec, error)
	}{
		{name: "generictracer", load: generictracer.LoadBpf},
		{name: "gotracer", load: gotracer.LoadBpf},
		{name: "tpinjector", load: tpinjector.LoadBpf},
		{name: "java_remote_parent", load: tpinjector.LoadBpfJavaRemoteParent},
	}

	for _, loader := range loaders {
		t.Run(loader.name, func(t *testing.T) {
			spec, err := loader.load()
			require.NoError(t, err)
			for programName, program := range spec.Programs {
				references := referencedProgramMaps(spec, program)
				require.LessOrEqualf(
					t,
					len(references),
					verifierMapLimit,
					"program %s references %d verifier-visible maps: %v",
					programName,
					len(references),
					references,
				)
			}
		})
	}

	spec, err := generictracer.LoadBpf()
	require.NoError(t, err)
	tcpClose := spec.Programs["obi_kprobe_tcp_close"]
	require.NotNil(t, tcpClose)
	references := referencedProgramMaps(spec, tcpClose)
	require.Len(t, references, verifierMapLimit)
	require.Contains(t, references, "java_remote_parent_alias_replays")
}

func referencedProgramMaps(
	spec *ebpf.CollectionSpec,
	program *ebpf.ProgramSpec,
) map[string]struct{} {
	references := make(map[string]struct{})
	for _, instruction := range program.Instructions {
		name := instruction.Reference()
		if _, ok := spec.Maps[name]; ok {
			references[name] = struct{}{}
		}
	}
	return references
}

func TestSSLPrewriteMapSpecsAreCompatible(t *testing.T) {
	genericSpec, err := generictracer.LoadBpf()
	require.NoError(t, err)
	tpSpec, err := tpinjector.LoadBpf()
	require.NoError(t, err)

	genericMap := genericSpec.Maps["ssl_prewrite_tp"]
	tpMap := tpSpec.Maps["ssl_prewrite_tp"]
	require.NotNil(t, genericMap)
	require.NotNil(t, tpMap)
	require.Equal(t, genericMap.Type, tpMap.Type)
	require.Equal(t, genericMap.KeySize, tpMap.KeySize)
	require.Equal(t, genericMap.ValueSize, tpMap.ValueSize)
	require.Equal(t, genericMap.MaxEntries, tpMap.MaxEntries)
	require.Equal(t, genericMap.Flags, tpMap.Flags)
	require.Equal(t, genericMap.Pinning, tpMap.Pinning)
	require.Equal(t, ebpf.LRUHash, genericMap.Type)
	require.Equal(t, uint32(24), genericMap.KeySize)
	require.Equal(t, uint32(152), genericMap.ValueSize)
	require.Equal(t, ebpfconvenience.PinInternal, genericMap.Pinning)

	storage := tpSpec.Maps["sk_ssl_prewrite_map"]
	require.NotNil(t, storage)
	require.Equal(t, ebpf.SkStorage, storage.Type)
	require.Equal(t, uint32(unix.BPF_F_NO_PREALLOC), storage.Flags)
	require.Equal(t, ebpfconvenience.PinInternal, storage.Pinning)
	require.Zero(t, storage.MaxEntries)

	ongoingHTTP := genericSpec.Maps["ongoing_http"]
	tpOngoingHTTP := tpSpec.Maps["ongoing_http"]
	require.NotNil(t, ongoingHTTP)
	require.NotNil(t, tpOngoingHTTP)
	assertMapSpecEqual(t, "ongoing_http", ongoingHTTP, tpOngoingHTTP)
	require.Equal(t, ebpfconvenience.PinInternal, ongoingHTTP.Pinning)

	for name, sizes := range map[string][2]uint32{
		"ssl_prewrite_connection_ambiguity": {48, 16},
		"ssl_prewrite_connection_claims":    {48, 40},
		"ssl_prewrite_connection_owners":    {48, 40},
		"ssl_to_conn":                       {24, 48},
		"ssl_prewrite_tp":                   {24, 152},
	} {
		genericShared := genericSpec.Maps[name]
		tpShared := tpSpec.Maps[name]
		require.NotNil(t, genericShared, name)
		require.NotNil(t, tpShared, name)
		require.Equal(t, sizes[0], genericShared.KeySize, name+" key size")
		require.Equal(t, sizes[1], genericShared.ValueSize, name+" value size")
		assertMapSpecEqual(t, name, genericShared, tpShared)
	}
	require.NotContains(t, tpSpec.Maps, "active_ssl_write_args")
	for _, name := range []string{
		"ssl_prewrite_connection_ambiguity",
		"ssl_prewrite_connection_claims",
		"ssl_prewrite_connection_owners",
	} {
		require.Equal(t, ebpf.Hash, genericSpec.Maps[name].Type, name)
	}
	activeWriteArgs := genericSpec.Maps["active_ssl_write_args"]
	require.NotNil(t, activeWriteArgs)
	require.Equal(t, ebpf.LRUHash, activeWriteArgs.Type)
	require.Equal(t, uint32(16), activeWriteArgs.KeySize)
	require.Equal(t, uint32(64), activeWriteArgs.ValueSize)
	shutdownArgs := genericSpec.Maps["active_ssl_shutdown_args"]
	require.NotNil(t, shutdownArgs)
	require.Equal(t, ebpf.LRUHash, shutdownArgs.Type)
	require.Equal(t, uint32(16), shutdownArgs.KeySize)
	require.Equal(t, uint32(24), shutdownArgs.ValueSize)
	require.Equal(t, ebpfconvenience.PinInternal, shutdownArgs.Pinning)
}

func assertMapSpecEqual(t *testing.T, name string, left, right *ebpf.MapSpec) {
	t.Helper()
	require.Equal(t, left.Type, right.Type, name+" type")
	require.Equal(t, left.KeySize, right.KeySize, name+" key size")
	require.Equal(t, left.ValueSize, right.ValueSize, name+" value size")
	require.Equal(t, left.MaxEntries, right.MaxEntries, name+" max entries")
	require.Equal(t, left.Flags, right.Flags, name+" flags")
	require.Equal(t, left.Pinning, right.Pinning, name+" pinning")
}

func assertSharedMapSpecs(t *testing.T, left, right *ebpf.CollectionSpec) {
	t.Helper()
	compared := 0
	for name, rightMap := range right.Maps {
		if name == "java_remote_parent_negotiations" ||
			name == "java_remote_parent_socket_cookies" {
			continue
		}
		if name != "incoming_trace_map" &&
			name != "active_ssl_write_args" &&
			name != "ssl_prewrite_tp" &&
			!strings.HasPrefix(name, "ssl_prewrite_connection_") &&
			name != "ssl_to_conn" &&
			!strings.HasPrefix(name, "incoming_trace_") &&
			!strings.HasPrefix(name, "java_remote_parent_") &&
			name != "java_authorized_processes" &&
			name != "java_process_incarnations" &&
			name != "java_retired_processes" &&
			name != "java_vt_identities" &&
			name != "java_vt_threads" {
			continue
		}
		leftMap := left.Maps[name]
		require.NotNil(t, leftMap, name+" missing")
		compared++
		assertMapSpecEqual(t, name, leftMap, rightMap)
	}
	require.Positive(t, compared)
}

func TestJavaRemoteParentExactLifecycleMapsDoNotEvict(t *testing.T) {
	spec, err := tpinjector.LoadBpfJavaRemoteParentMaps()
	require.NoError(t, err)
	mainSpec, err := tpinjector.LoadBpf()
	require.NoError(t, err)
	require.Equal(
		t,
		"tracepoint/sched/sched_process_exit",
		mainSpec.Programs["obi_java_remote_parent_process_exit"].SectionName,
	)

	for _, name := range []string{
		"java_remote_parent_ambiguity",
		"java_remote_parent_alias_replays",
		"java_remote_parent_claims",
		"java_remote_parent_owner_guards",
		"java_remote_parent_generation_index",
		"java_remote_parent_state",
		"java_retired_processes",
		"java_vt_threads",
	} {
		require.Equal(t, ebpf.Hash, spec.Maps[name].Type, name)
	}

	claims := spec.Maps["java_remote_parent_claims"]
	replays := spec.Maps["java_remote_parent_alias_replays"]
	guards := spec.Maps["java_remote_parent_owner_guards"]
	require.NotNil(t, claims)
	require.NotNil(t, replays)
	require.NotNil(t, guards)
	require.Equal(t, uint32(40), replays.KeySize)
	require.Equal(t, uint32(16), replays.ValueSize)
	require.Equal(t, uint32(30_000), replays.MaxEntries)
	require.Equal(t, ebpfconvenience.PinInternal, replays.Pinning)
	require.Equal(t, uint32(12), guards.KeySize)
	require.Equal(t, uint32(24), guards.ValueSize)
	require.Equal(t, claims.MaxEntries, guards.MaxEntries)
	require.Equal(t, claims.Flags, guards.Flags)
	require.Equal(t, ebpfconvenience.PinInternal, guards.Pinning)
}

func TestJavaRemoteParentGenerationMapsArePerCPU(t *testing.T) {
	spec, err := generictracer.LoadBpf()
	require.NoError(t, err)

	for _, name := range []string{
		"incoming_trace_generation",
		"java_remote_parent_generation",
	} {
		require.Equal(t, ebpf.PerCPUArray, spec.Maps[name].Type, name)
	}
}

func TestJavaRemoteParentSocketAuthorityIsSocketLocal(t *testing.T) {
	primarySpec, err := tpinjector.LoadBpfJavaRemoteParent()
	require.NoError(t, err)
	sockopsSpec, err := tpinjector.LoadBpf()
	require.NoError(t, err)

	negotiations := primarySpec.Maps["java_remote_parent_negotiations"]
	require.NotNil(t, negotiations)
	require.Equal(t, ebpf.SkStorage, negotiations.Type)
	require.Equal(t, uint32(unix.BPF_F_NO_PREALLOC), negotiations.Flags)
	require.NotEqual(t, ebpf.PinNone, negotiations.Pinning)
	require.Equal(t, primarySpec.Maps["java_authorized_processes"].Pinning, negotiations.Pinning)

	primaryCookies := primarySpec.Maps["java_remote_parent_socket_cookies"]
	sockopsCookies := sockopsSpec.Maps["java_remote_parent_socket_cookies"]
	require.NotNil(t, primaryCookies)
	require.NotNil(t, sockopsCookies)
	assertMapSpecEqual(
		t, "java_remote_parent_socket_cookies", primaryCookies, sockopsCookies,
	)
	require.Equal(t, ebpf.SkStorage, primaryCookies.Type)
	require.Equal(t, uint32(4), primaryCookies.KeySize)
	require.Equal(t, uint32(8), primaryCookies.ValueSize)
	require.Zero(t, primaryCookies.MaxEntries)
	require.Equal(t, uint32(unix.BPF_F_NO_PREALLOC), primaryCookies.Flags)
	require.Equal(t, negotiations.Pinning, primaryCookies.Pinning)
	require.Equal(
		t,
		"cgroup/setsockopt",
		primarySpec.Programs["obi_java_remote_parent_setsockopt"].SectionName,
	)
	require.Equal(
		t,
		"cgroup/getsockopt",
		primarySpec.Programs["obi_java_remote_parent_getsockopt"].SectionName,
	)

	require.Equal(t, ebpf.Hash, primarySpec.Maps["java_authorized_processes"].Type)
	require.Equal(t, ebpf.LRUHash, primarySpec.Maps["java_remote_parent_data_signals"].Type)
	require.Equal(t, ebpf.LRUHash, primarySpec.Maps["java_remote_parent_data_acks"].Type)
	readiness := primarySpec.Maps["java_remote_parent_data_hook_readiness"]
	require.NotNil(t, readiness)
	require.Equal(t, ebpf.Array, readiness.Type)
	require.Equal(t, uint32(1), readiness.MaxEntries)
	require.NotEqual(t, ebpf.PinNone, readiness.Pinning)
}

func TestJavaDataPathsUseExclusiveSharedReadinessGate(t *testing.T) {
	spec, err := generictracer.LoadBpf()
	require.NoError(t, err)

	// sys_ioctl handles data only while the shared gate is zero, and
	// security_file_ioctl handles it only while the same gate is one. Both
	// programs must retain the map reference or a partial attach could process
	// data twice or disable telemetry entirely.
	assertProgramReferencesMap(
		t, spec, "obi_kprobe_sys_ioctl", "java_remote_parent_data_hook_readiness",
	)
	assertProgramReferencesMap(
		t, spec, "obi_kprobe_security_file_ioctl", "java_remote_parent_data_hook_readiness",
	)
}

func assertProgramReferencesMap(
	t *testing.T,
	spec *ebpf.CollectionSpec,
	programName string,
	mapName string,
) {
	t.Helper()
	program := spec.Programs[programName]
	require.NotNil(t, program, programName)
	for _, instruction := range program.Instructions {
		if instruction.Reference() == mapName {
			return
		}
	}
	require.Failf(t, "missing map reference", "%s does not reference %s", programName, mapName)
}

func TestDisabledBridgeKeepsPerProcessAuthorizationCapacity(t *testing.T) {
	spec, err := generictracer.LoadBpf()
	require.NoError(t, err)
	authorizationCapacity := spec.Maps["java_authorized_processes"].MaxEntries
	incarnationCapacity := spec.Maps["java_process_incarnations"].MaxEntries
	require.Greater(t, authorizationCapacity, uint32(1))
	require.Greater(t, incarnationCapacity, uint32(1))

	javabridge.MinimizeDisabledMaps(spec)

	require.Equal(t, authorizationCapacity, spec.Maps["java_authorized_processes"].MaxEntries)
	require.Equal(t, incarnationCapacity, spec.Maps["java_process_incarnations"].MaxEntries)
	require.Equal(t, uint32(1), spec.Maps["java_remote_parent_data_signals"].MaxEntries)
	require.Equal(t, uint32(1), spec.Maps["java_remote_parent_data_acks"].MaxEntries)
	require.Equal(t, uint32(1), spec.Maps["java_remote_parent_owner_guards"].MaxEntries)
	require.Equal(t, uint32(1), spec.Maps["java_remote_parent_alias_replays"].MaxEntries)
}

func TestJavaThreadMappingMapsSpec(t *testing.T) {
	spec, err := generictracer.LoadBpf()
	require.NoError(t, err)

	incarnations := spec.Maps["java_process_incarnations"]
	require.NotNil(t, incarnations)
	require.Equal(t, ebpf.Hash, incarnations.Type)

	claims := spec.Maps["java_thread_mapping_claims"]
	require.NotNil(t, claims)
	require.Equal(t, ebpf.Hash, claims.Type)
	require.Equal(t, uint32(12), claims.KeySize)
	require.Equal(t, uint32(24), claims.ValueSize)
	require.Greater(t, claims.MaxEntries, uint32(1))
	require.Equal(t, ebpfconvenience.PinInternal, claims.Pinning)

	javabridge.MinimizeDisabledMaps(spec)
	require.Equal(t, uint32(1), claims.MaxEntries)
}
