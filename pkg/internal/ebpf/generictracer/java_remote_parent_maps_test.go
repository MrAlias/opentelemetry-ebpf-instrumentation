// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer_test

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

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

	t.Run("enabled", func(t *testing.T) {
		assertSharedMapSpecs(t, genericSpec, tpSpec)
		assertSharedMapSpecs(t, genericSpec, bridgeSpec)
		assertSharedMapSpecs(t, genericSpec, primarySpec)
		assertSharedMapSpecs(t, genericSpec, goSpec)
	})

	t.Run("disabled", func(t *testing.T) {
		genericDisabled := genericSpec.Copy()
		tpDisabled := tpSpec.Copy()
		goDisabled := goSpec.Copy()
		javabridge.MinimizeDisabledMaps(genericDisabled)
		javabridge.MinimizeDisabledMaps(tpDisabled)
		javabridge.MinimizeDisabledMaps(goDisabled)
		assertSharedMapSpecs(t, genericDisabled, tpDisabled)
		assertSharedMapSpecs(t, genericDisabled, goDisabled)
	})
}

func assertSharedMapSpecs(t *testing.T, left, right *ebpf.CollectionSpec) {
	t.Helper()
	compared := 0
	for name, rightMap := range right.Maps {
		if name == "java_remote_parent_negotiations" {
			continue
		}
		if name != "incoming_trace_map" &&
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
		require.Equal(t, leftMap.Type, rightMap.Type, name+" type")
		require.Equal(t, leftMap.KeySize, rightMap.KeySize, name+" key size")
		require.Equal(t, leftMap.ValueSize, rightMap.ValueSize, name+" value size")
		require.Equal(t, leftMap.MaxEntries, rightMap.MaxEntries, name+" max entries")
		require.Equal(t, leftMap.Flags, rightMap.Flags, name+" flags")
		require.Equal(t, leftMap.Pinning, rightMap.Pinning, name+" pinning")
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
		"java_remote_parent_claims",
		"java_remote_parent_generation_index",
		"java_remote_parent_state",
		"java_retired_processes",
	} {
		require.Equal(t, ebpf.Hash, spec.Maps[name].Type, name)
	}
}

func TestJavaRemoteParentSocketAuthorityIsSocketLocal(t *testing.T) {
	spec, err := tpinjector.LoadBpfJavaRemoteParent()
	require.NoError(t, err)

	negotiations := spec.Maps["java_remote_parent_negotiations"]
	require.NotNil(t, negotiations)
	require.Equal(t, ebpf.SkStorage, negotiations.Type)
	require.Equal(t, uint32(unix.BPF_F_NO_PREALLOC), negotiations.Flags)
	require.NotEqual(t, ebpf.PinNone, negotiations.Pinning)
	require.Equal(t, spec.Maps["java_authorized_processes"].Pinning, negotiations.Pinning)
	require.Equal(
		t,
		"cgroup/setsockopt",
		spec.Programs["obi_java_remote_parent_setsockopt"].SectionName,
	)
	require.Equal(
		t,
		"cgroup/getsockopt",
		spec.Programs["obi_java_remote_parent_getsockopt"].SectionName,
	)

	require.Equal(t, ebpf.Hash, spec.Maps["java_authorized_processes"].Type)
	require.Equal(t, ebpf.LRUHash, spec.Maps["java_remote_parent_data_signals"].Type)
	require.Equal(t, ebpf.LRUHash, spec.Maps["java_remote_parent_data_acks"].Type)
	readiness := spec.Maps["java_remote_parent_data_hook_readiness"]
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
}
