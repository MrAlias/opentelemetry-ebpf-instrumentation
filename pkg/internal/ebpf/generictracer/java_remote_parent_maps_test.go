// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer_test

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"
	"go.opentelemetry.io/obi/pkg/internal/javabridge"
)

//go:embed bpf_x86_bpfel.o
var legacyBPFX86Object []byte

//go:embed bpf_arm64_bpfel.o
var legacyBPFARM64Object []byte

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
				cursor := specs[loader].Maps["jrp_recv_cur"]
				require.NotNil(t, cursor, loader)
				require.Equal(t, ebpf.Hash, cursor.Type, loader)
				require.Equal(t, uint32(8), cursor.KeySize, loader)
				require.Equal(t, uint32(56), cursor.ValueSize, loader)
				require.Zero(t, cursor.Flags, loader)
				require.Equal(t, ebpfconvenience.PinInternal, cursor.Pinning, loader)
				guard := specs[loader].Maps["jrp_recv_guard"]
				require.NotNil(t, guard, loader)
				require.Equal(t, ebpf.Hash, guard.Type, loader)
				require.Equal(t, uint32(8), guard.KeySize, loader)
				require.Equal(t, uint32(56), guard.ValueSize, loader)
				require.Zero(t, guard.Flags, loader)
				require.Equal(t, ebpfconvenience.PinInternal, guard.Pinning, loader)
				if enabled {
					require.Greater(t, cursor.MaxEntries, uint32(1), loader)
					require.Equal(t, cursor.MaxEntries, guard.MaxEntries, loader)
				} else {
					require.Equal(t, uint32(1), cursor.MaxEntries, loader)
					require.Equal(t, uint32(1), guard.MaxEntries, loader)
				}
			}
			for _, loader := range []string{"tp", "go"} {
				require.NotContains(t, specs[loader].Maps, "jrp_recv_cur")
				require.NotContains(t, specs[loader].Maps, "jrp_recv_guard")
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
	require.LessOrEqual(t, len(references), verifierMapLimit)
	// Exact Java generation cleanup runs in the independently attached close
	// program. Keeping its lifecycle maps out of the baseline probe preserves
	// verifier headroom for the ordinary HTTP/TCP close path.
	require.NotContains(t, references, "java_remote_parent_alias_replays")
	require.NotContains(t, references, "java_remote_parent_state")
	require.NotContains(t, references, "jrp_recv_cur")
	require.NotContains(t, references, "jrp_recv_guard")

	javaClose := spec.Programs["obi_kprobe_java_remote_parent_tcp_close"]
	require.NotNil(t, javaClose)
	javaCloseReferences := referencedProgramMaps(spec, javaClose)
	require.LessOrEqual(t, len(javaCloseReferences), verifierMapLimit)
	require.Contains(t, javaCloseReferences, "jrp_recv_cur")
	require.Contains(t, javaCloseReferences, "jrp_recv_guard")
	require.NotContains(t, javaCloseReferences, "jump_table")
}

func TestJavaRemoteParentCloseWorkspaceIsPrivateAndBounded(t *testing.T) {
	const workspaceName = "java_remote_parent_close_workspace_storage"

	spec, err := generictracer.LoadBpf()
	require.NoError(t, err)

	workspace := spec.Maps[workspaceName]
	require.NotNil(t, workspace)
	require.Equal(t, ebpf.PerCPUArray, workspace.Type)
	require.Equal(t, uint32(4), workspace.KeySize)
	require.Equal(t, uint32(160), workspace.ValueSize)
	require.Equal(t, uint32(1), workspace.MaxEntries)
	require.Zero(t, workspace.Flags)
	require.Equal(t, ebpf.PinNone, workspace.Pinning)

	const javaCloseName = "obi_kprobe_java_remote_parent_tcp_close"
	javaClose := spec.Programs[javaCloseName]
	require.NotNil(t, javaClose)
	require.Contains(t, referencedProgramMaps(spec, javaClose), workspaceName)

	var referencingPrograms []string
	for programName, program := range spec.Programs {
		if _, referencesWorkspace := referencedProgramMaps(spec, program)[workspaceName]; referencesWorkspace {
			referencingPrograms = append(referencingPrograms, programName)
		}
	}
	require.ElementsMatch(t, []string{javaCloseName}, referencingPrograms)
}

const (
	legacyBPFStackLimit    = 512
	legacyBPFStackQuantum  = 32
	legacyBPFMaxCallFrames = 8
	// A non-entry subprogram that directly tail-calls must have less than
	// 256 bytes of previously accumulated caller stack on legacy kernels.
	legacyBPFTailCallCallerStackLimit = 256
	// Keep at least one allocation quantum below the verifier's hard limit so
	// a small compiler spill cannot silently break the supported old-kernel
	// matrix.
	legacyBPFStackBudget = legacyBPFStackLimit - legacyBPFStackQuantum
)

type legacyBPFFrame struct {
	name          string
	raw           int
	measured      bool
	hasTailCall   bool
	calls         []string
	pointerParams [5]bool
	start         int
	end           int
}

func TestJavaRemoteParentCloseFitsLegacyCombinedStack(t *testing.T) {
	const root = "obi_kprobe_java_remote_parent_tcp_close"

	for _, object := range []struct {
		name string
		data []byte
	}{
		{name: "bpf_x86_bpfel.o", data: legacyBPFX86Object},
		{name: "bpf_arm64_bpfel.o", data: legacyBPFARM64Object},
	} {
		t.Run(object.name, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object.data))
			require.NoError(t, err)
			program := spec.Programs[root]
			require.NotNil(t, program)

			combined, path, err := legacyBPFCombinedStack(program.Instructions, root)
			require.NoError(t, err)
			t.Logf(
				"legacy combined stack %d bytes (margin %d): %s",
				combined,
				legacyBPFStackLimit-combined,
				strings.Join(path, " -> "),
			)
			require.LessOrEqualf(
				t,
				combined,
				legacyBPFStackBudget,
				"legacy combined stack %d exceeds %d-byte budget (kernel limit %d, margin %d); path: %s",
				combined,
				legacyBPFStackBudget,
				legacyBPFStackLimit,
				legacyBPFStackLimit-combined,
				strings.Join(path, " -> "),
			)
		})
	}
}

func TestJavaRemoteParentIoctlFitsLegacyCombinedStack(t *testing.T) {
	const root = "obi_kprobe_security_file_ioctl"

	for _, object := range []struct {
		name string
		data []byte
	}{
		{name: "bpf_x86_bpfel.o", data: legacyBPFX86Object},
		{name: "bpf_arm64_bpfel.o", data: legacyBPFARM64Object},
	} {
		t.Run(object.name, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object.data))
			require.NoError(t, err)
			program := spec.Programs[root]
			require.NotNil(t, program)
			frames, err := legacyBPFFrames(program.Instructions)
			require.NoError(t, err)
			rootFrame := frames[root]
			require.NotNil(t, rootFrame)
			callPointerParams := make(legacyBPFCallPointerParams, len(frames))
			for name, frame := range frames {
				callPointerParams[name] = frame.pointerParams
			}
			rootDepth, err := legacyBPFFrameStackDepthWithCalls(
				program.Instructions[rootFrame.start:rootFrame.end],
				[5]bool{},
				callPointerParams,
				false,
			)
			require.NoError(t, err)
			rootRounded := legacyBPFRoundedFrame(rootDepth)
			require.LessOrEqual(t, rootRounded, legacyBPFStackBudget)
			require.NotEmpty(t, rootFrame.calls)
			seenBranches := make(map[string]struct{}, len(rootFrame.calls))

			for _, branch := range rootFrame.calls {
				if _, seen := seenBranches[branch]; seen {
					continue
				}
				seenBranches[branch] = struct{}{}
				t.Run(branch, func(t *testing.T) {
					// The root pass accounts for every current-frame pointer it derives.
					// Analyze each direct branch separately so its kernel, user, and
					// map-value parameters are not misclassified as ancestor stack;
					// preserve the real prefix depth for the tail-call caller limit.
					child, childPath, err := legacyBPFCombinedStackWithAncestor(
						program.Instructions, branch, rootRounded, 1,
					)
					require.NoError(t, err)
					combined := rootRounded + child
					path := append(
						[]string{fmt.Sprintf("%s(%d->%d)", root, rootDepth, rootRounded)},
						childPath...,
					)
					t.Logf(
						"legacy combined stack %d bytes (margin %d): %s",
						combined,
						legacyBPFStackLimit-combined,
						strings.Join(path, " -> "),
					)
					require.LessOrEqualf(
						t,
						combined,
						legacyBPFStackBudget,
						"legacy combined stack %d exceeds %d-byte budget (kernel limit %d, margin %d); path: %s",
						combined,
						legacyBPFStackBudget,
						legacyBPFStackLimit,
						legacyBPFStackLimit-combined,
						strings.Join(path, " -> "),
					)
				})
			}
		})
	}
}

func TestJavaRemoteParentControlCarriersFitLegacyCombinedStack(t *testing.T) {
	const (
		root         = "obi_kprobe_sys_ioctl"
		control      = "handle_java_control_ioctl"
		legacyThread = "handle_java_legacy_threads_ioctl"
		remoteThread = "handle_java_remote_threads_ioctl"
		threadTail   = "obi_java_threads_tail"
		marker       = "handle_java_thread_mapping_action"
	)
	controlBranches := []string{
		"handle_java_task_cancel_ioctl",
		"handle_java_task_unlink_ioctl",
		legacyThread,
		"handle_java_legacy_task_link_ioctl",
	}
	tailPrograms := []string{
		"obi_java_task_capture_tail",
		"obi_java_task_relay_capture_tail",
		"obi_java_task_link_tail",
		"obi_java_control_cleanup_tail",
		threadTail,
	}

	for _, object := range []struct {
		name string
		data []byte
	}{
		{name: "bpf_x86_bpfel.o", data: legacyBPFX86Object},
		{name: "bpf_arm64_bpfel.o", data: legacyBPFARM64Object},
	} {
		t.Run(object.name, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object.data))
			require.NoError(t, err)
			program := spec.Programs[root]
			require.NotNil(t, program)
			frames, err := legacyBPFFrames(program.Instructions)
			require.NoError(t, err)
			require.Contains(t, frames[root].calls, control)
			require.Contains(t, frames[root].calls, "prepare_java_control_tail")
			require.Contains(t, frames[root].calls, "prepare_java_control_cleanup_tail")
			require.Contains(t, frames[root].calls, "java_control_tail_dispatch_missed")
			for _, branch := range controlBranches {
				require.Contains(t, frames[control].calls, branch)
			}
			remoteProgram := spec.Programs[threadTail]
			require.NotNil(t, remoteProgram)
			remoteFrames, err := legacyBPFFrames(remoteProgram.Instructions)
			require.NoError(t, err)
			require.Contains(t, remoteFrames[threadTail].calls, remoteThread)
			require.Contains(t, remoteFrames[remoteThread].calls, marker)
			callPointerParams := make(legacyBPFCallPointerParams, len(frames))
			for name, frame := range frames {
				callPointerParams[name] = frame.pointerParams
			}
			measure := func(name string, stackParams [5]bool) int {
				frame := frames[name]
				require.NotNil(t, frame)
				depth, err := legacyBPFFrameStackDepthWithCalls(
					program.Instructions[frame.start:frame.end],
					stackParams,
					callPointerParams,
					false,
				)
				require.NoError(t, err)
				return legacyBPFRoundedFrame(depth)
			}

			rootDepth := measure(root, [5]bool{})
			controlDepth := measure(control, [5]bool{})
			for _, branch := range []string{
				"prepare_java_control_tail",
				"prepare_java_control_cleanup_tail",
				"java_control_tail_dispatch_missed",
			} {
				t.Run(branch, func(t *testing.T) {
					child, childPath, err := legacyBPFCombinedStackWithAncestor(
						program.Instructions, branch, rootDepth, 1,
					)
					require.NoError(t, err)
					combined := rootDepth + child
					path := append(
						[]string{fmt.Sprintf("%s(%d)", root, rootDepth)},
						childPath...,
					)
					t.Logf(
						"legacy %s dispatch stack %d bytes (margin %d): %s",
						branch,
						combined,
						legacyBPFStackLimit-combined,
						strings.Join(path, " -> "),
					)
					require.LessOrEqualf(
						t,
						combined,
						legacyBPFStackBudget,
						"legacy %s dispatch stack %d exceeds %d-byte budget (kernel limit %d, margin %d); path: %s",
						branch,
						combined,
						legacyBPFStackBudget,
						legacyBPFStackLimit,
						legacyBPFStackLimit-combined,
						strings.Join(path, " -> "),
					)
				})
			}
			ancestorDepth := rootDepth + controlDepth
			for _, branch := range controlBranches {
				t.Run(branch, func(t *testing.T) {
					child, childPath, err := legacyBPFCombinedStackWithAncestor(
						program.Instructions, branch, ancestorDepth, 2,
					)
					require.NoError(t, err)
					combined := ancestorDepth + child
					path := append(
						[]string{
							fmt.Sprintf("%s(%d)", root, rootDepth),
							fmt.Sprintf("%s(%d)", control, controlDepth),
						},
						childPath...,
					)
					t.Logf(
						"legacy %s carrier stack %d bytes (margin %d): %s",
						branch,
						combined,
						legacyBPFStackLimit-combined,
						strings.Join(path, " -> "),
					)
					require.LessOrEqualf(
						t,
						combined,
						legacyBPFStackBudget,
						"legacy %s carrier stack %d exceeds %d-byte budget (kernel limit %d, margin %d); path: %s",
						branch,
						combined,
						legacyBPFStackBudget,
						legacyBPFStackLimit,
						legacyBPFStackLimit-combined,
						strings.Join(path, " -> "),
					)
				})
			}

			// A successful tail call resets the verifier stack. Measure each
			// carrier transaction from its own program root, while the generic
			// ioctl test above independently covers parser preflight and miss
			// cleanup in the originating syscall program.
			for _, tailProgram := range tailPrograms {
				t.Run(tailProgram, func(t *testing.T) {
					target := spec.Programs[tailProgram]
					require.NotNil(t, target)
					combined, path, err := legacyBPFCombinedStack(
						target.Instructions, tailProgram,
					)
					require.NoError(t, err)
					t.Logf(
						"legacy %s carrier stack %d bytes (margin %d): %s",
						tailProgram,
						combined,
						legacyBPFStackLimit-combined,
						strings.Join(path, " -> "),
					)
					require.LessOrEqualf(
						t,
						combined,
						legacyBPFStackBudget,
						"legacy %s carrier stack %d exceeds %d-byte budget (kernel limit %d, margin %d); path: %s",
						tailProgram,
						combined,
						legacyBPFStackBudget,
						legacyBPFStackLimit,
						legacyBPFStackLimit-combined,
						strings.Join(path, " -> "),
					)
				})
			}
		})
	}
}

func TestJavaRemoteParentIoctlParserTailCallsStayInEntryFrame(t *testing.T) {
	for _, root := range []string{
		"obi_kprobe_security_file_ioctl",
		"obi_kprobe_sys_ioctl",
	} {
		t.Run(root, func(t *testing.T) {
			for _, object := range []struct {
				name string
				data []byte
			}{
				{name: "bpf_x86_bpfel.o", data: legacyBPFX86Object},
				{name: "bpf_arm64_bpfel.o", data: legacyBPFARM64Object},
			} {
				t.Run(object.name, func(t *testing.T) {
					spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object.data))
					require.NoError(t, err)
					program := spec.Programs[root]
					require.NotNil(t, program)

					frames, err := legacyBPFFrames(program.Instructions)
					require.NoError(t, err)
					rootFrame := frames[root]
					require.NotNil(t, rootFrame)
					require.True(t, rootFrame.hasTailCall, "entry frame must dispatch prepared Java data")

					for name, frame := range frames {
						if name == root {
							continue
						}
						require.Falsef(
							t, frame.hasTailCall,
							"subprogram %q must return preparation status to the entry frame before dispatch",
							name,
						)
					}
				})
			}
		})
	}
}

func TestLegacyBPFFrameDepthTracksDerivedFramePointers(t *testing.T) {
	chained := asm.Instructions{
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -32),
		asm.Mov.Reg(asm.R3, asm.R2),
		asm.Add.Imm(asm.R3, -32),
		asm.StoreImm(asm.R3, 0, 0, asm.DWord),
	}

	depth, err := legacyBPFFrameStackDepth(chained)
	require.NoError(t, err)
	require.Equal(t, 64, depth)

	spilled := asm.Instructions{
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -32),
		asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord),
		asm.LoadMem(asm.R3, asm.RFP, -8, asm.DWord),
		asm.Add.Imm(asm.R3, -32),
		asm.StoreImm(asm.R3, 0, 0, asm.DWord),
	}
	depth, err = legacyBPFFrameStackDepth(spilled)
	require.NoError(t, err)
	require.Equal(t, 64, depth)

	negativeParameter := asm.Instructions{
		asm.Mov.Reg(asm.R2, asm.R1),
		asm.Add.Imm(asm.R2, -8),
		asm.StoreImm(asm.R2, 0, 0, asm.DWord),
	}
	_, err = legacyBPFFrameStackDepthForParams(
		negativeParameter, [5]bool{true},
	)
	require.ErrorContains(t, err, "negative arithmetic on an external pointer parameter")

	_, err = legacyBPFFrameStackDepthForParams(
		asm.Instructions{asm.Mov.Reg(asm.R0, asm.R1), asm.Return()},
		[5]bool{true},
	)
	require.ErrorContains(t, err, "returns a derived pointer")

	_, err = legacyBPFFrameStackDepth(asm.Instructions{asm.LongJump("target")})
	require.ErrorContains(t, err, "unsupported long jump")
	// A successful tail call does not return through this function, and its
	// target is verified as a separate program. A failed tail call continues in
	// this frame, so following fallthrough measures this function's return path.
	depth, err = legacyBPFFrameStackDepth(asm.Instructions{
		asm.FnTailCall.Call(),
		asm.StoreImm(asm.RFP, -64, 0, asm.Word),
	})
	require.NoError(t, err)
	require.Equal(t, 64, depth)
	callback := asm.LoadImm(asm.R1, 0, asm.DWord).WithReference("callback")
	callback.Src = asm.PseudoFunc
	_, err = legacyBPFFrameStackDepth(asm.Instructions{callback})
	require.ErrorContains(t, err, "unsupported function pointer")

	knownOrUnknown := asm.Instructions{
		asm.JEq.Imm(asm.R4, 0, "unknown"),
		asm.Mov.Imm(asm.R2, 8),
		asm.Ja.Label("join"),
		asm.Mov.Reg(asm.R2, asm.R4),
		asm.Mov.Reg(asm.R3, asm.R1),
		asm.Add.Reg(asm.R3, asm.R2),
		asm.StoreImm(asm.R3, 0, 0, asm.DWord),
	}
	knownOrUnknown[0].Offset = 2
	knownOrUnknown[2].Offset = 1
	_, err = legacyBPFFrameStackDepthForParams(knownOrUnknown, [5]bool{true})
	require.ErrorContains(t, err, "derived pointer arithmetic uses an unknown register")

	embeddedCallerStackPointer := asm.Instructions{
		asm.LoadMem(asm.R2, asm.R1, 0, asm.DWord),
		asm.Add.Imm(asm.R2, -64),
		asm.StoreImm(asm.R2, 0, 0, asm.DWord),
	}
	_, err = legacyBPFFrameStackDepthForParams(
		embeddedCallerStackPointer, [5]bool{true},
	)
	require.ErrorContains(t, err, "possible caller-stack pointer")

	calleePointerParams := legacyBPFCallPointerParams{
		"callee": {true},
	}
	unsafeAggregateCall := asm.Instructions{
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -64),
		asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -16),
		asm.Call.Label("callee"),
		asm.Return(),
	}
	_, err = legacyBPFFrameStackDepthWithCalls(
		unsafeAggregateCall, [5]bool{}, calleePointerParams, false,
	)
	require.ErrorContains(t, err, "reachable embedded pointer spill")

	scalarAggregateCall := asm.Instructions{
		asm.StoreImm(asm.RFP, -16, 1, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -16),
		asm.Call.Label("callee"),
		asm.Return(),
	}
	depth, err = legacyBPFFrameStackDepthWithCalls(
		scalarAggregateCall, [5]bool{}, calleePointerParams, false,
	)
	require.NoError(t, err)
	require.Equal(t, 16, depth)

	joinedFrameOrExternalStore := asm.Instructions{
		asm.JEq.Imm(asm.R4, 0, "external"),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -16),
		asm.Ja.Label("join"),
		asm.Mov.Reg(asm.R3, asm.R1),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -64),
		asm.StoreMem(asm.R3, 0, asm.R2, asm.DWord),
	}
	joinedFrameOrExternalStore[0].Offset = 3
	joinedFrameOrExternalStore[3].Offset = 1
	_, err = legacyBPFFrameStackDepthForParams(
		joinedFrameOrExternalStore, [5]bool{true},
	)
	require.ErrorContains(t, err, "stores a derived pointer outside the current stack frame")
}

func TestLegacyBPFCombinedStackRejectsEveryDeepSibling(t *testing.T) {
	instructions := asm.Instructions{
		legacyBPFSyntheticFunctionStart("root", asm.Mov.Imm(asm.R0, 0)),
		asm.Call.Label("wide"),
		asm.Call.Label("deep1"),
		asm.Return(),
		legacyBPFSyntheticFunctionStart(
			"wide", asm.StoreImm(asm.RFP, -300, 0, asm.DWord),
		),
		asm.Return(),
	}
	for frame := 1; frame <= 8; frame++ {
		name := fmt.Sprintf("deep%d", frame)
		instructions = append(
			instructions,
			legacyBPFSyntheticFunctionStart(name, asm.Mov.Imm(asm.R0, 0)),
		)
		if frame < 8 {
			instructions = append(instructions, asm.Call.Label(fmt.Sprintf("deep%d", frame+1)))
		}
		instructions = append(instructions, asm.Return())
	}

	_, _, err := legacyBPFCombinedStack(instructions, "root")
	require.ErrorContains(t, err, "BPF call path exceeds 8 frames")
}

func TestLegacyBPFCombinedStackModelsPrefixedCallFrameLimit(t *testing.T) {
	chain := func(frames int) asm.Instructions {
		instructions := asm.Instructions{
			legacyBPFSyntheticFunctionStart("entry", asm.Mov.Imm(asm.R0, 0)),
			asm.Return(),
		}
		for frame := 1; frame <= frames; frame++ {
			name := fmt.Sprintf("branch%d", frame)
			instructions = append(
				instructions,
				legacyBPFSyntheticFunctionStart(
					name, asm.StoreImm(asm.RFP, -32, 0, asm.Word),
				),
			)
			if frame < frames {
				instructions = append(
					instructions, asm.Call.Label(fmt.Sprintf("branch%d", frame+1)),
				)
			}
			instructions = append(instructions, asm.Return())
		}
		return instructions
	}

	combined, _, err := legacyBPFCombinedStackWithAncestor(chain(7), "branch1", 32, 1)
	require.NoError(t, err)
	require.Equal(t, 224, combined)

	_, _, err = legacyBPFCombinedStackWithAncestor(chain(8), "branch1", 32, 1)
	require.ErrorContains(t, err, "BPF call path exceeds 8 frames")
}

func TestLegacyBPFCombinedStackModelsTailCallCallerLimit(t *testing.T) {
	directChild := func(rootDepth int, tailCall bool) asm.Instructions {
		childCall := asm.Mov.Imm(asm.R0, 0)
		if tailCall {
			childCall = asm.FnTailCall.Call()
		}
		return asm.Instructions{
			legacyBPFSyntheticFunctionStart(
				"root", asm.StoreImm(asm.RFP, int16(-rootDepth), 0, asm.Word),
			),
			asm.Call.Label("tail"),
			asm.Return(),
			legacyBPFSyntheticFunctionStart(
				"tail", asm.StoreImm(asm.RFP, -32, 0, asm.Word),
			),
			childCall,
			asm.Return(),
		}
	}

	entryTailCall := asm.Instructions{
		legacyBPFSyntheticFunctionStart(
			"root", asm.StoreImm(asm.RFP, -256, 0, asm.Word),
		),
		asm.FnTailCall.Call(),
		asm.Return(),
	}
	combined, _, err := legacyBPFCombinedStack(entryTailCall, "root")
	require.NoError(t, err)
	require.Equal(t, 256, combined)

	combined, _, err = legacyBPFCombinedStack(directChild(224, true), "root")
	require.NoError(t, err)
	require.Equal(t, 256, combined)

	_, _, err = legacyBPFCombinedStack(directChild(256, true), "root")
	require.ErrorContains(t, err, "tail-call subprogram")

	nestedTailCall := asm.Instructions{
		legacyBPFSyntheticFunctionStart(
			"root", asm.StoreImm(asm.RFP, -224, 0, asm.Word),
		),
		asm.Call.Label("middle"),
		asm.Return(),
		legacyBPFSyntheticFunctionStart(
			"middle", asm.StoreImm(asm.RFP, -32, 0, asm.Word),
		),
		asm.Call.Label("tail"),
		asm.Return(),
		legacyBPFSyntheticFunctionStart(
			"tail", asm.StoreImm(asm.RFP, -32, 0, asm.Word),
		),
		asm.FnTailCall.Call(),
		asm.Return(),
	}
	_, _, err = legacyBPFCombinedStack(nestedTailCall, "root")
	require.ErrorContains(t, err, "tail-call subprogram")

	combined, _, err = legacyBPFCombinedStack(directChild(256, false), "root")
	require.NoError(t, err)
	require.Equal(t, 288, combined)

	_, _, err = legacyBPFCombinedStackWithAncestor(directChild(32, true), "tail", 256, 1)
	require.ErrorContains(t, err, "tail-call subprogram")
}

func legacyBPFSyntheticFunctionStart(name string, instruction asm.Instruction) asm.Instruction {
	function := &btf.Func{
		Name: name,
		Type: &btf.FuncProto{Return: &btf.Int{Size: 4}},
	}
	return btf.WithFuncMetadata(instruction, function).WithSymbol(name)
}

func legacyBPFCombinedStack(
	instructions asm.Instructions,
	root string,
) (int, []string, error) {
	return legacyBPFCombinedStackWithAncestor(instructions, root, 0, 0)
}

func legacyBPFCombinedStackWithAncestor(
	instructions asm.Instructions,
	root string,
	ancestorDepth int,
	ancestorFrames int,
) (int, []string, error) {
	frames, err := legacyBPFFrames(instructions)
	if err != nil {
		return 0, nil, err
	}
	callPointerParams := make(legacyBPFCallPointerParams, len(frames))
	for name, frame := range frames {
		callPointerParams[name] = frame.pointerParams
	}

	active := make(map[string]bool)
	var walk func(string, int, int) (int, []string, error)
	walk = func(name string, callerDepth, callerFrames int) (int, []string, error) {
		frame := frames[name]
		if frame == nil {
			return 0, nil, fmt.Errorf("BPF function %q has no frame metadata", name)
		}
		if active[name] {
			return 0, nil, fmt.Errorf("recursive BPF call through %q", name)
		}
		if callerFrames >= legacyBPFMaxCallFrames {
			return 0, nil, fmt.Errorf(
				"BPF call path exceeds %d frames at %q", legacyBPFMaxCallFrames, name,
			)
		}
		if frame.start != 0 && frame.hasTailCall &&
			callerDepth >= legacyBPFTailCallCallerStackLimit {
			return 0, nil, fmt.Errorf(
				"tail-call subprogram %q has %d bytes of caller stack; limit is less than %d",
				name,
				callerDepth,
				legacyBPFTailCallCallerStackLimit,
			)
		}
		if !frame.measured {
			stackParams := frame.pointerParams
			if name == root {
				// Entry context is kernel-owned memory, never an ancestor BPF
				// stack frame. Only subprogram pointer parameters can carry
				// caller-stack provenance.
				stackParams = [5]bool{}
			}
			depth, err := legacyBPFFrameStackDepthWithCalls(
				instructions[frame.start:frame.end], stackParams, callPointerParams, false,
			)
			if err != nil {
				return 0, nil, fmt.Errorf("measure BPF function %q: %w", frame.name, err)
			}
			frame.raw = depth
			frame.measured = true
		}
		active[name] = true
		defer delete(active, name)

		rounded := legacyBPFRoundedFrame(frame.raw)
		frameLabel := fmt.Sprintf("%s(%d->%d)", name, frame.raw, rounded)
		maxChild := 0
		var maxChildPath []string
		for _, callee := range frame.calls {
			child, childPath, err := walk(
				callee, callerDepth+rounded, callerFrames+1,
			)
			if err != nil {
				return 0, nil, err
			}
			if child > maxChild {
				maxChild = child
				maxChildPath = childPath
			}
		}

		path := append([]string{frameLabel}, maxChildPath...)
		return rounded + maxChild, path, nil
	}

	return walk(root, ancestorDepth, ancestorFrames)
}

func legacyBPFFrames(instructions asm.Instructions) (map[string]*legacyBPFFrame, error) {
	frames := make(map[string]*legacyBPFFrame)
	var current *legacyBPFFrame
	for index := range instructions {
		instruction := &instructions[index]
		if function := btf.FuncMetadata(instruction); function != nil {
			if current != nil {
				current.end = index
			}
			symbol := instruction.Symbol()
			if symbol == "" || symbol != function.Name {
				return nil, fmt.Errorf(
					"BTF function %q does not match instruction symbol %q",
					function.Name,
					symbol,
				)
			}
			if frames[function.Name] != nil {
				return nil, fmt.Errorf("duplicate BPF function %q", function.Name)
			}
			current = &legacyBPFFrame{name: function.Name, start: index}
			prototype, ok := btf.UnderlyingType(function.Type).(*btf.FuncProto)
			if !ok {
				return nil, fmt.Errorf("BPF function %q has no prototype", function.Name)
			}
			if len(prototype.Params) > len(current.pointerParams) {
				return nil, fmt.Errorf(
					"BPF function %q has %d parameters; at most five are supported",
					function.Name,
					len(prototype.Params),
				)
			}
			for parameter, definition := range prototype.Params {
				_, current.pointerParams[parameter] = btf.UnderlyingType(definition.Type).(*btf.Pointer)
			}
			// Registers beyond the declared prototype are ignored by the
			// callee. Clang may leave a caller-stack pointer in one of those
			// scratch argument registers; accepting it cannot expose caller
			// memory because the callee has no parameter through which to use it.
			for parameter := len(prototype.Params); parameter < len(current.pointerParams); parameter++ {
				current.pointerParams[parameter] = true
			}
			frames[function.Name] = current
		}
		if current == nil {
			return nil, fmt.Errorf("instruction %d precedes BTF function metadata", index)
		}
		if instruction.OpCode.Class() == asm.Jump32Class &&
			instruction.OpCode.JumpOp() == asm.Ja {
			return nil, fmt.Errorf("long jump in BPF function %q is unsupported", current.name)
		}
		if instruction.IsLoadOfFunctionPointer() {
			return nil, fmt.Errorf(
				"function-pointer callback in BPF function %q is unsupported",
				current.name,
			)
		}

		if instruction.IsFunctionCall() {
			callee := instruction.Reference()
			if callee == "" {
				return nil, fmt.Errorf(
					"unresolved pseudo-call in %q at instruction %d",
					current.name,
					index,
				)
			}
			current.calls = append(current.calls, callee)
		}
		if instruction.IsBuiltinCall() && instruction.Constant == int64(asm.FnTailCall) {
			current.hasTailCall = true
		}
	}
	if current == nil {
		return nil, errors.New("BPF program has no function metadata")
	}
	current.end = len(instructions)

	return frames, nil
}

const (
	legacyBPFRegisterCount      = int(asm.RFP) + 1
	legacyBPFMaxRegisterOffsets = 64
)

type legacyBPFCallPointerParams map[string][5]bool

type legacyBPFRegisterState [legacyBPFRegisterCount]map[int]struct{}

type legacyBPFFrameState struct {
	frameOffsets         legacyBPFRegisterState
	externalOffsets      legacyBPFRegisterState
	constants            legacyBPFRegisterState
	constantKnown        [legacyBPFRegisterCount]bool
	possibleStackPointer [legacyBPFRegisterCount]bool
	stackPointers        map[int]legacyBPFSpilledPointer
}

type legacyBPFSpilledPointer struct {
	frameOffsets         map[int]struct{}
	externalOffsets      map[int]struct{}
	possibleStackPointer bool
}

func legacyBPFFrameStackDepth(instructions asm.Instructions) (int, error) {
	return legacyBPFFrameStackDepthForParams(instructions, [5]bool{})
}

func legacyBPFFrameStackDepthForParams(
	instructions asm.Instructions,
	pointerParams [5]bool,
) (int, error) {
	return legacyBPFFrameStackDepthWithCalls(instructions, pointerParams, nil, true)
}

func legacyBPFFrameStackDepthWithCalls(
	instructions asm.Instructions,
	pointerParams [5]bool,
	callPointerParams legacyBPFCallPointerParams,
	taintExternalLoads bool,
) (int, error) {
	if len(instructions) == 0 {
		return 0, errors.New("empty function")
	}

	rawPC := make([]int, len(instructions))
	rawToIndex := make(map[int]int, len(instructions))
	nextRawPC := 0
	for index, instruction := range instructions {
		rawPC[index] = nextRawPC
		rawToIndex[nextRawPC] = index
		nextRawPC += int(instruction.Width())
	}

	states := make([]legacyBPFFrameState, len(instructions))
	reached := make([]bool, len(instructions))
	queued := []int{0}
	reached[0] = true
	states[0].frameOffsets[asm.RFP] = map[int]struct{}{0: {}}
	for parameter, pointer := range pointerParams {
		if pointer {
			states[0].externalOffsets[asm.R1+asm.Register(parameter)] = map[int]struct{}{0: {}}
		}
	}
	depth := 0

	for len(queued) > 0 {
		index := queued[0]
		queued = queued[1:]
		instruction := &instructions[index]
		state := legacyBPFCloneFrameState(states[index])
		legacyBPFRecordStateDepth(state.frameOffsets, &depth)

		if instruction.IsLoadOfFunctionPointer() {
			return 0, fmt.Errorf("instruction %d loads an unsupported function pointer", index)
		}
		if err := legacyBPFApplyInstruction(
			&state, instruction, &depth, callPointerParams, taintExternalLoads,
		); err != nil {
			return 0, fmt.Errorf("instruction %d (%v): %w", index, instruction, err)
		}
		if instruction.OpCode.Class() == asm.Jump32Class &&
			instruction.OpCode.JumpOp() == asm.Ja {
			return 0, fmt.Errorf("instruction %d uses an unsupported long jump", index)
		}

		successors := make([]int, 0, 2)
		switch {
		case instruction.IsBuiltinCall() && instruction.Constant == int64(asm.FnTailCall):
			// The successful edge does not return through this function and its
			// target is verified separately. Only helper failure falls through here.
			if index+1 < len(instructions) {
				successors = append(successors, index+1)
			}
		case instruction.OpCode.Class().IsJump():
			switch instruction.OpCode.JumpOp() {
			case asm.Exit:
				continue
			case asm.Call:
				if index+1 < len(instructions) {
					successors = append(successors, index+1)
				}
			case asm.Ja:
				target, err := legacyBPFJumpTarget(instruction, index, rawPC, rawToIndex)
				if err != nil {
					return 0, err
				}
				successors = append(successors, target)
			default:
				target, err := legacyBPFJumpTarget(instruction, index, rawPC, rawToIndex)
				if err != nil {
					return 0, err
				}
				successors = append(successors, target)
				if index+1 < len(instructions) {
					successors = append(successors, index+1)
				}
			}
		case index+1 < len(instructions):
			successors = append(successors, index+1)
		}

		for _, successor := range successors {
			if !reached[successor] {
				states[successor] = legacyBPFCloneFrameState(state)
				reached[successor] = true
				queued = append(queued, successor)
				continue
			}
			changed, err := legacyBPFMergeFrameState(&states[successor], state)
			if err != nil {
				return 0, fmt.Errorf("merge into instruction %d: %w", successor, err)
			}
			if changed {
				queued = append(queued, successor)
			}
		}
	}

	return depth, nil
}

func legacyBPFApplyInstruction(
	state *legacyBPFFrameState,
	instruction *asm.Instruction,
	depth *int,
	callPointerParams legacyBPFCallPointerParams,
	taintExternalLoads bool,
) error {
	class := instruction.OpCode.Class()
	switch class {
	case asm.LdXClass:
		if err := legacyBPFRecordAccess(state, instruction.Src, int(instruction.Offset), depth); err != nil {
			return err
		}
		frameOffsets, externalOffsets, possibleStackPointer, err := legacyBPFLoadStackPointer(state, instruction)
		if err != nil {
			return err
		}
		if taintExternalLoads && instruction.OpCode.Size() == asm.DWord &&
			len(state.externalOffsets[instruction.Src]) > 0 {
			// A pointer parameter can address a caller stack aggregate. A DWord
			// field can therefore contain a spilled pointer whose verifier
			// provenance must not disappear at the load boundary.
			possibleStackPointer = true
		}
		state.frameOffsets[instruction.Dst] = frameOffsets
		state.externalOffsets[instruction.Dst] = externalOffsets
		state.constants[instruction.Dst] = nil
		state.constantKnown[instruction.Dst] = false
		state.possibleStackPointer[instruction.Dst] = possibleStackPointer
	case asm.LdClass:
		state.frameOffsets[instruction.Dst] = nil
		state.externalOffsets[instruction.Dst] = nil
		state.constants[instruction.Dst] = nil
		state.constantKnown[instruction.Dst] = false
		state.possibleStackPointer[instruction.Dst] = false
	case asm.StClass, asm.StXClass:
		if err := legacyBPFRecordAccess(state, instruction.Dst, int(instruction.Offset), depth); err != nil {
			return err
		}
		legacyBPFClearDirectStackStore(state, instruction)
		if class == asm.StXClass {
			if err := legacyBPFStoreStackPointer(state, instruction); err != nil {
				return err
			}
		}
	case asm.ALUClass:
		if legacyBPFRegisterHasPointer(state, instruction.Dst) ||
			(instruction.OpCode.Source() == asm.RegSource &&
				legacyBPFRegisterHasPointer(state, instruction.Src)) {
			return errors.New("32-bit ALU operation on a frame-derived pointer")
		}
		state.frameOffsets[instruction.Dst] = nil
		state.externalOffsets[instruction.Dst] = nil
		state.constants[instruction.Dst] = nil
		state.constantKnown[instruction.Dst] = false
		state.possibleStackPointer[instruction.Dst] = false
	case asm.ALU64Class:
		if err := legacyBPFApplyALU64(state, instruction); err != nil {
			return err
		}
	}

	if class.IsJump() && instruction.OpCode.JumpOp() == asm.Call {
		if instruction.IsFunctionCall() {
			callee := instruction.Reference()
			calleeParams, resolved := callPointerParams[callee]
			for register := asm.R1; register <= asm.R5; register++ {
				if state.possibleStackPointer[register] {
					return fmt.Errorf(
						"forwards a possible embedded caller-stack pointer %s to BPF function %q",
						register,
						callee,
					)
				}
				parameter := int(register - asm.R1)
				hasFramePointer := len(state.frameOffsets[register]) > 0
				hasExternalPointer := len(state.externalOffsets[register]) > 0
				if (hasFramePointer || hasExternalPointer) &&
					(!resolved || !calleeParams[parameter]) {
					return fmt.Errorf(
						"passes stack-derived pointer %s to non-pointer parameter of BPF function %q",
						register,
						callee,
					)
				}
				if hasFramePointer && legacyBPFFrameArgumentCanReachPointerSpill(state, register) {
					return fmt.Errorf(
						"passes current-frame pointer %s with a reachable embedded pointer spill to BPF function %q",
						register,
						callee,
					)
				}
			}
		}
		for register := asm.R0; register <= asm.R5; register++ {
			state.frameOffsets[register] = nil
			state.externalOffsets[register] = nil
			state.constants[register] = nil
			state.constantKnown[register] = false
			state.possibleStackPointer[register] = false
		}
	}
	if class.IsJump() && instruction.OpCode.JumpOp() == asm.Exit &&
		(legacyBPFRegisterHasPointer(state, asm.R0) || state.possibleStackPointer[asm.R0]) {
		return errors.New("returns a derived pointer")
	}
	legacyBPFRecordStateDepth(state.frameOffsets, depth)
	return nil
}

func legacyBPFApplyALU64(state *legacyBPFFrameState, instruction *asm.Instruction) error {
	if instruction.Dst == asm.RFP {
		return errors.New("writes frame pointer")
	}
	sourceIsRegister := instruction.OpCode.Source() == asm.RegSource
	switch instruction.OpCode.ALUOp() {
	case asm.Mov:
		if sourceIsRegister {
			state.frameOffsets[instruction.Dst] = legacyBPFCloneOffsets(state.frameOffsets[instruction.Src])
			state.externalOffsets[instruction.Dst] = legacyBPFCloneOffsets(state.externalOffsets[instruction.Src])
			state.constants[instruction.Dst] = legacyBPFCloneOffsets(state.constants[instruction.Src])
			state.constantKnown[instruction.Dst] = state.constantKnown[instruction.Src]
			state.possibleStackPointer[instruction.Dst] = state.possibleStackPointer[instruction.Src]
		} else {
			state.frameOffsets[instruction.Dst] = nil
			state.externalOffsets[instruction.Dst] = nil
			state.constants[instruction.Dst] = map[int]struct{}{int(instruction.Constant): {}}
			state.constantKnown[instruction.Dst] = true
			state.possibleStackPointer[instruction.Dst] = false
		}
	case asm.Add, asm.Sub:
		if state.possibleStackPointer[instruction.Dst] ||
			(sourceIsRegister && state.possibleStackPointer[instruction.Src]) {
			return errors.New("arithmetic on a possible caller-stack pointer loaded through a parameter")
		}
		if sourceIsRegister {
			destinationPointer := legacyBPFRegisterHasPointer(state, instruction.Dst)
			sourcePointer := legacyBPFRegisterHasPointer(state, instruction.Src)
			if destinationPointer && sourcePointer {
				return errors.New("arithmetic combines two derived pointers")
			}
			switch {
			case destinationPointer:
				if !state.constantKnown[instruction.Src] {
					return errors.New("derived pointer arithmetic uses an unknown register")
				}
				sign := 1
				if instruction.OpCode.ALUOp() == asm.Sub {
					sign = -1
				}
				state.frameOffsets[instruction.Dst] = legacyBPFCombineOffsets(
					state.frameOffsets[instruction.Dst], state.constants[instruction.Src], sign,
				)
				state.externalOffsets[instruction.Dst] = legacyBPFCombineOffsets(
					state.externalOffsets[instruction.Dst], state.constants[instruction.Src], sign,
				)
				state.constants[instruction.Dst] = nil
				state.constantKnown[instruction.Dst] = false
			case sourcePointer:
				if instruction.OpCode.ALUOp() == asm.Sub {
					return errors.New("subtracts a derived pointer from a scalar")
				}
				if !state.constantKnown[instruction.Dst] {
					return errors.New("derived pointer arithmetic uses an unknown register")
				}
				state.frameOffsets[instruction.Dst] = legacyBPFCombineOffsets(
					state.frameOffsets[instruction.Src], state.constants[instruction.Dst], 1,
				)
				state.externalOffsets[instruction.Dst] = legacyBPFCombineOffsets(
					state.externalOffsets[instruction.Src], state.constants[instruction.Dst], 1,
				)
				state.constants[instruction.Dst] = nil
				state.constantKnown[instruction.Dst] = false
			default:
				if state.constantKnown[instruction.Dst] && state.constantKnown[instruction.Src] {
					sign := 1
					if instruction.OpCode.ALUOp() == asm.Sub {
						sign = -1
					}
					state.constants[instruction.Dst] = legacyBPFCombineOffsets(
						state.constants[instruction.Dst], state.constants[instruction.Src], sign,
					)
				} else {
					state.constants[instruction.Dst] = nil
					state.constantKnown[instruction.Dst] = false
				}
				state.frameOffsets[instruction.Dst] = nil
				state.externalOffsets[instruction.Dst] = nil
			}
		} else {
			delta := int(instruction.Constant)
			if instruction.OpCode.ALUOp() == asm.Sub {
				delta = -delta
			}
			switch {
			case legacyBPFRegisterHasPointer(state, instruction.Dst):
				state.frameOffsets[instruction.Dst] = legacyBPFAdjustOffsets(state.frameOffsets[instruction.Dst], delta)
				state.externalOffsets[instruction.Dst] = legacyBPFAdjustOffsets(state.externalOffsets[instruction.Dst], delta)
				state.constants[instruction.Dst] = nil
				state.constantKnown[instruction.Dst] = false
			case state.constantKnown[instruction.Dst]:
				state.constants[instruction.Dst] = legacyBPFAdjustOffsets(state.constants[instruction.Dst], delta)
			default:
				state.constants[instruction.Dst] = nil
			}
		}
		for offset := range state.externalOffsets[instruction.Dst] {
			if offset < 0 {
				return errors.New("negative arithmetic on an external pointer parameter")
			}
		}
	default:
		if legacyBPFRegisterHasPointer(state, instruction.Dst) ||
			(sourceIsRegister && legacyBPFRegisterHasPointer(state, instruction.Src)) {
			return errors.New("unsupported ALU operation on a frame-derived pointer")
		}
		state.frameOffsets[instruction.Dst] = nil
		state.externalOffsets[instruction.Dst] = nil
		state.constants[instruction.Dst] = nil
		state.constantKnown[instruction.Dst] = false
		state.possibleStackPointer[instruction.Dst] = false
	}
	if len(state.frameOffsets[instruction.Dst]) > legacyBPFMaxRegisterOffsets ||
		len(state.externalOffsets[instruction.Dst]) > legacyBPFMaxRegisterOffsets ||
		len(state.constants[instruction.Dst]) > legacyBPFMaxRegisterOffsets {
		return fmt.Errorf("too many frame-pointer offsets in register %s", instruction.Dst)
	}
	return nil
}

func legacyBPFRecordAccess(
	state *legacyBPFFrameState,
	register asm.Register,
	offset int,
	depth *int,
) error {
	if int(register) >= legacyBPFRegisterCount {
		return fmt.Errorf("invalid memory-base register %s", register)
	}
	if state.possibleStackPointer[register] {
		return errors.New("dereferences a possible caller-stack pointer loaded through a parameter")
	}
	for base := range state.frameOffsets[register] {
		legacyBPFRecordOffset(base+offset, depth)
	}
	for base := range state.externalOffsets[register] {
		if base+offset < 0 {
			return errors.New("negative access through an external pointer parameter")
		}
	}
	return nil
}

func legacyBPFClearDirectStackStore(
	state *legacyBPFFrameState,
	instruction *asm.Instruction,
) {
	if instruction.Dst != asm.RFP || len(state.stackPointers) == 0 {
		return
	}
	storeStart := int(instruction.Offset)
	storeEnd := storeStart + instruction.OpCode.Size().Sizeof()
	for slot := range state.stackPointers {
		if storeStart < slot+8 && slot < storeEnd {
			delete(state.stackPointers, slot)
		}
	}
}

func legacyBPFFrameArgumentCanReachPointerSpill(
	state *legacyBPFFrameState,
	register asm.Register,
) bool {
	for base := range state.frameOffsets[register] {
		for slot := range state.stackPointers {
			// A callee may only move forward from a caller-stack argument.
			// Any negative derivation is rejected while measuring that callee.
			// Therefore only pointer spills at or above the argument base can
			// be loaded through it and hide their verifier provenance.
			if slot >= base && slot < 0 {
				return true
			}
		}
	}
	return false
}

func legacyBPFStoreStackPointer(
	state *legacyBPFFrameState,
	instruction *asm.Instruction,
) error {
	if !legacyBPFRegisterHasPointer(state, instruction.Src) &&
		!state.possibleStackPointer[instruction.Src] {
		return nil
	}
	if instruction.OpCode.Size() != asm.DWord {
		return errors.New("stores a derived pointer with non-DWord width")
	}
	if len(state.externalOffsets[instruction.Dst]) > 0 {
		return errors.New("stores a derived pointer outside the current stack frame")
	}
	if len(state.frameOffsets[instruction.Dst]) == 0 {
		return errors.New("stores a derived pointer outside the current stack frame")
	}
	if state.stackPointers == nil {
		state.stackPointers = make(map[int]legacyBPFSpilledPointer)
	}
	// Direct RFP stores clear definite overlaps above. For derived or joined
	// bases, retain earlier provenance and union the new pointer. That can
	// overcount ambiguous slot reuse but cannot hide a deeper verifier path.
	for base := range state.frameOffsets[instruction.Dst] {
		address := base + int(instruction.Offset)
		if address >= 0 {
			return fmt.Errorf("stores a derived pointer at non-stack offset %d", address)
		}
		slot := state.stackPointers[address]
		slot.frameOffsets = legacyBPFUnionOffsets(
			slot.frameOffsets, state.frameOffsets[instruction.Src],
		)
		slot.externalOffsets = legacyBPFUnionOffsets(
			slot.externalOffsets, state.externalOffsets[instruction.Src],
		)
		slot.possibleStackPointer = slot.possibleStackPointer ||
			state.possibleStackPointer[instruction.Src]
		if len(slot.frameOffsets) > legacyBPFMaxRegisterOffsets ||
			len(slot.externalOffsets) > legacyBPFMaxRegisterOffsets {
			return fmt.Errorf("too many spilled pointer offsets at stack offset %d", address)
		}
		state.stackPointers[address] = slot
	}
	return nil
}

func legacyBPFLoadStackPointer(
	state *legacyBPFFrameState,
	instruction *asm.Instruction,
) (map[int]struct{}, map[int]struct{}, bool, error) {
	if instruction.OpCode.Size() != asm.DWord {
		return nil, nil, false, nil
	}
	var frameOffsets map[int]struct{}
	var externalOffsets map[int]struct{}
	possibleStackPointer := false
	for base := range state.frameOffsets[instruction.Src] {
		address := base + int(instruction.Offset)
		slot, ok := state.stackPointers[address]
		if !ok {
			continue
		}
		frameOffsets = legacyBPFUnionOffsets(frameOffsets, slot.frameOffsets)
		externalOffsets = legacyBPFUnionOffsets(externalOffsets, slot.externalOffsets)
		possibleStackPointer = possibleStackPointer || slot.possibleStackPointer
	}
	if len(frameOffsets) > legacyBPFMaxRegisterOffsets ||
		len(externalOffsets) > legacyBPFMaxRegisterOffsets {
		return nil, nil, false, errors.New("too many pointer offsets loaded from stack")
	}
	return frameOffsets, externalOffsets, possibleStackPointer, nil
}

func legacyBPFRegisterHasPointer(state *legacyBPFFrameState, register asm.Register) bool {
	return len(state.frameOffsets[register]) > 0 || len(state.externalOffsets[register]) > 0
}

func legacyBPFAdjustOffsets(offsets map[int]struct{}, delta int) map[int]struct{} {
	if len(offsets) == 0 {
		return nil
	}
	adjusted := make(map[int]struct{}, len(offsets))
	for offset := range offsets {
		adjusted[offset+delta] = struct{}{}
	}
	return adjusted
}

func legacyBPFCombineOffsets(left, right map[int]struct{}, rightSign int) map[int]struct{} {
	if len(left) == 0 || len(right) == 0 {
		return nil
	}
	combined := make(map[int]struct{}, len(left)*len(right))
	for leftValue := range left {
		for rightValue := range right {
			combined[leftValue+rightSign*rightValue] = struct{}{}
		}
	}
	return combined
}

func legacyBPFUnionOffsets(destination, source map[int]struct{}) map[int]struct{} {
	if len(source) == 0 {
		return destination
	}
	if destination == nil {
		destination = make(map[int]struct{}, len(source))
	}
	for offset := range source {
		destination[offset] = struct{}{}
	}
	return destination
}

func legacyBPFRecordStateDepth(state legacyBPFRegisterState, depth *int) {
	for _, offsets := range state {
		for offset := range offsets {
			legacyBPFRecordOffset(offset, depth)
		}
	}
}

func legacyBPFRecordOffset(offset int, depth *int) {
	if offset < 0 {
		*depth = max(*depth, -offset)
	}
}

func legacyBPFJumpTarget(
	instruction *asm.Instruction,
	index int,
	rawPC []int,
	rawToIndex map[int]int,
) (int, error) {
	targetRaw := rawPC[index] + int(instruction.Width()) + int(instruction.Offset)
	target, ok := rawToIndex[targetRaw]
	if !ok {
		return 0, fmt.Errorf(
			"jump at instruction %d targets unknown raw instruction %d",
			index,
			targetRaw,
		)
	}
	return target, nil
}

func legacyBPFCloneRegisterState(state legacyBPFRegisterState) legacyBPFRegisterState {
	var clone legacyBPFRegisterState
	for register, offsets := range state {
		clone[register] = legacyBPFCloneOffsets(offsets)
	}
	return clone
}

func legacyBPFCloneFrameState(state legacyBPFFrameState) legacyBPFFrameState {
	clone := legacyBPFFrameState{
		frameOffsets:         legacyBPFCloneRegisterState(state.frameOffsets),
		externalOffsets:      legacyBPFCloneRegisterState(state.externalOffsets),
		constants:            legacyBPFCloneRegisterState(state.constants),
		constantKnown:        state.constantKnown,
		possibleStackPointer: state.possibleStackPointer,
	}
	if len(state.stackPointers) > 0 {
		clone.stackPointers = make(map[int]legacyBPFSpilledPointer, len(state.stackPointers))
		for address, pointer := range state.stackPointers {
			clone.stackPointers[address] = legacyBPFSpilledPointer{
				frameOffsets:         legacyBPFCloneOffsets(pointer.frameOffsets),
				externalOffsets:      legacyBPFCloneOffsets(pointer.externalOffsets),
				possibleStackPointer: pointer.possibleStackPointer,
			}
		}
	}
	return clone
}

func legacyBPFCloneOffsets(offsets map[int]struct{}) map[int]struct{} {
	if len(offsets) == 0 {
		return nil
	}
	clone := make(map[int]struct{}, len(offsets))
	for offset := range offsets {
		clone[offset] = struct{}{}
	}
	return clone
}

func legacyBPFMergeRegisterState(
	destination *legacyBPFRegisterState,
	source legacyBPFRegisterState,
) (bool, error) {
	changed := false
	for register, offsets := range source {
		if len(offsets) == 0 {
			continue
		}
		if destination[register] == nil {
			destination[register] = make(map[int]struct{}, len(offsets))
		}
		for offset := range offsets {
			if _, exists := destination[register][offset]; exists {
				continue
			}
			destination[register][offset] = struct{}{}
			changed = true
		}
		if len(destination[register]) > legacyBPFMaxRegisterOffsets {
			return false, fmt.Errorf("too many offsets in register r%d", register)
		}
	}
	return changed, nil
}

func legacyBPFMergeFrameState(
	destination *legacyBPFFrameState,
	source legacyBPFFrameState,
) (bool, error) {
	frameChanged, err := legacyBPFMergeRegisterState(
		&destination.frameOffsets, source.frameOffsets,
	)
	if err != nil {
		return false, err
	}
	externalChanged, err := legacyBPFMergeRegisterState(
		&destination.externalOffsets, source.externalOffsets,
	)
	if err != nil {
		return false, err
	}
	constantsChanged := false
	for register := range destination.constantKnown {
		switch {
		case destination.constantKnown[register] && source.constantKnown[register]:
			if legacyBPFMergeOffsetsInto(
				&destination.constants[register], source.constants[register],
			) {
				constantsChanged = true
			}
			if len(destination.constants[register]) > legacyBPFMaxRegisterOffsets {
				return false, fmt.Errorf("too many constants in register r%d", register)
			}
		case destination.constantKnown[register] && !source.constantKnown[register]:
			destination.constantKnown[register] = false
			destination.constants[register] = nil
			constantsChanged = true
		case !destination.constantKnown[register]:
			destination.constants[register] = nil
		}
	}
	stackChanged := false
	possibleStackPointerChanged := false
	for register, possible := range source.possibleStackPointer {
		if possible && !destination.possibleStackPointer[register] {
			destination.possibleStackPointer[register] = true
			possibleStackPointerChanged = true
		}
	}
	if len(source.stackPointers) > 0 && destination.stackPointers == nil {
		destination.stackPointers = make(map[int]legacyBPFSpilledPointer)
	}
	for address, sourcePointer := range source.stackPointers {
		destinationPointer := destination.stackPointers[address]
		changed := legacyBPFMergeOffsetsInto(
			&destinationPointer.frameOffsets, sourcePointer.frameOffsets,
		)
		changed = legacyBPFMergeOffsetsInto(
			&destinationPointer.externalOffsets, sourcePointer.externalOffsets,
		) || changed
		if sourcePointer.possibleStackPointer && !destinationPointer.possibleStackPointer {
			destinationPointer.possibleStackPointer = true
			changed = true
		}
		if len(destinationPointer.frameOffsets) > legacyBPFMaxRegisterOffsets ||
			len(destinationPointer.externalOffsets) > legacyBPFMaxRegisterOffsets {
			return false, fmt.Errorf("too many spilled offsets at stack offset %d", address)
		}
		if changed {
			destination.stackPointers[address] = destinationPointer
			stackChanged = true
		}
	}
	return frameChanged || externalChanged || constantsChanged ||
		possibleStackPointerChanged || stackChanged, nil
}

func legacyBPFMergeOffsetsInto(destination *map[int]struct{}, source map[int]struct{}) bool {
	changed := false
	if len(source) > 0 && *destination == nil {
		*destination = make(map[int]struct{}, len(source))
	}
	for offset := range source {
		if _, exists := (*destination)[offset]; exists {
			continue
		}
		(*destination)[offset] = struct{}{}
		changed = true
	}
	return changed
}

func legacyBPFRoundedFrame(raw int) int {
	if raw < 1 {
		raw = 1
	}
	return (raw + legacyBPFStackQuantum - 1) &^ (legacyBPFStackQuantum - 1)
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
			name != "java_thread_mapping_claims" &&
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
		"java_remote_parent_handoffs",
		"java_remote_parent_handoff_claims",
		"java_remote_parent_handoff_mutations",
		"java_remote_parent_state",
		"java_remote_parent_task_claims",
		"java_remote_parent_tasks",
		"java_retired_processes",
		"java_thread_mapping_claims",
		"java_vt_threads",
	} {
		require.Equal(t, ebpf.Hash, spec.Maps[name].Type, name)
	}

	claims := spec.Maps["java_remote_parent_claims"]
	replays := spec.Maps["java_remote_parent_alias_replays"]
	guards := spec.Maps["java_remote_parent_owner_guards"]
	tasks := spec.Maps["java_remote_parent_tasks"]
	taskClaims := spec.Maps["java_remote_parent_task_claims"]
	handoffs := spec.Maps["java_remote_parent_handoffs"]
	handoffMutations := spec.Maps["java_remote_parent_handoff_mutations"]
	handoffClaims := spec.Maps["java_remote_parent_handoff_claims"]
	require.NotNil(t, claims)
	require.NotNil(t, replays)
	require.NotNil(t, guards)
	require.Equal(t, uint32(40), replays.KeySize)
	require.Equal(t, uint32(72), replays.ValueSize)
	require.Equal(t, uint32(30_000), replays.MaxEntries)
	require.Equal(t, ebpfconvenience.PinInternal, replays.Pinning)
	require.Equal(t, uint32(12), guards.KeySize)
	require.Equal(t, uint32(24), guards.ValueSize)
	require.Equal(t, claims.MaxEntries, guards.MaxEntries)
	require.Equal(t, claims.Flags, guards.Flags)
	require.Equal(t, ebpfconvenience.PinInternal, guards.Pinning)
	require.Equal(t, uint32(12), tasks.KeySize)
	require.Equal(t, uint32(40), tasks.ValueSize)
	require.Equal(t, tasks.MaxEntries, taskClaims.MaxEntries)
	require.Equal(t, uint32(12), taskClaims.KeySize)
	require.Equal(t, uint32(16), taskClaims.ValueSize)
	require.Equal(t, ebpfconvenience.PinInternal, taskClaims.Pinning)
	require.Equal(t, uint32(24), handoffs.KeySize)
	require.Equal(t, ebpfconvenience.PinInternal, handoffs.Pinning)
	require.Equal(t, tasks.MaxEntries, handoffs.MaxEntries)
	require.Equal(t, uint32(24), handoffMutations.KeySize)
	require.Equal(t, uint32(16), handoffMutations.ValueSize)
	require.Equal(t, handoffs.MaxEntries, handoffMutations.MaxEntries)
	require.Equal(t, ebpfconvenience.PinInternal, handoffMutations.Pinning)
	require.Equal(t, ebpf.Hash, handoffClaims.Type)
	require.Equal(t, uint32(24), handoffClaims.KeySize)
	require.Equal(t, ebpfconvenience.PinInternal, handoffClaims.Pinning)
	require.Equal(t, uint32(40), handoffs.ValueSize)
	require.Equal(t, uint32(16), handoffClaims.ValueSize)
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
	bridgeSpec, err := tpinjector.LoadBpfJavaRemoteParentMaps()
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
	bridgeClaims := bridgeSpec.Maps["java_thread_mapping_claims"]
	require.NotNil(t, bridgeClaims)
	assertMapSpecEqual(t, "java_thread_mapping_claims", claims, bridgeClaims)

	javabridge.MinimizeDisabledMaps(spec)
	require.Equal(t, uint32(1), claims.MaxEntries)
	javabridge.MinimizeDisabledMaps(bridgeSpec)
	require.Equal(t, uint32(1), bridgeClaims.MaxEntries)
}
