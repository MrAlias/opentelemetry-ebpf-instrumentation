// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

type allowRecordingFilter struct {
	ebpfcommon.IdentityPidsFilter
	allowed int
}

func (f *allowRecordingFilter) AllowPID(
	app.PID,
	uint32,
	*exec.FileInfo,
	*exec.FileInfo,
	ebpfcommon.PIDType,
) {
	f.allowed++
}

func TestGoChannelLinkProbesRequireChannelOffsets(t *testing.T) {
	disableContextPropagationForTest(t)

	tracer := &Tracer{
		log:                      slog.New(slog.NewTextHandler(io.Discard, nil)),
		goChannelOffsetsByFileID: map[exec.FileID]bool{},
	}

	assertNoGoChannelLinkProbes(t, tracer.GoProbes())

	tracer.recordGoChannelOffsetAvailability(
		exec.New(exec.Init{Ino: 1}),
		&goexec.Offsets{Field: goexec.FieldOffsets{
			goexec.HchanQcountPos:   uint64(0),
			goexec.HchanDataqsizPos: uint64(8),
			goexec.HchanSendxPos:    uint64(48),
		}},
	)
	assertNoGoChannelLinkProbes(t, tracer.GoProbes())

	tracer.recordGoChannelOffsetAvailability(exec.New(exec.Init{Ino: 2}), goChannelOffsets())
	probes := tracer.GoProbes()
	for _, symbol := range GoChannelLinkProbeSymbols() {
		require.Contains(t, probes, symbol)
	}
}

func TestRuntimeMetricTargetStaleLifetimeDeletionPreservesReplacement(t *testing.T) {
	key := runtimeMetricTargetKey{pid: 42, ns: 7}
	predecessor := exec.New(exec.Init{Pid: 42})
	replacement := exec.New(exec.Init{Pid: 42})
	tracer := &Tracer{
		runtimeMetricTargetKeys:   map[runtimeMetricTargetKey]BpfPidInfo{key: {}},
		runtimeMetricTargetOwners: map[runtimeMetricTargetKey]*exec.FileInfo{key: replacement},
	}

	tracer.deleteRuntimeMetricTarget(key.pid, key.ns, predecessor)
	assert.Contains(t, tracer.runtimeMetricTargetKeys, key)
	assert.Same(t, replacement, tracer.runtimeMetricTargetOwners[key])

	tracer.deleteRuntimeMetricTarget(key.pid, key.ns, replacement)
	assert.NotContains(t, tracer.runtimeMetricTargetKeys, key)
	assert.NotContains(t, tracer.runtimeMetricTargetOwners, key)
}

func TestRuntimeMetricTargetReplacementRetiresPredecessorBeforeEarlyReturn(t *testing.T) {
	key := runtimeMetricTargetKey{pid: 42, ns: 7}
	oldPIDInfo := BpfPidInfo{HostPid: 42, UserPid: 7, Ns: key.ns}
	predecessor := exec.New(exec.Init{Pid: key.pid})
	replacement := exec.New(exec.Init{Pid: key.pid})
	var deleted []BpfPidInfo
	tracer := &Tracer{
		runtimeMetricTargetKeys:   map[runtimeMetricTargetKey]BpfPidInfo{key: oldPIDInfo},
		runtimeMetricTargetOwners: map[runtimeMetricTargetKey]*exec.FileInfo{key: predecessor},
		deleteRuntimeMetricTargetForTest: func(pidInfo BpfPidInfo) error {
			deleted = append(deleted, pidInfo)
			return nil
		},
	}

	// A nil BPF target map forces registerRuntimeMetricTarget's ordinary early
	// return. The predecessor must already be gone before that boundary.
	tracer.registerRuntimeMetricTarget(key.pid, key.ns, replacement, replacement)

	require.Equal(t, []BpfPidInfo{oldPIDInfo}, deleted)
	require.NotContains(t, tracer.runtimeMetricTargetKeys, key)
	require.NotContains(t, tracer.runtimeMetricTargetOwners, key)
}

func TestRuntimeMetricTargetReplacementRetiresPredecessorAcrossNamespaces(t *testing.T) {
	const pid = app.PID(42)
	oldKey := runtimeMetricTargetKey{pid: pid, ns: 7}
	oldPIDInfo := BpfPidInfo{HostPid: uint32(pid), UserPid: 3, Ns: oldKey.ns}
	predecessor := exec.New(exec.Init{Pid: pid})
	replacement := exec.New(exec.Init{Pid: pid})
	var deleted []BpfPidInfo
	registered := 0
	tracer := &Tracer{
		runtimeMetricTargetKeys:   map[runtimeMetricTargetKey]BpfPidInfo{oldKey: oldPIDInfo},
		runtimeMetricTargetOwners: map[runtimeMetricTargetKey]*exec.FileInfo{oldKey: predecessor},
		deleteRuntimeMetricTargetForTest: func(pidInfo BpfPidInfo) error {
			deleted = append(deleted, pidInfo)
			return nil
		},
		registerRuntimeMetricTargetForTest: func(
			app.PID, uint32, *exec.FileInfo, *exec.FileInfo,
		) {
			registered++
		},
	}

	tracer.registerRuntimeMetricTarget(pid, 8, replacement, replacement)

	require.Equal(t, []BpfPidInfo{oldPIDInfo}, deleted)
	require.Equal(t, 1, registered)
	require.NotContains(t, tracer.runtimeMetricTargetKeys, oldKey)
	require.NotContains(t, tracer.runtimeMetricTargetOwners, oldKey)
}

func TestRuntimeMetricTargetCleanupFailureBlocksReplacementAdmission(t *testing.T) {
	const pid = app.PID(42)
	oldKey := runtimeMetricTargetKey{pid: pid, ns: 7}
	oldPIDInfo := BpfPidInfo{HostPid: uint32(pid), UserPid: 3, Ns: oldKey.ns}
	predecessor := exec.New(exec.Init{Pid: pid})
	replacement := exec.New(exec.Init{Pid: pid})
	filter := &allowRecordingFilter{}
	publicationCalls := 0
	tracer := &Tracer{
		log:                         slog.New(slog.NewTextHandler(io.Discard, nil)),
		pidsFilter:                  filter,
		runtimeMetricTargetKeys:     map[runtimeMetricTargetKey]BpfPidInfo{oldKey: oldPIDInfo},
		runtimeMetricTargetOwners:   map[runtimeMetricTargetKey]*exec.FileInfo{oldKey: predecessor},
		goRuntimeMetricMaskByFileID: map[exec.FileID]uint64{},
		goChannelOffsetsByFileID:    map[exec.FileID]bool{},
		deleteRuntimeMetricTargetForTest: func(BpfPidInfo) error {
			return errors.New("injected BPF delete failure")
		},
		registerRuntimeMetricTargetForTest: func(
			app.PID, uint32, *exec.FileInfo, *exec.FileInfo,
		) {
			publicationCalls++
		},
	}

	tracer.AllowPID(pid, 8, replacement, replacement)

	assert.Zero(t, filter.allowed, "replacement tracing must remain fail-closed")
	assert.Zero(t, publicationCalls)
	assert.Equal(t, oldPIDInfo, tracer.runtimeMetricTargetKeys[oldKey],
		"failed cleanup must stay tracked for a later retry")
	assert.Same(t, predecessor, tracer.runtimeMetricTargetOwners[oldKey])
}

func TestRuntimeMetricTargetPostPublicationValidationRollsBack(t *testing.T) {
	const (
		pid = app.PID(42)
		ns  = uint32(7)
	)
	owner := exec.New(exec.Init{Pid: pid})
	pidInfo := BpfPidInfo{HostPid: uint32(pid), UserPid: 3, Ns: ns}
	validations := 0
	puts := 0
	var deleted []BpfPidInfo
	tracer := &Tracer{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		putRuntimeMetricTargetForTest: func(got BpfPidInfo, _ BpfGoRuntimeMetricTargetT) error {
			require.Equal(t, pidInfo, got)
			puts++
			return nil
		},
		deleteRuntimeMetricTargetForTest: func(got BpfPidInfo) error {
			deleted = append(deleted, got)
			return nil
		},
		validateRuntimeMetricOwnerForTest: func(app.PID, *exec.FileInfo) error {
			validations++
			if validations == 1 {
				return nil
			}
			return errors.New("injected post-publication PID reuse")
		},
	}

	tracer.publishRuntimeMetricTarget(
		pid, ns, exec.New(exec.Init{Ino: 9}), owner, pidInfo, BpfGoRuntimeMetricTargetT{},
	)

	require.Equal(t, 1, puts)
	require.Equal(t, []BpfPidInfo{pidInfo}, deleted)
	require.Empty(t, tracer.runtimeMetricTargetKeys)
	require.Empty(t, tracer.runtimeMetricTargetOwners)
}

func TestRegisterOffsetsCannotPublishRuntimeTargetBeforeAllowPID(t *testing.T) {
	publicationCalls := 0
	tracer := &Tracer{
		log:                         slog.New(slog.NewTextHandler(io.Discard, nil)),
		pidsFilter:                  &ebpfcommon.IdentityPidsFilter{},
		goChannelOffsetsByFileID:    map[exec.FileID]bool{},
		goRuntimeMetricMaskByFileID: map[exec.FileID]uint64{},
		putGoOffsetsForTest: func(BpfGoOffsetsKeyT, BpfOffTableT) error {
			return nil
		},
		registerRuntimeMetricTargetForTest: func(
			app.PID, uint32, *exec.FileInfo, *exec.FileInfo,
		) {
			publicationCalls++
		},
	}
	fileInfo := exec.New(exec.Init{Pid: 42, Ino: 7})
	offsets := &goexec.Offsets{Field: goexec.FieldOffsets{
		goexec.RuntimeMemstatsNumGCPos:         uint64(0),
		goexec.RuntimeGCControllerGCPercentPos: uint64(8),
	}}

	require.NoError(t, tracer.RegisterOffsets(fileInfo, offsets))
	assert.Zero(t, publicationCalls,
		"executable registration must not publish process-scoped runtime targets")

	tracer.AllowPID(fileInfo.Pid(), fileInfo.Ns(), fileInfo, fileInfo)
	assert.Equal(t, 1, publicationCalls,
		"the exact PID admission is the runtime-target publication boundary")
}

func TestRegisterOffsetsFailsClosedWhenOffsetMapWriteFails(t *testing.T) {
	writeErr := errors.New("offset map write failed")
	tracer := &Tracer{
		log:                         slog.New(slog.NewTextHandler(io.Discard, nil)),
		goChannelOffsetsByFileID:    map[exec.FileID]bool{},
		goRuntimeMetricMaskByFileID: map[exec.FileID]uint64{},
		putGoOffsetsForTest: func(BpfGoOffsetsKeyT, BpfOffTableT) error {
			return writeErr
		},
	}
	fileInfo := exec.New(exec.Init{Pid: 42, Ino: 7})
	offsets := &goexec.Offsets{Field: goexec.FieldOffsets{}}

	err := tracer.RegisterOffsets(fileInfo, offsets)

	require.ErrorIs(t, err, writeErr)
	assert.Empty(t, tracer.goChannelOffsetsByFileID)
	assert.Empty(t, tracer.goRuntimeMetricMaskByFileID)
	assert.Zero(t, tracer.currentBinaryID)
}

func TestRegisterOffsetsSeparatesSameInodeAcrossDevices(t *testing.T) {
	const ino = uint64(7)
	withoutChannelOffsets := exec.New(exec.Init{Dev: 11, Ino: ino})
	withChannelOffsets := exec.New(exec.Init{Dev: 12, Ino: ino})
	var keys []BpfGoOffsetsKeyT
	tracer := &Tracer{
		putGoOffsetsForTest: func(key BpfGoOffsetsKeyT, _ BpfOffTableT) error {
			keys = append(keys, key)
			return nil
		},
	}

	baseOffsets := &goexec.Offsets{Field: goexec.FieldOffsets{}}
	runtimeOffsets := goChannelOffsets()
	runtimeOffsets.Field[goexec.RuntimeMemstatsNumGCPos] = uint64(64)
	runtimeOffsets.Field[goexec.RuntimeGCControllerGCPercentPos] = uint64(72)

	require.NoError(t, tracer.RegisterOffsets(withoutChannelOffsets, baseOffsets))
	require.NoError(t, tracer.RegisterOffsets(withChannelOffsets, runtimeOffsets))

	require.Equal(t, []BpfGoOffsetsKeyT{
		{Dev: withoutChannelOffsets.Dev(), Ino: ino},
		{Dev: withChannelOffsets.Dev(), Ino: ino},
	}, keys)
	assert.False(t, tracer.goChannelOffsetsByFileID[withoutChannelOffsets.ID()])
	assert.True(t, tracer.goChannelOffsetsByFileID[withChannelOffsets.ID()])
	assert.Equal(t, goRuntimeMetricProcessorLimitMask,
		tracer.goRuntimeMetricMaskByFileID[withoutChannelOffsets.ID()])
	assert.True(t, hasBaseGoRuntimeMetrics(
		tracer.goRuntimeMetricMaskByFileID[withChannelOffsets.ID()]))
}

func TestGoOffsetsMapKeyABI(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)
	mapSpec := spec.Maps[BpfMapGoOffsetsMap]
	require.NotNil(t, mapSpec)

	var key BpfGoOffsetsKeyT
	assert.Equal(t, uintptr(16), unsafe.Sizeof(key))
	assert.Equal(t, uintptr(0), unsafe.Offsetof(key.Dev))
	assert.Equal(t, uintptr(8), unsafe.Offsetof(key.Ino))
	assert.Equal(t, uint32(unsafe.Sizeof(key)), mapSpec.KeySize)
}

func TestMissingGoChannelOffsetsUseSentinel(t *testing.T) {
	var offTable BpfOffTableT

	initMissingGoChannelOffsets(&offTable)

	for _, field := range goChannelOffsetFields {
		assert.Equal(t, missingGoOffset, offTable.Table[field])
	}
	assert.Zero(t, offTable.Table[goexec.ConnFdPos])
}

func TestGoRuntimeMetricAvailability(t *testing.T) {
	baseOffsets := &goexec.Offsets{Field: goexec.FieldOffsets{
		goexec.RuntimeMemstatsNumGCPos:         uint64(0),
		goexec.RuntimeGCControllerGCPercentPos: uint64(8),
	}}

	mask := goRuntimeMetricMask(baseOffsets)
	assert.True(t, hasBaseGoRuntimeMetrics(mask))
	assert.NotZero(t, mask&goRuntimeMetricGCCyclesMask)
	assert.Zero(t, mask&goRuntimeMetricMemoryLimitMask)
	assert.NotZero(t, mask&goRuntimeMetricProcessorLimitMask)
	assert.NotZero(t, mask&goRuntimeMetricGOGCMask)
	assert.Zero(t, mask&goRuntimeMetricCPUTimeMask)
	assert.Zero(t, mask&goRuntimeMetricMemoryUsedMask)
	assert.Zero(t, mask&goRuntimeMetricMemoryAllocsMask)

	baseOffsets.Field[goexec.RuntimeGCControllerMemoryLimitPos] = uint64(16)
	assert.NotZero(t, goRuntimeMetricMask(baseOffsets)&goRuntimeMetricMemoryLimitMask)

	for _, field := range goRuntimeCPUTimeOffsetFields {
		baseOffsets.Field[field] = uint64(field)
	}
	assert.NotZero(t, goRuntimeMetricMask(baseOffsets)&goRuntimeMetricCPUTimeMask)

	delete(baseOffsets.Field, goRuntimeCPUTimeOffsetFields[0])
	assert.Zero(t, goRuntimeMetricMask(baseOffsets)&goRuntimeMetricCPUTimeMask)

	for _, field := range goRuntimeMemoryOffsetFields {
		baseOffsets.Field[field] = uint64(field)
	}
	memoryMask := goRuntimeMetricMask(baseOffsets)
	assert.NotZero(t, memoryMask&goRuntimeMetricMemoryUsedMask)
	assert.NotZero(t, memoryMask&goRuntimeMetricMemoryAllocsMask)

	delete(baseOffsets.Field, goRuntimeMemoryOffsetFields[0])
	memoryMask = goRuntimeMetricMask(baseOffsets)
	assert.Zero(t, memoryMask&goRuntimeMetricMemoryUsedMask)
	assert.Zero(t, memoryMask&goRuntimeMetricMemoryAllocsMask)

	delete(baseOffsets.Field, goexec.RuntimeMemstatsNumGCPos)
	assert.False(t, hasBaseGoRuntimeMetrics(goRuntimeMetricMask(baseOffsets)))
}

func TestGoRuntimeMetricMaskABI(t *testing.T) {
	assert.Equal(t, goRuntimeMetricGCCyclesMask, uint64(1<<0))
	assert.Equal(t, goRuntimeMetricMemoryLimitMask, uint64(1<<1))
	assert.Equal(t, goRuntimeMetricProcessorLimitMask, uint64(1<<2))
	assert.Equal(t, goRuntimeMetricGOGCMask, uint64(1<<3))
	assert.Equal(t, goRuntimeMetricCPUTimeMask, uint64(1<<4))
	assert.Equal(t, goRuntimeMetricMemoryUsedMask, uint64(1<<5))
	assert.Equal(t, goRuntimeMetricMemoryAllocsMask, uint64(1<<6))
}

func TestGoRuntimeMetricsUseHeapSnapshotProbe(t *testing.T) {
	disableContextPropagationForTest(t)

	ids := []exec.FileID{
		{Dev: 1, Ino: 7},
		{Dev: 2, Ino: 7},
		{Dev: 3, Ino: 7},
	}
	tracer := &Tracer{
		currentBinaryID: ids[0],
		goRuntimeMetricMaskByFileID: map[exec.FileID]uint64{
			ids[0]: goRuntimeMetricBaseMask,
			ids[1]: goRuntimeMetricBaseMask | goRuntimeMetricCPUTimeMask,
			ids[2]: goRuntimeMetricBaseMask | goRuntimeMetricMemoryUsedMask,
		},
	}

	probes := tracer.GoProbes()
	require.Contains(t, probes, "runtime.gcMarkDone")
	assert.NotContains(t, probes, "runtime.(*scavengeIndex).nextGen")

	tracer.currentBinaryID = ids[1]
	probes = tracer.GoProbes()
	require.Contains(t, probes, "runtime.gcMarkDone")
	assert.NotContains(t, probes, "runtime.(*scavengeIndex).nextGen")

	tracer.currentBinaryID = ids[2]
	probes = tracer.GoProbes()
	require.Contains(t, probes, "runtime.(*scavengeIndex).nextGen")
	assert.NotContains(t, probes, "runtime.gcMarkDone")
}

func TestGoRuntimeMetricsFallBackWhenHeapProbeIsMissing(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}
	disableContextPropagationForTest(t)

	var logs bytes.Buffer
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(&logs, nil))}
	fileInfo := exec.New(exec.Init{
		ELF:        currentExecutableELF(t),
		Ino:        1,
		Pid:        123,
		CmdExePath: "/test/server",
	})
	offsets := goRuntimeMetricOffsets()

	tracer.recordGoRuntimeMetricAvailability(fileInfo, offsets)
	tracer.ProcessBinary(fileInfo)

	mask := tracer.goRuntimeMetricMaskByFileID[fileInfo.ID()]
	assert.True(t, hasBaseGoRuntimeMetrics(mask))
	assert.NotZero(t, mask&goRuntimeMetricMemoryLimitMask)
	assert.NotZero(t, mask&goRuntimeMetricProcessorLimitMask)
	assert.NotZero(t, mask&goRuntimeMetricCPUTimeMask)
	assert.Zero(t, mask&goRuntimeMetricHeapSnapshotMask)

	probes := tracer.GoProbes()
	require.Contains(t, probes, goRuntimeMetricProbeSymbols[0])
	assert.NotContains(t, probes, goRuntimeMetricProbeSymbols[1])
	assert.Contains(t, logs.String(), "Go runtime heap metric symbol unresolved; using scalar fallback")
}

func TestGoRuntimeMetricsUseResolvedHeapProbe(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}
	disableContextPropagationForTest(t)

	tracer := &Tracer{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	fileInfo := exec.New(exec.Init{ELF: currentExecutableELF(t), Ino: 1})
	offsets := goRuntimeMetricOffsets()
	offsets.Funcs[goRuntimeMetricProbeSymbols[1]] = goexec.FuncOffsets{}

	tracer.recordGoRuntimeMetricAvailability(fileInfo, offsets)
	tracer.ProcessBinary(fileInfo)

	mask := tracer.goRuntimeMetricMaskByFileID[fileInfo.ID()]
	assert.NotZero(t, mask&goRuntimeMetricCPUTimeMask)
	assert.Equal(t, goRuntimeMetricHeapSnapshotMask, mask&goRuntimeMetricHeapSnapshotMask)

	probes := tracer.GoProbes()
	require.Contains(t, probes, goRuntimeMetricProbeSymbols[1])
	assert.NotContains(t, probes, goRuntimeMetricProbeSymbols[0])
}

func TestGoRuntimeMetricMaskRequiresSizeClassTableForAllocations(t *testing.T) {
	var logs bytes.Buffer
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(&logs, nil))}
	fileInfo := exec.New(exec.Init{Ino: 1, Pid: 123, CmdExePath: "/test/server"})
	mask := goRuntimeMetricBaseMask |
		goRuntimeMetricCPUTimeMask |
		goRuntimeMetricMemoryUsedMask |
		goRuntimeMetricMemoryAllocsMask

	got := tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, goexec.RuntimeMetricSymbols{})

	assert.Zero(t, got&goRuntimeMetricMemoryAllocsMask)
	assert.NotZero(t, got&goRuntimeMetricMemoryUsedMask)
	assert.NotZero(t, got&goRuntimeMetricCPUTimeMask)
	assert.True(t, hasBaseGoRuntimeMetrics(got))
	assert.Contains(t, logs.String(),
		"Go runtime size-class table symbol unresolved; disabling allocation metrics")
}

func TestGoRuntimeMetricMaskKeepsAllocationsWithSizeClassTable(t *testing.T) {
	var logs bytes.Buffer
	tracer := &Tracer{log: slog.New(slog.NewTextHandler(&logs, nil))}
	fileInfo := exec.New(exec.Init{Ino: 1})
	mask := goRuntimeMetricBaseMask | goRuntimeMetricMemoryAllocsMask

	got := tracer.goRuntimeMetricMaskForSymbols(fileInfo, mask, goexec.RuntimeMetricSymbols{
		SizeClassToSizesAddr: 0x1234,
	})

	assert.Equal(t, mask, got)
	assert.Empty(t, logs.String())
}

func TestProcessBinarySelectsRecordedChannelOffsetState(t *testing.T) {
	const ino = uint64(7)
	withOffsets := exec.FileID{Dev: 1, Ino: ino}
	withoutOffsets := exec.FileID{Dev: 2, Ino: ino}
	tracer := &Tracer{
		goChannelOffsetsByFileID: map[exec.FileID]bool{
			withOffsets:    true,
			withoutOffsets: false,
		},
	}

	tracer.ProcessBinary(exec.New(exec.Init{Dev: withOffsets.Dev, Ino: ino}))
	assert.True(t, tracer.goChannelLinkProbesEnabled())

	tracer.ProcessBinary(exec.New(exec.Init{Dev: withoutOffsets.Dev, Ino: ino}))
	assert.False(t, tracer.goChannelLinkProbesEnabled())

	tracer.ProcessBinary(nil)
	assert.False(t, tracer.goChannelLinkProbesEnabled())
}

func TestJavaRemoteParentModeSelectsConsumerProtocolAndMapSizes(t *testing.T) {
	disableContextPropagationForTest(t)

	unsupported := errors.New("network namespace cookie helper unavailable")
	for _, tt := range []struct {
		configured    bool
		probeErr      error
		expected      bool
		expectedCalls int
	}{
		{configured: false, expected: false},
		{configured: true, expected: true, expectedCalls: 1},
		{configured: true, probeErr: unsupported, expected: false, expectedCalls: 1},
	} {
		name := fmt.Sprintf("configured=%t/supported=%t", tt.configured, tt.probeErr == nil)
		t.Run(name, func(t *testing.T) {
			probeCalls := 0
			tracer := &Tracer{
				log:                        slog.New(slog.NewTextHandler(io.Discard, nil)),
				cfg:                        &config.EBPFTracer{},
				javaRemoteParentConfigured: tt.configured,
				haveSockOpsNetnsCookie: func() error {
					probeCalls++
					return tt.probeErr
				},
			}

			bundles, err := tracer.LoadSpecs()
			require.NoError(t, err)
			require.Len(t, bundles, 1)
			assert.Equal(t, tt.expectedCalls, probeCalls)
			assert.Equal(t, tt.expected, bundles[0].Constants["java_remote_parent_enabled"])
			writeArgs := bundles[0].Spec.Maps["active_ssl_write_args"]
			require.NotNil(t, writeArgs)
			assert.Equal(t, uint32(16), writeArgs.KeySize)
			assert.Equal(t, uint32(64), writeArgs.ValueSize)
			assert.Equal(t, ebpf.LRUHash, writeArgs.Type)

			for _, name := range []string{"incoming_trace_heads", "incoming_trace_candidates"} {
				mapSpec := bundles[0].Spec.Maps[name]
				require.NotNil(t, mapSpec, name)
				if tt.expected {
					assert.Greater(t, mapSpec.MaxEntries, uint32(1), name)
				} else {
					assert.Equal(t, uint32(1), mapSpec.MaxEntries, name)
				}
			}
		})
	}
}

func goChannelOffsets() *goexec.Offsets {
	return &goexec.Offsets{Field: goexec.FieldOffsets{
		goexec.HchanQcountPos:   uint64(0),
		goexec.HchanDataqsizPos: uint64(8),
		goexec.HchanSendxPos:    uint64(48),
		goexec.HchanRecvxPos:    uint64(56),
	}}
}

func goRuntimeMetricOffsets() *goexec.Offsets {
	offsets := &goexec.Offsets{
		Funcs: map[string]goexec.FuncOffsets{
			goRuntimeMetricProbeSymbols[0]: {},
		},
		Field: goexec.FieldOffsets{},
	}
	for _, field := range goRuntimeMetricOffsetFields {
		offsets.Field[field] = uint64(field)
	}
	return offsets
}

func currentExecutableELF(t *testing.T) *elf.File {
	t.Helper()

	executable, err := os.Executable()
	require.NoError(t, err)

	elfFile, err := elf.Open(executable)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, elfFile.Close())
	})
	return elfFile
}

func assertNoGoChannelLinkProbes(t *testing.T, probes map[string][]*ebpfcommon.ProbeDesc) {
	t.Helper()

	for _, symbol := range GoChannelLinkProbeSymbols() {
		assert.NotContains(t, probes, symbol)
	}
}

func disableContextPropagationForTest(t *testing.T) {
	t.Helper()

	previous := ebpfcommon.IntegrityModeOverride
	ebpfcommon.IntegrityModeOverride = true
	t.Cleanup(func() {
		ebpfcommon.IntegrityModeOverride = previous
	})
}
