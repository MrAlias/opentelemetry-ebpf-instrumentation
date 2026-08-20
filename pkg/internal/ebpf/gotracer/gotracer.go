// Copyright The OpenTelemetry Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gotracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/javabridge"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../../bpf/gotracer/gotracer.c -- -I../../../../bpf

type runtimeMetricTargetKey struct {
	pid app.PID
	ns  uint32
}

type executableIdentity = BpfGoExecutableKeyT

// Linux's internal dev_t reserves its lower 20 bits for the minor number.
const linuxMinorDeviceBits = 20

func kernelDeviceNumber(dev uint64) uint64 {
	return uint64(unix.Major(dev))<<linuxMinorDeviceBits | uint64(unix.Minor(dev))
}

func goOffsetsMapKey(fileInfo *exec.FileInfo) executableIdentity {
	return executableIdentity{
		Dev: kernelDeviceNumber(fileInfo.Dev()),
		Ino: fileInfo.Ino(),
	}
}

type goAutoSDKTargetState struct {
	generation         uint64
	needsRotation      bool
	cleanupGenerations []uint64
	owner              *exec.FileInfo
	dev                uint64
	ino                uint64
	startTime          uint64
	lifecycleEpoch     uint64
	activated          bool
}

type goProcessLifecycleEpochState struct {
	owner *exec.FileInfo
	epoch uint64
}

type goAutoSDKActivationLinkKey struct {
	pid        app.PID
	generation uint64
}

type goAutoSDKActivationProbe struct {
	program *ebpf.Program
	offset  uint64
}

type goAutoSDKExecutableKey struct {
	dev uint64
	ino uint64
}

func normalizeDeviceID[T ~int32 | ~uint64](dev T) uint64 {
	return uint64(dev)
}

type goAutoSDKActivationLink struct {
	executable goAutoSDKExecutableKey
	link       *onceCloser
}

type onceCloser struct {
	closer io.Closer
	once   sync.Once
	err    error
}

func (c *onceCloser) Close() error {
	c.once.Do(func() {
		if c.closer != nil {
			c.err = c.closer.Close()
		}
	})
	return c.err
}

type goAutoSDKActivationEvent struct {
	Type       uint8
	Pad        [3]uint8
	Pid        uint32
	Generation uint64
}

const missingGoOffset = ^uint64(0)

const goAutoSDKActivationMaxAttempts = 3

var nextRuntimeMetricGeneration atomic.Uint64

func newRuntimeMetricGeneration() uint64 {
	for {
		if generation := nextRuntimeMetricGeneration.Add(1); generation != 0 {
			return generation
		}
	}
}

// Mirrors go_runtime_metric_valid_t in bpf/gotracer/maps/runtime.h. Scalar
// bits also mirror the raw snapshot masks in pkg/runtimemetrics/reader.go.
const (
	goRuntimeMetricGCCyclesMask                  uint64 = 1 << 0
	goRuntimeMetricMemoryLimitMask               uint64 = 1 << 1
	goRuntimeMetricProcessorLimitMask            uint64 = 1 << 2
	goRuntimeMetricGOGCMask                      uint64 = 1 << 3
	goRuntimeMetricCPUTimeMask                   uint64 = 1 << 4
	goRuntimeMetricMemoryUsedMask                uint64 = 1 << 5
	goRuntimeMetricMemoryAllocsMask              uint64 = 1 << 6
	goRuntimeMetricGCPauseHistogramMask          uint64 = 1 << 7
	goRuntimeMetricScheduleDurationHistogramMask uint64 = 1 << 8
	goRuntimeMetricGoroutineCountMask            uint64 = 1 << 9
	goRuntimeMetricMemoryGCGoalMask              uint64 = 1 << 10
)

type goRuntimeGCGoalSource uint32

const (
	goRuntimeGCGoalSourceNone goRuntimeGCGoalSource = iota
	goRuntimeGCGoalSourceHeapGoalField
	goRuntimeGCGoalSourcePaceScavengerArgument
)

const goRuntimeMetricBaseMask = goRuntimeMetricGCCyclesMask | goRuntimeMetricGOGCMask

const goRuntimeMetricHeapSnapshotMask = goRuntimeMetricMemoryUsedMask |
	goRuntimeMetricMemoryAllocsMask

const goRuntimeMetricHistogramMask = goRuntimeMetricGCPauseHistogramMask |
	goRuntimeMetricScheduleDurationHistogramMask

const (
	goRuntimeHistogramMaxBuckets uint64 = 160
	goRuntimeHistogramBucketSize uint64 = 8
)

var goChannelOffsetFields = [...]goexec.GoOffset{
	goexec.HchanQcountPos,
	goexec.HchanDataqsizPos,
	goexec.HchanSendxPos,
	goexec.HchanRecvxPos,
}

var goAutoSDKSpanContextOffsetFields = [...]goexec.GoOffset{
	goexec.SpanContextTraceIDPos,
	goexec.SpanContextSpanIDPos,
	goexec.SpanContextTraceFlagsPos,
	goexec.AutoSDKSpanContextPos,
	goexec.AutoSDKActivationSupported,
}

var goRuntimeMetricOffsetFields = [...]goexec.GoOffset{
	goexec.RuntimeMemstatsNumGCPos,
	goexec.RuntimeGCControllerMemoryLimitPos,
	goexec.RuntimeGCControllerGCPercentPos,
	goexec.RuntimeWorkCPUStatsPos,
	goexec.RuntimeCPUStatsGCAssistTimePos,
	goexec.RuntimeCPUStatsGCDedicatedTimePos,
	goexec.RuntimeCPUStatsGCIdleTimePos,
	goexec.RuntimeCPUStatsGCPauseTimePos,
	goexec.RuntimeCPUStatsScavengeAssistTimePos,
	goexec.RuntimeCPUStatsScavengeBgTimePos,
	goexec.RuntimeCPUStatsIdleTimePos,
	goexec.RuntimeCPUStatsUserTimePos,
	goexec.RuntimeMemstatsHeapStatsPos,
	goexec.RuntimeMemstatsStacksSysPos,
	goexec.RuntimeMemstatsMspanSysPos,
	goexec.RuntimeMemstatsMcacheSysPos,
	goexec.RuntimeMemstatsBuckhashSysPos,
	goexec.RuntimeMemstatsGCMiscSysPos,
	goexec.RuntimeMemstatsOtherSysPos,
	goexec.RuntimeConsistentHeapStatsStatsPos,
	goexec.RuntimeHeapStatsDeltaCommittedPos,
	goexec.RuntimeHeapStatsDeltaInStacksPos,
	goexec.RuntimeHeapStatsDeltaLargeAllocPos,
	goexec.RuntimeHeapStatsDeltaLargeAllocCountPos,
	goexec.RuntimeHeapStatsDeltaSmallAllocCountPos,
	goexec.RuntimeHeapStatsDeltaSmallFreeCountPos,
	goexec.RuntimeSchedNgSysPos,
	goexec.RuntimeSchedGFreeStackPos,
	goexec.RuntimeSchedGFreeNoStackPos,
	goexec.RuntimePFreeGPos,
	goexec.RuntimeGListSizePos,
	goexec.RuntimeGCControllerHeapGoalPos,
	goexec.RuntimeSchedTimeToRunPos,
	goexec.RuntimeSchedSTWTotalTimeGCPos,
	goexec.RuntimeTimeHistogramUnderflowPos,
	goexec.RuntimeTimeHistogramOverflowPos,
}

var goRuntimeCPUTimeOffsetFields = [...]goexec.GoOffset{
	goexec.RuntimeWorkCPUStatsPos,
	goexec.RuntimeCPUStatsGCAssistTimePos,
	goexec.RuntimeCPUStatsGCDedicatedTimePos,
	goexec.RuntimeCPUStatsGCIdleTimePos,
	goexec.RuntimeCPUStatsGCPauseTimePos,
	goexec.RuntimeCPUStatsScavengeAssistTimePos,
	goexec.RuntimeCPUStatsScavengeBgTimePos,
	goexec.RuntimeCPUStatsIdleTimePos,
	goexec.RuntimeCPUStatsUserTimePos,
}

var goRuntimeMemoryOffsetFields = [...]goexec.GoOffset{
	goexec.RuntimeMemstatsHeapStatsPos,
	goexec.RuntimeMemstatsStacksSysPos,
	goexec.RuntimeMemstatsMspanSysPos,
	goexec.RuntimeMemstatsMcacheSysPos,
	goexec.RuntimeMemstatsBuckhashSysPos,
	goexec.RuntimeMemstatsGCMiscSysPos,
	goexec.RuntimeMemstatsOtherSysPos,
	goexec.RuntimeConsistentHeapStatsStatsPos,
	goexec.RuntimeHeapStatsDeltaCommittedPos,
	goexec.RuntimeHeapStatsDeltaInStacksPos,
	goexec.RuntimeHeapStatsDeltaLargeAllocPos,
	goexec.RuntimeHeapStatsDeltaLargeAllocCountPos,
	goexec.RuntimeHeapStatsDeltaSmallAllocCountPos,
	goexec.RuntimeHeapStatsDeltaSmallFreeCountPos,
}

var goRuntimeGoroutineCountCommonOffsetFields = [...]goexec.GoOffset{
	goexec.RuntimeSchedGFreeStackPos,
	goexec.RuntimeSchedGFreeNoStackPos,
	goexec.RuntimePFreeGPos,
	goexec.RuntimeGListSizePos,
}

var goRuntimeMetricOffsetGroups = [...]struct {
	mask   uint64
	fields []goexec.GoOffset
}{
	{goRuntimeMetricGCCyclesMask, []goexec.GoOffset{goexec.RuntimeMemstatsNumGCPos}},
	{goRuntimeMetricMemoryLimitMask, []goexec.GoOffset{goexec.RuntimeGCControllerMemoryLimitPos}},
	{goRuntimeMetricGOGCMask, []goexec.GoOffset{goexec.RuntimeGCControllerGCPercentPos}},
	{goRuntimeMetricCPUTimeMask, goRuntimeCPUTimeOffsetFields[:]},
	{goRuntimeMetricMemoryUsedMask | goRuntimeMetricMemoryAllocsMask, goRuntimeMemoryOffsetFields[:]},
	{goRuntimeMetricGCPauseHistogramMask, []goexec.GoOffset{
		goexec.RuntimeSchedSTWTotalTimeGCPos,
		goexec.RuntimeTimeHistogramUnderflowPos,
		goexec.RuntimeTimeHistogramOverflowPos,
	}},
	{goRuntimeMetricScheduleDurationHistogramMask, []goexec.GoOffset{
		goexec.RuntimeSchedTimeToRunPos,
		goexec.RuntimeTimeHistogramUnderflowPos,
		goexec.RuntimeTimeHistogramOverflowPos,
	}},
}

var supportsContextPropagationWithProbe = ebpfcommon.SupportsContextPropagationWithProbe

type Tracer struct {
	log                               *slog.Logger
	pidsFilter                        ebpfcommon.ServiceFilter
	cfg                               *config.EBPFTracer
	metrics                           imetrics.Reporter
	bpfObjects                        BpfObjects
	closers                           []io.Closer
	disabledRouteHarvesting           bool
	javaRemoteParentConfigured        bool
	javaRemoteParentEnabled           bool
	haveSockOpsNetnsCookie            func() error
	supportsBPFLoop                   bool
	runtimeMetricTargetKeys           map[runtimeMetricTargetKey]BpfPidInfo
	runtimeMetricTargetOwners         map[runtimeMetricTargetKey]*exec.FileInfo
	goChannelOffsetsByExecutable      map[executableIdentity]bool
	goRuntimeMetricMaskByExecutable   map[executableIdentity]uint64
	goRuntimeGCGoalSourceByExecutable map[executableIdentity]goRuntimeGCGoalSource
	currentBinary                     executableIdentity
	goAutoSDKActivationByExecutable   map[executableIdentity]bool
	goAutoSDKTargetsMu                sync.Mutex
	goAutoSDKTargets                  map[app.PID]goAutoSDKTargetState
	goAutoSDKActivationProbes         map[goAutoSDKExecutableKey]goAutoSDKActivationProbe
	goAutoSDKActivationLinks          map[goAutoSDKActivationLinkKey]goAutoSDKActivationLink
	goAutoSDKTargetGeneration         uint64
	goAutoSDKTargetMap                mapKeyPutDeleter
	goAutoSDKAttemptMap               mapKeyDeleter
	goProcessLifecycleEpochs          map[app.PID]goProcessLifecycleEpochState
	attachGoAutoSDKProbe              func(goAutoSDKActivationProbe, app.PID, uint64, uint64, uint64) (io.Closer, error)
	goAutoSDKProcessStartTime         func(app.PID) (uint64, error)
	// Test seams for the two lifecycle boundaries in RegisterOffsets/AllowPID.
	// Production instances leave these nil and use the loaded BPF maps.
	putGoOffsetsForTest                  func(executableIdentity, BpfOffTableT) error
	registerRuntimeMetricTargetForTest   func(app.PID, uint32, *exec.FileInfo, *exec.FileInfo)
	deleteRuntimeMetricTargetForTest     func(BpfPidInfo) error
	putRuntimeMetricTargetForTest        func(BpfPidInfo, BpfGoRuntimeMetricTargetT) error
	validateRuntimeMetricOwnerForTest    func(app.PID, *exec.FileInfo) error
	newGoProcessLifecycleEpochForTest    func() (uint64, error)
	lookupGoProcessLifecycleEpochForTest func(uint32) (uint64, error)
	putGoProcessLifecycleEpochForTest    func(uint32, uint64) error
	deleteGoProcessLifecycleEpochForTest func(uint32) error
}

func New(
	pidFilter ebpfcommon.ServiceFilter,
	cfg *obi.Config,
	metrics imetrics.Reporter,
) *Tracer {
	log := slog.With("component", "go.Tracer")

	disabledRouteHarvesting := false

	for _, lang := range cfg.Discovery.DisabledRouteHarvesters {
		if lang == services.RouteHarvesterLanguageGo {
			disabledRouteHarvesting = true
			break
		}
	}

	return &Tracer{
		log:                               log,
		pidsFilter:                        pidFilter,
		cfg:                               &cfg.EBPF,
		metrics:                           metrics,
		disabledRouteHarvesting:           disabledRouteHarvesting,
		javaRemoteParentConfigured:        cfg.Java.RemoteParent.Enabled(),
		haveSockOpsNetnsCookie:            javabridge.HaveSockOpsNetnsCookie,
		supportsBPFLoop:                   ebpfcommon.SupportsEBPFLoops(log, cfg.EBPF.OverrideBPFLoopEnabled),
		runtimeMetricTargetKeys:           map[runtimeMetricTargetKey]BpfPidInfo{},
		runtimeMetricTargetOwners:         map[runtimeMetricTargetKey]*exec.FileInfo{},
		goChannelOffsetsByExecutable:      map[executableIdentity]bool{},
		goRuntimeMetricMaskByExecutable:   map[executableIdentity]uint64{},
		goRuntimeGCGoalSourceByExecutable: map[executableIdentity]goRuntimeGCGoalSource{},
		goAutoSDKActivationByExecutable:   map[executableIdentity]bool{},
		goAutoSDKTargets:                  map[app.PID]goAutoSDKTargetState{},
		goAutoSDKActivationProbes:         map[goAutoSDKExecutableKey]goAutoSDKActivationProbe{},
		goAutoSDKActivationLinks:          map[goAutoSDKActivationLinkKey]goAutoSDKActivationLink{},
		goProcessLifecycleEpochs:          map[app.PID]goProcessLifecycleEpochState{},
		attachGoAutoSDKProbe:              attachGoAutoSDKActivationProbe,
		goAutoSDKProcessStartTime:         readGoAutoSDKProcessStartTime,
	}
}

func (p *Tracer) AllowPID(pid app.PID, ns uint32, fi, owner *exec.FileInfo) bool {
	if owner == nil {
		owner = fi
	}
	p.goAutoSDKTargetsMu.Lock()
	lifecycleEpoch := uint64(0)
	if !p.pidsFilter.AllowPID(
		pid, ns, fi, owner, ebpfcommon.PIDTypeGo,
		func() bool {
			// Rotate the separately authoritative kernel lifetime token before
			// retiring process-scoped targets. A target that cannot be deleted is
			// already inert when this commit rejects the replacement.
			epoch, _, err := p.establishGoProcessLifecycleEpoch(pid, owner)
			if err != nil {
				if p.log != nil {
					p.log.Error("establishing Go process lifecycle epoch failed; rejecting admission",
						"pid", pid, "error", err)
				}
				return false
			}
			if !p.retireRuntimeMetricTargetReplacement(pid, ns, owner) {
				if err := p.invalidateGoProcessLifecycleEpoch(pid, owner); err != nil && p.log != nil {
					p.log.Error("invalidating Go lifecycle epoch after admission cleanup failure failed",
						"pid", pid, "error", err)
				}
				return false
			}
			lifecycleEpoch = epoch
			return true
		},
	) {
		p.goAutoSDKTargetsMu.Unlock()
		return false
	}
	ino := uint64(0)
	dev := uint64(0)
	if fi != nil {
		ino = fi.Ino()
		dev = fi.Dev()
	}
	startTime := uint64(0)
	var identityErr error
	if p.goAutoSDKProcessStartTime != nil {
		startTime, identityErr = p.goAutoSDKProcessStartTime(pid)
		if identityErr == nil && startTime == 0 {
			identityErr = errors.New("target process start time is unavailable")
		}
		if identityErr != nil && p.log != nil {
			p.log.Debug("reading Go Auto SDK target identity failed",
				"pid", pid, "error", identityErr)
		}
		if identityErr == nil && owner != nil && owner.ProcessStartTime() != 0 &&
			startTime != owner.ProcessStartTime() {
			identityErr = errors.New("target process lifetime changed")
		}
	} else {
		identityErr = errors.New("target process identity reader is unavailable")
	}
	state := p.goAutoSDKTargets[pid]
	processChanged := startTime != 0 &&
		(state.startTime == 0 || state.startTime != startTime)
	if state.generation != 0 &&
		(state.owner != owner || state.dev != dev || state.ino != ino || processChanged ||
			state.lifecycleEpoch != lifecycleEpoch) {
		p.disableGoAutoSDKTarget(pid)
		p.closeGoAutoSDKActivationLinksLocked(func(key goAutoSDKActivationLinkKey, _ goAutoSDKActivationLink) bool {
			return key.pid == pid
		})
	}
	generation := uint64(0)
	err := identityErr
	if err == nil {
		generation, err = p.enableGoAutoSDKTarget(
			pid, dev, ino, startTime, lifecycleEpoch, owner,
		)
		if err == nil {
			err = p.ensureGoAutoSDKActivationLinkLocked(pid, ino, generation)
		}
	}
	if err != nil {
		// Never leave a generation enabled when its exact process identity or
		// process-scoped activation link could not be established. A later Allow
		// retries from a fresh generation.
		p.disableGoAutoSDKTarget(pid)
		p.closeGoAutoSDKActivationLinksLocked(func(key goAutoSDKActivationLinkKey, _ goAutoSDKActivationLink) bool {
			return key.pid == pid
		})
		if p.log != nil {
			p.log.Warn("attaching process-scoped Go Auto SDK activation probe failed",
				"pid", pid, "generation", generation, "error", err)
		}
	}
	p.registerRuntimeMetricTarget(pid, ns, fi, owner, lifecycleEpoch)
	p.goAutoSDKTargetsMu.Unlock()
	return true
}

func (p *Tracer) BlockPID(pid app.PID, ns uint32, fi, owner *exec.FileInfo) {
	if owner == nil {
		owner = fi
	}
	p.goAutoSDKTargetsMu.Lock()
	if err := p.invalidateGoProcessLifecycleEpoch(pid, owner); err != nil && p.log != nil {
		p.log.Error("invalidating Go lifecycle epoch during process cleanup failed",
			"pid", pid, "error", err)
	}
	p.deleteRuntimeMetricTarget(pid, ns, owner)
	state, tracked := p.goAutoSDKTargets[pid]
	ownerMatches := !tracked || owner == nil || state.owner == owner
	if ownerMatches {
		p.disableGoAutoSDKTarget(pid)
		p.closeGoAutoSDKActivationLinksLocked(func(key goAutoSDKActivationLinkKey, _ goAutoSDKActivationLink) bool {
			return key.pid == pid
		})
	}
	p.pidsFilter.BlockPID(pid, ns, fi, owner)
	p.goAutoSDKTargetsMu.Unlock()
}

func (p *Tracer) supportsContextPropagation() bool {
	return !ebpfcommon.IntegrityModeOverride && supportsContextPropagationWithProbe(p.log)
}

func (p *Tracer) headerPropagationEnabled() bool {
	return p != nil && p.cfg != nil && p.cfg.ContextPropagation.HasHeaders() &&
		p.supportsContextPropagation()
}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	if !p.supportsContextPropagation() {
		p.log.Info("Kernel in lockdown mode or missing CAP_SYS_ADMIN.")
	}

	if p.cfg.TrackRequestHeaders ||
		p.cfg.ContextPropagation.IsEnabled() {
		p.log.Info("Enabling trace information parsing", "bpf_loop_enabled", ebpfcommon.SupportsEBPFLoops(p.log, p.cfg.OverrideBPFLoopEnabled))
	}

	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}

	ebpfcommon.FixupSpec(spec, p.cfg.OverrideBPFLoopEnabled)
	p.javaRemoteParentEnabled = p.javaRemoteParentConfigured &&
		p.haveSockOpsNetnsCookie() == nil
	if !p.javaRemoteParentEnabled {
		javabridge.MinimizeDisabledMaps(spec)
	}

	return []*ebpfcommon.SpecBundle{{
		Spec:      spec,
		Objects:   &p.bpfObjects,
		Constants: p.constants(),
	}}, nil
}

func (p *Tracer) constants() map[string]any {
	blackBoxCP := uint32(0)
	if p.cfg.DisableBlackBoxCP {
		blackBoxCP = uint32(1)
	}

	m := map[string]any{
		"g_bpf_debug":                    p.cfg.BpfDebug,
		"g_bpf_header_propagation":       p.cfg.ContextPropagation.HasHeaders(),
		"g_bpf_probe_write_user_enabled": p.supportsContextPropagation(),
		"wakeup_data_bytes":              uint32(p.cfg.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{})),
		"disable_black_box_cp":           blackBoxCP,
		"attr_type_invalid":              uint64(attribute.INVALID),
		"attr_type_bool":                 uint64(attribute.BOOL),
		"attr_type_int64":                uint64(attribute.INT64),
		"attr_type_float64":              uint64(attribute.FLOAT64),
		"attr_type_string":               uint64(attribute.STRING),
		"attr_type_boolslice":            uint64(attribute.BOOLSLICE),
		"attr_type_int64slice":           uint64(attribute.INT64SLICE),
		"attr_type_float64slice":         uint64(attribute.FLOAT64SLICE),
		"attr_type_stringslice":          uint64(attribute.STRINGSLICE),
		"g_bpf_traceparent_enabled":      true,
		"g_bpf_loop_enabled":             p.supportsBPFLoop,
		"java_remote_parent_enabled":     p.javaRemoteParentEnabled,
	}

	if p.cfg.TrackRequestHeaders ||
		p.cfg.ContextPropagation.IsEnabled() {
		m["capture_header_buffer"] = int32(1)
	} else {
		m["capture_header_buffer"] = int32(0)
	}

	if p.cfg.HighRequestVolume {
		m["high_request_volume"] = uint32(1)
	} else {
		m["high_request_volume"] = uint32(0)
	}

	m["http_max_captured_bytes"] = p.cfg.BufferSizes.HTTP
	m["tcp_max_captured_bytes"] = p.cfg.BufferSizes.TCP
	m["mysql_max_captured_bytes"] = p.cfg.BufferSizes.MySQL
	m["kafka_max_captured_bytes"] = p.cfg.BufferSizes.Kafka
	m["postgres_max_captured_bytes"] = p.cfg.BufferSizes.Postgres
	m["max_transaction_time"] = uint64(p.cfg.MaxTransactionTime.Nanoseconds())

	return m
}

func (p *Tracer) SetupTailCalls() {
	// Order must match the k_tail_* enum in bpf/generictracer/k_tracer_tailcall.h
	for i, prog := range []*ebpf.Program{
		// HTTP/1
		p.bpfObjects.ObiProtocolHttp,           // 0  k_tail_protocol_http
		p.bpfObjects.ObiContinueProtocolHttp,   // 1  k_tail_continue_protocol_http
		p.bpfObjects.ObiContinue2ProtocolHttp,  // 2  k_tail_continue2_protocol_http
		p.bpfObjects.ObiContinueProtocolHttpTp, // 3  k_tail_continue_protocol_http_tp
		// TCP
		p.bpfObjects.ObiProtocolTcp, // 4  k_tail_protocol_tcp
		// Generic
		p.bpfObjects.ObiHandleBufWithArgs, // 5  k_tail_handle_buf_with_args
		p.bpfObjects.ObiContinueNetfdRead, // 6  k_tail_continue_netfd_read
		// HTTP/2 + gRPC
		p.bpfObjects.ObiProtocolHttp2,                                   // 7
		p.bpfObjects.ObiProtocolHttp2GrpcFrames,                         // 8
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrame,               // 9
		p.bpfObjects.ObiProtocolHttp2GrpcHandleEndFrame,                 // 10
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServer,         // 11
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServerFinalize, // 12
		// Large buffer multi-batch emission
		p.bpfObjects.ObiLargeBufEmitContinue,                            // 13  k_tail_large_buf_emit_continue
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServerCommit,   // 14
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServerHuffman,  // 15
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServerHuffscan, // 16
		// Traceparent validation
		p.bpfObjects.ObiContinueProtocolHttpTpValidate, // 17
	} {
		p.log.Debug("loading program into tail call jump table", "index", i, "program", prog.String())
		if err := p.bpfObjects.JumpTable.Update(uint32(i), uint32(prog.FD()), ebpf.UpdateAny); err != nil {
			p.log.Error("error loading info tail call jump table", "error", err)
		}
	}
}

func (p *Tracer) RegisterOffsets(fileInfo *exec.FileInfo, offsets *goexec.Offsets) error {
	offTable := BpfOffTableT{}
	initMissingGoChannelOffsets(&offTable)
	initMissingGoAutoSDKSpanContextOffsets(&offTable)
	// Set the field offsets and the logLevel for the Go BPF program in a map
	for _, field := range []goexec.GoOffset{
		goexec.ConnFdPos,
		goexec.FdLaddrPos,
		goexec.FdRaddrPos,
		goexec.TCPAddrPortPtrPos,
		goexec.TCPAddrIPPtrPos,
		// http
		goexec.URLPtrPos,
		goexec.PathPtrPos,
		goexec.RawQueryPtrPos,
		goexec.HostPtrPos,
		goexec.SchemePtrPos,
		goexec.MethodPtrPos,
		goexec.StatusCodePtrPos,
		goexec.ResponseLengthPtrPos,
		goexec.ContentLengthPtrPos,
		goexec.ReqHeaderPtrPos,
		goexec.IoWriterBufPtrPos,
		goexec.IoWriterNPos,
		goexec.IoWriterWrPos,
		goexec.CcNextStreamIDPos,
		goexec.CcNextStreamIDVendoredPos,
		goexec.CcFramerPos,
		goexec.CcFramerVendoredPos,
		goexec.FramerWPos,
		goexec.PcConnPos,
		goexec.PcTLSPos,
		goexec.NetConnPos,
		goexec.CcTconnPos,
		goexec.CcTconnVendoredPos,
		goexec.ScConnPos,
		goexec.CRwcPos,
		goexec.CTlsPos,
		goexec.TextReaderRPos,
		goexec.BufReaderBufPos,
		goexec.BufReaderWPos,
		// grpc
		goexec.GrpcStreamStPtrPos,
		goexec.GrpcStreamMethodPtrPos,
		goexec.GrpcStatusSPos,
		goexec.GrpcStatusCodePtrPos,
		goexec.MetaHeadersFrameFieldsPtrPos,
		goexec.ValueContextValPtrPos,
		goexec.GrpcStConnPos,
		goexec.GrpcTConnPos,
		goexec.GrpcTSchemePos,
		goexec.GrpcTransportStreamIDPos,
		goexec.GrpcTransportBufWriterBufPos,
		goexec.GrpcTransportBufWriterOffsetPos,
		goexec.GrpcTransportBufWriterConnPos,
		// redis
		goexec.RedisConnBwPos,
		// kafka go
		goexec.KafkaGoWriterTopicPos,
		goexec.KafkaGoProtocolConnPos,
		goexec.KafkaGoReaderTopicPos,
		// kafka sarama
		goexec.SaramaBrokerCorrIDPos,
		goexec.SaramaResponseCorrIDPos,
		goexec.SaramaBrokerConnPos,
		goexec.SaramaBufconnConnPos,
		// grpc versioning
		goexec.GrpcOneSixZero,
		goexec.GrpcOneSixNine,
		goexec.GrpcOneSevenSeven,
		// HTTP2 versioning
		goexec.HTTP2ZeroFortyFive,
		// grpc
		goexec.GrpcServerStreamStream,
		goexec.GrpcServerStreamStPtr,
		goexec.GrpcClientStreamStream,
		// go manual spans
		goexec.GoTracerDelegatePos,
		// go runtime channels
		goexec.HchanQcountPos,
		goexec.HchanDataqsizPos,
		goexec.HchanSendxPos,
		goexec.HchanRecvxPos,
		// go jsonrpc
		goexec.GoJsonrpcRequestHeaderServiceMethodPos,
		// go mongodb
		goexec.MongoConnNamePos,
		goexec.MongoOpNamePos,
		goexec.MongoOpDBPos,
		goexec.MongoOneThirteenOne,
		// database/sql stdlib
		goexec.DriverConnCiPos,
		// lib/pq driver
		goexec.PqConnCfgPos,
		goexec.PqConfigHostPos,
		goexec.PqOneElevenZero,
		// mysql driver
		goexec.MySQLConnCfgPos,
		goexec.MySQLConfigAddrPos,
		// pgx driver
		goexec.PgxConnConfigPos,
		goexec.PgxConfigHostPos,
		goexec.MuxTemplatePos,
		goexec.GinFullpathPos,
	} {
		if val, ok := offsets.Field[field].(uint64); ok {
			offTable.Table[field] = val
		}
	}
	setGoAutoSDKSpanContextOffsets(&offTable, offsets)
	for _, field := range goRuntimeMetricOffsetFields {
		if val, ok := offsets.Field[field].(uint64); ok {
			offTable.Table[field] = val
		}
	}

	for _, iType := range []struct {
		symbol string
		field  goexec.GoOffset
	}{
		{
			symbol: "go.opentelemetry.io/otel/trace.attributeOption",
			field:  goexec.GoTracerAttributeOptOffset,
		},
		{
			symbol: "*errors.errorString",
			field:  goexec.GoErrorStringOffset,
		},
		{
			symbol: "*github.com/go-sql-driver/mysql.mysqlConn",
			field:  goexec.MySQLConnTypeOffset,
		},
		{
			symbol: "*github.com/lib/pq.conn",
			field:  goexec.PqConnTypeOffset,
		},
	} {
		if offset, ok := offsets.ITypes[iType.symbol]; ok {
			offTable.Table[iType.field] = offset
		}
	}

	identity := goOffsetsMapKey(fileInfo)
	if err := p.putGoOffsets(identity, offTable); err != nil {
		return fmt.Errorf(
			"setting Go offsets map for pid %d device %d inode %d: %w",
			fileInfo.Pid(), identity.Dev, identity.Ino, err,
		)
	}

	p.recordGoAutoSDKActivationSupport(fileInfo, offsets)
	p.recordGoChannelOffsetAvailability(fileInfo, offsets)
	p.recordGoRuntimeMetricAvailability(fileInfo, offsets)
	return nil
}

func (p *Tracer) putGoOffsets(key executableIdentity, offsets BpfOffTableT) error {
	if p.putGoOffsetsForTest != nil {
		return p.putGoOffsetsForTest(key, offsets)
	}
	return p.bpfObjects.GoOffsetsMap.Put(key, offsets)
}

func initMissingGoChannelOffsets(offTable *BpfOffTableT) {
	if offTable == nil {
		return
	}

	for _, field := range goChannelOffsetFields {
		offTable.Table[field] = missingGoOffset
	}
}

func initMissingGoAutoSDKSpanContextOffsets(offTable *BpfOffTableT) {
	if offTable == nil {
		return
	}

	for _, field := range goAutoSDKSpanContextOffsetFields {
		offTable.Table[field] = missingGoOffset
	}
}

func setGoAutoSDKSpanContextOffsets(offTable *BpfOffTableT, offsets *goexec.Offsets) {
	if offTable == nil || offsets == nil {
		return
	}

	for _, field := range goAutoSDKSpanContextOffsetFields {
		if value, ok := offsets.Field[field].(uint64); ok {
			offTable.Table[field] = value
		}
	}
}

type mapKeyDeleter interface {
	Delete(key any) error
}

type mapKeyPutter interface {
	Put(key, value any) error
}

type mapKeyPutDeleter interface {
	mapKeyDeleter
	mapKeyPutter
}

func (p *Tracer) newGoProcessLifecycleEpoch() (uint64, error) {
	if p.newGoProcessLifecycleEpochForTest != nil {
		return p.newGoProcessLifecycleEpochForTest()
	}

	var encoded [8]byte
	for {
		if _, err := rand.Read(encoded[:]); err != nil {
			return 0, fmt.Errorf("generate Go process lifecycle epoch: %w", err)
		}
		if epoch := binary.LittleEndian.Uint64(encoded[:]); epoch != 0 {
			return epoch, nil
		}
	}
}

func (p *Tracer) lookupGoProcessLifecycleEpoch(hostPID uint32) (uint64, error) {
	if p.lookupGoProcessLifecycleEpochForTest != nil {
		return p.lookupGoProcessLifecycleEpochForTest(hostPID)
	}
	if p.bpfObjects.GoProcessLifecycleEpochs == nil {
		return 0, fmt.Errorf("BPF objects not loaded, cannot read Go lifecycle epoch for pid %d", hostPID)
	}

	var epoch uint64
	if err := p.bpfObjects.GoProcessLifecycleEpochs.Lookup(hostPID, &epoch); err != nil {
		return 0, fmt.Errorf("read Go lifecycle epoch for pid %d from BPF map: %w", hostPID, err)
	}
	if epoch == 0 {
		return 0, fmt.Errorf("Go lifecycle epoch for pid %d is zero", hostPID)
	}
	return epoch, nil
}

func (p *Tracer) putGoProcessLifecycleEpoch(hostPID uint32, epoch uint64) error {
	if p.putGoProcessLifecycleEpochForTest != nil {
		return p.putGoProcessLifecycleEpochForTest(hostPID, epoch)
	}
	if p.bpfObjects.GoProcessLifecycleEpochs == nil {
		return fmt.Errorf("BPF objects not loaded, cannot publish Go lifecycle epoch for pid %d", hostPID)
	}
	if err := p.bpfObjects.GoProcessLifecycleEpochs.Update(hostPID, epoch, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("publish Go lifecycle epoch for pid %d to BPF map: %w", hostPID, err)
	}
	return nil
}

func (p *Tracer) deleteGoProcessLifecycleEpoch(hostPID uint32) error {
	if p.deleteGoProcessLifecycleEpochForTest != nil {
		return p.deleteGoProcessLifecycleEpochForTest(hostPID)
	}
	if p.bpfObjects.GoProcessLifecycleEpochs == nil {
		return fmt.Errorf("BPF objects not loaded, cannot remove Go lifecycle epoch for pid %d", hostPID)
	}
	if err := p.bpfObjects.GoProcessLifecycleEpochs.Delete(hostPID); err != nil &&
		!errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("remove Go lifecycle epoch for pid %d from BPF map: %w", hostPID, err)
	}
	return nil
}

// disarmGoProcessLifecycleEpoch makes every nonzero target epoch fail closed.
// Deletion is preferred; a zero overwrite is the independent fallback because
// zero can never be a valid target or lifecycle token.
func (p *Tracer) disarmGoProcessLifecycleEpoch(hostPID uint32) error {
	deleteErr := p.deleteGoProcessLifecycleEpoch(hostPID)
	if deleteErr == nil {
		return nil
	}
	if zeroErr := p.putGoProcessLifecycleEpoch(hostPID, 0); zeroErr != nil {
		return errors.Join(deleteErr, fmt.Errorf("zero Go lifecycle epoch after delete failure: %w", zeroErr))
	}
	return nil
}

// establishGoProcessLifecycleEpoch binds both process-scoped target maps to a
// random kernel-visible lifetime token. The caller holds goAutoSDKTargetsMu
// and invokes this at the ServiceFilter admission commit boundary.
func (p *Tracer) establishGoProcessLifecycleEpoch(
	pid app.PID,
	owner *exec.FileInfo,
) (uint64, bool, error) {
	if owner == nil || owner.ProcessStartTime() == 0 || owner.ProcessInstanceID() == 0 {
		return 0, false, fmt.Errorf("exact Go process lifetime for pid %d is incomplete", pid)
	}
	if err := p.validateRuntimeMetricOwner(pid, owner); err != nil {
		return 0, false, fmt.Errorf("validate Go lifecycle owner before epoch publication: %w", err)
	}

	if state, ok := p.goProcessLifecycleEpochs[pid]; ok && state.owner == owner {
		current, err := p.lookupGoProcessLifecycleEpoch(uint32(pid))
		if err != nil {
			if disarmErr := p.disarmGoProcessLifecycleEpoch(uint32(pid)); disarmErr != nil {
				err = errors.Join(err, disarmErr)
			}
			return 0, false, err
		}
		if current != state.epoch {
			return 0, false, fmt.Errorf(
				"Go lifecycle epoch for pid %d changed from %d to %d",
				pid, state.epoch, current,
			)
		}
		if err := p.validateRuntimeMetricOwner(pid, owner); err != nil {
			return 0, false, fmt.Errorf("revalidate Go lifecycle owner: %w", err)
		}
		return current, false, nil
	}

	epoch, err := p.newGoProcessLifecycleEpoch()
	if err != nil {
		return 0, false, err
	}
	if epoch == 0 {
		return 0, false, errors.New("generated Go process lifecycle epoch is zero")
	}
	if err := p.putGoProcessLifecycleEpoch(uint32(pid), epoch); err != nil {
		if disarmErr := p.disarmGoProcessLifecycleEpoch(uint32(pid)); disarmErr != nil {
			err = errors.Join(err, disarmErr)
		}
		return 0, false, err
	}
	if err := p.validateRuntimeMetricOwner(pid, owner); err != nil {
		if disarmErr := p.disarmGoProcessLifecycleEpoch(uint32(pid)); disarmErr != nil {
			err = errors.Join(err, disarmErr)
		}
		return 0, false, fmt.Errorf("Go lifecycle owner changed during epoch publication: %w", err)
	}
	current, err := p.lookupGoProcessLifecycleEpoch(uint32(pid))
	if err != nil {
		if disarmErr := p.disarmGoProcessLifecycleEpoch(uint32(pid)); disarmErr != nil {
			err = errors.Join(err, disarmErr)
		}
		return 0, false, err
	}
	if current != epoch {
		err := fmt.Errorf(
			"Go lifecycle epoch for pid %d changed during publication from %d to %d",
			pid, epoch, current,
		)
		if disarmErr := p.disarmGoProcessLifecycleEpoch(uint32(pid)); disarmErr != nil {
			err = errors.Join(err, disarmErr)
		}
		return 0, false, err
	}
	if p.goProcessLifecycleEpochs == nil {
		p.goProcessLifecycleEpochs = map[app.PID]goProcessLifecycleEpochState{}
	}
	p.goProcessLifecycleEpochs[pid] = goProcessLifecycleEpochState{owner: owner, epoch: epoch}
	return epoch, true, nil
}

// invalidateGoProcessLifecycleEpoch removes the kernel token before target
// cleanup. A zero overwrite is the fallback when deletion fails, so every
// process-scoped target becomes inert before cleanup proceeds. Successful
// deletion also prevents retired PIDs from evicting idle live entries from the
// bounded lifecycle LRU.
func (p *Tracer) invalidateGoProcessLifecycleEpoch(pid app.PID, owner *exec.FileInfo) error {
	state, ok := p.goProcessLifecycleEpochs[pid]
	if !ok || (owner != nil && state.owner != owner) {
		return nil
	}
	if err := p.disarmGoProcessLifecycleEpoch(uint32(pid)); err != nil {
		return err
	}
	delete(p.goProcessLifecycleEpochs, pid)
	return nil
}

func resetGoAutoSDKActivationAttempts(
	attempts mapKeyDeleter,
	pid app.PID,
	generation uint64,
	log *slog.Logger,
) error {
	if attempts == nil {
		return nil
	}

	var cleanupErrors []error
	for attempt := uint8(0); attempt < goAutoSDKActivationMaxAttempts; attempt++ {
		key := BpfGoAutoActivationAttemptKeyT{
			Generation: generation,
			Pid:        uint32(pid),
			Attempt:    attempt,
		}
		if err := attempts.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			if log != nil {
				log.Warn("resetting Go Auto SDK activation attempt failed",
					"pid", pid, "attempt", attempt, "error", err)
			}
			cleanupErrors = append(cleanupErrors,
				fmt.Errorf("delete activation attempt %d for PID %d: %w", attempt, pid, err))
		}
	}
	return errors.Join(cleanupErrors...)
}

func retryGoAutoSDKActivationAttemptCleanup(
	attempts mapKeyDeleter,
	pid app.PID,
	generations []uint64,
	log *slog.Logger,
) ([]uint64, error) {
	var pending []uint64
	var cleanupErrors []error
	for _, generation := range generations {
		if err := resetGoAutoSDKActivationAttempts(attempts, pid, generation, log); err != nil {
			pending = append(pending, generation)
			cleanupErrors = append(cleanupErrors, err)
		}
	}

	return pending, errors.Join(cleanupErrors...)
}

func activateGoAutoSDKTarget(
	targets mapKeyPutter,
	attempts mapKeyDeleter,
	active map[app.PID]goAutoSDKTargetState,
	nextGeneration *uint64,
	pid app.PID,
	log *slog.Logger,
	processIdentity ...uint64,
) (uint64, error) {
	current := active[pid]
	if current.generation != 0 && !current.needsRotation {
		current.cleanupGenerations, _ = retryGoAutoSDKActivationAttemptCleanup(
			attempts,
			pid,
			current.cleanupGenerations,
			log,
		)
		active[pid] = current
		return current.generation, nil
	}

	(*nextGeneration)++
	if *nextGeneration == 0 {
		(*nextGeneration)++
	}
	generation := *nextGeneration
	key := uint32(pid)
	target := BpfGoAutoTargetT{Generation: generation}
	if len(processIdentity) != 0 {
		target.ProcessStartTicks = processIdentity[0]
	}
	if len(processIdentity) > 1 {
		target.ProcessLifecycleEpoch = processIdentity[1]
	}
	if err := targets.Put(&key, &target); err != nil {
		return generation, err
	}

	if current.generation != 0 {
		current.cleanupGenerations = append(current.cleanupGenerations, current.generation)
	}
	current.cleanupGenerations, _ = retryGoAutoSDKActivationAttemptCleanup(
		attempts,
		pid,
		current.cleanupGenerations,
		log,
	)
	active[pid] = goAutoSDKTargetState{
		generation:         generation,
		cleanupGenerations: current.cleanupGenerations,
		startTime:          target.ProcessStartTicks,
		lifecycleEpoch:     target.ProcessLifecycleEpoch,
	}

	return generation, nil
}

func deactivateGoAutoSDKTarget(
	targets mapKeyPutDeleter,
	attempts mapKeyDeleter,
	active map[app.PID]goAutoSDKTargetState,
	pid app.PID,
	log *slog.Logger,
) error {
	state := active[pid]
	key := uint32(pid)
	var cleanupErr error
	if err := targets.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		disabled := BpfGoAutoTargetT{}
		if updateErr := targets.Put(&key, &disabled); updateErr != nil {
			if state.generation != 0 {
				state.needsRotation = true
			}
			state.cleanupGenerations, cleanupErr = retryGoAutoSDKActivationAttemptCleanup(
				attempts,
				pid,
				state.cleanupGenerations,
				log,
			)
			active[pid] = state
			return errors.Join(err, updateErr, cleanupErr)
		}
	}

	if state.generation != 0 {
		state.cleanupGenerations = append(state.cleanupGenerations, state.generation)
		state.generation = 0
		state.needsRotation = false
	}
	state.cleanupGenerations, cleanupErr = retryGoAutoSDKActivationAttemptCleanup(
		attempts,
		pid,
		state.cleanupGenerations,
		log,
	)
	if len(state.cleanupGenerations) == 0 {
		delete(active, pid)
	} else {
		active[pid] = state
	}

	return cleanupErr
}

func (p *Tracer) enableGoAutoSDKTarget(
	pid app.PID,
	dev uint64,
	ino uint64,
	startTime uint64,
	lifecycleEpoch uint64,
	owner *exec.FileInfo,
) (uint64, error) {
	targets, attempts := p.goAutoSDKMaps()
	if targets == nil {
		return 0, nil
	}
	if p.goAutoSDKTargets == nil {
		p.goAutoSDKTargets = map[app.PID]goAutoSDKTargetState{}
	}

	generation, err := activateGoAutoSDKTarget(
		targets,
		attempts,
		p.goAutoSDKTargets,
		&p.goAutoSDKTargetGeneration,
		pid,
		p.log,
		startTime,
		lifecycleEpoch,
	)
	if err != nil {
		if p.log != nil {
			p.log.Warn("enabling Go Auto SDK target failed",
				"pid", pid, "generation", generation, "error", err)
		}
		return generation, err
	}

	state := p.goAutoSDKTargets[pid]
	state.owner = owner
	state.dev = dev
	state.ino = ino
	if startTime != 0 {
		state.startTime = startTime
	}
	state.lifecycleEpoch = lifecycleEpoch
	p.goAutoSDKTargets[pid] = state
	return generation, nil
}

func (p *Tracer) disableGoAutoSDKTarget(pid app.PID) {
	targets, attempts := p.goAutoSDKMaps()
	if targets == nil {
		delete(p.goAutoSDKTargets, pid)
		return
	}

	if err := deactivateGoAutoSDKTarget(
		targets,
		attempts,
		p.goAutoSDKTargets,
		pid,
		p.log,
	); err != nil && p.log != nil {
		p.log.Warn("disabling Go Auto SDK target failed", "pid", pid, "error", err)
	}
}

func (p *Tracer) goAutoSDKMaps() (mapKeyPutDeleter, mapKeyDeleter) {
	targets := p.goAutoSDKTargetMap
	if targets == nil && p.bpfObjects.GoAutoTargets != nil {
		targets = p.bpfObjects.GoAutoTargets
	}
	attempts := p.goAutoSDKAttemptMap
	if attempts == nil && p.bpfObjects.GoAutoActivationAttempts != nil {
		attempts = p.bpfObjects.GoAutoActivationAttempts
	}
	return targets, attempts
}

func readGoAutoSDKProcessStartTime(pid app.PID) (uint64, error) {
	process, err := procfs.NewProc(int(pid))
	if err != nil {
		return 0, fmt.Errorf("opening process: %w", err)
	}
	stat, err := process.Stat()
	if err != nil {
		return 0, fmt.Errorf("reading process stat: %w", err)
	}
	return stat.Starttime, nil
}

func attachGoAutoSDKActivationProbe(
	probe goAutoSDKActivationProbe,
	pid app.PID,
	dev uint64,
	ino uint64,
	startTime uint64,
) (io.Closer, error) {
	if probe.program == nil {
		return nil, errors.New("process-scoped Go Auto SDK activation probe is incomplete")
	}

	target, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return nil, fmt.Errorf("opening target executable: %w", err)
	}
	defer target.Close()

	info, err := target.Stat()
	if err != nil {
		return nil, fmt.Errorf("stating target executable: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("reading target executable identity")
	}
	actualDev := normalizeDeviceID(stat.Dev)
	if actualDev != dev || stat.Ino != ino {
		return nil, fmt.Errorf(
			"target executable identity changed: got %d:%d, want %d:%d",
			actualDev,
			stat.Ino,
			dev,
			ino,
		)
	}
	if err := validateGoAutoSDKProcessStartTime(pid, startTime); err != nil {
		return nil, err
	}

	executable, err := link.OpenExecutable(fmt.Sprintf("/proc/self/fd/%d", target.Fd()))
	if err != nil {
		return nil, fmt.Errorf("opening target executable: %w", err)
	}

	activationLink, err := executable.Uprobe(
		"",
		probe.program,
		goAutoSDKActivationUprobeOptions(probe, pid),
	)
	if err != nil {
		return nil, err
	}
	if err := validateGoAutoSDKProcessStartTime(pid, startTime); err != nil {
		_ = activationLink.Close()
		return nil, err
	}
	return activationLink, nil
}

func validateGoAutoSDKProcessStartTime(pid app.PID, expected uint64) error {
	if expected == 0 {
		return nil
	}

	actual, err := readGoAutoSDKProcessStartTime(pid)
	if err != nil {
		return err
	}
	if actual != expected {
		return fmt.Errorf("target process identity changed: got %d, want %d", actual, expected)
	}
	return nil
}

func goAutoSDKActivationUprobeOptions(
	probe goAutoSDKActivationProbe,
	pid app.PID,
) *link.UprobeOptions {
	return &link.UprobeOptions{
		Address: probe.offset,
		PID:     int(pid),
	}
}

func (p *Tracer) RegisterProcessScopedGoProbe(
	dev uint64,
	ino uint64,
	candidate ebpfcommon.GoProbe,
) {
	if p == nil || !candidate.ProcessScoped || candidate.Probe == nil ||
		candidate.Probe.Start == nil {
		return
	}

	p.goAutoSDKTargetsMu.Lock()
	defer p.goAutoSDKTargetsMu.Unlock()

	if p.goAutoSDKActivationProbes == nil {
		p.goAutoSDKActivationProbes = map[goAutoSDKExecutableKey]goAutoSDKActivationProbe{}
	}
	executable := goAutoSDKExecutableKey{dev: dev, ino: ino}
	p.goAutoSDKActivationProbes[executable] = goAutoSDKActivationProbe{
		program: candidate.Probe.Start,
		offset:  candidate.Probe.StartOffset,
	}
	for pid, state := range p.goAutoSDKTargets {
		if state.dev != dev || state.ino != ino {
			continue
		}
		if err := p.ensureGoAutoSDKActivationLinkLocked(pid, ino, state.generation); err != nil {
			p.disableGoAutoSDKTarget(pid)
			p.closeGoAutoSDKActivationLinksLocked(func(key goAutoSDKActivationLinkKey, _ goAutoSDKActivationLink) bool {
				return key.pid == pid
			})
			if p.log != nil {
				p.log.Warn("attaching process-scoped Go Auto SDK activation probe failed",
					"pid", pid, "generation", state.generation, "error", err)
			}
		}
	}
}

func (p *Tracer) UnregisterProcessScopedGoProbes(dev, ino uint64) {
	if p == nil {
		return
	}

	p.goAutoSDKTargetsMu.Lock()
	defer p.goAutoSDKTargetsMu.Unlock()

	executable := goAutoSDKExecutableKey{dev: dev, ino: ino}
	delete(p.goAutoSDKActivationProbes, executable)
	p.closeGoAutoSDKActivationLinksLocked(func(_ goAutoSDKActivationLinkKey, activationLink goAutoSDKActivationLink) bool {
		return activationLink.executable == executable
	})
}

func (p *Tracer) ensureGoAutoSDKActivationLinkLocked(
	pid app.PID,
	ino uint64,
	generation uint64,
) error {
	if generation == 0 {
		return nil
	}

	state, ok := p.goAutoSDKTargets[pid]
	if !ok || state.generation != generation || state.ino != ino || state.activated {
		return nil
	}

	key := goAutoSDKActivationLinkKey{pid: pid, generation: generation}
	if _, ok := p.goAutoSDKActivationLinks[key]; ok {
		return nil
	}

	executable := goAutoSDKExecutableKey{dev: state.dev, ino: ino}
	probe, ok := p.goAutoSDKActivationProbes[executable]
	if !ok {
		return nil
	}

	attach := p.attachGoAutoSDKProbe
	if attach == nil {
		attach = attachGoAutoSDKActivationProbe
	}
	activationLink, err := attach(probe, pid, state.dev, ino, state.startTime)
	if err != nil {
		return err
	}
	if activationLink == nil {
		return errors.New("process-scoped Go Auto SDK activation probe returned no link")
	}

	if p.goAutoSDKActivationLinks == nil {
		p.goAutoSDKActivationLinks = map[goAutoSDKActivationLinkKey]goAutoSDKActivationLink{}
	}
	p.goAutoSDKActivationLinks[key] = goAutoSDKActivationLink{
		executable: executable,
		link:       &onceCloser{closer: activationLink},
	}
	return nil
}

func (p *Tracer) closeGoAutoSDKActivationLinksLocked(
	match func(goAutoSDKActivationLinkKey, goAutoSDKActivationLink) bool,
) {
	for key, activationLink := range p.goAutoSDKActivationLinks {
		if !match(key, activationLink) {
			continue
		}

		delete(p.goAutoSDKActivationLinks, key)
		if err := activationLink.link.Close(); err != nil && p.log != nil {
			p.log.Debug("closing process-scoped Go Auto SDK activation probe failed",
				"pid", key.pid, "generation", key.generation, "error", err)
		}
	}
}

func (p *Tracer) closeAllGoAutoSDKActivationLinks() error {
	if p == nil {
		return nil
	}

	p.goAutoSDKTargetsMu.Lock()
	defer p.goAutoSDKTargetsMu.Unlock()

	p.closeGoAutoSDKActivationLinksLocked(func(goAutoSDKActivationLinkKey, goAutoSDKActivationLink) bool {
		return true
	})
	return nil
}

func (p *Tracer) handleGoAutoSDKActivationEvent(record *ringbuf.Record) (bool, error) {
	if len(record.RawSample) == 0 ||
		record.RawSample[0] != ebpfcommon.EventTypeGoAutoActivated {
		return false, nil
	}

	event, err := ebpfcommon.ReinterpretCast[goAutoSDKActivationEvent](record.RawSample)
	if err != nil {
		return true, err
	}

	key := goAutoSDKActivationLinkKey{
		pid:        app.PID(event.Pid),
		generation: event.Generation,
	}

	p.goAutoSDKTargetsMu.Lock()
	defer p.goAutoSDKTargetsMu.Unlock()

	state, ok := p.goAutoSDKTargets[key.pid]
	if !ok || state.generation != key.generation {
		return true, nil
	}
	activationLink, ok := p.goAutoSDKActivationLinks[key]
	if !ok {
		return true, nil
	}

	state.activated = true
	p.goAutoSDKTargets[key.pid] = state
	delete(p.goAutoSDKActivationLinks, key)
	if err := activationLink.link.Close(); err != nil && p.log != nil {
		p.log.Debug("closing completed Go Auto SDK activation probe failed",
			"pid", key.pid, "generation", key.generation, "error", err)
	}
	return true, nil
}

func (p *Tracer) recordGoChannelOffsetAvailability(fileInfo *exec.FileInfo, offsets *goexec.Offsets) {
	if p == nil || fileInfo == nil {
		return
	}

	if p.goChannelOffsetsByExecutable == nil {
		p.goChannelOffsetsByExecutable = map[executableIdentity]bool{}
	}

	identity := goOffsetsMapKey(fileInfo)
	hasOffsets := offsets.HasGoChannelOffsets()
	p.goChannelOffsetsByExecutable[identity] = hasOffsets
	p.currentBinary = identity

	if !hasOffsets && p.log != nil {
		p.log.Debug("skipping Go channel link probes for binary with missing runtime.hchan offsets",
			"pid", fileInfo.Pid(), "dev", identity.Dev, "ino", identity.Ino,
			"cmd", fileInfo.CmdExePath())
	}
}

func (p *Tracer) recordGoRuntimeMetricAvailability(fileInfo *exec.FileInfo, offsets *goexec.Offsets) {
	if p == nil || fileInfo == nil {
		return
	}

	if p.goRuntimeMetricMaskByExecutable == nil {
		p.goRuntimeMetricMaskByExecutable = map[executableIdentity]uint64{}
	}
	if p.goRuntimeGCGoalSourceByExecutable == nil {
		p.goRuntimeGCGoalSourceByExecutable = map[executableIdentity]goRuntimeGCGoalSource{}
	}

	identity := goOffsetsMapKey(fileInfo)
	mask := goRuntimeMetricMask(offsets)
	gcGoalSource := selectGoRuntimeGCGoalSource(
		offsets,
		goexec.RuntimeMetricGCGoalArgumentSupported(fileInfo.ELF()),
	)
	if gcGoalSource != goRuntimeGCGoalSourceNone {
		mask |= goRuntimeMetricMemoryGCGoalMask
	}
	p.goRuntimeGCGoalSourceByExecutable[identity] = gcGoalSource
	includesSystem, modeKnown := goexec.RuntimeMetricGoroutineCountMode(fileInfo.ELF())
	if hasGoRuntimeGoroutineCountOffsets(offsets, includesSystem, modeKnown) {
		mask |= goRuntimeMetricGoroutineCountMask
	}
	supportsStableHeapSnapshotVersion, err := goexec.SupportsGoRuntimeMemoryMetrics(fileInfo.ELF())
	if err != nil && p.log != nil {
		p.log.Debug("Go runtime memory metric version detection failed",
			"pid", fileInfo.Pid(),
			"dev", identity.Dev,
			"ino", identity.Ino,
			"cmd", fileInfo.CmdExePath(),
			"error", err)
	}

	heapMetricsEnabled := mask&goRuntimeMetricHeapSnapshotMask != 0
	nextGenResolved := false
	if offsets != nil {
		nextGenResolved = len(offsets.Funcs[goRuntimeMetricHeapSnapshotSymbol]) > 0
	}

	if !supportsStableHeapSnapshotVersion {
		mask &^= goRuntimeMetricHeapSnapshotMask
	} else if heapMetricsEnabled && !nextGenResolved {
		mask &^= goRuntimeMetricHeapSnapshotMask
		if p.log != nil {
			p.log.Warn("Go runtime heap metric symbol unresolved; using scalar fallback",
				"pid", fileInfo.Pid(),
				"dev", identity.Dev,
				"ino", identity.Ino,
				"cmd", fileInfo.CmdExePath(),
				"missing_probe", goRuntimeMetricHeapSnapshotSymbol,
				"fallback_probe", goRuntimeMetricGCMarkDoneSymbol)
		}
	}
	p.goRuntimeMetricMaskByExecutable[identity] = mask

	if p.log != nil {
		p.log.Debug("Go runtime metric availability",
			"pid", fileInfo.Pid(),
			"dev", identity.Dev,
			"ino", identity.Ino,
			"cmd", fileInfo.CmdExePath(),
			"available_mask", mask,
			"base_available", hasBaseGoRuntimeMetrics(mask),
			"cpu_time_available", mask&goRuntimeMetricCPUTimeMask != 0,
			"memory_available", mask&goRuntimeMetricMemoryUsedMask != 0,
			"goroutine_count_available", mask&goRuntimeMetricGoroutineCountMask != 0,
			"memory_gc_goal_available", mask&goRuntimeMetricMemoryGCGoalMask != 0,
			"memory_gc_goal_source", gcGoalSource,
			"gc_pause_histogram_available", mask&goRuntimeMetricGCPauseHistogramMask != 0,
			"schedule_duration_histogram_available", mask&goRuntimeMetricScheduleDurationHistogramMask != 0)
	}
}

func (p *Tracer) recordGoAutoSDKActivationSupport(fileInfo *exec.FileInfo, offsets *goexec.Offsets) {
	if p == nil || fileInfo == nil {
		return
	}

	if p.goAutoSDKActivationByExecutable == nil {
		p.goAutoSDKActivationByExecutable = map[executableIdentity]bool{}
	}

	identity := goOffsetsMapKey(fileInfo)
	p.goAutoSDKActivationByExecutable[identity] = offsets.SupportsGoAutoSDKActivation()
}

func selectGoRuntimeGCGoalSource(
	offsets *goexec.Offsets,
	goalArgumentSupported bool,
) goRuntimeGCGoalSource {
	if offsets == nil {
		return goRuntimeGCGoalSourceNone
	}
	if hasGoRuntimeMetricOffsets(offsets, goexec.RuntimeGCControllerHeapGoalPos) {
		return goRuntimeGCGoalSourceHeapGoalField
	}
	if len(offsets.Funcs[goRuntimeMetricGCGoalSymbol]) > 0 && goalArgumentSupported {
		return goRuntimeGCGoalSourcePaceScavengerArgument
	}
	return goRuntimeGCGoalSourceNone
}

func goRuntimeMetricMask(offsets *goexec.Offsets) uint64 {
	if offsets == nil {
		return 0
	}

	mask := goRuntimeMetricProcessorLimitMask
	for _, group := range goRuntimeMetricOffsetGroups {
		if hasGoRuntimeMetricOffsets(offsets, group.fields...) {
			mask |= group.mask
		}
	}
	if !hasSupportedGoRuntimeHistogramLayout(offsets) {
		mask &^= goRuntimeMetricHistogramMask
	}

	return mask
}

func hasSupportedGoRuntimeHistogramLayout(offsets *goexec.Offsets) bool {
	underflowOffset, underflowOK := offsets.Field[goexec.RuntimeTimeHistogramUnderflowPos].(uint64)
	overflowOffset, overflowOK := offsets.Field[goexec.RuntimeTimeHistogramOverflowPos].(uint64)
	if !underflowOK || !overflowOK {
		return false
	}

	expectedUnderflowOffset := goRuntimeHistogramMaxBuckets * goRuntimeHistogramBucketSize
	return underflowOffset == expectedUnderflowOffset &&
		overflowOffset == expectedUnderflowOffset+goRuntimeHistogramBucketSize
}

func hasGoRuntimeMetricOffsets(offsets *goexec.Offsets, fields ...goexec.GoOffset) bool {
	if offsets == nil {
		return false
	}
	for _, field := range fields {
		if _, ok := offsets.Field[field].(uint64); !ok {
			return false
		}
	}
	return true
}

func hasGoRuntimeGoroutineCountOffsets(
	offsets *goexec.Offsets,
	includesSystem bool,
	modeKnown bool,
) bool {
	if !modeKnown || !hasGoRuntimeMetricOffsets(offsets, goRuntimeGoroutineCountCommonOffsetFields[:]...) {
		return false
	}
	return includesSystem || hasGoRuntimeMetricOffsets(offsets, goexec.RuntimeSchedNgSysPos)
}

func hasBaseGoRuntimeMetrics(mask uint64) bool {
	return mask&goRuntimeMetricBaseMask == goRuntimeMetricBaseMask
}

// registerRuntimeMetricTarget writes per-process Go runtime global addresses
// into BPF. Offsets stay file-scoped in go_offsets_map, but these addresses are
// process-scoped for PIE/ASLR and must follow the PID allow lifecycle.
func (p *Tracer) registerRuntimeMetricTarget(
	pid app.PID,
	ns uint32,
	fileInfo *exec.FileInfo,
	owner *exec.FileInfo,
	lifecycleEpoch uint64,
) {
	if owner == nil {
		owner = fileInfo
	}
	if !p.retireRuntimeMetricTargetReplacement(pid, ns, owner) {
		return
	}
	if p.registerRuntimeMetricTargetForTest != nil {
		p.registerRuntimeMetricTargetForTest(pid, ns, fileInfo, owner)
		return
	}
	if lifecycleEpoch == 0 || fileInfo == nil || p.bpfObjects.GoRuntimeMetricTargets == nil {
		return
	}
	identity := goOffsetsMapKey(fileInfo)
	availableMask := p.goRuntimeMetricMaskByExecutable[identity]
	if !hasBaseGoRuntimeMetrics(availableMask) {
		return
	}

	pidInfo, err := runtimeMetricPIDInfo(pid, ns, owner)
	if err != nil {
		p.log.Debug("runtime metrics PID key lookup failed", "pid", pid, "ns", ns, "error", err)
		return
	}

	symbols, err := goexec.ResolveRuntimeMetricSymbols(fileInfo, owner)
	if err != nil {
		p.log.Debug("runtime metrics disabled for executable", "pid", pid, "ino", fileInfo.Ino(), "error", err)
		return
	}
	availableMask = p.goRuntimeMetricMaskForSymbols(fileInfo, availableMask, symbols)
	p.goRuntimeMetricMaskByExecutable[identity] = availableMask
	generation := fileInfo.RuntimeMetricGeneration(pid)
	if generation == 0 {
		generation = newRuntimeMetricGeneration()
	}

	value := BpfGoRuntimeMetricTargetT{
		MemstatsAddr:                 symbols.MemstatsAddr,
		GcControllerAddr:             symbols.GCControllerAddr,
		GomaxprocsAddr:               symbols.GOMAXPROCSAddr,
		WorkAddr:                     symbols.WorkAddr,
		AvailableMask:                availableMask,
		SizeClassToSizesAddr:         symbols.SizeClassToSizesAddr,
		SchedAddr:                    symbols.SchedAddr,
		AllglenAddr:                  symbols.AllgLenAddr,
		AllpAddr:                     symbols.AllpAddr,
		GoroutineCountIncludesSystem: symbols.GoroutineCountIncludesSystem,
		GcGoalSource:                 uint32(p.goRuntimeGCGoalSourceByExecutable[identity]),
		Generation:                   generation,
		ProcessLifecycleEpoch:        lifecycleEpoch,
	}
	if owner != nil {
		value.ProcessStartTicks = owner.ProcessStartTime()
	}

	p.publishRuntimeMetricTarget(pid, ns, fileInfo, owner, pidInfo, value)
}

func (p *Tracer) publishRuntimeMetricTarget(
	pid app.PID,
	ns uint32,
	fileInfo *exec.FileInfo,
	owner *exec.FileInfo,
	pidInfo BpfPidInfo,
	value BpfGoRuntimeMetricTargetT,
) {
	if err := p.validateRuntimeMetricOwner(pid, owner); err != nil {
		if p.log != nil {
			p.log.Debug("runtime metric owner changed before target publication",
				"pid", pid, "ns", ns, "error", err)
		}
		return
	}
	if err := p.putRuntimeMetricTarget(pidInfo, value); err != nil {
		if p.log != nil {
			p.log.Debug("setting runtime metric target failed",
				"pid", pid, "ino", fileInfo.Ino(), "error", err)
		}
		return
	}
	fileInfo.SetRuntimeMetricGeneration(pid, value.Generation)

	if p.runtimeMetricTargetKeys == nil {
		p.runtimeMetricTargetKeys = map[runtimeMetricTargetKey]BpfPidInfo{}
	}
	if p.runtimeMetricTargetOwners == nil {
		p.runtimeMetricTargetOwners = map[runtimeMetricTargetKey]*exec.FileInfo{}
	}
	key := runtimeMetricTargetKey{pid: pid, ns: ns}
	p.runtimeMetricTargetKeys[key] = pidInfo
	p.runtimeMetricTargetOwners[key] = owner

	// Close the final validate-to-Put window. Tracking is published first so a
	// failed rollback remains retryable by BlockPID or a replacement AllowPID.
	if err := p.validateRuntimeMetricOwner(pid, owner); err != nil {
		if p.log != nil {
			p.log.Debug("runtime metric owner changed during target publication",
				"pid", pid, "ns", ns, "error", err)
		}
		p.deleteRuntimeMetricTarget(pid, ns, owner)
	}
}

func (p *Tracer) validateRuntimeMetricOwner(pid app.PID, owner *exec.FileInfo) error {
	if p.validateRuntimeMetricOwnerForTest != nil {
		return p.validateRuntimeMetricOwnerForTest(pid, owner)
	}
	return ebpfcommon.ValidateProcessOwner(pid, owner)
}

func (p *Tracer) putRuntimeMetricTarget(
	pidInfo BpfPidInfo,
	value BpfGoRuntimeMetricTargetT,
) error {
	if p.putRuntimeMetricTargetForTest != nil {
		return p.putRuntimeMetricTargetForTest(pidInfo, value)
	}
	return p.bpfObjects.GoRuntimeMetricTargets.Put(pidInfo, value)
}

// retireRuntimeMetricTargetReplacement removes predecessor process-scoped
// addresses at the replacement admission's precommit boundary. It must finish
// after exact-owner validation and before the service filter unlocks: once the
// replacement is admitted, keeping predecessor ASLR-derived addresses active
// would be unsafe.
func (p *Tracer) retireRuntimeMetricTargetReplacement(
	pid app.PID,
	ns uint32,
	owner *exec.FileInfo,
) bool {
	currentKey := runtimeMetricTargetKey{pid: pid, ns: ns}
	keys := make(map[runtimeMetricTargetKey]struct{})
	for key := range p.runtimeMetricTargetKeys {
		if key.pid == pid {
			keys[key] = struct{}{}
		}
	}
	for key := range p.runtimeMetricTargetOwners {
		if key.pid == pid {
			keys[key] = struct{}{}
		}
	}
	orderedKeys := make([]runtimeMetricTargetKey, 0, len(keys))
	for key := range keys {
		orderedKeys = append(orderedKeys, key)
	}
	sort.Slice(orderedKeys, func(i, j int) bool {
		if orderedKeys[i].pid != orderedKeys[j].pid {
			return orderedKeys[i].pid < orderedKeys[j].pid
		}
		return orderedKeys[i].ns < orderedKeys[j].ns
	})

	for _, key := range orderedKeys {
		previousOwner, ownerTracked := p.runtimeMetricTargetOwners[key]
		if key == currentKey && ownerTracked && previousOwner == owner {
			continue
		}
		previousPIDInfo, targetTracked := p.runtimeMetricTargetKeys[key]
		if targetTracked {
			if err := p.removeRuntimeMetricTarget(previousPIDInfo); err != nil {
				if p.log != nil {
					p.log.Error("retiring predecessor runtime metric target failed; rejecting admission",
						"pid", pid, "previous_ns", key.ns, "new_ns", ns, "error", err)
				}
				return false
			}
		}
		delete(p.runtimeMetricTargetKeys, key)
		delete(p.runtimeMetricTargetOwners, key)
	}
	return true
}

func (p *Tracer) removeRuntimeMetricTarget(pidInfo BpfPidInfo) error {
	var deleteErr error
	if p.deleteRuntimeMetricTargetForTest != nil {
		deleteErr = p.deleteRuntimeMetricTargetForTest(pidInfo)
	} else if p.bpfObjects.GoRuntimeMetricTargets == nil {
		return nil
	} else {
		deleteErr = p.bpfObjects.GoRuntimeMetricTargets.Delete(pidInfo)
	}
	if deleteErr == nil || errors.Is(deleteErr, ebpf.ErrKeyNotExist) {
		return nil
	}

	// Go runtime collection looks this map up directly, without consulting the
	// trace PID filter. If deletion fails, overwrite the entry with an inert
	// value so a reused PID cannot dereference predecessor ASLR addresses.
	if zeroErr := p.putRuntimeMetricTarget(pidInfo, BpfGoRuntimeMetricTargetT{}); zeroErr != nil {
		return errors.Join(
			deleteErr,
			fmt.Errorf("disabling runtime metric target after delete failure: %w", zeroErr),
		)
	}
	return nil
}

func (p *Tracer) goRuntimeMetricMaskForSymbols(
	fileInfo *exec.FileInfo,
	mask uint64,
	symbols goexec.RuntimeMetricSymbols,
) uint64 {
	if mask&goRuntimeMetricMemoryAllocsMask != 0 && symbols.SizeClassToSizesAddr == 0 {
		mask &^= goRuntimeMetricMemoryAllocsMask
		if p.log != nil {
			p.log.Warn("Go runtime size-class table symbol unresolved; disabling allocation metrics",
				"pid", fileInfo.Pid(),
				"ino", fileInfo.Ino(),
				"cmd", fileInfo.CmdExePath())
		}
	}

	if mask&goRuntimeMetricGoroutineCountMask != 0 &&
		(symbols.SchedAddr == 0 || symbols.AllgLenAddr == 0 || symbols.AllpAddr == 0 ||
			!symbols.GoroutineCountModeKnown) {
		mask &^= goRuntimeMetricGoroutineCountMask
		if p.log != nil {
			p.log.Warn("Go runtime goroutine count metadata unresolved; disabling goroutine metric",
				"pid", fileInfo.Pid(),
				"ino", fileInfo.Ino(),
				"cmd", fileInfo.CmdExePath())
		}
	}

	if mask&goRuntimeMetricHistogramMask != 0 && symbols.SchedAddr == 0 {
		mask &^= goRuntimeMetricHistogramMask
		if p.log != nil {
			p.log.Warn("Go runtime scheduler symbol unresolved; disabling histogram metrics",
				"pid", fileInfo.Pid(),
				"ino", fileInfo.Ino(),
				"cmd", fileInfo.CmdExePath())
		}
	}
	return mask
}

// deleteRuntimeMetricTarget removes process-scoped runtime metadata whenever
// the process is no longer eligible for runtime metric collection.
func (p *Tracer) deleteRuntimeMetricTarget(pid app.PID, ns uint32, owner *exec.FileInfo) {
	key := runtimeMetricTargetKey{pid: pid, ns: ns}
	if owner != nil && p.runtimeMetricTargetOwners[key] != owner {
		return
	}
	pidInfo, ok := p.runtimeMetricTargetKeys[key]
	if !ok {
		var err error
		pidInfo, err = runtimeMetricPIDInfo(pid, ns, nil)
		if err != nil {
			p.log.Debug("runtime metrics PID key lookup failed", "pid", pid, "ns", ns, "error", err)
			return
		}
	}

	if err := p.removeRuntimeMetricTarget(pidInfo); err != nil {
		if p.log != nil {
			p.log.Warn("deleting runtime metric target failed",
				"pid", pid, "ns", ns, "error", err)
		}
		return
	}
	delete(p.runtimeMetricTargetKeys, key)
	delete(p.runtimeMetricTargetOwners, key)
}

func runtimeMetricPIDInfo(pid app.PID, ns uint32, owner *exec.FileInfo) (BpfPidInfo, error) {
	pidInfo := BpfPidInfo{
		HostPid: uint32(pid),
		UserPid: uint32(pid),
		Ns:      ns,
	}

	pids, err := ebpfcommon.NamespacedPIDsForOwner(pid, owner)
	if err != nil {
		return BpfPidInfo{}, fmt.Errorf("reading namespaced PIDs: %w", err)
	}
	if len(pids) == 0 {
		return pidInfo, nil
	}

	pidInfo.HostPid = uint32(pids[0])
	pidInfo.UserPid = uint32(pids[len(pids)-1])
	return pidInfo, nil
}

func (p *Tracer) ProcessBinary(fileInfo *exec.FileInfo) {
	if p == nil {
		return
	}
	if fileInfo == nil {
		p.currentBinary = executableIdentity{}
		return
	}

	p.currentBinary = goOffsetsMapKey(fileInfo)
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

var goChannelLinkProbeSymbols = []string{
	"runtime.chansend1",
	"runtime.chanrecv1",
	"runtime.chanrecv2",
}

const (
	goRuntimeMetricGCMarkDoneSymbol   = "runtime.gcMarkDone"
	goRuntimeMetricHeapSnapshotSymbol = "runtime.(*scavengeIndex).nextGen"
	goRuntimeMetricGCGoalSymbol       = "runtime.gcPaceScavenger"
)

var goRuntimeMetricProbeSymbols = []string{
	goRuntimeMetricGCMarkDoneSymbol,
	goRuntimeMetricHeapSnapshotSymbol,
	goRuntimeMetricGCGoalSymbol,
}

var goAutoSDKActivationProbeSymbols = []string{
	"go.opentelemetry.io/auto/sdk.(*tracer).start",
	"context.WithValue",
	"go.opentelemetry.io/auto/sdk.(*span).ended",
	"go.opentelemetry.io/otel/internal/global.(*tracer).newSpan",
}

var goAutoSDKActivationPrerequisiteSymbols = []string{
	"go.opentelemetry.io/otel/internal/global.(*tracer).Start",
	"go.opentelemetry.io/auto/sdk.(*tracer).Start",
	"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).End",
	"go.opentelemetry.io/auto/sdk.(*span).End",
}

// GoChannelLinkProbeSymbols returns the Go runtime symbols used to correlate direct channel handoffs.
func GoChannelLinkProbeSymbols() []string {
	return append([]string(nil), goChannelLinkProbeSymbols...)
}

// GoRuntimeMetricProbeSymbols returns every candidate used for per-binary runtime metric probes.
func GoRuntimeMetricProbeSymbols() []string {
	return append([]string(nil), goRuntimeMetricProbeSymbols...)
}

// GoAutoSDKActivationProbeSymbols returns the symbols in activation-safe attachment order.
func GoAutoSDKActivationProbeSymbols() []string {
	return append([]string(nil), goAutoSDKActivationProbeSymbols...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	m := map[string][]*ebpfcommon.ProbeDesc{
		// Go runtime
		"runtime.newproc1": {{
			Start: p.bpfObjects.ObiUprobeRuntimeNewproc1,
			End:   p.bpfObjects.ObiUprobeRuntimeNewproc1Return,
		}},
		"runtime.casgstatus": {{
			Start: p.bpfObjects.ObiUprobeRuntimeCasgstatus,
		}},
		"runtime.mstart1": {{
			Start: p.bpfObjects.ObiUprobeRuntimeMstart1,
		}},
		"runtime.mexit": {{
			Start: p.bpfObjects.ObiUprobeRuntimeMexit,
		}},
		// Go net/http
		"net/http.serverHandler.ServeHTTP": {{
			Start: p.bpfObjects.ObiUprobeServeHTTP,
		}},
		"net/http.(*response).finishRequest": {{
			End: p.bpfObjects.ObiUprobeServeHTTPReturns,
		}},
		"net/http.(*conn).readRequest": {{
			Start: p.bpfObjects.ObiUprobeReadRequestStart,
			End:   p.bpfObjects.ObiUprobeReadRequestReturns,
		}},
		// Go net/rpc/jsonrpc
		"net/rpc/jsonrpc.(*serverCodec).ReadRequestHeader": {{
			Start: p.bpfObjects.ObiUprobeJsonrpcReadRequestHeader,
			End:   p.bpfObjects.ObiUprobeJsonrpcReadRequestHeaderReturns,
		}},
		"net/http.(*Transport).roundTrip": {{ // HTTP client, works with Client.Do as well as using the RoundTripper directly
			Start: p.bpfObjects.ObiUprobeRoundTrip,
			End:   p.bpfObjects.ObiUprobeRoundTripReturn,
		}},
		"golang.org/x/net/http2.(*ClientConn).roundTrip": {{ // http2 client after 0.22
			Start: p.bpfObjects.ObiUprobeHttp2RoundTrip,
			End:   p.bpfObjects.ObiUprobeRoundTripReturn, // return is the same as for http 1.1
		}},
		"golang.org/x/net/http2.(*ClientConn).RoundTrip": {{ // http2 client
			Start: p.bpfObjects.ObiUprobeHttp2RoundTrip,
			End:   p.bpfObjects.ObiUprobeRoundTripReturn, // return is the same as for http 1.1
		}},
		"net/http.(*http2ClientConn).RoundTrip": {{ // http2 client vendored in Go
			Start: p.bpfObjects.ObiUprobeHttp2RoundTrip,
			End:   p.bpfObjects.ObiUprobeRoundTripReturn, // return is the same as for http 1.1
		}},
		"net/http.(*http2responseWriter).handlerDone": {{
			End: p.bpfObjects.ObiUprobeServeHTTPReturns,
		}},
		"golang.org/x/net/http2.(*responseWriter).handlerDone": {{
			End: p.bpfObjects.ObiUprobeServeHTTPReturns,
		}},
		"golang.org/x/net/http2.(*ClientConn).writeHeaders": {{ // http2 client
			Start: p.bpfObjects.ObiUprobeHttp2WriteHeaders,
		}},
		"net/http.(*http2ClientConn).writeHeaders": {{ // http2 client vendored in Go, but used from http 1.1 transition
			Start: p.bpfObjects.ObiUprobeHttp2WriteHeadersVendored,
		}},
		"golang.org/x/net/http2.(*responseWriterState).writeHeader": {{ // http2 server request done, capture the response code
			Start: p.bpfObjects.ObiUprobeHttp2ResponseWriterStateWriteHeader,
		}},
		"net/http.(*http2responseWriterState).writeHeader": {{ // same as above, vendored in go
			Start: p.bpfObjects.ObiUprobeHttp2ResponseWriterStateWriteHeader,
		}},
		"net/http.(*response).WriteHeader": {{
			Start: p.bpfObjects.ObiUprobeHttp2ResponseWriterStateWriteHeader, // http response code capture
		}},
		"golang.org/x/net/http2.(*serverConn).runHandler": {{
			Start: p.bpfObjects.ObiUprobeHttp2serverConnRunHandler, // http2 server connection tracking
		}},
		"net/http.(*http2serverConn).runHandler": {{
			Start: p.bpfObjects.ObiUprobeHttp2serverConnRunHandler, // http2 server connection tracking, vendored in go
		}},
		"golang.org/x/net/http2.(*serverConn).processHeaders": {{
			Start: p.bpfObjects.ObiUprobeHttp2ServerProcessHeaders, // http2 server request header parsing
		}},
		"net/http.(*http2serverConn).processHeaders": {{
			Start: p.bpfObjects.ObiUprobeHttp2ServerProcessHeaders, // http2 server request header parsing, vendored in go
		}},
		// tracking of tcp connections for black-box propagation
		"net/http.(*conn).serve": {{ // http server
			Start: p.bpfObjects.ObiUprobeConnServe,
			End:   p.bpfObjects.ObiUprobeConnServeRet,
		}},
		"net.(*netFD).Read": {{
			Start: p.bpfObjects.ObiUprobeNetFdRead,
			End:   p.bpfObjects.ObiUprobeNetFdReadRet,
		}},
		"net.(*netFD).Write": {{
			Start: p.bpfObjects.ObiUprobeNetFdWrite,
		}},
		"crypto/tls.(*Conn).Read": {{
			Start: p.bpfObjects.ObiUprobeCryptoTlsRead,
			End:   p.bpfObjects.ObiUprobeCryptoTlsReadRet,
		}},
		"crypto/tls.(*Conn).Write": {{
			Start: p.bpfObjects.ObiUprobeCryptoTlsWrite,
			End:   p.bpfObjects.ObiUprobeCryptoTlsWriteRet,
		}},
		"net.(*netFD).Close": {{
			Start: p.bpfObjects.ObiUprobeNetFdClose,
		}},
		"net/http.(*persistConn).roundTrip": {{ // http client
			Start: p.bpfObjects.ObiUprobePersistConnRoundTrip,
		}},
		// runs on persistConn.writeLoop, the only place the request's connection can be
		// read when the application wraps net.Conn
		"net/http.persistConnWriter.Write": {{
			Start: p.bpfObjects.ObiUprobePersistConnWriterWrite,
		}},
		// sql
		"database/sql.(*DB).queryDC": {{
			Start: p.bpfObjects.ObiUprobeQueryDC,
			End:   p.bpfObjects.ObiUprobeQueryReturn,
		}},
		"database/sql.(*DB).execDC": {{
			Start: p.bpfObjects.ObiUprobeExecDC,
			End:   p.bpfObjects.ObiUprobeQueryReturn,
		}},
		// PostgreSQL lib/pq
		"github.com/lib/pq.network": {{
			End: p.bpfObjects.ObiUprobePqNetworkReturn,
		}},
		// PostgreSQL pgx
		"github.com/jackc/pgx/v5.(*Conn).Query": {{
			Start: p.bpfObjects.ObiUprobePgxQuery,
			End:   p.bpfObjects.ObiUprobePgxQueryReturn,
		}},
		"github.com/jackc/pgx/v5.(*Conn).Exec": {{
			Start: p.bpfObjects.ObiUprobePgxExec,
			End:   p.bpfObjects.ObiUprobePgxQueryReturn,
		}},
		// Go gRPC
		"google.golang.org/grpc.(*Server).handleStream": {{
			Start: p.bpfObjects.ObiUprobeServerHandleStream,
			End:   p.bpfObjects.ObiUprobeServerHandleStreamReturn,
		}},
		"google.golang.org/grpc/internal/transport.(*http2Server).WriteStatus": {{
			Start: p.bpfObjects.ObiUprobeTransportWriteStatus,
		}},
		// in grpc 1.69.0 they renamed the above WriteStatus to writeStatus lowercase
		"google.golang.org/grpc/internal/transport.(*http2Server).writeStatus": {{
			Start: p.bpfObjects.ObiUprobeTransportWriteStatus,
		}},
		"google.golang.org/grpc.(*ClientConn).Invoke": {{
			Start: p.bpfObjects.ObiUprobeClientConnInvoke,
			End:   p.bpfObjects.ObiUprobeClientConnInvokeReturn,
		}},
		"google.golang.org/grpc.(*ClientConn).NewStream": {{
			Start: p.bpfObjects.ObiUprobeClientConnNewStream,
			End:   p.bpfObjects.ObiUprobeClientConnNewStreamReturn,
		}},
		"google.golang.org/grpc.(*ClientConn).Close": {{
			Start: p.bpfObjects.ObiUprobeClientConnClose,
		}},
		"google.golang.org/grpc.(*clientStream).RecvMsg": {{
			End: p.bpfObjects.ObiUprobeClientStreamRecvMsgReturn,
		}},
		"google.golang.org/grpc.(*clientStream).CloseSend": {{
			End: p.bpfObjects.ObiUprobeClientConnInvokeReturn,
		}},
		"google.golang.org/grpc/internal/transport.(*http2Client).NewStream": {{
			Start: p.bpfObjects.ObiUprobeTransportHttp2ClientNewStream,
			End:   p.bpfObjects.ObiUprobeTransportHttp2ClientNewStreamReturns,
		}},
		// Closes the loopyWriter race for stream registration — see
		// the two-hop bridge in go_grpc.c (executeAndPut → originateStream)
		"google.golang.org/grpc/internal/transport.(*controlBuffer).executeAndPut": {{
			Start: p.bpfObjects.ObiUprobeGrpcControlBufferExecuteAndPut,
		}},
		"google.golang.org/grpc/internal/transport.(*loopyWriter).originateStream": {{
			Start: p.bpfObjects.ObiUprobeGrpcLoopyWriterOriginateStream,
		}},
		"google.golang.org/grpc/internal/transport.(*http2Server).operateHeaders": {{
			Start: p.bpfObjects.ObiUprobeHttp2ServerOperateHeaders,
		}},
		"google.golang.org/grpc/internal/transport.(*serverHandlerTransport).HandleStreams": {{
			Start: p.bpfObjects.ObiUprobeServerHandlerTransportHandleStreams,
		}},
		// Redis
		"github.com/redis/go-redis/v9/internal/pool.(*Conn).WithWriter": {{
			Start: p.bpfObjects.ObiUprobeRedisWithWriter,
			End:   p.bpfObjects.ObiUprobeRedisWithWriterRet,
		}},
		"github.com/redis/go-redis/v9.(*baseClient)._process": {{
			Start: p.bpfObjects.ObiUprobeRedisProcess,
			End:   p.bpfObjects.ObiUprobeRedisProcessRet,
		}},
		"github.com/redis/go-redis/v9.(*baseClient).pipelineProcessCmds": {{
			Start: p.bpfObjects.ObiUprobeRedisProcess,
			End:   p.bpfObjects.ObiUprobeRedisProcessRet,
		}},
		"github.com/redis/go-redis/v9.(*baseClient).txPipelineProcessCmds": {{
			Start: p.bpfObjects.ObiUprobeRedisProcess,
			End:   p.bpfObjects.ObiUprobeRedisProcessRet,
		}},
		// Kafka Go
		"github.com/segmentio/kafka-go.(*Writer).WriteMessages": {{ // runs on the same gorountine as other requests, finds traceparent info
			Start: p.bpfObjects.ObiUprobeWriterWriteMessages,
			End:   p.bpfObjects.ObiUprobeWriterWriteMessagesRet,
		}},
		"github.com/segmentio/kafka-go.(*Writer).produce": {{ // stores the current topic
			Start: p.bpfObjects.ObiUprobeWriterProduce,
		}},
		"github.com/segmentio/kafka-go.(*Client).roundTrip": {{ // has the goroutine connection with (*Writer).produce and msg* connection with protocol.RoundTrip
			Start: p.bpfObjects.ObiUprobeClientRoundTrip,
		}},
		"github.com/segmentio/kafka-go/protocol.RoundTrip": {{ // used for collecting the connection information
			Start: p.bpfObjects.ObiUprobeProtocolRoundtrip,
			End:   p.bpfObjects.ObiUprobeProtocolRoundtripRet,
		}},
		"github.com/segmentio/kafka-go.(*reader).read": {{ // used for capturing the info for the fetch operations
			Start: p.bpfObjects.ObiUprobeReaderRead,
			End:   p.bpfObjects.ObiUprobeReaderReadRet,
		}},
		"github.com/segmentio/kafka-go.(*reader).sendMessage": {{ // to accurately measure the start time
			Start: p.bpfObjects.ObiUprobeReaderSendMessage,
		}},
		// Kafka sarama
		"github.com/IBM/sarama.(*Broker).write": {{
			Start: p.bpfObjects.ObiUprobeSaramaBrokerWrite,
		}},
		"github.com/IBM/sarama.(*responsePromise).handle": {{
			Start: p.bpfObjects.ObiUprobeSaramaResponsePromiseHandle,
		}},
		"github.com/IBM/sarama.(*Broker).sendInternal": {{
			Start: p.bpfObjects.ObiUprobeSaramaSendInternal,
		}},
		"github.com/Shopify/sarama.(*Broker).write": {{
			Start: p.bpfObjects.ObiUprobeSaramaBrokerWrite,
		}},
		"github.com/Shopify/sarama.(*responsePromise).handle": {{
			Start: p.bpfObjects.ObiUprobeSaramaResponsePromiseHandle,
		}},
		"github.com/Shopify/sarama.(*Broker).sendInternal": {{
			Start: p.bpfObjects.ObiUprobeSaramaSendInternal,
		}},
		// Go OTel SDK
		"go.opentelemetry.io/otel/internal/global.(*tracer).Start": {{
			Start: p.bpfObjects.ObiUprobeTracerStartGlobal,
			End:   p.bpfObjects.ObiUprobeTracerStartReturns,
		}},
		"go.opentelemetry.io/auto/sdk.(*tracer).Start": {{
			Start: p.bpfObjects.ObiUprobeTracerStart,
			End:   p.bpfObjects.ObiUprobeTracerStartReturns,
		}},
		"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).End": {{
			Start: p.bpfObjects.ObiUprobeNonRecordingSpanEnd,
		}},
		"go.opentelemetry.io/auto/sdk.(*span).End": {{
			Start: p.bpfObjects.ObiUprobeNonRecordingSpanEnd,
		}},
		"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).SetStatus": {{
			Start: p.bpfObjects.ObiUprobeSetStatus,
		}},
		"go.opentelemetry.io/auto/sdk.(*span).SetStatus": {{
			Start: p.bpfObjects.ObiUprobeSetStatus,
		}},
		"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).SetAttributes": {{
			Start: p.bpfObjects.ObiUprobeSetAttributes,
		}},
		"go.opentelemetry.io/auto/sdk.(*span).SetAttributes": {{
			Start: p.bpfObjects.ObiUprobeSetAttributes,
		}},
		"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).SetName": {{
			Start: p.bpfObjects.ObiUprobeSetName,
		}},
		"go.opentelemetry.io/auto/sdk.(*span).SetName": {{
			Start: p.bpfObjects.ObiUprobeSetName,
		}},
		"go.opentelemetry.io/otel/internal/global.(*nonRecordingSpan).RecordError": {{
			Start: p.bpfObjects.ObiUprobeRecordError,
		}},
		"go.opentelemetry.io/auto/sdk.(*span).RecordError": {{
			Start: p.bpfObjects.ObiUprobeRecordError,
		}},
		// Go MongoDB
		"go.mongodb.org/mongo-driver/x/mongo/driver.Operation.Execute": {{
			Start: p.bpfObjects.ObiUprobeMongoOpExecute,
			End:   p.bpfObjects.ObiUprobeMongoOpExecuteRet,
		}},
		"go.mongodb.org/mongo-driver/v2/x/mongo/driver.Operation.Execute": {{
			Start: p.bpfObjects.ObiUprobeMongoOpExecute,
			End:   p.bpfObjects.ObiUprobeMongoOpExecuteRet,
		}},
		// all of these point to the same probe, we just use it to find start time and collection name
		"go.mongodb.org/mongo-driver/mongo.(*Collection).insert": {{
			Start: p.bpfObjects.ObiUprobeMongoOpInsert,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).insert": {{
			Start: p.bpfObjects.ObiUprobeMongoOpInsert,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).delete": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDelete,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).delete": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDelete,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).updateOrReplace": {{
			Start: p.bpfObjects.ObiUprobeMongoOpUpdateOrReplace,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).updateOrReplace": {{
			Start: p.bpfObjects.ObiUprobeMongoOpUpdateOrReplace,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).find": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFind,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).find": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFind,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).Find": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFind,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).Find": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFind,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).drop": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDrop,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).drop": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDrop,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).findAndModify": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFindAndModify,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).findAndModify": {{
			Start: p.bpfObjects.ObiUprobeMongoOpFindAndModify,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).Aggregate": {{
			Start: p.bpfObjects.ObiUprobeMongoOpAggregate,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).Aggregate": {{
			Start: p.bpfObjects.ObiUprobeMongoOpAggregate,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).CountDocuments": {{
			Start: p.bpfObjects.ObiUprobeMongoOpCountDocuments,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).CountDocuments": {{
			Start: p.bpfObjects.ObiUprobeMongoOpCountDocuments,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).EstimatedDocumentCount": {{
			Start: p.bpfObjects.ObiUprobeMongoOpEstimatedDocumentCount,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).EstimatedDocumentCount": {{
			Start: p.bpfObjects.ObiUprobeMongoOpEstimatedDocumentCount,
		}},
		"go.mongodb.org/mongo-driver/mongo.(*Collection).Distinct": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDistinct,
		}},
		"go.mongodb.org/mongo-driver/v2/mongo.(*Collection).Distinct": {{
			Start: p.bpfObjects.ObiUprobeMongoOpDistinct,
		}},
	}

	if p.goRuntimeHeapSnapshotProbeEnabled() {
		// Go 1.23+ heap statistics use a rotating ring. Collect at nextGen after GC
		// accounting and before the world restarts so the ring cannot rotate mid-read.
		m[goRuntimeMetricHeapSnapshotSymbol] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeGoRuntimeMetrics,
		}}
	} else {
		// Older Go versions expose only the scalar metric set and may not contain
		// nextGen. Keep the gcMarkDone return probe for backward compatibility.
		m[goRuntimeMetricGCMarkDoneSymbol] = []*ebpfcommon.ProbeDesc{{
			End: p.bpfObjects.ObiUprobeGoRuntimeMetrics,
		}}
	}

	if p.goRuntimeGCGoalSourceEnabled() {
		m[goRuntimeMetricGCGoalSymbol] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeGoRuntimeGcGoal,
		}}
	}

	if p.goChannelLinkProbesEnabled() {
		m[goChannelLinkProbeSymbols[0]] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeRuntimeChansend1,
			End:   p.bpfObjects.ObiUprobeRuntimeChansend1Return,
		}}
		m[goChannelLinkProbeSymbols[1]] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeRuntimeChanrecv1,
			End:   p.bpfObjects.ObiUprobeRuntimeChanrecv1Return,
		}}
		m[goChannelLinkProbeSymbols[2]] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeRuntimeChanrecv2,
			End:   p.bpfObjects.ObiUprobeRuntimeChanrecv2Return,
		}}
	}

	// HTTP Header extraction
	// with bpf_loop we scan the buffer with a single uprobe - this is less overhead
	// otherwise we have a probe per header net/textproto.(*Reader).readContinuedLineSlice
	if p.supportsBPFLoop {
		m["net/textproto.readMIMEHeader"] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeReadMimeHeader,
		}}
		// old go versions
		m["net/textproto.(*Reader).ReadMIMEHeader"] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeReadMimeHeader,
		}}
	} else {
		m["net/textproto.(*Reader).readContinuedLineSlice"] = []*ebpfcommon.ProbeDesc{{
			End: p.bpfObjects.ObiUprobeReadContinuedLineSliceReturns,
		}}
	}

	// Route extraction
	if !p.disabledRouteHarvesting {
		// Go mux router
		m["net/http.(*ServeMux).findHandler"] = []*ebpfcommon.ProbeDesc{{
			End: p.bpfObjects.ObiUprobeFindHandlerRet,
		}}
		m["net/http.(*serveMux121).findHandler"] = []*ebpfcommon.ProbeDesc{{
			End: p.bpfObjects.ObiUprobeFindHandlerRet,
		}}
		// Gorilla mux router
		m["github.com/gorilla/mux.routeRegexpGroup.setMatch"] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeMuxSetMatch,
		}}
		// Gin router
		m["github.com/gin-gonic/gin.(*node).getValue"] = []*ebpfcommon.ProbeDesc{{
			End: p.bpfObjects.ObiUprobeGinGetValueRet,
		}}
	}

	if p.headerPropagationEnabled() {
		m["net/http.Header.writeSubset"] = []*ebpfcommon.ProbeDesc{{
			Start: p.bpfObjects.ObiUprobeWriteSubset,        // http 1.x context propagation
			End:   p.bpfObjects.ObiUprobeWriteSubsetReturns, // inject only if no traceparent present
		}}
		m["golang.org/x/net/http2.(*Framer).WriteHeaders"] = []*ebpfcommon.ProbeDesc{
			{ // http2 context propagation
				Start: p.bpfObjects.ObiUprobeGolangHttp2FramerWriteHeaders,
				End:   p.bpfObjects.ObiUprobeHttp2FramerWriteHeadersReturns,
			},
			{ // for grpc
				Start: p.bpfObjects.ObiUprobeGrpcFramerWriteHeaders,
				End:   p.bpfObjects.ObiUprobeGrpcFramerWriteHeadersReturns,
			},
		}
		m["net/http.(*http2Framer).WriteHeaders"] = []*ebpfcommon.ProbeDesc{{ // http2 context propagation
			Start: p.bpfObjects.ObiUprobeNetHttp2FramerWriteHeaders,
			End:   p.bpfObjects.ObiUprobeHttp2FramerWriteHeadersReturns,
		}}
	}

	return m
}

func (p *Tracer) GoProbeGroups() []ebpfcommon.GoProbeGroup {
	if !p.goAutoSDKActivationProbesEnabled() {
		return nil
	}

	return []ebpfcommon.GoProbeGroup{{
		Name:          "go_auto_sdk_activation",
		Prerequisites: append([]string(nil), goAutoSDKActivationPrerequisiteSymbols...),
		Probes: []ebpfcommon.GoProbe{
			{
				Symbol: goAutoSDKActivationProbeSymbols[0],
				Probe: &ebpfcommon.ProbeDesc{
					Start: p.bpfObjects.ObiUprobeAutoSdkTracerStart,
				},
			},
			{
				Symbol: goAutoSDKActivationProbeSymbols[1],
				Probe: &ebpfcommon.ProbeDesc{
					Start: p.bpfObjects.ObiUprobeAutoSdkContextWithValue,
				},
			},
			{
				Symbol: goAutoSDKActivationProbeSymbols[2],
				Probe: &ebpfcommon.ProbeDesc{
					Start: p.bpfObjects.ObiUprobeAutoSdkSpanEnded,
				},
			},
			{
				Symbol: goAutoSDKActivationProbeSymbols[3],
				Probe: &ebpfcommon.ProbeDesc{
					Start: p.bpfObjects.ObiUprobeTracerNewSpan,
				},
				ProcessScoped: true,
			},
		},
	}}
}

func (p *Tracer) goAutoSDKActivationProbesEnabled() bool {
	if p == nil || p.currentBinary.Ino == 0 {
		return false
	}

	return p.goAutoSDKActivationByExecutable[p.currentBinary] && p.supportsContextPropagation()
}

func (p *Tracer) goChannelLinkProbesEnabled() bool {
	if p == nil || p.currentBinary.Ino == 0 {
		return false
	}

	return p.goChannelOffsetsByExecutable[p.currentBinary]
}

func (p *Tracer) goRuntimeHeapSnapshotProbeEnabled() bool {
	if p == nil || p.currentBinary.Ino == 0 {
		return false
	}

	return p.goRuntimeMetricMaskByExecutable[p.currentBinary]&goRuntimeMetricHeapSnapshotMask != 0
}

func (p *Tracer) goRuntimeGCGoalSourceEnabled() bool {
	if p == nil || p.currentBinary.Ino == 0 {
		return false
	}
	return p.goRuntimeGCGoalSourceByExecutable[p.currentBinary] ==
		goRuntimeGCGoalSourcePaceScavengerArgument
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	return map[string]ebpfcommon.ProbeDesc{
		"uprobe_register": {Start: p.bpfObjects.ObiCaptureGoExecutableIdentity},
	}
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc {
	return nil
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return map[string]ebpfcommon.ProbeDesc{
		"sched/sched_process_exec": {
			Start:    p.bpfObjects.ObiGoProcessExec,
			Required: true,
		},
		"sched/sched_process_exit": {
			Start:    p.bpfObjects.ObiGoProcessExit,
			Required: true,
		},
	}
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg { return nil }

func (p *Tracer) SockOps() []ebpfcommon.SockOps { return nil }

func (p *Tracer) Iters() []*ebpfcommon.Iter { return nil }

func (p *Tracer) Tracing() []*ebpfcommon.Tracing { return nil }

func (p *Tracer) RecordInstrumentedLib(_ exec.FileID, _ []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(_ exec.FileID) {}

func (p *Tracer) UnlinkInstrumentedLib(_ exec.FileID) {}

func (p *Tracer) AlreadyInstrumentedLib(_ exec.FileID) bool {
	return false
}

func (p *Tracer) Run(ctx context.Context, ebpfEventContext *ebpfcommon.EBPFEventContext, eventsChan *msg.Queue[[]request.Span]) {
	parseContext := ebpfcommon.NewEBPFParseContext(p.cfg, eventsChan, p.pidsFilter)
	defer parseContext.Close()
	defer func() {
		_ = p.closeAllGoAutoSDKActivationLinks()
	}()

	p.SetEventContext(ebpfEventContext)
	ebpfcommon.SharedRingbuf(
		ebpfEventContext,
		p.cfg,
		p.bpfObjects.Events,
		func(record *ringbuf.Record) (request.Span, bool, error) {
			if handled, err := ebpfEventContext.HandleInternalEvent(record); handled {
				return request.Span{}, true, err
			}
			if handled, err := ebpfcommon.HandleRuntimeMetricsRecord(ctx, ebpfEventContext, record, p.pidsFilter, p.log); handled {
				return request.Span{}, true, err
			}
			s, ignore, err := ebpfcommon.ReadBPFTraceAsSpan(parseContext, p.cfg, record, p.pidsFilter)
			if !ignore && err == nil && !s.IsValid() {
				return s, true, nil
			}
			return s, ignore, err
		},
		p.pidsFilter.Filter,
		slog.With("component", "ringbuf.Tracer"),
		p.metrics,
	)(ctx, append(p.closers, &p.bpfObjects), eventsChan)
}

func (p *Tracer) SetEventContext(eventContext *ebpfcommon.EBPFEventContext) {
	eventContext.RegisterInternalEventHandler(
		ebpfcommon.EventTypeGoAutoActivated,
		func(record *ringbuf.Record) error {
			_, err := p.handleGoAutoSDKActivationEvent(record)
			return err
		},
	)
}

func (p *Tracer) Capabilities() ebpfcommon.TracerCapability { return 0 }

func (p *Tracer) Required() bool {
	return true
}
