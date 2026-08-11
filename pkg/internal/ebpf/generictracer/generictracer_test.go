// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/javabridge"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func TestBitPositionCalculation(t *testing.T) {
	for _, v := range [][4]uint32{
		{0, 1, 0, 1},
		{0, 2, 0, 2},
		{0, 65, 1, 1},
		{0, 66, 1, 2},
		{0, primeHash, 0, 0},
		{0, primeHash + 1, 0, 1},
	} {
		k := makeKey(v[0], v[1])
		segment, bit := pidSegmentBit(k)
		assert.Equal(t, segment, v[2])
		assert.Equal(t, bit, v[3])
	}
}

func makeKey(first, second uint32) uint64 {
	return (uint64(first) << 32) | uint64(second)
}

type testCloserFunc func() error

func (f testCloserFunc) Close() error {
	return f()
}

func TestJavaProcessIdentityUsesInnermostNamespacePID(t *testing.T) {
	original := findJavaNamespacedPIDs
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) {
		return []app.PID{9001, 42, 7}, nil
	}
	t.Cleanup(func() { findJavaNamespacedPIDs = original })

	identity, err := javaProcessIdentity(9001, 1234, nil)
	require.NoError(t, err)
	assert.Equal(t, uint32(7), identity.TID)
	assert.Equal(t, uint32(7), identity.PID)
	assert.Equal(t, uint32(1234), identity.Namespace)
}

func TestDelayedJavaDeletionPreservesReplacementAuthorization(t *testing.T) {
	key := javaAuthorizationKey{pid: 9001, ns: 1234}
	old := javaAuthorization{
		identity:   javabridge.Identity{TID: 7, PID: 7, Namespace: 1234},
		capability: 11,
	}
	replacement := javaAuthorization{
		identity:   old.identity,
		capability: 22,
	}
	oldFile := exec.New(exec.Init{Pid: key.pid})
	replacementFile := exec.New(exec.Init{Pid: key.pid})
	oldEvent := &javaAuthorizationEvent{authorization: old, file: oldFile, confirmed: true}
	replacementEvent := &javaAuthorizationEvent{
		authorization: replacement, file: replacementFile, confirmed: true,
	}
	tracer := &Tracer{
		javaAuthKeys: map[javaAuthorizationKey][]javaAuthorization{
			key: {old, replacement},
		},
		javaAuthEvents: map[javaAuthorizationKey][]*javaAuthorizationEvent{
			key: {oldEvent, replacementEvent},
		},
	}

	tracer.deauthorizeJavaProcess(key.pid, key.ns, oldFile)

	require.Len(t, tracer.javaAuthKeys[key], 1)
	assert.Equal(t, replacement, tracer.javaAuthKeys[key][0])
	require.Len(t, tracer.javaAuthEvents[key], 1)
	assert.Same(t, replacementEvent, tracer.javaAuthEvents[key][0])
}

func TestJavaDeletionMatchesExactFileLifetimeOutOfOrder(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	originalDeauthorize := deauthorizeJavaProcessCapability
	originalSuspend := suspendJavaProcessAuthorization
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
		deauthorizeJavaProcessCapability = originalDeauthorize
		suspendJavaProcessAuthorization = originalSuspend
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	var authorized uint64
	authorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) (bool, error) {
		authorized = capability
		return true, nil
	}
	suspendJavaProcessAuthorization = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) error {
		if authorized == capability {
			authorized = 0
		}
		return nil
	}
	var deauthorized []uint64
	deauthorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64, _ bool,
	) error {
		deauthorized = append(deauthorized, capability)
		if authorized == capability {
			authorized = 0
		}
		return nil
	}

	const pid = app.PID(9001)
	const ns = uint32(1234)
	key := javaAuthorizationKey{pid: pid, ns: ns}
	newFile := func(capability uint64) *exec.FileInfo {
		fi := exec.New(exec.Init{
			Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
		})
		fi.SetJavaAgentCapability(capability)
		return fi
	}
	tracer := &Tracer{log: tlog(), javaRemoteParentEnabled: true}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	predecessor := newFile(11)
	replacement := newFile(22)
	tracer.authorizeJavaProcess(pid, ns, predecessor)
	tracer.authorizeJavaProcess(pid, ns, replacement)
	require.Equal(t, uint64(22), authorized)

	unknownLifetime := newFile(99)
	tracer.deauthorizeJavaProcess(pid, ns, unknownLifetime)
	assert.Equal(t, uint64(22), authorized)
	require.Len(t, tracer.javaAuthEvents[key], 2)

	// B can be observed deleted before delayed A. Exact matching removes only B.
	tracer.deauthorizeJavaProcess(pid, ns, replacement)
	assert.Zero(t, authorized)
	assert.Zero(t, replacement.JavaAgentCapability())
	require.Len(t, tracer.javaAuthEvents[key], 1)
	assert.Same(t, predecessor, tracer.javaAuthEvents[key][0].file)
	require.Len(t, tracer.javaAuthKeys[key], 1)
	assert.Equal(t, uint64(11), tracer.javaAuthKeys[key][0].capability)

	tracer.deauthorizeJavaProcess(pid, ns, predecessor)
	assert.Equal(t, []uint64{22, 11}, deauthorized)
	assert.NotContains(t, tracer.javaAuthEvents, key)
	assert.NotContains(t, tracer.javaAuthKeys, key)

	// The ordinary A-before-B order must preserve the replacement gate and Q.
	predecessor = newFile(33)
	replacement = newFile(44)
	tracer.authorizeJavaProcess(pid, ns, predecessor)
	tracer.authorizeJavaProcess(pid, ns, replacement)
	tracer.deauthorizeJavaProcess(pid, ns, predecessor)
	assert.Equal(t, uint64(44), authorized)
	assert.Equal(t, uint64(44), replacement.JavaAgentCapability())
	tracer.deauthorizeJavaProcess(pid, ns, replacement)
	assert.Zero(t, authorized)
	assert.Equal(t, []uint64{22, 11, 33, 44}, deauthorized)
}

func TestJavaAuthorizationEventSnapshotsCapabilityBeforeFileMutation(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	var observed uint64
	authorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) (bool, error) {
		observed = capability
		return true, nil
	}

	const pid = app.PID(9001)
	const ns = uint32(1234)
	fi := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	fi.SetJavaAgentCapability(11)
	tracer := &Tracer{log: tlog(), javaRemoteParentEnabled: true}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}
	event, created := tracer.beginJavaAuthorizationEvent(
		javaAuthorizationKey{pid: pid, ns: ns}, fi,
	)
	require.True(t, created)
	fi.SetJavaAgentCapability(22)

	tracer.authorizeJavaProcessForEvent(pid, ns, fi, event)

	assert.Equal(t, uint64(11), observed)
	assert.Equal(t, uint64(11), fi.JavaAgentCapability())
}

func TestJavaAuthorizationDoesNotRequireRemoteParent(t *testing.T) {
	original := findJavaNamespacedPIDs
	identityCalls := 0
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) {
		identityCalls++
		return nil, errors.New("stop before map update")
	}
	t.Cleanup(func() { findJavaNamespacedPIDs = original })

	const pid = app.PID(9001)
	fileInfo := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava},
		Pid:     pid,
	})
	fileInfo.SetJavaAgentCapability(11)
	tracer := &Tracer{
		log:                     tlog(),
		javaRemoteParentEnabled: false,
	}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	tracer.authorizeJavaProcess(pid, 1234, fileInfo)

	assert.Equal(t, 1, identityCalls)
	assert.Zero(t, fileInfo.JavaAgentCapability(), "failed identity resolution must gate attach")
}

func TestJavaAuthorizationRetiredCapabilityRotatesBeforeAttach(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	originalGenerate := generateJavaProcessCapability
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
		generateJavaProcessCapability = originalGenerate
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	var capabilities []uint64
	authorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) (bool, error) {
		capabilities = append(capabilities, capability)
		if capability == 11 {
			return false, javabridge.ErrProcessCapabilityRetired
		}
		return true, nil
	}
	generateJavaProcessCapability = func() (uint64, error) { return 22, nil }

	const pid = app.PID(9001)
	fileInfo := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	fileInfo.SetJavaAgentCapability(11)
	tracer := &Tracer{
		log: tlog(), javaRemoteParentEnabled: true,
		javaAuthKeys: make(map[javaAuthorizationKey][]javaAuthorization),
	}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	tracer.authorizeJavaProcess(pid, 1234, fileInfo)

	assert.Equal(t, []uint64{11, 22}, capabilities)
	assert.Equal(t, uint64(22), fileInfo.JavaAgentCapability())
	require.Len(t, tracer.javaAuthKeys[javaAuthorizationKey{pid: pid, ns: 1234}], 1)
	assert.Equal(t, uint64(22),
		tracer.javaAuthKeys[javaAuthorizationKey{pid: pid, ns: 1234}][0].capability)
}

func TestRepeatedConfirmedJavaLifetimeCompletesFreshAttachmentGate(t *testing.T) {
	const pid = app.PID(9001)
	key := javaAuthorizationKey{pid: pid, ns: 1234}
	fileInfo := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	event := &javaAuthorizationEvent{
		sequence:  1,
		file:      fileInfo,
		confirmed: true,
		authorization: javaAuthorization{
			capability: 11,
		},
	}
	tracer := &Tracer{
		javaAuthEvents: map[javaAuthorizationKey][]*javaAuthorizationEvent{
			key: {event},
		},
		javaAuthLatest: map[javaAuthorizationKey]uint64{key: event.sequence},
	}
	fileInfo.PrepareJavaAgentCapability(22)

	got, created := tracer.beginJavaAuthorizationEvent(key, fileInfo)

	assert.Same(t, event, got)
	assert.False(t, created)
	capability, err := fileInfo.WaitJavaAgentAuthorization(t.Context())
	require.NoError(t, err)
	assert.Equal(t, uint64(11), capability,
		"a repeated FileInfo must reuse its already-confirmed exact capability")
}

func TestRepeatedInFlightJavaLifetimeChainsFreshAttachmentGate(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Uint32
	authorizeJavaProcessCapability = func(
		javabridge.Maps, javabridge.Identity, uint64,
	) (bool, error) {
		calls.Add(1)
		close(started)
		<-release
		return true, nil
	}

	const pid = app.PID(9001)
	key := javaAuthorizationKey{pid: pid, ns: 1234}
	fileInfo := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	fileInfo.PrepareJavaAgentCapability(11)
	tracer := &Tracer{log: tlog(), javaRemoteParentEnabled: true}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}
	event, created := tracer.beginJavaAuthorizationEvent(key, fileInfo)
	require.True(t, created)
	require.True(t, tracer.supersedeJavaAuthorizationEvent(key, event, fileInfo))
	done := make(chan struct{})
	go func() {
		defer close(done)
		tracer.authorizeJavaProcessForEvent(pid, key.ns, fileInfo, event)
	}()
	<-started

	fileInfo.PrepareJavaAgentCapability(22)
	got, created := tracer.beginJavaAuthorizationEvent(key, fileInfo)
	assert.Same(t, event, got)
	assert.False(t, created, "one FileInfo lifetime must run one authorization goroutine")
	result := make(chan uint64, 1)
	go func() {
		capability, _ := fileInfo.WaitJavaAgentAuthorization(t.Context())
		result <- capability
	}()
	select {
	case capability := <-result:
		t.Fatalf("fresh gate completed before the in-flight authorization: %d", capability)
	default:
	}

	close(release)
	<-done
	assert.Equal(t, uint64(11), <-result)
	assert.Equal(t, uint32(1), calls.Load())
}

func TestJavaRetiredRotationSkipsPendingSuspensionCapabilities(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	originalGenerate := generateJavaProcessCapability
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
		generateJavaProcessCapability = originalGenerate
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	var authorized []uint64
	authorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) (bool, error) {
		authorized = append(authorized, capability)
		if capability == 11 {
			return false, javabridge.ErrProcessCapabilityRetired
		}
		return true, nil
	}
	generated := []uint64{22, 33}
	generateJavaProcessCapability = func() (uint64, error) {
		capability := generated[0]
		generated = generated[1:]
		return capability, nil
	}

	const pid = app.PID(9001)
	key := javaAuthorizationKey{pid: pid, ns: 1234}
	identity := javabridge.Identity{TID: uint32(pid), PID: uint32(pid), Namespace: key.ns}
	fileInfo := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	fileInfo.SetJavaAgentCapability(11)
	tracer := &Tracer{
		log: tlog(), javaRemoteParentEnabled: true,
		javaSuspendPending: map[javaAuthorizationKey]map[javaAuthorization]struct{}{
			key: {{identity: identity, capability: 22}: {}},
		},
	}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	tracer.authorizeJavaProcess(pid, key.ns, fileInfo)

	assert.Equal(t, []uint64{11, 33}, authorized)
	assert.Equal(t, uint64(33), fileInfo.JavaAgentCapability())
}

func TestFailedJavaAllowTombstonePreservesReplacementAuthorization(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	originalDeauthorize := deauthorizeJavaProcessCapability
	originalSuspend := suspendJavaProcessAuthorization
	originalTimeout := javaAuthorizationRetryTimeout
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
		deauthorizeJavaProcessCapability = originalDeauthorize
		suspendJavaProcessAuthorization = originalSuspend
		javaAuthorizationRetryTimeout = originalTimeout
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	authorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) (bool, error) {
		if capability == 11 {
			return false, errors.New("injected predecessor authorization failure")
		}
		return true, nil
	}
	suspendJavaProcessAuthorization = func(
		javabridge.Maps, javabridge.Identity, uint64,
	) error {
		return nil
	}
	var removed []uint64
	deauthorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64, _ bool,
	) error {
		removed = append(removed, capability)
		return nil
	}
	javaAuthorizationRetryTimeout = 0

	const pid = app.PID(9001)
	key := javaAuthorizationKey{pid: pid, ns: 1234}
	predecessor := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	replacement := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	tracer := &Tracer{log: tlog(), javaRemoteParentEnabled: true}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	predecessor.SetJavaAgentCapability(11)
	tracer.authorizeJavaProcess(pid, key.ns, predecessor)
	assert.Zero(t, predecessor.JavaAgentCapability())
	replacement.SetJavaAgentCapability(22)
	tracer.authorizeJavaProcess(pid, key.ns, replacement)
	require.Len(t, tracer.javaAuthEvents[key], 2)
	assert.Equal(t, uint64(22), replacement.JavaAgentCapability())

	tracer.deauthorizeJavaProcess(pid, key.ns, predecessor)
	assert.Equal(t, uint64(22), replacement.JavaAgentCapability(),
		"Block for failed A must not close replacement B's FileInfo gate")
	assert.Empty(t, removed)
	require.Len(t, tracer.javaAuthKeys[key], 1)
	assert.Equal(t, uint64(22), tracer.javaAuthKeys[key][0].capability)

	tracer.deauthorizeJavaProcess(pid, key.ns, replacement)
	assert.Zero(t, replacement.JavaAgentCapability())
	assert.Equal(t, []uint64{22}, removed)
	assert.NotContains(t, tracer.javaAuthKeys, key)
}

func TestRepeatedJavaAllowUsesOneExactLifetimeEvent(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	originalDeauthorize := deauthorizeJavaProcessCapability
	originalSuspend := suspendJavaProcessAuthorization
	originalTimeout := javaAuthorizationRetryTimeout
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
		deauthorizeJavaProcessCapability = originalDeauthorize
		suspendJavaProcessAuthorization = originalSuspend
		javaAuthorizationRetryTimeout = originalTimeout
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	var attempts []uint64
	authorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) (bool, error) {
		attempts = append(attempts, capability)
		if capability == 11 {
			return false, errors.New("injected first attempt failure")
		}
		return true, nil
	}
	suspendJavaProcessAuthorization = func(
		javabridge.Maps, javabridge.Identity, uint64,
	) error {
		return nil
	}
	var deauthorized []uint64
	deauthorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64, _ bool,
	) error {
		deauthorized = append(deauthorized, capability)
		return nil
	}
	javaAuthorizationRetryTimeout = 0

	const pid = app.PID(9001)
	const ns = uint32(1234)
	key := javaAuthorizationKey{pid: pid, ns: ns}
	fi := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	tracer := &Tracer{log: tlog(), javaRemoteParentEnabled: true}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	fi.SetJavaAgentCapability(11)
	tracer.authorizeJavaProcess(pid, ns, fi)
	assert.Zero(t, fi.JavaAgentCapability())
	require.Len(t, tracer.javaAuthEvents[key], 1)

	fi.SetJavaAgentCapability(22)
	tracer.authorizeJavaProcess(pid, ns, fi)
	assert.Equal(t, []uint64{11, 22}, attempts)
	assert.Equal(t, uint64(22), fi.JavaAgentCapability())
	require.Len(t, tracer.javaAuthEvents[key], 1,
		"one discovery lifetime must require exactly one deletion")

	tracer.deauthorizeJavaProcess(pid, ns, fi)
	assert.Equal(t, []uint64{22}, deauthorized)
	assert.NotContains(t, tracer.javaAuthEvents, key)
	assert.NotContains(t, tracer.javaAuthKeys, key)
}

func TestJavaAuthorizationWaitsPastOldRetryWindowForClaimRecovery(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalFindForOwner := findJavaNamespacedPIDsForOwner
	originalAuthorize := authorizeJavaProcessCapability
	originalValidateOwner := validateJavaProcessOwner
	originalTimeout := javaAuthorizationRetryTimeout
	originalInterval := javaAuthorizationRetryInterval
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		findJavaNamespacedPIDsForOwner = originalFindForOwner
		authorizeJavaProcessCapability = originalAuthorize
		validateJavaProcessOwner = originalValidateOwner
		javaAuthorizationRetryTimeout = originalTimeout
		javaAuthorizationRetryInterval = originalInterval
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	findJavaNamespacedPIDsForOwner = func(app.PID, *exec.FileInfo) ([]app.PID, error) {
		return nil, nil
	}
	validateJavaProcessOwner = func(app.PID, *exec.FileInfo) error { return nil }
	started := time.Now()
	authorizeJavaProcessCapability = func(
		javabridge.Maps, javabridge.Identity, uint64,
	) (bool, error) {
		if time.Since(started) < 150*time.Millisecond {
			return false, javabridge.ErrProcessClaimContended
		}
		return true, nil
	}
	javaAuthorizationRetryTimeout = 500 * time.Millisecond
	javaAuthorizationRetryInterval = 5 * time.Millisecond

	const pid = app.PID(9001)
	const ns = uint32(1234)
	fi := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava},
		Pid:     pid, ProcessStart: 77,
	})
	fi.SetJavaAgentCapability(11)
	tracer := &Tracer{log: tlog(), javaRemoteParentEnabled: true}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	tracer.authorizeJavaProcess(pid, ns, fi)

	assert.GreaterOrEqual(t, time.Since(started), 150*time.Millisecond)
	assert.Equal(t, uint64(11), fi.JavaAgentCapability())
}

func TestJavaAuthorizationRejectsPIDReuseBeforePublishingAttachGate(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalFindForOwner := findJavaNamespacedPIDsForOwner
	originalAuthorize := authorizeJavaProcessCapability
	originalSuspend := suspendJavaProcessAuthorization
	originalValidateOwner := validateJavaProcessOwner
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		findJavaNamespacedPIDsForOwner = originalFindForOwner
		authorizeJavaProcessCapability = originalAuthorize
		suspendJavaProcessAuthorization = originalSuspend
		validateJavaProcessOwner = originalValidateOwner
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	findJavaNamespacedPIDsForOwner = func(app.PID, *exec.FileInfo) ([]app.PID, error) {
		return nil, nil
	}
	var startReads atomic.Int32
	validateJavaProcessOwner = func(app.PID, *exec.FileInfo) error {
		if startReads.Add(1) <= 2 {
			return nil
		}
		return errors.New("injected PID reuse")
	}
	var authorized []uint64
	authorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) (bool, error) {
		authorized = append(authorized, capability)
		return true, nil
	}
	var suspended []uint64
	suspendJavaProcessAuthorization = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) error {
		suspended = append(suspended, capability)
		return nil
	}

	const pid = app.PID(9001)
	const ns = uint32(1234)
	fi := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava},
		Pid:     pid, ProcessStart: 77,
	})
	fi.SetJavaAgentCapability(11)
	tracer := &Tracer{log: tlog(), javaRemoteParentEnabled: true}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	tracer.authorizeJavaProcess(pid, ns, fi)

	assert.Equal(t, []uint64{11}, authorized)
	assert.Equal(t, []uint64{11}, suspended)
	assert.Zero(t, fi.JavaAgentCapability())
}

func TestFailedJavaReplacementRevokesPredecessorAuthorization(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	originalDeauthorize := deauthorizeJavaProcessCapability
	originalSuspend := suspendJavaProcessAuthorization
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
		deauthorizeJavaProcessCapability = originalDeauthorize
		suspendJavaProcessAuthorization = originalSuspend
	})
	var identityCalls atomic.Int32
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) {
		if identityCalls.Add(1) == 2 {
			return nil, errors.New("injected replacement identity failure")
		}
		return nil, nil
	}
	var authorized uint64
	authorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) (bool, error) {
		authorized = capability
		return true, nil
	}
	var suspended []uint64
	suspendJavaProcessAuthorization = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) error {
		suspended = append(suspended, capability)
		if authorized == capability {
			authorized = 0
		}
		return nil
	}
	deauthorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64, _ bool,
	) error {
		if authorized == capability {
			authorized = 0
		}
		return nil
	}

	const pid = app.PID(9001)
	key := javaAuthorizationKey{pid: pid, ns: 1234}
	newFile := func(capability uint64) *exec.FileInfo {
		fi := exec.New(exec.Init{
			Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
		})
		fi.SetJavaAgentCapability(capability)
		return fi
	}
	predecessor := newFile(11)
	replacement := newFile(22)
	tracer := &Tracer{log: tlog(), javaRemoteParentEnabled: true}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	tracer.authorizeJavaProcess(pid, key.ns, predecessor)
	require.Equal(t, uint64(11), authorized)
	tracer.authorizeJavaProcess(pid, key.ns, replacement)

	assert.Zero(t, authorized, "failed B must not leave predecessor Q(A) live")
	assert.Equal(t, []uint64{11}, suspended)
	assert.Zero(t, predecessor.JavaAgentCapability())
	assert.Zero(t, replacement.JavaAgentCapability())

	tracer.deauthorizeJavaProcess(pid, key.ns, predecessor)
	tracer.deauthorizeJavaProcess(pid, key.ns, replacement)
	successor := newFile(33)
	tracer.authorizeJavaProcess(pid, key.ns, successor)
	require.Equal(t, uint64(33), authorized)
	tracer.deauthorizeJavaProcess(pid, key.ns, successor)
	assert.Zero(t, authorized)
}

func TestFailedJavaBlockDuringReplacementAttemptPreservesReplacement(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	originalSuspend := suspendJavaProcessAuthorization
	originalTimeout := javaAuthorizationRetryTimeout
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
		suspendJavaProcessAuthorization = originalSuspend
		javaAuthorizationRetryTimeout = originalTimeout
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	started := make(chan struct{})
	release := make(chan struct{})
	authorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) (bool, error) {
		if capability == 11 {
			return false, errors.New("injected predecessor authorization failure")
		}
		close(started)
		<-release
		return true, nil
	}
	suspendJavaProcessAuthorization = func(
		javabridge.Maps, javabridge.Identity, uint64,
	) error {
		return nil
	}
	javaAuthorizationRetryTimeout = 0

	const pid = app.PID(9001)
	key := javaAuthorizationKey{pid: pid, ns: 1234}
	predecessor := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	replacement := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	tracer := &Tracer{log: tlog(), javaRemoteParentEnabled: true}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}
	predecessor.SetJavaAgentCapability(11)
	tracer.authorizeJavaProcess(pid, key.ns, predecessor)
	replacement.SetJavaAgentCapability(22)

	allowDone := make(chan struct{})
	go func() {
		defer close(allowDone)
		tracer.authorizeJavaProcess(pid, key.ns, replacement)
	}()
	<-started
	blockDone := make(chan struct{})
	go func() {
		defer close(blockDone)
		tracer.deauthorizeJavaProcess(pid, key.ns, predecessor)
	}()
	close(release)
	<-allowDone
	<-blockDone

	assert.Equal(t, uint64(22), replacement.JavaAgentCapability())
	require.Len(t, tracer.javaAuthKeys[key], 1)
	assert.Equal(t, uint64(22), tracer.javaAuthKeys[key][0].capability)
}

func TestOutOfOrderJavaAllowCompletionCannotOverwriteNewerEvent(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
	})
	firstResolver := make(chan struct{})
	releaseFirst := make(chan struct{})
	var resolverCalls atomic.Int32
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) {
		if resolverCalls.Add(1) == 1 {
			close(firstResolver)
			<-releaseFirst
		}
		return nil, nil
	}
	var authorized []uint64
	authorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) (bool, error) {
		authorized = append(authorized, capability)
		return true, nil
	}

	const pid = app.PID(9001)
	key := javaAuthorizationKey{pid: pid, ns: 1234}
	predecessor := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	replacement := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	predecessor.SetJavaAgentCapability(11)
	replacement.SetJavaAgentCapability(22)
	tracer := &Tracer{log: tlog(), javaRemoteParentEnabled: true}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	predecessorDone := make(chan struct{})
	go func() {
		defer close(predecessorDone)
		tracer.authorizeJavaProcess(pid, key.ns, predecessor)
	}()
	<-firstResolver
	assert.Zero(t, predecessor.JavaAgentCapability(),
		"FileInfo gate must close before namespace resolution blocks")
	tracer.authorizeJavaProcess(pid, key.ns, replacement)
	close(releaseFirst)
	<-predecessorDone

	assert.Equal(t, []uint64{22}, authorized)
	assert.Zero(t, predecessor.JavaAgentCapability())
	assert.Equal(t, uint64(22), replacement.JavaAgentCapability())
	require.Len(t, tracer.javaAuthKeys[key], 1)
	assert.Equal(t, uint64(22), tracer.javaAuthKeys[key][0].capability)
}

func TestRemovedReplacementCannotMakeSupersededAllowCurrentAgain(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	var authorized []uint64
	authorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) (bool, error) {
		authorized = append(authorized, capability)
		return true, nil
	}

	const pid = app.PID(9001)
	const ns = uint32(1234)
	key := javaAuthorizationKey{pid: pid, ns: ns}
	predecessor := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	replacement := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	predecessor.SetJavaAgentCapability(11)
	replacement.SetJavaAgentCapability(22)
	tracer := &Tracer{log: tlog(), javaRemoteParentEnabled: true}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	predecessorEvent, created := tracer.beginJavaAuthorizationEvent(key, predecessor)
	require.True(t, created)
	_, created = tracer.beginJavaAuthorizationEvent(key, replacement)
	require.True(t, created)
	tracer.deauthorizeJavaProcess(pid, ns, replacement)

	tracer.authorizeJavaProcessForEvent(pid, ns, predecessor, predecessorEvent)

	assert.Empty(t, authorized)
	assert.Zero(t, predecessor.JavaAgentCapability())
	require.Len(t, tracer.javaAuthEvents[key], 1)
	assert.Same(t, predecessorEvent, tracer.javaAuthEvents[key][0])
	assert.NotEqual(t, predecessorEvent.sequence, tracer.javaAuthLatest[key])
}

func TestContendedJavaAuthorizationDoesNotBlockUnrelatedDeletion(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	started := make(chan struct{})
	release := make(chan struct{})
	authorizeJavaProcessCapability = func(
		javabridge.Maps, javabridge.Identity, uint64,
	) (bool, error) {
		close(started)
		<-release
		return true, nil
	}

	const pid = app.PID(9001)
	const ns = uint32(1234)
	fi := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	fi.SetJavaAgentCapability(11)
	tracer := &Tracer{
		log: tlog(), pidsFilter: &ebpfcommon.IdentityPidsFilter{},
		javaRemoteParentEnabled: true,
	}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	allowDone := make(chan struct{})
	go func() {
		defer close(allowDone)
		tracer.AllowPID(pid, ns, fi, fi)
	}()
	<-started

	unrelated := exec.New(exec.Init{Pid: 42})
	blockDone := make(chan struct{})
	go func() {
		defer close(blockDone)
		tracer.BlockPID(42, ns, unrelated, unrelated)
	}()
	select {
	case <-blockDone:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("unrelated BlockPID waited behind Java authorization")
	}
	close(release)
	<-allowDone
}

func TestJavaPendingDeauthorizationDoesNotConsumeReplacementBlock(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	originalDeauthorize := deauthorizeJavaProcessCapability
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
		deauthorizeJavaProcessCapability = originalDeauthorize
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	authorizeJavaProcessCapability = func(
		javabridge.Maps, javabridge.Identity, uint64,
	) (bool, error) {
		return true, nil
	}
	var removed []uint64
	deauthorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64, _ bool,
	) error {
		removed = append(removed, capability)
		if len(removed) == 1 {
			return errors.New("transient deletion failure")
		}
		return nil
	}

	const pid = app.PID(9001)
	key := javaAuthorizationKey{pid: pid, ns: 1234}
	predecessor := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	replacement := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	predecessor.SetJavaAgentCapability(11)
	tracer := &Tracer{
		log: tlog(), javaRemoteParentEnabled: true,
		javaAuthKeys: make(map[javaAuthorizationKey][]javaAuthorization),
	}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	tracer.authorizeJavaProcess(pid, key.ns, predecessor)
	tracer.deauthorizeJavaProcess(pid, key.ns, predecessor)
	require.Contains(t, tracer.javaDeauthPending, key)

	replacement.SetJavaAgentCapability(22)
	tracer.authorizeJavaProcess(pid, key.ns, replacement)
	require.Len(t, tracer.javaAuthKeys[key], 1)
	assert.Equal(t, uint64(22), tracer.javaAuthKeys[key][0].capability)

	tracer.deauthorizeJavaProcess(pid, key.ns, replacement)
	assert.Equal(t, []uint64{11, 22}, removed)
	assert.NotContains(t, tracer.javaAuthKeys, key)
	require.Contains(t, tracer.javaDeauthPending, key)

	tracer.retryPendingJavaDeauthorizations()
	assert.Equal(t, []uint64{11, 22, 11}, removed)
	assert.NotContains(t, tracer.javaDeauthPending, key)
}

func TestJavaBlockCancelsAuthorizationWithoutWaitingForRetryLoop(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	originalDeauthorize := deauthorizeJavaProcessCapability
	originalSuspend := suspendJavaProcessAuthorization
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
		deauthorizeJavaProcessCapability = originalDeauthorize
		suspendJavaProcessAuthorization = originalSuspend
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	started := make(chan struct{})
	release := make(chan struct{})
	var authorized atomic.Uint64
	authorizeJavaProcessCapability = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) (bool, error) {
		close(started)
		<-release
		authorized.Store(capability)
		return true, nil
	}
	deauthorizeJavaProcessCapability = func(
		javabridge.Maps, javabridge.Identity, uint64, bool,
	) error {
		return nil
	}
	var suspensionCount atomic.Uint32
	firstSuspension := make(chan struct{})
	compensated := make(chan struct{})
	suspendJavaProcessAuthorization = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) error {
		authorized.CompareAndSwap(capability, 0)
		switch suspensionCount.Add(1) {
		case 1:
			close(firstSuspension)
		case 2:
			close(compensated)
		}
		return nil
	}

	const pid = app.PID(9001)
	key := javaAuthorizationKey{pid: pid, ns: 1234}
	fileInfo := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	fileInfo.SetJavaAgentCapability(11)
	tracer := &Tracer{
		log: tlog(), javaRemoteParentEnabled: true,
		javaAuthKeys: make(map[javaAuthorizationKey][]javaAuthorization),
	}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		tracer.authorizeJavaProcess(pid, key.ns, fileInfo)
	}()
	<-started
	blockDone := make(chan struct{})
	go func() {
		defer close(blockDone)
		tracer.deauthorizeJavaProcess(pid, key.ns, fileInfo)
	}()
	<-firstSuspension
	close(release)
	<-compensated
	<-blockDone
	<-done

	assert.Zero(t, authorized.Load(),
		"stale authorization commit must be exactly suspended after Block")
	assert.Equal(t, uint32(2), suspensionCount.Load(),
		"Block and the stale post-call completion each need an exact suspension")
	assert.Zero(t, fileInfo.JavaAgentCapability())
	assert.NotContains(t, tracer.javaAuthKeys, key)
}

func TestJavaDisabledAuthorizationSerializesPublicAllowAndBlock(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalUpdate := updateJavaAuthorizedProcess
	originalSuspend := suspendJavaProcessAuthorization
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		updateJavaAuthorizedProcess = originalUpdate
		suspendJavaProcessAuthorization = originalSuspend
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	started := make(chan struct{})
	release := make(chan struct{})
	var authorized atomic.Uint64
	updateJavaAuthorizedProcess = func(
		_ *ebpf.Map, _ javabridge.Identity, capability uint64,
	) error {
		close(started)
		<-release
		authorized.Store(capability)
		return nil
	}
	var suspensionCount atomic.Uint32
	firstSuspension := make(chan struct{})
	compensated := make(chan struct{})
	suspendJavaProcessAuthorization = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) error {
		authorized.CompareAndSwap(capability, 0)
		switch suspensionCount.Add(1) {
		case 1:
			close(firstSuspension)
		case 2:
			close(compensated)
		}
		return nil
	}

	const pid = app.PID(9001)
	const ns = uint32(1234)
	fileInfo := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	fileInfo.SetJavaAgentCapability(11)
	tracer := &Tracer{
		log:                     tlog(),
		pidsFilter:              &ebpfcommon.IdentityPidsFilter{},
		javaRemoteParentEnabled: false,
	}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	tracer.AllowPID(pid, ns, fileInfo, fileInfo)
	<-started
	blockDone := make(chan struct{})
	go func() {
		defer close(blockDone)
		tracer.BlockPID(pid, ns, fileInfo, fileInfo)
	}()
	<-firstSuspension
	close(release)
	<-compensated
	<-blockDone
	require.Eventually(t, func() bool {
		tracer.javaAuthMu.Lock()
		defer tracer.javaAuthMu.Unlock()
		for _, event := range tracer.javaAuthEvents[javaAuthorizationKey{pid: pid, ns: ns}] {
			if event.authorizing {
				return false
			}
		}
		return true
	}, time.Second, time.Millisecond)

	assert.Zero(t, authorized.Load(), "Block must remove a stale committed direct Q")
	assert.Equal(t, uint32(2), suspensionCount.Load())
	assert.Zero(t, fileInfo.JavaAgentCapability())
	assert.Empty(t, tracer.javaAuthEvents)
	assert.Empty(t, tracer.javaAuthKeys)
}

func TestJavaDisabledStalePublicationPreservesConfirmedReplacement(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalUpdate := updateJavaAuthorizedProcess
	originalSuspend := suspendJavaProcessAuthorization
	originalLock := lockJavaAuthorizationPublication
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		updateJavaAuthorizedProcess = originalUpdate
		suspendJavaProcessAuthorization = originalSuspend
		lockJavaAuthorizationPublication = originalLock
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }

	var authorized atomic.Uint64
	var updateCount atomic.Uint32
	updateJavaAuthorizedProcess = func(
		_ *ebpf.Map, _ javabridge.Identity, capability uint64,
	) error {
		updateCount.Add(1)
		authorized.Store(capability)
		return nil
	}
	suspendJavaProcessAuthorization = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) error {
		authorized.CompareAndSwap(capability, 0)
		return nil
	}

	predecessorChecked := make(chan struct{})
	releasePredecessor := make(chan struct{})
	var lockCalls atomic.Uint32
	lockJavaAuthorizationPublication = func(
		coordinator *javaAuthorizationPublicationCoordinator,
		key javaAuthorizationKey,
	) func() {
		if lockCalls.Add(1) == 1 {
			close(predecessorChecked)
			<-releasePredecessor
		}
		return coordinator.lock(key)
	}

	const pid = app.PID(9001)
	const ns = uint32(1234)
	key := javaAuthorizationKey{pid: pid, ns: ns}
	newFile := func(capability uint64) *exec.FileInfo {
		fi := exec.New(exec.Init{
			Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
		})
		fi.SetJavaAgentCapability(capability)
		return fi
	}
	predecessor := newFile(11)
	replacement := newFile(22)
	tracer := &Tracer{log: tlog(), javaRemoteParentEnabled: false}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	predecessorDone := make(chan struct{})
	go func() {
		defer close(predecessorDone)
		tracer.authorizeJavaProcess(pid, ns, predecessor)
	}()
	select {
	case <-predecessorChecked:
	case <-time.After(time.Second):
		close(releasePredecessor)
		t.Fatal("predecessor did not reach the post-ownership publication boundary")
	}

	// Complete B while A is paused after its optimistic ownership check. The
	// publication transaction must make A recheck before it can touch Q.
	tracer.authorizeJavaProcess(pid, ns, replacement)
	tracer.javaAuthMu.Lock()
	events := tracer.javaAuthEvents[key]
	replacementConfirmed := len(events) != 0 && events[len(events)-1].file == replacement &&
		events[len(events)-1].confirmed
	tracer.javaAuthMu.Unlock()
	assert.True(t, replacementConfirmed, "replacement must confirm before predecessor resumes")
	assert.Equal(t, uint64(22), authorized.Load())
	assert.Equal(t, uint64(22), replacement.JavaAgentCapability())

	close(releasePredecessor)
	select {
	case <-predecessorDone:
	case <-time.After(time.Second):
		t.Fatal("stale predecessor publication did not finish")
	}

	assert.Equal(t, uint32(1), updateCount.Load(), "stale A must not overwrite Q(B)")
	assert.Equal(t, uint64(22), authorized.Load(), "Q must retain confirmed B")
	assert.Zero(t, predecessor.JavaAgentCapability())
	assert.Equal(t, uint64(22), replacement.JavaAgentCapability())
	require.Len(t, tracer.javaAuthKeys[key], 1)
	assert.Equal(t, uint64(22), tracer.javaAuthKeys[key][0].capability)
}

func TestJavaUnconfirmedAuthorizationRetriesExactSuspensionWithoutHistory(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	originalSuspend := suspendJavaProcessAuthorization
	originalTimeout := javaAuthorizationRetryTimeout
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
		suspendJavaProcessAuthorization = originalSuspend
		javaAuthorizationRetryTimeout = originalTimeout
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }
	authorizeJavaProcessCapability = func(
		javabridge.Maps, javabridge.Identity, uint64,
	) (bool, error) {
		return false, errors.New("authorization commit is unknown")
	}
	javaAuthorizationRetryTimeout = 0
	suspensions := 0
	suspendJavaProcessAuthorization = func(
		_ javabridge.Maps, _ javabridge.Identity, capability uint64,
	) error {
		assert.Equal(t, uint64(11), capability)
		suspensions++
		if suspensions == 1 {
			return errors.New("suspension readback failed")
		}
		return nil
	}

	const pid = app.PID(9001)
	key := javaAuthorizationKey{pid: pid, ns: 1234}
	fileInfo := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	fileInfo.SetJavaAgentCapability(11)
	tracer := &Tracer{
		log: tlog(), javaRemoteParentEnabled: true,
		javaAuthKeys: make(map[javaAuthorizationKey][]javaAuthorization),
	}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}

	tracer.authorizeJavaProcess(pid, key.ns, fileInfo)

	assert.Zero(t, fileInfo.JavaAgentCapability())
	require.Contains(t, tracer.javaSuspendPending, key)
	assert.NotContains(t, tracer.javaAuthKeys, key)

	tracer.retryPendingJavaDeauthorizations()
	assert.Equal(t, 2, suspensions)
	assert.NotContains(t, tracer.javaSuspendPending, key)
	require.Len(t, tracer.javaAuthEvents[key], 1,
		"failed Allow must retain a tombstone for its paired Block")
	assert.Contains(t, tracer.javaAuthVersions, key)

	tracer.deauthorizeJavaProcess(pid, key.ns, fileInfo)
	assert.NotContains(t, tracer.javaAuthEvents, key)
	assert.NotContains(t, tracer.javaAuthVersions, key)
}

func TestJavaWorkerShutdownPrecedesResourceClose(t *testing.T) {
	originalFind := findJavaNamespacedPIDs
	originalAuthorize := authorizeJavaProcessCapability
	originalSuspend := suspendJavaProcessAuthorization
	t.Cleanup(func() {
		findJavaNamespacedPIDs = originalFind
		authorizeJavaProcessCapability = originalAuthorize
		suspendJavaProcessAuthorization = originalSuspend
	})
	findJavaNamespacedPIDs = func(app.PID) ([]app.PID, error) { return nil, nil }

	authorizationStarted := make(chan struct{})
	releaseAuthorization := make(chan struct{})
	operations := make(chan string, 3)
	authorizeJavaProcessCapability = func(
		javabridge.Maps, javabridge.Identity, uint64,
	) (bool, error) {
		close(authorizationStarted)
		<-releaseAuthorization
		operations <- "authorize"
		return true, nil
	}
	suspendJavaProcessAuthorization = func(
		javabridge.Maps, javabridge.Identity, uint64,
	) error {
		operations <- "suspend"
		return nil
	}

	const pid = app.PID(9001)
	const ns = uint32(1234)
	fileInfo := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	fileInfo.SetJavaAgentCapability(11)
	tracer := &Tracer{
		log: tlog(), pidsFilter: &ebpfcommon.IdentityPidsFilter{},
		javaRemoteParentEnabled: true,
	}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}
	resourceCloser := newOrderedResourceCloser(
		tracer.stopJavaWorkers,
		testCloserFunc(func() error {
			operations <- "close"
			return nil
		}),
	)

	tracer.AllowPID(pid, ns, fileInfo, fileInfo)
	<-authorizationStarted
	closeDone := make(chan error, 1)
	go func() { closeDone <- resourceCloser.Close() }()
	select {
	case err := <-closeDone:
		close(releaseAuthorization)
		t.Fatalf("resource close overtook the authorization worker: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseAuthorization)
	require.NoError(t, <-closeDone)
	assert.Equal(t, []string{"authorize", "suspend", "close"}, []string{
		<-operations,
		<-operations,
		<-operations,
	})
	assert.Zero(t, fileInfo.JavaAgentCapability())
}

func TestPendingJavaDeauthorizationWorkerShutdownPrecedesResourceClose(t *testing.T) {
	originalDeauthorize := deauthorizeJavaProcessCapability
	originalInterval := javaDeauthorizationRetryInterval
	t.Cleanup(func() {
		deauthorizeJavaProcessCapability = originalDeauthorize
		javaDeauthorizationRetryInterval = originalInterval
	})
	javaDeauthorizationRetryInterval = time.Millisecond

	deauthorizationStarted := make(chan struct{})
	releaseDeauthorization := make(chan struct{})
	operations := make(chan string, 2)
	deauthorizeJavaProcessCapability = func(
		javabridge.Maps, javabridge.Identity, uint64, bool,
	) error {
		close(deauthorizationStarted)
		<-releaseDeauthorization
		operations <- "deauthorize"
		return nil
	}

	key := javaAuthorizationKey{pid: 9001, ns: 1234}
	authorization := javaAuthorization{
		identity:   javabridge.Identity{TID: 9001, PID: 9001, Namespace: key.ns},
		capability: 11,
	}
	tracer := &Tracer{
		log: tlog(),
		javaDeauthPending: map[javaAuthorizationKey]map[javaAuthorization]struct{}{
			key: {authorization: {}},
		},
	}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}
	require.True(t, tracer.startPendingJavaDeauthorizationWorker())
	<-deauthorizationStarted
	resourceCloser := newOrderedResourceCloser(
		tracer.stopJavaWorkers,
		testCloserFunc(func() error {
			operations <- "close"
			return nil
		}),
	)

	closeDone := make(chan error, 1)
	go func() { closeDone <- resourceCloser.Close() }()
	select {
	case err := <-closeDone:
		close(releaseDeauthorization)
		t.Fatalf("resource close overtook the deauthorization worker: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseDeauthorization)
	require.NoError(t, <-closeDone)
	assert.Equal(t, []string{"deauthorize", "close"}, []string{
		<-operations,
		<-operations,
	})
}

func TestJavaAuthorizationRetryWaitStopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan bool, 1)
	go func() {
		done <- waitJavaAuthorizationRetry(ctx, 11*time.Second)
	}()
	cancel()

	select {
	case completedInterval := <-done:
		assert.False(t, completedInterval)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("authorization retry did not stop promptly after cancellation")
	}
}

func TestLateJavaAllowAndBlockFailClosedAfterShutdown(t *testing.T) {
	originalAuthorize := authorizeJavaProcessCapability
	t.Cleanup(func() { authorizeJavaProcessCapability = originalAuthorize })
	var authorizationCalls atomic.Int32
	authorizeJavaProcessCapability = func(
		javabridge.Maps, javabridge.Identity, uint64,
	) (bool, error) {
		authorizationCalls.Add(1)
		return true, nil
	}

	tracer := &Tracer{
		log: tlog(), pidsFilter: &ebpfcommon.IdentityPidsFilter{},
		javaRemoteParentEnabled: true,
	}
	tracer.bpfObjects.JavaAuthorizedProcesses = &ebpf.Map{}
	tracer.stopJavaWorkers()

	const pid = app.PID(9001)
	const ns = uint32(1234)
	allowed := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	allowGeneration := allowed.PrepareJavaAgentCapability(11)
	tracer.AllowPID(pid, ns, allowed, allowed)
	capability, err := allowed.WaitJavaAgentAuthorizationGeneration(t.Context(), allowGeneration)
	require.NoError(t, err)
	assert.Zero(t, capability)

	blocked := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid,
	})
	blockGeneration := blocked.PrepareJavaAgentCapability(22)
	tracer.BlockPID(pid, ns, blocked, blocked)
	capability, err = blocked.WaitJavaAgentAuthorizationGeneration(t.Context(), blockGeneration)
	require.NoError(t, err)
	assert.Zero(t, capability)
	assert.Zero(t, authorizationCalls.Load())
	assert.Empty(t, tracer.javaAuthEvents)

	parent := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava}, Pid: pid + 1,
	})
	parent.PrepareJavaAgentCapability(33)
	childOwner := exec.New(exec.Init{Pid: pid + 2})
	tracer.AllowPID(childOwner.Pid(), ns, parent, childOwner)
	tracer.BlockPID(childOwner.Pid(), ns, parent, childOwner)
	assert.Equal(t, uint64(33), parent.JavaAgentCapability(),
		"a substituted child cannot fail the live parent's attachment gate during shutdown")
}

func TestJavaDataHookIsOptional(t *testing.T) {
	tracer := &Tracer{cfg: &obi.Config{}}
	assert.False(t, tracer.KProbes()["security_file_ioctl"].Required)
}

func TestSSLAllocationProbeFencesPointerReuse(t *testing.T) {
	program := &ebpf.Program{}
	tracer := &Tracer{cfg: &obi.Config{}}
	tracer.bpfObjects.ObiUretprobeSslNew = program

	probes := tracer.UProbes()["libssl.so"]["SSL_new"]
	require.Len(t, probes, 1)
	assert.False(t, probes[0].Required)
	assert.Nil(t, probes[0].Start)
	assert.Same(t, program, probes[0].End)
}

func TestJavaDataHookAttachResultPublishesReadiness(t *testing.T) {
	originalUpdate := updateJavaRemoteParentDataHookReadiness
	t.Cleanup(func() { updateJavaRemoteParentDataHookReadiness = originalUpdate })

	var states []uint32
	updateJavaRemoteParentDataHookReadiness = func(_ *ebpf.Map, state uint32) error {
		states = append(states, state)
		return nil
	}

	tracer := &Tracer{
		cfg:                     &obi.Config{},
		log:                     tlog(),
		javaRemoteParentEnabled: true,
	}
	tracer.bpfObjects.JavaRemoteParentDataHookReadiness = &ebpf.Map{}
	tracer.bpfObjects.ObiKprobeJavaRemoteParentTcpClose = &ebpf.Program{}
	probes := tracer.KProbes()
	dataAttachResult := probes["security_file_ioctl"].AttachResult
	closeProbe := probes["tcp_close/java_remote_parent"]
	closeAttachResult := closeProbe.AttachResult
	require.NotNil(t, dataAttachResult)
	require.NotNil(t, closeAttachResult)
	assert.True(t, closeProbe.Required)
	assert.Equal(t, "tcp_close", closeProbe.KProbeTarget)
	assert.Same(t, tracer.bpfObjects.ObiKprobeJavaRemoteParentTcpClose, closeProbe.Start)
	assert.NotSame(t, probes["tcp_close"].Start, closeProbe.Start)

	dataAttachResult(nil)
	closeAttachResult(nil)
	closeAttachResult(errors.New("missing close hook"))
	closeAttachResult(nil)
	dataAttachResult(errors.New("missing security hook"))

	assert.Equal(t, []uint32{0, 1, 0, 1, 0}, states)

	states = nil
	reverse := &Tracer{
		cfg:                     &obi.Config{},
		log:                     tlog(),
		javaRemoteParentEnabled: true,
	}
	reverse.bpfObjects.JavaRemoteParentDataHookReadiness = &ebpf.Map{}
	reverse.bpfObjects.ObiKprobeJavaRemoteParentTcpClose = &ebpf.Program{}
	reverseProbes := reverse.KProbes()
	reverseProbes["tcp_close/java_remote_parent"].AttachResult(nil)
	reverseProbes["security_file_ioctl"].AttachResult(nil)
	assert.Equal(t, []uint32{0, 1}, states)

	disabled := &Tracer{cfg: &obi.Config{}, log: tlog()}
	_, found := disabled.KProbes()["tcp_close/java_remote_parent"]
	assert.False(t, found)
}

func TestJavaControlTailReadinessUsesExactBooleanState(t *testing.T) {
	originalUpdate := updateJavaRemoteParentControlTailReadiness
	t.Cleanup(func() { updateJavaRemoteParentControlTailReadiness = originalUpdate })

	var states []uint32
	updateJavaRemoteParentControlTailReadiness = func(_ *ebpf.Map, state uint32) error {
		states = append(states, state)
		return nil
	}

	tracer := &Tracer{log: tlog()}
	tracer.bpfObjects.JavaRemoteParentControlTailReadiness = &ebpf.Map{}
	tracer.setJavaRemoteParentControlTailReadiness(false)
	tracer.setJavaRemoteParentControlTailReadiness(true)
	tracer.setJavaRemoteParentControlTailReadiness(false)

	assert.Equal(t, []uint32{0, 1, 0}, states)
}

func TestJavaLifecycleTailCallWiring(t *testing.T) {
	const lifecycleSlot = 20

	lifecycle := &ebpf.Program{}
	tracer := &Tracer{}
	tracer.bpfObjects.ObiJavaLifecycleTail = lifecycle

	programs := tracer.tailCallPrograms()
	require.Len(t, programs, lifecycleSlot+1)
	require.Same(t, lifecycle, programs[lifecycleSlot])
}

func TestJavaRemoteParentRequiresSockOpsNetnsCookie(t *testing.T) {
	unsupported := errors.New("network namespace cookie helper unavailable")
	tests := []struct {
		name          string
		transport     obi.JavaRemoteParentTransport
		probeErr      error
		expected      bool
		expectedCalls int
	}{
		{name: "disabled", transport: obi.JavaRemoteParentDisabled},
		{
			name:          "supported",
			transport:     obi.JavaRemoteParentUnix,
			expected:      true,
			expectedCalls: 1,
		},
		{
			name:          "unsupported",
			transport:     obi.JavaRemoteParentUnix,
			probeErr:      unsupported,
			expectedCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := obi.DefaultConfig
			cfg.Java.RemoteParent.Transport = tt.transport
			tracer := New(nil, &cfg, nil)
			probeCalls := 0
			tracer.haveSockOpsNetnsCookie = func() error {
				probeCalls++
				return tt.probeErr
			}

			bundles, err := tracer.LoadSpecs()
			require.NoError(t, err)
			require.Len(t, bundles, 1)
			assert.Equal(t, tt.expectedCalls, probeCalls)
			assert.Equal(t, tt.expected, bundles[0].Constants["java_remote_parent_enabled"])

			for _, name := range []string{"incoming_trace_heads", "incoming_trace_candidates"} {
				mapSpec := bundles[0].Spec.Maps[name]
				require.NotNil(t, mapSpec, name)
				if tt.expected {
					assert.Greater(t, mapSpec.MaxEntries, uint32(1), name)
				} else {
					assert.Equal(t, uint32(1), mapSpec.MaxEntries, name)
				}
			}
			writeArgs := bundles[0].Spec.Maps["active_ssl_write_args"]
			require.NotNil(t, writeArgs)
			assert.Equal(t, uint32(16), writeArgs.KeySize)
			assert.Equal(t, ebpf.LRUHash, writeArgs.Type)
		})
	}
}

func TestSSLProcessExitCleanupIsAlwaysAttached(t *testing.T) {
	tracepoints := (&Tracer{}).Tracepoints()
	require.Contains(t, tracepoints, "sched/sched_process_exit")
	assert.True(t, tracepoints["sched/sched_process_exit"].Required)
}

func TestParseJVMMemoryPoolRecordDecoratesServiceByPIDNamespace(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders", Namespace: "prod"}}
	currentPIDsCalls := 0
	tracer := &Tracer{
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				7:  {1234: {UID: svc.UID{Name: "wrong"}}},
				42: {1234: service},
			},
			currentPIDsCalls: &currentPIDsCalls,
		},
	}

	events, ignore, err := tracer.parseJVMMemoryPoolRecord(&ringbuf.Record{
		RawSample: rawMemoryPoolPayload(t, BpfJvmMemPoolGcEvent{
			Timestamp:  123,
			NsPid:      1234,
			PidNsId:    42,
			GcWhenType: uint32(jvmruntime.RawJVMGCWhenAfter),
			Used:       100,
			Committed:  200,
			MaxSize:    300,
			Pool:       rawJVMString("G1 Eden Space"),
		}),
	})

	require.NoError(t, err)
	require.False(t, ignore)
	require.Len(t, events, 4)
	for _, event := range events {
		assert.Equal(t, service, event.Service)
	}
	assert.Equal(t, 1, currentPIDsCalls)
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsed, events[0].Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryCommitted, events[1].Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryLimit, events[2].Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsedAfterLastGC, events[3].Kind)
}

func TestParseJVMMemoryPoolRecordIgnoresUnknownPID(t *testing.T) {
	tracer := &Tracer{
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				42: {1234: {UID: svc.UID{Name: "orders"}}},
			},
		},
	}

	events, ignore, err := tracer.parseJVMMemoryPoolRecord(&ringbuf.Record{
		RawSample: rawMemoryPoolPayload(t, BpfJvmMemPoolGcEvent{
			NsPid:      9999,
			PidNsId:    42,
			GcWhenType: uint32(jvmruntime.RawJVMGCWhenAfter),
			Used:       100,
			Committed:  200,
			Pool:       rawJVMString("G1 Eden Space"),
		}),
	})

	require.NoError(t, err)
	assert.True(t, ignore)
	assert.Empty(t, events)
}

func TestProcessSharedRingbufRecordConsumesJVMRuntimeMetricRecordsWithoutForwarding(t *testing.T) {
	for _, tt := range []struct {
		name    string
		enabled bool
	}{
		{name: "metrics disabled"},
		{name: "queue missing", enabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tracer := &Tracer{cfg: &obi.Config{}}
			if tt.enabled {
				tracer.cfg.Metrics.Features = export.FeatureApplicationRuntime
			}

			span, ignore, err := tracer.processSharedRingbufRecord(context.Background(), nil, &tracer.cfg.EBPF, &ringbuf.Record{
				RawSample: []byte{ebpfcommon.EventTypeJVMMemoryPoolGC},
			})

			require.NoError(t, err)
			assert.True(t, ignore)
			assert.Empty(t, span)
		})
	}
}

func TestProcessSharedRingbufRecordDispatchesJVMMemoryPoolRecord(t *testing.T) {
	service := svc.Attrs{UID: svc.UID{Name: "orders", Namespace: "prod"}}
	runtimeMetrics := msg.NewQueue[[]runtimemetrics.RuntimeMetricSnapshot](msg.ChannelBufferLen(1))
	received := runtimeMetrics.Subscribe(msg.SubscriberName("jvm-test"))
	tracer := &Tracer{
		cfg: &obi.Config{},
		pidsFilter: fakeServiceFilter{
			current: map[uint32]map[app.PID]svc.Attrs{
				42: {1234: service},
			},
		},
		eventCtx: &ebpfcommon.EBPFEventContext{RuntimeMetrics: runtimemetrics.NewQueueSender(runtimeMetrics)},
	}
	tracer.cfg.Metrics.Features = export.FeatureApplicationRuntime

	span, ignore, err := tracer.processSharedRingbufRecord(context.Background(), nil, &tracer.cfg.EBPF, &ringbuf.Record{
		RawSample: rawMemoryPoolPayload(t, BpfJvmMemPoolGcEvent{
			Type:       ebpfcommon.EventTypeJVMMemoryPoolGC,
			Timestamp:  100,
			NsPid:      1234,
			PidNsId:    42,
			GcWhenType: uint32(jvmruntime.RawJVMGCWhenAfter),
			Used:       100,
			Committed:  200,
			MaxSize:    300,
			Pool:       rawJVMString("G1 Eden Space"),
		}),
	})

	require.NoError(t, err)
	assert.True(t, ignore)
	assert.Empty(t, span)

	batch := readJVMTestBatch(t, received)
	require.Len(t, batch, 4)
	for _, snapshot := range batch {
		assert.Equal(t, service, snapshot.Service)
		require.NotNil(t, snapshot.JVM)
	}
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsed, batch[0].JVM.Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryCommitted, batch[1].JVM.Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryLimit, batch[2].JVM.Kind)
	assert.Equal(t, jvmruntime.JVMMetricMemoryUsedAfterLastGC, batch[3].JVM.Kind)
}

func TestJVMBPFMapsAreInternallyPinnedAndUseSharedEventsRingBuffer(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)

	require.NotContains(t, spec.Maps, "jvm_gc_heap_summary_events")
	require.NotContains(t, spec.Maps, "jvm_mem_pool_gc_events")
	require.NotContains(t, spec.Maps, "jvm_heap_summary_samples")

	for _, name := range []string{
		"jvm_mem_pool_samples",
		"obi_usdt_specs",
		"obi_usdt_ip_to_spec_id",
	} {
		require.Contains(t, spec.Maps, name)
		assert.Equal(t, ebpfconvenience.PinInternal, spec.Maps[name].Pinning)
	}
	assert.Equal(t, ebpf.LRUHash, spec.Maps["obi_usdt_ip_to_spec_id"].Type)
}

func TestJVMRuntimeMetricsExposeHotSpotUSDTProbes(t *testing.T) {
	tracer := Tracer{cfg: &obi.Config{}}
	assert.Empty(t, tracer.USDTProbes())

	tracer.cfg.Metrics.Features = export.FeatureApplicationRuntime
	assert.NotContains(t, tracer.UProbes(), "libjvm.so")

	probes := tracer.USDTProbes()

	require.Contains(t, probes, "libjvm.so")
	require.Len(t, probes["libjvm.so"], 2)
	assert.Equal(t, "hotspot", probes["libjvm.so"][0].Provider)
	assert.Equal(t, "mem__pool__gc__begin", probes["libjvm.so"][0].Name)
	assert.Equal(t, "hotspot", probes["libjvm.so"][1].Provider)
	assert.Equal(t, "mem__pool__gc__end", probes["libjvm.so"][1].Name)
}

func TestJVMRuntimeMetricsConstantOverridesUseApplicationRuntimeAsFeatureGate(t *testing.T) {
	for _, tt := range []struct {
		name             string
		configure        func(*obi.Config)
		samplingInterval time.Duration
		expectedInterval uint64
	}{
		{name: "disabled", samplingInterval: time.Second},
		{
			name: "enabled globally",
			configure: func(cfg *obi.Config) {
				cfg.Metrics.Features = export.FeatureApplicationRuntime
			},
			samplingInterval: 250 * time.Millisecond,
			expectedInterval: uint64((250 * time.Millisecond).Nanoseconds()),
		},
		{
			name: "enabled for instrument selector",
			configure: func(cfg *obi.Config) {
				cfg.Discovery.Instrument = services.GlobDefinitionCriteria{
					{Metrics: perapp.SvcMetricsConfig{Features: export.FeatureApplicationRuntime}},
				}
			},
			samplingInterval: 500 * time.Millisecond,
			expectedInterval: uint64((500 * time.Millisecond).Nanoseconds()),
		},
		{
			name: "enabled for deprecated services selector",
			configure: func(cfg *obi.Config) {
				cfg.Discovery.Services = services.RegexDefinitionCriteria{
					{Metrics: perapp.SvcMetricsConfig{Features: export.FeatureApplicationRuntime}},
				}
			},
			samplingInterval: 750 * time.Millisecond,
			expectedInterval: uint64((750 * time.Millisecond).Nanoseconds()),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tracer := Tracer{cfg: &obi.Config{}}
			if tt.configure != nil {
				tt.configure(tracer.cfg)
			}
			tracer.cfg.JVMRuntimeMetrics.SamplingInterval = tt.samplingInterval

			overrides := tracer.constants()

			assert.Equal(t, tt.expectedInterval, overrides["jvm_sampling_interval_ns"])
		})
	}
}

func TestTracerUsesRemoteParentRetentionTTLForPrewrite(t *testing.T) {
	cfg := obi.DefaultConfig
	cfg.Java.RemoteParent.TTL = 30 * time.Second
	cfg.Java.RemoteParent.RetrievalTTL = time.Nanosecond

	tracer := Tracer{cfg: &cfg}
	overrides := tracer.constants()

	assert.Equal(t, uint64((30 * time.Second).Nanoseconds()), overrides["ssl_prewrite_max_age_ns"])
}

func TestRawJVMEventLayoutsUseGeneratedBPFStructs(t *testing.T) {
	assert.Equal(t, 200, int(unsafe.Sizeof(BpfJvmMemPoolGcEvent{})))
}

func rawMemoryPoolPayload(t *testing.T, raw BpfJvmMemPoolGcEvent) []byte {
	t.Helper()

	return rawPayload(raw)
}

func rawPayload[T any](raw T) []byte {
	size := int(unsafe.Sizeof(raw))
	out := make([]byte, size)
	copy(out, unsafe.Slice((*byte)(unsafe.Pointer(&raw)), size))
	return out
}

func rawJVMString(value string) [jvmruntime.JVMRawStringLen]byte {
	var raw [jvmruntime.JVMRawStringLen]byte
	copy(raw[:], []byte(value))
	return raw
}

func readJVMTestBatch(t *testing.T, events <-chan []runtimemetrics.RuntimeMetricSnapshot) []runtimemetrics.RuntimeMetricSnapshot {
	t.Helper()

	select {
	case batch := <-events:
		return batch
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for JVM runtime events")
		return nil
	}
}

type fakeServiceFilter struct {
	current          map[uint32]map[app.PID]svc.Attrs
	currentPIDsCalls *int
}

func (f fakeServiceFilter) AllowPID(app.PID, uint32, *exec.FileInfo, *exec.FileInfo, ebpfcommon.PIDType) {
}
func (f fakeServiceFilter) BlockPID(app.PID, uint32, *exec.FileInfo, *exec.FileInfo) {}
func (f fakeServiceFilter) ValidPID(app.PID, uint32, ebpfcommon.PIDType) bool        { return false }
func (f fakeServiceFilter) Filter(inputSpans []request.Span) []request.Span          { return inputSpans }
func (f fakeServiceFilter) CurrentPIDs(ebpfcommon.PIDType) map[uint32]map[app.PID]svc.Attrs {
	if f.currentPIDsCalls != nil {
		(*f.currentPIDsCalls)++
	}
	return f.current
}
