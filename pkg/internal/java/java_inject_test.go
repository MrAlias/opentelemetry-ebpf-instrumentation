// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javaagent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/obi"
)

type blockingTestAttacher struct {
	initialized bool
	cleaned     bool
	deadline    bool
	started     chan struct{}
}

type responseTestAttacher struct {
	response string
}

type lifecycleTestAttacher struct {
	responses    []string
	active       bool
	initCalls    int
	attachCalls  int
	cleanupCalls int
}

type exactTargetTestAttacher struct {
	valid         atomic.Bool
	bindCalls     atomic.Uint32
	validateCalls atomic.Uint32
	attachCalls   atomic.Uint32
	closeCalls    atomic.Uint32
	boundFromProc atomic.Bool
	boundPID      int
	boundStart    uint64
}

func (a *exactTargetTestAttacher) BindTarget(pid int, start uint64) error {
	a.boundPID = pid
	a.boundStart = start
	a.bindCalls.Add(1)
	a.valid.Store(true)
	return nil
}

func (a *exactTargetTestAttacher) BindTargetFromProcFD(
	pid int, start uint64, _ int,
) error {
	a.boundFromProc.Store(true)
	return a.BindTarget(pid, start)
}

func (a *exactTargetTestAttacher) ValidateTarget() error {
	a.validateCalls.Add(1)
	if !a.valid.Load() {
		return errors.New("prepared exact target exited")
	}
	return nil
}

func (a *exactTargetTestAttacher) CloseTarget() error {
	a.closeCalls.Add(1)
	return nil
}

func (*exactTargetTestAttacher) Init()          {}
func (*exactTargetTestAttacher) Cleanup() error { return nil }

func (a *exactTargetTestAttacher) AttachContext(
	context.Context, int, []string, bool,
) (io.ReadCloser, error) {
	a.attachCalls.Add(1)
	return nil, errors.New("unexpected attach to invalid exact target")
}

type testJavaAgentTarget struct {
	readErr  error
	chmodErr error
	closeErr error
	closed   bool
}

func (t *testJavaAgentTarget) ReadFrom(io.Reader) (int64, error) {
	return 0, t.readErr
}

func (t *testJavaAgentTarget) Chmod(os.FileMode) error {
	return t.chmodErr
}

func (t *testJavaAgentTarget) Close() error {
	t.closed = true
	return t.closeErr
}

func (a *responseTestAttacher) Init() {}

func (a *responseTestAttacher) BindTarget(int, uint64) error { return nil }
func (a *responseTestAttacher) BindTargetFromProcFD(int, uint64, int) error {
	return nil
}
func (a *responseTestAttacher) ValidateTarget() error { return nil }
func (a *responseTestAttacher) CloseTarget() error    { return nil }

func (a *responseTestAttacher) Cleanup() error { return nil }

func (a *responseTestAttacher) AttachContext(
	context.Context, int, []string, bool,
) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(a.response)), nil
}

func (a *lifecycleTestAttacher) Init() {
	if a.active {
		panic("attacher initialized before previous credentials were restored")
	}
	a.active = true
	a.initCalls++
}

func (a *lifecycleTestAttacher) BindTarget(int, uint64) error { return nil }
func (a *lifecycleTestAttacher) BindTargetFromProcFD(int, uint64, int) error {
	return nil
}
func (a *lifecycleTestAttacher) ValidateTarget() error { return nil }
func (a *lifecycleTestAttacher) CloseTarget() error    { return nil }

func (a *lifecycleTestAttacher) Cleanup() error {
	if !a.active {
		return errors.New("attacher cleanup without initialization")
	}
	a.active = false
	a.cleanupCalls++
	return nil
}

func (a *lifecycleTestAttacher) AttachContext(
	context.Context, int, []string, bool,
) (io.ReadCloser, error) {
	if !a.active {
		return nil, errors.New("attach without initialized credentials")
	}
	if a.attachCalls >= len(a.responses) {
		return nil, errors.New("unexpected attach call")
	}
	response := a.responses[a.attachCalls]
	a.attachCalls++
	return io.NopCloser(strings.NewReader(response)), nil
}

func (a *blockingTestAttacher) Init() {
	a.initialized = true
}

func (a *blockingTestAttacher) BindTarget(int, uint64) error { return nil }
func (a *blockingTestAttacher) BindTargetFromProcFD(int, uint64, int) error {
	return nil
}
func (a *blockingTestAttacher) ValidateTarget() error { return nil }
func (a *blockingTestAttacher) CloseTarget() error    { return nil }

func (a *blockingTestAttacher) Cleanup() error {
	a.cleaned = true
	return nil
}

func (a *blockingTestAttacher) AttachContext(
	ctx context.Context, _ int, _ []string, _ bool,
) (io.ReadCloser, error) {
	_, a.deadline = ctx.Deadline()
	if a.started != nil {
		close(a.started)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestJavaInjectorAttachUsesConfiguredDeadlineAndCleansUp(t *testing.T) {
	attacher := &blockingTestAttacher{}
	originalFactory := newJavaAttacher
	newJavaAttacher = func(*slog.Logger) javaAttacher { return attacher }
	t.Cleanup(func() { newJavaAttacher = originalFactory })

	injector := &JavaInjector{
		cfg: &obi.Config{Java: obi.JavaConfig{Timeout: 10 * time.Millisecond}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ie := &ebpf.Instrumentable{
		FileInfo: exec.New(exec.Init{Pid: 123}),
		Type:     svc.InstrumentableJava,
	}
	ie.FileInfo.SetJavaAgentCapability(17)

	started := time.Now()
	err := injector.NewExecutable(ie)
	require.ErrorContains(t, err, "java attach timed out")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(started), time.Second)
	assert.True(t, attacher.initialized)
	assert.True(t, attacher.deadline)
	assert.True(t, attacher.cleaned)
}

func TestJavaInjectorAttachPreservesCallerCancellation(t *testing.T) {
	attacher := &blockingTestAttacher{started: make(chan struct{})}
	originalFactory := newJavaAttacher
	newJavaAttacher = func(*slog.Logger) javaAttacher { return attacher }
	t.Cleanup(func() { newJavaAttacher = originalFactory })

	injector := &JavaInjector{
		cfg: &obi.Config{Java: obi.JavaConfig{Timeout: time.Minute}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ie := &ebpf.Instrumentable{
		FileInfo: exec.New(exec.Init{Pid: 123}),
		Type:     svc.InstrumentableJava,
	}
	ie.FileInfo.SetJavaAgentCapability(17)

	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- injector.NewExecutableContext(ctx, ie) }()
	<-attacher.started
	cancel()

	err := <-result
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorContains(t, err, "java attach canceled")
	require.NotContains(t, err.Error(), "timed out")
	assert.True(t, attacher.initialized)
	assert.True(t, attacher.deadline)
	assert.True(t, attacher.cleaned)
}

func TestJavaInjectorPreparesFreshProcessCapabilityPerAttachment(t *testing.T) {
	originalFactory := newJavaAttacher
	newJavaAttacher = func(*slog.Logger) javaAttacher { return &responseTestAttacher{} }
	t.Cleanup(func() { newJavaAttacher = originalFactory })
	injector := &JavaInjector{}
	ie := &ebpf.Instrumentable{
		FileInfo: exec.New(exec.Init{Pid: 123}),
		Type:     svc.InstrumentableJava,
	}

	first, err := injector.PrepareExecutable(ie)
	require.NoError(t, err)
	require.NotNil(t, first)
	capability := ie.FileInfo.JavaAgentCapability()
	require.NotZero(t, capability)
	require.NoError(t, first.Close())
	second, err := injector.PrepareExecutable(ie)
	require.NoError(t, err)
	require.NotNil(t, second)
	t.Cleanup(func() { require.NoError(t, second.Close()) })
	assert.NotZero(t, ie.FileInfo.JavaAgentCapability())
	assert.NotEqual(t, capability, ie.FileInfo.JavaAgentCapability())
}

func TestJavaInjectorCapabilityGenerationFailureClosesRecycledAttachmentGate(t *testing.T) {
	target := &exactTargetTestAttacher{}
	originalFactory := newJavaAttacher
	newJavaAttacher = func(*slog.Logger) javaAttacher { return target }
	t.Cleanup(func() { newJavaAttacher = originalFactory })
	originalRead := readJavaCapabilityRandom
	t.Cleanup(func() { readJavaCapabilityRandom = originalRead })
	readJavaCapabilityRandom = func([]byte) (int, error) {
		return 0, errors.New("random source unavailable")
	}
	injector := &JavaInjector{}
	ie := &ebpf.Instrumentable{
		FileInfo: exec.New(exec.Init{Pid: 123}),
		Type:     svc.InstrumentableJava,
	}
	ie.FileInfo.SetJavaAgentCapability(17)

	prepared, err := injector.PrepareExecutable(ie)

	assert.Nil(t, prepared)
	require.ErrorContains(t, err, "random source unavailable")
	assert.Zero(t, ie.FileInfo.JavaAgentCapability())
	assert.Equal(t, uint32(1), target.closeCalls.Load())
}

func TestPreparedJavaTargetSurvivesAuthorizationWithoutNumericRebind(t *testing.T) {
	target := &exactTargetTestAttacher{}
	var factoryCalls atomic.Uint32
	originalFactory := newJavaAttacher
	newJavaAttacher = func(*slog.Logger) javaAttacher {
		factoryCalls.Add(1)
		return target
	}
	t.Cleanup(func() { newJavaAttacher = originalFactory })
	originalStartTime := javaTargetProcessStartTime
	javaTargetProcessStartTime = func(app.PID) (uint64, error) { return 77, nil }
	t.Cleanup(func() { javaTargetProcessStartTime = originalStartTime })

	injector := &JavaInjector{
		cfg: &obi.Config{Java: obi.JavaConfig{Timeout: time.Second}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	processHandle, err := os.Open("/proc/self")
	require.NoError(t, err)
	fileInfo := exec.New(exec.Init{
		Pid:           123,
		ProcessStart:  77,
		ProcessHandle: processHandle,
	})
	t.Cleanup(func() { require.NoError(t, fileInfo.CloseProcessHandle()) })
	ie := &ebpf.Instrumentable{FileInfo: fileInfo, Type: svc.InstrumentableJava}

	prepared, err := injector.PrepareExecutable(ie)
	require.NoError(t, err)
	require.NotNil(t, prepared)
	assert.Equal(t, uint32(1), factoryCalls.Load(), "target must be bound during preparation")
	assert.Equal(t, uint32(1), target.bindCalls.Load())
	assert.True(t, target.boundFromProc.Load())
	assert.Equal(t, 123, target.boundPID)
	assert.Equal(t, uint64(77), target.boundStart)

	capability, generation := fileInfo.BeginJavaAgentAuthorization()
	require.NotZero(t, capability)
	require.NotZero(t, generation)
	fileInfo.CompleteJavaAgentAuthorization(generation, capability)
	// Model the prepared pidfd reporting that process A exited while the
	// numeric PID and coarse /proc start tick now appear unchanged for B.
	target.valid.Store(false)

	err = prepared.NewExecutableContext(t.Context())
	require.ErrorContains(t, err, "prepared exact target exited")
	assert.Equal(t, uint32(1), factoryCalls.Load(), "readiness must not construct a successor attacher")
	assert.Zero(t, target.attachCalls.Load(), "no attach command may reach a replacement target")
	assert.Equal(t, uint32(1), target.closeCalls.Load())
}

func TestPreparedJavaTargetRequiresDiscoveryProcessHandle(t *testing.T) {
	target := &exactTargetTestAttacher{}
	originalFactory := newJavaAttacher
	newJavaAttacher = func(*slog.Logger) javaAttacher { return target }
	t.Cleanup(func() { newJavaAttacher = originalFactory })
	originalStartTime := javaTargetProcessStartTime
	javaTargetProcessStartTime = func(app.PID) (uint64, error) { return 77, nil }
	t.Cleanup(func() { javaTargetProcessStartTime = originalStartTime })

	injector := &JavaInjector{}
	fileInfo := exec.New(exec.Init{Pid: 123, ProcessStart: 77})
	prepared, err := injector.PrepareExecutable(&ebpf.Instrumentable{
		FileInfo: fileInfo,
		Type:     svc.InstrumentableJava,
	})

	require.Nil(t, prepared)
	require.ErrorContains(t, err, "stable process handle is unavailable")
	assert.Zero(t, target.bindCalls.Load())
	assert.Zero(t, fileInfo.JavaAgentCapability())
}

func TestUnusedPreparedJavaTargetFailsReadinessClosedAndClosesOnce(t *testing.T) {
	target := &exactTargetTestAttacher{}
	originalFactory := newJavaAttacher
	newJavaAttacher = func(*slog.Logger) javaAttacher { return target }
	t.Cleanup(func() { newJavaAttacher = originalFactory })

	injector := &JavaInjector{}
	fileInfo := exec.New(exec.Init{Pid: 123})
	ie := &ebpf.Instrumentable{FileInfo: fileInfo, Type: svc.InstrumentableJava}
	prepared, err := injector.PrepareExecutable(ie)
	require.NoError(t, err)
	require.NotNil(t, prepared)

	result := make(chan uint64, 1)
	go func() {
		capability, _ := fileInfo.WaitJavaAgentAuthorization(t.Context())
		result <- capability
	}()
	require.NoError(t, prepared.Close())
	assert.Zero(t, <-result)
	assert.Zero(t, fileInfo.JavaAgentCapability())
	require.NoError(t, prepared.Close())
	assert.Equal(t, uint32(1), target.closeCalls.Load())
}

func TestJavaAttachGateIsProcessWideAndContextAware(t *testing.T) {
	originalGate := javaAttachSerial
	javaAttachSerial = make(chan struct{}, 1)
	t.Cleanup(func() { javaAttachSerial = originalGate })

	releaseFirst, err := acquireJavaAttach(t.Context())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	secondResult := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		release, err := acquireJavaAttach(ctx)
		if release != nil {
			release()
		}
		secondResult <- err
	}()
	<-started
	select {
	case err := <-secondResult:
		t.Fatalf("second process-wide attach entered while the gate was held: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	require.ErrorIs(t, <-secondResult, context.Canceled)
	releaseFirst()

	releaseSecond, err := acquireJavaAttach(t.Context())
	require.NoError(t, err)
	releaseSecond()
}

func TestAttachOptionsIncludeProcessCapability(t *testing.T) {
	injector := &JavaInjector{cfg: &obi.Config{Java: obi.JavaConfig{}}}

	opts, err := injector.attachOptsWithCapability(123, 42)
	require.NoError(t, err)
	assert.Contains(t, opts, "processCapability=42")
}

func TestAttachJDKAgentRequiresProtocolAcknowledgement(t *testing.T) {
	tests := []struct {
		name          string
		response      string
		errorContains string
	}{
		{name: "HotSpot success", response: "0\nreturn code: 0\n"},
		{name: "HotSpot 8 success", response: "0\n0\n"},
		{name: "OpenJ9 success", response: "ATTACH_ACK\x00"},
		{name: "HotSpot nonzero status", response: "17\n", errorContains: "status 17"},
		{name: "agent nonzero return code", response: "0\nreturn code: 42\n", errorContains: "return code 42"},
		{name: "HotSpot 8 agent nonzero return code", response: "0\n42\n", errorContains: "return code 42"},
		{
			name: "dynamic loading disabled",
			response: "0\nDynamic agent loading is not enabled. " +
				"Use -XX:+EnableDynamicAgentLoading to launch target VM.\n",
			errorContains: "Dynamic agent loading is not enabled",
		},
		{
			name:          "agent load error response",
			response:      "0\ninstrument was not loaded.\n",
			errorContains: "instrument was not loaded",
		},
		{
			name:          "missing agent result",
			response:      "0\n",
			errorContains: "without an agent result",
		},
		{name: "empty HotSpot response", response: "", errorContains: "without a status"},
		{name: "missing HotSpot status", response: "return code: 0\n", errorContains: "without a status"},
		{name: "empty OpenJ9 response", response: "\x00", errorContains: "without ATTACH_ACK"},
		{name: "truncated OpenJ9 response", response: "ATTACH_AC\x00", errorContains: "without ATTACH_ACK"},
		{
			name:          "oversized response",
			response:      strings.Repeat("x", maxJVMAttachResponseBytes+1),
			errorContains: "exceeds 65536 bytes",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			injector := &JavaInjector{
				cfg: &obi.Config{},
				log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			err := injector.attachJDKAgent(
				context.Background(), &responseTestAttacher{response: test.response}, 123, "/agent.jar",
			)
			if test.errorContains == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.errorContains)
		})
	}
}

func TestJavaInjectorRestoresCredentialsAfterEveryAttachCommand(t *testing.T) {
	attacher := &lifecycleTestAttacher{responses: []string{
		"JDK 21\n",
		"",
		"0\nreturn code: 0\n",
	}}
	injector := &JavaInjector{
		cfg: &obi.Config{},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	supported, jdk8, err := injector.verifyJVMVersion(
		context.Background(), attacher, 123,
	)
	require.NoError(t, err)
	require.True(t, supported)
	require.False(t, jdk8)
	require.False(t, attacher.active)

	loaded, err := injector.jdkAgentAlreadyLoaded(context.Background(), attacher, 123)
	require.NoError(t, err)
	require.False(t, loaded)
	require.False(t, attacher.active)

	require.NoError(t, injector.attachJDKAgent(
		context.Background(), attacher, 123, "/agent.jar",
	))
	require.False(t, attacher.active)
	require.Equal(t, 3, attacher.initCalls)
	require.Equal(t, 3, attacher.attachCalls)
	require.Equal(t, 3, attacher.cleanupCalls)
}

func TestRunIfCurrentAttachHoldsLockWhileRunningAction(t *testing.T) {
	injector := &JavaInjector{}
	attachID := injector.nextAttachID()

	actionStarted := make(chan struct{})
	finishAction := make(chan struct{})
	actionDone := make(chan error, 1)
	go func() {
		actionDone <- injector.runIfCurrentAttach(attachID, func() error {
			close(actionStarted)
			<-finishAction
			return nil
		})
	}()

	<-actionStarted
	lockWasAvailable := injector.mu.TryLock()
	if lockWasAvailable {
		injector.mu.Unlock()
	}

	nextAttachID := make(chan int64, 1)
	go func() {
		nextAttachID <- injector.nextAttachID()
	}()

	close(finishAction)
	require.NoError(t, <-actionDone)
	require.Equal(t, int64(2), <-nextAttachID)
	require.False(t, lockWasAvailable)

	actionRan := false
	require.NoError(t, injector.runIfCurrentAttach(attachID, func() error {
		actionRan = true
		return nil
	}))
	require.False(t, actionRan)
}

func TestJavaInjector_CopyAgent(t *testing.T) {
	oldJavaAgentBytes := embeddedJavaAgentBytes
	embeddedJavaAgentBytes = []byte("test agent content")
	t.Cleanup(func() {
		embeddedJavaAgentBytes = oldJavaAgentBytes
	})

	tests := []struct {
		name          string
		setupTempDir  func(t *testing.T, pid app.PID) string
		envVars       map[string]string
		pid           app.PID
		expectError   bool
		errorContains string
		verifyFile    bool
		verifyOutside bool
	}{
		{
			name: "successful copy to /tmp",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "tmp"), 0o755))
				return tmpDir
			},
			envVars:     map[string]string{},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "successful copy to TMPDIR from env",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				customTmpDir := filepath.Join(procRoot, "custom", "tmp")
				require.NoError(t, os.MkdirAll(customTmpDir, 0o755))
				return tmpDir
			},
			envVars: map[string]string{
				"TMPDIR": "/custom/tmp",
			},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "TMPDIR absolute path outside process root is ignored",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "tmp"), 0o755))
				return tmpDir
			},
			envVars: map[string]string{
				"TMPDIR": "/proc/1/root/etc",
			},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "TMPDIR relative path escape is ignored",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "tmp"), 0o755))
				return tmpDir
			},
			envVars: map[string]string{
				"TMPDIR": "../../../etc",
			},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "fallback to /var/tmp when /tmp not available",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "var", "tmp"), 0o755))
				return tmpDir
			},
			envVars:     map[string]string{},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "error when no temp directory available",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(procRoot, 0o755))
				return tmpDir
			},
			envVars:       map[string]string{},
			pid:           1000,
			expectError:   true,
			errorContains: "error accessing temp directory",
			verifyFile:    false,
		},
		{
			name: "error when target directory not writable",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				tmpPath := filepath.Join(procRoot, "tmp")
				require.NoError(t, os.MkdirAll(tmpPath, 0o755))
				require.NoError(t, os.Chmod(tmpPath, 0o555))
				return tmpDir
			},
			envVars:       map[string]string{},
			pid:           1000,
			expectError:   true,
			errorContains: "unable to create target OBI java agent",
			verifyFile:    false,
		},
		{
			name: "agent content correctly copied",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "tmp"), 0o755))
				return tmpDir
			},
			envVars:     map[string]string{},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "copy does not follow existing symlink target",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				targetDir := filepath.Join(procRoot, "tmp")
				require.NoError(t, os.MkdirAll(targetDir, 0o755))

				victim := filepath.Join(tmpDir, "victim")
				require.NoError(t, os.WriteFile(victim, []byte("do not overwrite"), 0o644))
				require.NoError(t, os.Symlink(victim, filepath.Join(targetDir, ObiJavaAgentFileName)))
				return tmpDir
			},
			envVars:     map[string]string{},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "TMPDIR symlink component outside process root is rejected",
			setupTempDir: func(t *testing.T, _ app.PID) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "custom"), 0o755))

				outsideDir := filepath.Join(tmpDir, "outside")
				require.NoError(t, os.MkdirAll(outsideDir, 0o755))
				require.NoError(t, os.WriteFile(
					filepath.Join(outsideDir, ObiJavaAgentFileName),
					[]byte("do not overwrite"),
					0o644,
				))
				require.NoError(t, os.Symlink(outsideDir, filepath.Join(procRoot, "custom", "tmp")))
				return tmpDir
			},
			envVars: map[string]string{
				"TMPDIR": "/custom/tmp",
			},
			pid:           1000,
			expectError:   true,
			errorContains: "error accessing temp directory",
			verifyOutside: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := tt.setupTempDir(t, tt.pid)

			// Override the root directory function
			originalRootFunc := rootDirForPID
			defer func() { rootDirForPID = originalRootFunc }()
			rootDirForPID = func(_ app.PID) string {
				return filepath.Join(tmpDir, "proc", "root")
			}

			injector := &JavaInjector{
				cfg: &obi.DefaultConfig,
				log: slog.With("component", "javaagent.Injector"),
			}

			ie := &ebpf.Instrumentable{
				FileInfo: exec.New(exec.Init{
					Pid: tt.pid,
					Service: svc.Attrs{
						EnvVars: tt.envVars,
					},
				}),
				Type: svc.InstrumentableJava,
			}

			resultPath, err := injector.copyAgent(ie)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, resultPath)

				if tt.verifyFile {
					// Verify the file was created in the host filesystem
					procRoot := filepath.Join(tmpDir, "proc", "root")
					expectedHostPath := filepath.Join(procRoot, strings.TrimPrefix(resultPath, "/"))

					info, err := os.Stat(expectedHostPath)
					require.NoError(t, err)
					assert.False(t, info.IsDir())
					assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())

					// Verify content matches
					originalContent := embeddedJavaAgentBytes
					copiedContent, err := os.ReadFile(expectedHostPath)
					require.NoError(t, err)
					assert.Equal(t, originalContent, copiedContent)

					victimPath := filepath.Join(tmpDir, "victim")
					if _, err := os.Stat(victimPath); err == nil {
						victimContent, readErr := os.ReadFile(victimPath)
						require.NoError(t, readErr)
						assert.Equal(t, []byte("do not overwrite"), victimContent)
					}
				}
			}

			if tt.verifyOutside {
				outsideAgent := filepath.Join(tmpDir, "outside", ObiJavaAgentFileName)
				content, readErr := os.ReadFile(outsideAgent)
				require.NoError(t, readErr)
				assert.Equal(t, []byte("do not overwrite"), content)
			}
		})
	}
}

func TestPopulateJavaAgentTargetClosesOnEveryFailure(t *testing.T) {
	testError := errors.New("injected target failure")
	closeError := errors.New("injected close failure")

	for _, test := range []struct {
		name       string
		target     *testJavaAgentTarget
		wantDetail string
	}{
		{
			name:       "write",
			target:     &testJavaAgentTarget{readErr: testError},
			wantDetail: "writing java agent",
		},
		{
			name:       "permissions",
			target:     &testJavaAgentTarget{chmodErr: testError},
			wantDetail: "setting permissions",
		},
		{
			name:       "close",
			target:     &testJavaAgentTarget{closeErr: closeError},
			wantDetail: "closing target",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := populateJavaAgentTarget(test.target, strings.NewReader("agent"))

			require.Error(t, err)
			assert.Contains(t, err.Error(), test.wantDetail)
			assert.True(t, test.target.closed)
		})
	}

	target := &testJavaAgentTarget{readErr: testError, closeErr: closeError}
	err := populateJavaAgentTarget(target, strings.NewReader("agent"))
	require.ErrorIs(t, err, testError)
	require.ErrorIs(t, err, closeError)
	assert.True(t, target.closed)
}

func TestJavaInjector_FindTempDir(t *testing.T) {
	tests := []struct {
		name        string
		setupDirs   func(t *testing.T, root string)
		envVars     map[string]string
		expectError bool
		expectedDir string
	}{
		{
			name: "prefer TMPDIR from env",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "custom", "tmp"), 0o755))
				require.NoError(t, os.MkdirAll(filepath.Join(root, "tmp"), 0o755))
			},
			envVars: map[string]string{
				"TMPDIR": "/custom/tmp",
			},
			expectError: false,
			expectedDir: "/custom/tmp",
		},
		{
			name: "fallback to /tmp",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "tmp"), 0o755))
			},
			envVars:     map[string]string{},
			expectError: false,
			expectedDir: "/tmp",
		},
		{
			name: "fallback to /var/tmp when /tmp missing",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "var", "tmp"), 0o755))
			},
			envVars:     map[string]string{},
			expectError: false,
			expectedDir: "/var/tmp",
		},
		{
			name: "error when no temp dir available",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(root, 0o755))
			},
			envVars:     map[string]string{},
			expectError: true,
		},
		{
			name: "ignore invalid TMPDIR from env",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "tmp"), 0o755))
			},
			envVars: map[string]string{
				"TMPDIR": "/nonexistent",
			},
			expectError: false,
			expectedDir: "/tmp",
		},
		{
			name: "ignore escaping TMPDIR from env",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "tmp"), 0o755))
			},
			envVars: map[string]string{
				"TMPDIR": "/proc/1/root/etc",
			},
			expectError: false,
			expectedDir: "/tmp",
		},
		{
			name: "ignore relative TMPDIR from env",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "tmp"), 0o755))
			},
			envVars: map[string]string{
				"TMPDIR": "../../../etc",
			},
			expectError: false,
			expectedDir: "/tmp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			tt.setupDirs(t, root)

			injector := &JavaInjector{
				cfg: &obi.Config{},
			}

			ie := &ebpf.Instrumentable{
				FileInfo: exec.New(exec.Init{
					Service: svc.Attrs{
						EnvVars: tt.envVars,
					},
				}),
			}

			tmpDir, err := injector.findTempDir(root, ie)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "couldn't find suitable temp directory")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedDir, tmpDir)
			}
		})
	}
}

func TestDirOK(t *testing.T) {
	tests := []struct {
		name      string
		setupDirs func(t *testing.T) (root string, dir string)
		expected  bool
	}{
		{
			name: "valid directory exists",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				dir := "/testdir"
				require.NoError(t, os.MkdirAll(filepath.Join(root, strings.TrimPrefix(dir, "/")), 0o755))
				return root, dir
			},
			expected: true,
		},
		{
			name: "directory does not exist",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				return root, "/nonexistent"
			},
			expected: false,
		},
		{
			name: "path is a file not a directory",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				file := "/testfile"
				require.NoError(t, os.WriteFile(filepath.Join(root, strings.TrimPrefix(file, "/")), []byte("content"), 0o644))
				return root, file
			},
			expected: false,
		},
		{
			name: "nested directory exists",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				dir := "/nested/path/dir"
				require.NoError(t, os.MkdirAll(filepath.Join(root, strings.TrimPrefix(dir, "/")), 0o755))
				return root, dir
			},
			expected: true,
		},
		{
			name: "empty root path",
			setupDirs: func(_ *testing.T) (string, string) {
				return "", "/tmp"
			},
			expected: false,
		},
		{
			name: "empty dir path",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				return root, ""
			},
			expected: false,
		},
		{
			name: "absolute path directory",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				dir := "/abs/path"
				require.NoError(t, os.MkdirAll(filepath.Join(root, strings.TrimPrefix(dir, "/")), 0o755))
				return root, dir
			},
			expected: true,
		},
		{
			name: "relative traversal escapes root",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				return root, "../../../etc"
			},
			expected: false,
		},
		{
			name: "symlink directory is rejected",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				outside := t.TempDir()
				require.NoError(t, os.Symlink(outside, filepath.Join(root, "linked")))
				return root, "/linked"
			},
			expected: false,
		},
		{
			name: "intermediate symlink directory is rejected",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				outside := t.TempDir()
				require.NoError(t, os.Mkdir(filepath.Join(outside, "nested"), 0o755))
				require.NoError(t, os.Symlink(outside, filepath.Join(root, "linked")))
				return root, "/linked/nested"
			},
			expected: false,
		},
		{
			name: "directory with no permissions",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				dir := "/noperm"
				dirPath := filepath.Join(root, strings.TrimPrefix(dir, "/"))
				require.NoError(t, os.MkdirAll(dirPath, 0o755))
				require.NoError(t, os.Chmod(dirPath, 0o000))
				t.Cleanup(func() {
					err := os.Chmod(dirPath, 0o755)
					assert.NoError(t, err)
				})
				return root, dir
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, dir := tt.setupDirs(t)
			result := dirOK(root, dir)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJavaInjector_AttachOpts(t *testing.T) {
	serverUID := strconv.Itoa(os.Geteuid())
	originalUIDMapReader := readUIDMapForPID
	readUIDMapForPID = func(app.PID) ([]byte, error) {
		return []byte("0 0 4294967295\n"), nil
	}
	t.Cleanup(func() { readUIDMapForPID = originalUIDMapReader })

	tests := []struct {
		name         string
		debug        bool
		debugBB      bool
		remoteParent obi.JavaRemoteParentConfig
		expected     string
	}{
		{
			name:     "no options enabled",
			debug:    false,
			debugBB:  false,
			expected: "=remoteParentTransport=disabled",
		},
		{
			name:     "debug only",
			debug:    true,
			debugBB:  false,
			expected: "=debug=true,remoteParentTransport=disabled",
		},
		{
			name:     "debugBB only",
			debug:    false,
			debugBB:  true,
			expected: "=debugBB=true,remoteParentTransport=disabled",
		},
		{
			name:     "both options enabled",
			debug:    true,
			debugBB:  true,
			expected: "=debug=true,debugBB=true,remoteParentTransport=disabled",
		},
		{
			name: "remote parent options",
			remoteParent: obi.JavaRemoteParentConfig{
				Transport:  obi.JavaRemoteParentUnix,
				SocketPath: "/run/obi/remote-parent.sock",
				Timeout:    7 * time.Millisecond,
			},
			expected: "=remoteParentTransport=unix,remoteParentServerUid=" + serverUID + ",remoteParentSocket=/run/obi/remote-parent.sock,remoteParentTimeoutMillis=7",
		},
		{
			name: "sub-millisecond timeout is rounded up",
			remoteParent: obi.JavaRemoteParentConfig{
				Transport: obi.JavaRemoteParentGetsockopt,
				Timeout:   time.Microsecond,
			},
			expected: "=remoteParentTransport=getsockopt,remoteParentTimeoutMillis=1",
		},
		{
			name: "timeout longer than one second is preserved",
			remoteParent: obi.JavaRemoteParentConfig{
				Transport: obi.JavaRemoteParentUnix,
				Timeout:   1500 * time.Millisecond,
			},
			expected: "=remoteParentTransport=unix,remoteParentServerUid=" + serverUID + ",remoteParentTimeoutMillis=1500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &obi.Config{
				Java: obi.JavaConfig{
					Debug:                tt.debug,
					DebugInstrumentation: tt.debugBB,
					RemoteParent:         tt.remoteParent,
				},
			}

			injector := &JavaInjector{
				cfg:                   cfg,
				log:                   slog.With("component", "javaagent.Injector"),
				remoteParentServerUID: os.Geteuid(),
			}

			result, err := injector.attachOptsWithCapability(123, 0)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestJavaInjectorAttachOptsPreservesConfiguredSocketAlias(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "run")
	require.NoError(t, os.Mkdir(target, 0o700))
	alias := filepath.Join(root, "var-run")
	require.NoError(t, os.Symlink(target, alias))
	socketPath := filepath.Join(alias, "obi", "bridge.sock")

	cfg, err := obi.LoadConfig(bytes.NewBufferString(fmt.Sprintf(`
executable_path: java
trace_printer: text
ebpf:
  context_propagation: tcp
javaagent:
  remote_parent:
    transport: unix
    socket_path: %s
`, socketPath)))
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	require.Equal(t, socketPath, cfg.Java.RemoteParent.SocketPath)

	originalUIDMapReader := readUIDMapForPID
	readUIDMapForPID = func(app.PID) ([]byte, error) {
		return []byte("0 0 4294967295\n"), nil
	}
	t.Cleanup(func() { readUIDMapForPID = originalUIDMapReader })

	injector := &JavaInjector{
		cfg:                   cfg,
		log:                   slog.With("component", "javaagent.Injector"),
		remoteParentServerUID: os.Geteuid(),
	}
	opts, err := injector.attachOptsWithCapability(123, 0)
	require.NoError(t, err)
	assert.Contains(t, opts, "remoteParentSocket="+socketPath)
	assert.NotContains(t, opts, "remoteParentSocket="+filepath.Join(target, "obi", "bridge.sock"))
}

func TestJavaInjector_RemoteParentServerUIDRemainsStable(t *testing.T) {
	const serverUID = 1000
	originalUIDMapReader := readUIDMapForPID
	readUIDMapForPID = func(app.PID) ([]byte, error) {
		return []byte("0 0 4294967295\n"), nil
	}
	t.Cleanup(func() { readUIDMapForPID = originalUIDMapReader })

	injector := &JavaInjector{
		cfg: &obi.Config{
			Java: obi.JavaConfig{
				RemoteParent: obi.JavaRemoteParentConfig{
					Transport: obi.JavaRemoteParentUnix,
				},
			},
		},
		remoteParentServerUID: serverUID,
	}

	opts, err := injector.attachOptsWithCapability(123, 0)
	require.NoError(t, err)
	assert.Contains(t, opts, "remoteParentServerUid=1000")
}

func TestMapUID(t *testing.T) {
	for _, test := range []struct {
		name          string
		uidMap        string
		hostUID       int
		want          uint64
		errorContains string
	}{
		{
			name:    "identity mapping",
			uidMap:  "0 0 4294967295\n",
			hostUID: 1000,
			want:    1000,
		},
		{
			name:    "translated mapping",
			uidMap:  "0 100000 65536\n",
			hostUID: 101234,
			want:    1234,
		},
		{
			name:    "selects matching range",
			uidMap:  "0 100000 65536\n2000 2000 1\n",
			hostUID: 2000,
			want:    2000,
		},
		{
			name:    "maximum target UID",
			uidMap:  "4294967290 100 6\n",
			hostUID: 105,
			want:    4294967295,
		},
		{
			name:          "unmapped host UID",
			uidMap:        "0 100000 65536\n",
			hostUID:       1000,
			errorContains: "is not mapped",
		},
		{
			name:          "malformed entry",
			uidMap:        "0 100000\n",
			hostUID:       1000,
			errorContains: "invalid UID map entry",
		},
		{
			name:          "zero length",
			uidMap:        "0 0 0\n",
			hostUID:       0,
			errorContains: "mapping length is zero",
		},
		{
			name:          "range exceeds UID space",
			uidMap:        "4294967295 0 2\n",
			hostUID:       0,
			errorContains: "exceeds the UID address space",
		},
		{
			name:          "negative host UID",
			uidMap:        "0 0 1\n",
			hostUID:       -1,
			errorContains: "invalid host UID",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := mapUID(strings.NewReader(test.uidMap), test.hostUID)
			if test.errorContains != "" {
				require.ErrorContains(t, err, test.errorContains)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestJavaInjectorAttachOptsTranslatesRemoteParentServerUID(t *testing.T) {
	originalUIDMapReader := readUIDMapForPID
	t.Cleanup(func() { readUIDMapForPID = originalUIDMapReader })

	const targetPID app.PID = 123
	readUIDMapForPID = func(pid app.PID) ([]byte, error) {
		assert.Equal(t, targetPID, pid)
		return []byte("0 100000 65536\n"), nil
	}

	injector := &JavaInjector{
		cfg: &obi.Config{Java: obi.JavaConfig{RemoteParent: obi.JavaRemoteParentConfig{
			Transport: obi.JavaRemoteParentUnix,
		}}},
		remoteParentServerUID: 101234,
	}

	opts, err := injector.attachOptsWithCapability(targetPID, 0)
	require.NoError(t, err)
	assert.Contains(t, opts, "remoteParentServerUid=1234")
}

func TestJavaInjectorAttachOptsFailsClosedForUnmappedRemoteParentUID(t *testing.T) {
	originalUIDMapReader := readUIDMapForPID
	t.Cleanup(func() { readUIDMapForPID = originalUIDMapReader })

	readUIDMapForPID = func(app.PID) ([]byte, error) {
		return []byte("0 100000 65536\n"), nil
	}
	injector := &JavaInjector{
		cfg: &obi.Config{Java: obi.JavaConfig{RemoteParent: obi.JavaRemoteParentConfig{
			Transport: obi.JavaRemoteParentUnix,
		}}},
		remoteParentServerUID: 1000,
	}

	_, err := injector.attachOptsWithCapability(123, 0)
	require.ErrorContains(t, err, "host UID 1000 is not mapped")
}

func TestJavaInjectorAttachOptsFailsClosedWhenUIDMapCannotBeRead(t *testing.T) {
	originalUIDMapReader := readUIDMapForPID
	t.Cleanup(func() { readUIDMapForPID = originalUIDMapReader })

	readUIDMapForPID = func(app.PID) ([]byte, error) {
		return nil, os.ErrPermission
	}
	injector := &JavaInjector{
		cfg: &obi.Config{Java: obi.JavaConfig{RemoteParent: obi.JavaRemoteParentConfig{
			Transport: obi.JavaRemoteParentUnix,
		}}},
		remoteParentServerUID: 1000,
	}

	_, err := injector.attachOptsWithCapability(123, 0)
	require.ErrorIs(t, err, os.ErrPermission)
	require.ErrorContains(t, err, "read target UID map")
}

func TestJavaInjectorAttachOptsDoesNotMapUIDForForcedGetsockopt(t *testing.T) {
	originalUIDMapReader := readUIDMapForPID
	t.Cleanup(func() { readUIDMapForPID = originalUIDMapReader })

	readUIDMapForPID = func(app.PID) ([]byte, error) {
		return nil, errors.New("unexpected UID map read")
	}
	injector := &JavaInjector{
		cfg: &obi.Config{Java: obi.JavaConfig{RemoteParent: obi.JavaRemoteParentConfig{
			Transport: obi.JavaRemoteParentGetsockopt,
		}}},
		remoteParentServerUID: 1000,
	}

	opts, err := injector.attachOptsWithCapability(123, 0)
	require.NoError(t, err)
	assert.Equal(t, "=remoteParentTransport=getsockopt", opts)
}

func TestJavaInjectorAttachOptsDegradesAutoWhenUIDIsUnmapped(t *testing.T) {
	originalUIDMapReader := readUIDMapForPID
	t.Cleanup(func() { readUIDMapForPID = originalUIDMapReader })

	readUIDMapForPID = func(app.PID) ([]byte, error) {
		return []byte("0 100000 65536\n"), nil
	}
	injector := &JavaInjector{
		cfg: &obi.Config{Java: obi.JavaConfig{RemoteParent: obi.JavaRemoteParentConfig{
			Transport: obi.JavaRemoteParentAuto,
		}}},
		remoteParentServerUID: 1000,
	}

	opts, err := injector.attachOptsWithCapability(123, 0)
	require.NoError(t, err)
	assert.Equal(t, "=remoteParentTransport=getsockopt", opts)
}

func TestJavaInjectorAttachOptsDoesNotReadUIDMapWhenRemoteParentDisabled(t *testing.T) {
	originalUIDMapReader := readUIDMapForPID
	t.Cleanup(func() { readUIDMapForPID = originalUIDMapReader })

	readUIDMapForPID = func(app.PID) ([]byte, error) {
		return nil, errors.New("unexpected UID map read")
	}
	injector := &JavaInjector{
		cfg:                   &obi.Config{},
		remoteParentServerUID: 1000,
	}

	opts, err := injector.attachOptsWithCapability(123, 0)
	require.NoError(t, err)
	assert.NotContains(t, opts, "remoteParentServerUid")
}

func TestNewJavaInjector_CapturesRemoteParentServerUID(t *testing.T) {
	originalEmbeddedBytes := embeddedJavaAgentBytes
	embeddedJavaAgentBytes = []byte("test agent content")
	t.Cleanup(func() {
		embeddedJavaAgentBytes = originalEmbeddedBytes
	})

	injector, err := NewJavaInjector(&obi.Config{
		Java: obi.JavaConfig{
			Enabled: true,
			RemoteParent: obi.JavaRemoteParentConfig{
				Transport: obi.JavaRemoteParentUnix,
			},
		},
	})

	require.NoError(t, err)
	assert.Equal(t, os.Geteuid(), injector.remoteParentServerUID)
}

func TestNewJavaInjector_Disabled(t *testing.T) {
	injector, err := NewJavaInjector(&obi.Config{
		Java: obi.JavaConfig{
			Enabled: false,
		},
	})

	require.NoError(t, err)
	assert.Nil(t, injector)
}

func TestNewJavaInjector_RejectsCommaInRemoteParentSocketPath(t *testing.T) {
	for _, transport := range []obi.JavaRemoteParentTransport{"", obi.JavaRemoteParentUnix} {
		injectionMode := "disabled"
		if transport != "" {
			injectionMode = "enabled"
		}
		t.Run(injectionMode, func(t *testing.T) {
			injector, err := NewJavaInjector(&obi.Config{
				Java: obi.JavaConfig{
					Enabled: true,
					RemoteParent: obi.JavaRemoteParentConfig{
						Transport:  transport,
						SocketPath: "/run/obi,remoteParentTransport=unix",
					},
				},
			})

			require.EqualError(t, err, "javaagent.remote_parent.socket_path must not contain a comma")
			assert.Nil(t, injector)
		})
	}
}

func TestNewJavaInjector_RemoteParentTimeoutUpperBound(t *testing.T) {
	originalEmbeddedBytes := embeddedJavaAgentBytes
	embeddedJavaAgentBytes = []byte("test agent content")
	t.Cleanup(func() {
		embeddedJavaAgentBytes = originalEmbeddedBytes
	})

	for _, tc := range []struct {
		name      string
		timeout   time.Duration
		wantError string
	}{
		{
			name:    "maximum supported timeout",
			timeout: time.Duration(maxJavaRemoteParentTimeoutMillis) * time.Millisecond,
		},
		{
			name:      "timeout exceeding Java integer range",
			timeout:   time.Duration(maxJavaRemoteParentTimeoutMillis+1) * time.Millisecond,
			wantError: "javaagent.remote_parent.timeout must not exceed 2147483647ms",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			injector, err := NewJavaInjector(&obi.Config{
				Java: obi.JavaConfig{
					Enabled: true,
					RemoteParent: obi.JavaRemoteParentConfig{
						Transport: obi.JavaRemoteParentUnix,
						Timeout:   tc.timeout,
					},
				},
			})

			if tc.wantError != "" {
				require.EqualError(t, err, tc.wantError)
				assert.Nil(t, injector)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, injector)
		})
	}
}

func TestNewJavaInjector_MissingEmbeddedAgent(t *testing.T) {
	originalEmbeddedBytes := embeddedJavaAgentBytes
	t.Cleanup(func() {
		embeddedJavaAgentBytes = originalEmbeddedBytes
	})

	embeddedJavaAgentBytes = nil

	injector, err := NewJavaInjector(&obi.Config{
		Java: obi.JavaConfig{
			Enabled: true,
		},
	})

	require.Error(t, err)
	assert.Nil(t, injector)
	assert.Contains(t, err.Error(), "embedded OBI java agent artifact is missing from this build")
}

func TestNewJavaInjector_PlaceholderEmbeddedAgent(t *testing.T) {
	originalEmbeddedBytes := embeddedJavaAgentBytes
	t.Cleanup(func() {
		embeddedJavaAgentBytes = originalEmbeddedBytes
	})

	embeddedJavaAgentBytes = []byte(javaAgentEmbedPlaceholder + "\n")

	injector, err := NewJavaInjector(&obi.Config{
		Java: obi.JavaConfig{
			Enabled: true,
		},
	})

	require.Error(t, err)
	assert.Nil(t, injector)
	assert.Contains(t, err.Error(), "embedded OBI java agent artifact is missing from this build")
}

func TestEnsureEmbeddedAgent_ForgotToEmbed(t *testing.T) {
	originalEmbeddedBytes := embeddedJavaAgentBytes
	t.Cleanup(func() {
		embeddedJavaAgentBytes = originalEmbeddedBytes
	})

	embeddedJavaAgentBytes = nil
	err := ensureEmbeddedAgent()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "embedded OBI java agent artifact is missing from this build")
}

func TestEnsureEmbeddedAgent_PlaceholderBytesError(t *testing.T) {
	originalEmbeddedBytes := embeddedJavaAgentBytes
	t.Cleanup(func() {
		embeddedJavaAgentBytes = originalEmbeddedBytes
	})

	embeddedJavaAgentBytes = []byte(javaAgentEmbedPlaceholder + "\n")
	err := ensureEmbeddedAgent()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "embedded OBI java agent artifact is missing from this build")
}
