// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvm"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/jvmtools/util"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// extracted for testing
var (
	getEUID = syscall.Geteuid
	getEGID = syscall.Getegid
)

var errTerminated = errors.New("attach terminated")

type JAttacher struct {
	logger             *slog.Logger
	j9attacher         *j9Attacher
	myUID              int
	myGID              int
	mu                 sync.Mutex
	initialized        bool
	terminated         bool
	attachID           int64
	runIfCurrentAttach func(int64, func() error) error
	targetPID          int
	targetStart        uint64
	targetPIDFD        int
	targetProcFD       int
}

var (
	openJVMTargetPIDFD         = unix.PidfdOpen
	signalJVMTargetPIDFD       = unix.PidfdSendSignal
	setAttachThreadCredentials = setThreadCredentials
)

func NewJAttacher(
	logger *slog.Logger,
	attachID int64,
	runIfCurrentAttach func(int64, func() error) error,
) *JAttacher {
	if logger == nil {
		logger = slog.Default()
	}

	return &JAttacher{
		logger:             logger,
		j9attacher:         nil,
		attachID:           attachID,
		runIfCurrentAttach: runIfCurrentAttach,
		targetPIDFD:        -1,
		targetProcFD:       -1,
	}
}

// ConfigureAttachLifecycle connects this exact target to the injector's
// serialized attach generation. A canceled, superseded operation is then
// prevented from changing credentials or performing delayed cleanup after a
// newer operation has started.
func (j *JAttacher) ConfigureAttachLifecycle(
	attachID int64,
	runIfCurrentAttach func(int64, func() error) error,
) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.attachID = attachID
	j.runIfCurrentAttach = runIfCurrentAttach
}

// BindTarget pins the exact process that subsequent attach commands may
// mutate. The stable proc-directory descriptor supports exact signaling on
// older kernels; an anonymous pidfd is retained when available.
func (j *JAttacher) BindTarget(pid int, processStart uint64) error {
	if pid <= 0 || processStart == 0 {
		return errors.New("exact JVM target requires a positive PID and process start time")
	}
	sourceProcFD, err := unix.Open(
		fmt.Sprintf("/proc/%d", pid),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return fmt.Errorf("opening exact JVM proc directory: %w", err)
	}
	defer unix.Close(sourceProcFD)
	return j.BindTargetFromProcFD(pid, processStart, sourceProcFD)
}

// BindTargetFromProcFD binds to the lifetime already pinned by sourceProcFD.
// It never resolves the numeric /proc path; the attacher owns an independent
// close-on-exec duplicate and revalidates it around optional pidfd_open.
func (j *JAttacher) BindTargetFromProcFD(
	pid int,
	processStart uint64,
	sourceProcFD int,
) error {
	if pid <= 0 || processStart == 0 || sourceProcFD < 0 {
		return errors.New("exact JVM target requires a positive PID, process start time, and procfd")
	}
	if err := j.CloseTarget(); err != nil {
		return err
	}
	procfd, err := unix.FcntlInt(
		uintptr(sourceProcFD), unix.F_DUPFD_CLOEXEC, 0,
	)
	if err != nil {
		return fmt.Errorf("duplicating exact JVM proc directory: %w", err)
	}
	j.targetPID = pid
	j.targetStart = processStart
	j.targetPIDFD = -1
	j.targetProcFD = procfd
	if err := j.validateProcIdentity(); err != nil {
		return errors.Join(err, j.CloseTarget())
	}
	pidfd, pidfdErr := openJVMTargetPIDFD(pid, 0)
	if pidfdErr != nil {
		pidfd = -1
	}
	j.targetPIDFD = pidfd
	if err := j.ValidateTarget(); err != nil {
		return errors.Join(err, j.CloseTarget())
	}
	return nil
}

func (j *JAttacher) validateProcIdentity() error {
	currentPID, currentStart, state, err := procs.ProcessIdentityFromProcFD(j.targetProcFD)
	if err != nil {
		return fmt.Errorf("reading exact JVM target identity: %w", err)
	}
	if state == 'Z' || state == 'X' || state == 'x' {
		return errors.New("exact JVM target exited")
	}
	if int(currentPID) != j.targetPID {
		return fmt.Errorf(
			"exact JVM target procfd identifies PID %d, not %d",
			currentPID, j.targetPID,
		)
	}
	if currentStart != j.targetStart {
		return fmt.Errorf(
			"exact JVM target PID %d changed from start %d to %d",
			j.targetPID, j.targetStart, currentStart,
		)
	}
	return nil
}

func pidfdExited(pidfd int) (bool, error) {
	pollFD := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	if _, err := unix.Poll(pollFD, 0); err != nil {
		return false, err
	}
	if pollFD[0].Revents&unix.POLLNVAL != 0 {
		return false, syscall.EBADF
	}
	return pollFD[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0, nil
}

// ValidateTarget proves that the process pinned by BindTarget is still alive
// and still owns the original /proc lifetime before a namespace or attach
// operation proceeds.
func (j *JAttacher) ValidateTarget() error {
	if j.targetProcFD < 0 {
		return errors.New("exact JVM target is not bound")
	}
	if j.targetPIDFD >= 0 {
		exited, err := pidfdExited(j.targetPIDFD)
		if err != nil {
			return fmt.Errorf("polling JVM target pidfd: %w", err)
		}
		if exited {
			return errors.New("exact JVM target exited")
		}
	} else if err := signalJVMTargetPIDFD(j.targetProcFD, 0, nil, 0); err != nil {
		return fmt.Errorf(
			"exact dynamic Java attachment requires kernel pidfd_send_signal support: %w",
			err,
		)
	}
	if err := j.validateProcIdentity(); err != nil {
		return err
	}
	if j.targetPIDFD >= 0 {
		exited, err := pidfdExited(j.targetPIDFD)
		if err != nil {
			return fmt.Errorf("rechecking JVM target pidfd: %w", err)
		}
		if exited {
			return errors.New("exact JVM target exited during validation")
		}
	} else if err := signalJVMTargetPIDFD(j.targetProcFD, 0, nil, 0); err != nil {
		return fmt.Errorf("rechecking exact JVM target through procfd: %w", err)
	}
	return nil
}

func (j *JAttacher) CloseTarget() error {
	pidfd := j.targetPIDFD
	procfd := j.targetProcFD
	j.targetPIDFD = -1
	j.targetProcFD = -1
	j.targetPID = 0
	j.targetStart = 0
	var closeErr error
	if procfd >= 0 {
		closeErr = errors.Join(closeErr, unix.Close(procfd))
	}
	if pidfd >= 0 {
		closeErr = errors.Join(closeErr, unix.Close(pidfd))
	}
	return closeErr
}

func (j *JAttacher) signalTarget(pid int, signal syscall.Signal) error {
	if j.targetProcFD < 0 {
		return errors.New("cannot signal an unbound JVM target")
	}
	if pid != j.targetPID {
		return fmt.Errorf("attach PID %d does not match bound JVM target %d", pid, j.targetPID)
	}
	if err := j.ValidateTarget(); err != nil {
		return err
	}
	signalFD := j.targetPIDFD
	if signalFD < 0 {
		signalFD = j.targetProcFD
	}
	return signalJVMTargetPIDFD(signalFD, signal, nil, 0)
}

func (j *JAttacher) Init() {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.initialized {
		return
	}

	j.myUID = getEUID()
	j.myGID = getEGID()
	j.initialized = true
}

func setThreadEffectiveID(trap uintptr, id int) error {
	const unchangedID = ^uintptr(0)
	_, _, errno := unix.RawSyscall(
		trap, unchangedID, uintptr(id), unchangedID,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// setThreadCredentials intentionally uses raw Linux syscalls. Go's
// syscall.Set{euid,egid} wrappers coordinate the change across every runtime
// thread, which would make discovery, cleanup, and tracer goroutines run as the
// target application during an asynchronous JVM attach. This function is used
// only on the locked sacrificial thread that is destroyed after attach.
func setThreadCredentials(uid, gid int) error {
	if err := setThreadEffectiveID(unix.SYS_SETRESGID, gid); err != nil {
		return fmt.Errorf("setting attach-thread effective GID %d: %w", gid, err)
	}
	if err := setThreadEffectiveID(unix.SYS_SETRESUID, uid); err != nil {
		return fmt.Errorf("setting attach-thread effective UID %d: %w", uid, err)
	}
	return nil
}

func (j *JAttacher) Terminate() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.terminated = true
	return nil
}

func (j *JAttacher) Cleanup() error {
	j.mu.Lock()
	j9attacher := j.j9attacher
	attachID := j.attachID
	runIfCurrentAttach := j.runIfCurrentAttach
	j.mu.Unlock()

	if j9attacher == nil {
		return nil
	}
	if runIfCurrentAttach == nil {
		return j9attacher.detach()
	}
	return runIfCurrentAttach(attachID, j9attacher.detach)
}

func (j *JAttacher) changeThreadCredentials(uid, gid int) error {
	j.mu.Lock()
	attachID := j.attachID
	runIfCurrentAttach := j.runIfCurrentAttach
	j.mu.Unlock()

	change := func() error {
		j.mu.Lock()
		defer j.mu.Unlock()
		if j.terminated {
			return errTerminated
		}
		return setAttachThreadCredentials(uid, gid)
	}
	if runIfCurrentAttach == nil {
		return change()
	}
	return runIfCurrentAttach(attachID, change)
}

func (j *JAttacher) Attach(pid int, argv []string, ignoreOnJ9 bool) (io.ReadCloser, error) {
	return j.AttachContext(context.Background(), pid, argv, ignoreOnJ9)
}

func (j *JAttacher) AttachContext(ctx context.Context, pid int, argv []string, ignoreOnJ9 bool) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if j.targetProcFD < 0 {
		return nil, errors.New("exact JVM target is not bound")
	}
	if pid != j.targetPID {
		return nil, fmt.Errorf("attach PID %d does not match bound JVM target %d", pid, j.targetPID)
	}
	if err := j.ValidateTarget(); err != nil {
		return nil, err
	}

	targetUID := j.myUID
	targetGID := j.myGID
	var nspid int

	// Resolve the target's credentials and in-namespace PID from the host
	// namespace, before we move anywhere.
	if err := util.GetProcessInfo(pid, &targetUID, &targetGID, &nspid); err != nil {
		return nil, fmt.Errorf("process not found: %d: %w", pid, err)
	}
	if err := j.ValidateTarget(); err != nil {
		return nil, err
	}

	// Entering the target's mount namespace requires setns(CLONE_NEWNS), which
	// the kernel refuses for any thread that shares filesystem attributes with
	// the rest of the Go runtime's thread pool (see util.EnterNS). We therefore
	// run the entire namespace-sensitive attach sequence on a dedicated OS
	// thread that is locked and never unlocked: when this goroutine returns,
	// the runtime destroys the thread instead of recycling one that is stranded
	// in the target's namespaces with an unshared, private filesystem context.
	//
	// The attach result is an fd-backed io.ReadCloser (a unix socket conn for
	// HotSpot, or a raw fd reader for OpenJ9). Once established, that fd belongs
	// to the process and can be read from any thread, so the caller is free to
	// consume it after this sacrificial thread is gone.
	type attachResult struct {
		reader io.ReadCloser
		err    error
	}
	resultCh := make(chan attachResult, 1)

	go func() {
		// This goroutine runs independently of the caller's goroutine, so a
		// panic here would escape the callers' own recover take down the whole process.
		// Convert it into an attach error instead.
		defer func() {
			if r := recover(); r != nil {
				j.logger.Error("recovered from panic during JVM attach",
					"pid", pid, "panic", r, "stack", string(debug.Stack()))
				resultCh <- attachResult{err: fmt.Errorf("panic during JVM attach: %v", r)}
			}
		}()

		runtime.LockOSThread()
		// Deliberately no runtime.UnlockOSThread: this thread is tainted by the
		// namespace switch and CLONE_FS unshare, so we let it die with the
		// goroutine rather than return it to the pool.
		reader, err := j.attachInNamespace(ctx, pid, nspid, targetUID, targetGID, argv, ignoreOnJ9)
		resultCh <- attachResult{reader: reader, err: err}
	}()

	res := <-resultCh
	return res.reader, res.err
}

// attachInNamespace performs the namespace switch, credential change and JVM
// handshake. It MUST be called from a goroutine pinned to a dedicated,
// never-unlocked OS thread (see Attach), because it both joins the target's
// mount namespace and unshares CLONE_FS on the calling thread.
func (j *JAttacher) attachInNamespace(ctx context.Context, pid, nspid, targetUID, targetGID int, argv []string, ignoreOnJ9 bool) (io.ReadCloser, error) {
	if err := j.ValidateTarget(); err != nil {
		return nil, err
	}
	// Container support: switch to the target namespaces.
	// Network and IPC namespaces are essential for OpenJ9 connection.
	if util.EnterNS(pid, "net") < 0 {
		return nil, errors.New("failed to enter target net namespace")
	}
	if util.EnterNS(pid, "ipc") < 0 {
		return nil, errors.New("failed to enter target ipc namespace")
	}
	mntChanged := util.EnterNS(pid, "mnt")
	if mntChanged < 0 {
		return nil, errors.New("failed to enter target mnt namespace")
	}
	if err := j.ValidateTarget(); err != nil {
		return nil, err
	}

	// Dynamic attach requires the client to have the target's euid/egid. Change
	// only this locked sacrificial OS thread; process-wide Go wrappers would
	// transiently deprivilege every tracer and discovery goroutine.
	if j.myGID != targetGID || j.myUID != targetUID {
		if err := j.changeThreadCredentials(targetUID, targetGID); err != nil {
			return nil, fmt.Errorf("failed to change attach-thread credentials: %w", err)
		}
	}

	attachPid := pid
	if mntChanged > 0 {
		attachPid = nspid
	}

	tmpPath := util.GetTmpPath(attachPid)

	// Make write() return EPIPE instead of abnormal process termination
	signal.Ignore(syscall.SIGPIPE)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if isOpenJ9Process(tmpPath, attachPid) {
		if ignoreOnJ9 {
			return nil, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		j9attacher := newJ9Attacher(j.logger)
		j.j9attacher = j9attacher
		return j.j9attacher.jattachOpenJ9(ctx, tmpPath, nspid, argv, j)
	}

	return jattachHotspot(ctx, pid, nspid, attachPid, argv, tmpPath, j.logger, j)
}
