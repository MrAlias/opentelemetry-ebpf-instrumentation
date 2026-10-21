// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package pythonagent // import "go.opentelemetry.io/obi/pkg/internal/pythonagent"

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const (
	attachmentSupported = true
	debugRegisterOffset = 848 // Linux x86_64 struct user.u_debugreg ABI.
	attachmentStackSize = 64 * 1024
	attachmentPoll      = 5 * time.Millisecond
	trapBreakpoint      = 1
	trapTrace           = 2
	trapHardware        = 4
)

type tracedThread struct {
	tid       int
	stopped   bool
	original  [4]uint64 // DR0, DR1, DR6, DR7.
	saved     bool
	signal    int
	inherited bool
	foreign   bool
}

type pythonTrace struct {
	process   *procs.ProcessHandle
	threads   map[int]*tracedThread
	armed     bool
	frame     uint64
	alternate uint64
	stepTID   int
	stepIP    uint64
	replaced  bool
	exitErr   error
}

var errPythonExec = errors.New("python process executed a new program during attachment")

func ptrace(request, tid int, address, data uintptr) error {
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, uintptr(request), uintptr(tid), address, data, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func trapCode(tid int) (int32, error) {
	var information unix.Siginfo
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_GETSIGINFO,
		uintptr(tid), 0, uintptr(unsafe.Pointer(&information)), 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return information.Code, nil
}

func debugRegister(tid, index int) (uint64, error) {
	var data [8]byte
	_, err := unix.PtracePeekUser(tid, uintptr(debugRegisterOffset+8*index), data[:])
	return binary.LittleEndian.Uint64(data[:]), err
}

func setDebugRegister(tid, index int, value uint64) error {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	_, err := unix.PtracePokeUser(tid, uintptr(debugRegisterOffset+8*index), data[:])
	return err
}

func (thread *tracedThread) arm(frame, alternate uint64) error {
	if !thread.saved {
		for position, index := range []int{0, 1, 6, 7} {
			value, err := debugRegister(thread.tid, index)
			if err != nil {
				return err
			}
			thread.original[position] = value
		}
		thread.saved = true
	}
	if thread.original[3]&0xff != 0 {
		return errors.New("hardware breakpoints are already configured")
	}
	if err := setDebugRegister(thread.tid, 0, frame); err != nil {
		return err
	}
	enabled := uint64(1)
	if alternate != 0 {
		if err := setDebugRegister(thread.tid, 1, alternate); err != nil {
			return err
		}
		enabled |= 1 << 2
	}
	if err := setDebugRegister(thread.tid, 6, 0); err != nil {
		return err
	}
	return setDebugRegister(thread.tid, 7, (thread.original[3]&^(uint64(255)<<16))|enabled)
}

func (trace *pythonTrace) resume(thread *tracedThread, signal int) error {
	if err := unix.PtraceCont(thread.tid, signal); err != nil {
		return err
	}
	thread.stopped = false
	thread.signal = 0
	return nil
}

func (trace *pythonTrace) poll() (*tracedThread, unix.WaitStatus, error) {
	for tid, thread := range trace.threads {
		if thread.stopped {
			continue
		}
		var status unix.WaitStatus
		result, err := unix.Wait4(tid, &status, unix.WNOHANG|unix.WALL, nil)
		if errors.Is(err, unix.ECHILD) || errors.Is(err, unix.ESRCH) {
			delete(trace.threads, tid)
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		if result == 0 {
			continue
		}
		if status.Exited() || status.Signaled() {
			if status.Signaled() {
				trace.exitErr = fmt.Errorf("python thread %d terminated by %v", tid, status.Signal())
			}
			delete(trace.threads, tid)
			continue
		}
		if !status.Stopped() {
			continue
		}
		thread.stopped = true
		switch cause := status.TrapCause(); {
		case cause == unix.PTRACE_EVENT_CLONE:
			child, err := unix.PtraceGetEventMsg(tid)
			if err != nil {
				return nil, 0, err
			}
			// Linux copies the tracer's virtual debug state into the child.
			// Its pre-attachment state is the parent's saved state.
			trace.threads[int(child)] = &tracedThread{
				tid: int(child), original: thread.original,
				saved: thread.saved, inherited: true,
			}
			member, err := trace.process.Open(fmt.Sprintf("task/%d", child), os.O_RDONLY|unix.O_DIRECTORY)
			if err != nil {
				trace.threads[int(child)].foreign = true
			} else {
				_ = member.Close()
			}
		case cause == unix.PTRACE_EVENT_EXEC:
			// exec resets hardware debug registers; never restore addresses from
			// the previous executable into its replacement.
			for _, previous := range trace.threads {
				previous.saved = false
			}
			trace.replaced = true
			return thread, status, errPythonExec
		case !thread.inherited && (cause <= 0 ||
			(cause == unix.PTRACE_EVENT_STOP && status.StopSignal() != unix.SIGTRAP)):
			thread.signal = int(status.StopSignal())
			if status.StopSignal() == unix.SIGTRAP {
				var registers unix.PtraceRegs
				if err := unix.PtraceGetRegs(tid, &registers); err != nil {
					return nil, 0, err
				}
				debugStatus, err := debugRegister(tid, 6)
				if err != nil {
					return nil, 0, err
				}
				code, err := trapCode(tid)
				if err != nil {
					return nil, 0, err
				}
				if trace.breakpoint(registers.Rip, debugStatus, code) ||
					trace.singleStep(tid, registers.Rip, code) {
					thread.signal = 0
				}
			}
		}
		return thread, status, nil
	}
	return nil, 0, nil
}

func (trace *pythonTrace) stopAll(ctx context.Context) error {
	for tid, thread := range trace.threads {
		if !thread.stopped {
			if err := unix.PtraceInterrupt(tid); err != nil && !errors.Is(err, unix.ESRCH) {
				return err
			}
		}
	}
	for {
		complete := true
		for _, thread := range trace.threads {
			complete = complete && thread.stopped
		}
		if complete {
			return nil
		}
		thread, _, err := trace.poll()
		if err != nil {
			return err
		}
		if thread != nil {
			continue
		}
		if err := pauseAttachment(ctx); err != nil {
			return err
		}
	}
}

func (trace *pythonTrace) singleStep(tid int, ip uint64, code int32) bool {
	// A single-stepped syscall can report TRAP_BRKPT rather than TRAP_TRACE.
	// Only the verified syscall's next instruction is an owned step stop.
	return tid == trace.stepTID && ip == trace.stepIP && (code == trapBreakpoint || code == trapTrace)
}

func (trace *pythonTrace) breakpoint(ip, status uint64, code int32) bool {
	return trace.armed && code == trapHardware &&
		((status&1 != 0 && ip == trace.frame) ||
			(trace.alternate != 0 && status&2 != 0 && ip == trace.alternate))
}

func (trace *pythonTrace) stopThread(thread *tracedThread) error {
	if thread.stopped {
		return nil
	}
	if err := unix.PtraceInterrupt(thread.tid); err != nil && !errors.Is(err, unix.ESRCH) {
		return err
	}
	for !thread.stopped {
		if _, exists := trace.threads[thread.tid]; !exists {
			break
		}
		stopped, _, err := trace.poll()
		if err != nil {
			return err
		}
		if stopped == nil {
			_ = pauseAttachment(context.Background())
		}
	}
	return nil
}

func stoppingSignal(signal int) bool {
	return signal == int(unix.SIGSTOP) || signal == int(unix.SIGTSTP) ||
		signal == int(unix.SIGTTIN) || signal == int(unix.SIGTTOU)
}

func (trace *pythonTrace) detach(thread *tracedThread) error {
	var result error
	if thread.saved {
		result = errors.Join(result, setDebugRegister(thread.tid, 7, thread.original[3]&^15))
		result = errors.Join(result, setDebugRegister(thread.tid, 0, thread.original[0]))
		result = errors.Join(result, setDebugRegister(thread.tid, 1, thread.original[1]))
		result = errors.Join(result, setDebugRegister(thread.tid, 6, thread.original[2]))
		result = errors.Join(result, setDebugRegister(thread.tid, 7, thread.original[3]))
	}
	err := ptrace(unix.PTRACE_DETACH, thread.tid, 0, uintptr(thread.signal))
	if !errors.Is(err, unix.ESRCH) {
		result = errors.Join(result, err)
	}
	delete(trace.threads, thread.tid)
	return result
}

func (trace *pythonTrace) close() error {
	var result error
	for tid, thread := range trace.threads {
		if !thread.stopped {
			err := unix.PtraceInterrupt(tid)
			if !errors.Is(err, unix.ESRCH) {
				result = errors.Join(result, err)
			}
		}
	}
	// Release each stopped thread immediately; a thread waiting in the kernel
	// must not keep the rest of the application suspended during cleanup.
	for len(trace.threads) != 0 {
		for _, thread := range trace.threads {
			if thread.stopped {
				result = errors.Join(result, trace.detach(thread))
			}
		}
		if len(trace.threads) == 0 {
			break
		}
		thread, _, err := trace.poll()
		if !errors.Is(err, errPythonExec) {
			result = errors.Join(result, err)
		}
		if thread == nil {
			_ = pauseAttachment(context.Background())
		}
	}
	return result
}

func pauseAttachment(ctx context.Context) error {
	timer := time.NewTimer(attachmentPoll)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (trace *pythonTrace) seize(ctx context.Context) error {
	// Stop and enumerate again before enabling clone tracing. A thread created
	// during enumeration is then seized normally, without racing an inherited
	// ptrace attachment.
	for {
		added, err := trace.seizeThreads()
		if err != nil {
			return err
		}
		if err := trace.stopAll(ctx); err != nil {
			return err
		}
		if !added {
			break
		}
	}
	return trace.process.Alive()
}

func (trace *pythonTrace) seizeThreads() (bool, error) {
	tasks, err := trace.process.Open("task", os.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return false, err
	}
	defer tasks.Close()
	entries, err := tasks.ReadDir(-1)
	if err != nil {
		return false, err
	}
	added := false
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if _, exists := trace.threads[tid]; exists {
			continue
		}
		if err := ptrace(unix.PTRACE_SEIZE, tid, 0, unix.PTRACE_O_TRACEEXEC); err != nil {
			if errors.Is(err, unix.ESRCH) {
				continue
			}
			return false, fmt.Errorf("seize Python thread %d: %w", tid, err)
		}
		trace.threads[tid] = &tracedThread{tid: tid}
		added = true
	}
	return added, nil
}

func (trace *pythonTrace) arm(frame, alternate uint64) error {
	trace.frame = frame
	trace.alternate = alternate
	for _, thread := range trace.threads {
		if stoppingSignal(thread.signal) {
			return errors.New("python process is stopped")
		}
		if err := unix.PtraceSetOptions(thread.tid, unix.PTRACE_O_TRACECLONE|unix.PTRACE_O_TRACEEXEC); err != nil {
			return err
		}
		if err := thread.arm(frame, alternate); err != nil {
			return err
		}
	}
	trace.armed = true
	for _, thread := range trace.threads {
		if err := trace.resume(thread, thread.signal); err != nil {
			return err
		}
	}
	return nil
}

func (trace *pythonTrace) waitAt(ctx context.Context, address uint64, only int) (*tracedThread, unix.PtraceRegs, error) {
	for len(trace.threads) != 0 {
		thread, status, err := trace.poll()
		if err != nil {
			return nil, unix.PtraceRegs{}, err
		}
		if thread != nil {
			if thread.inherited {
				if thread.foreign {
					if err := trace.detach(thread); err != nil {
						return nil, unix.PtraceRegs{}, err
					}
					continue
				}
				if trace.armed {
					if err := thread.arm(trace.frame, trace.alternate); err != nil {
						return nil, unix.PtraceRegs{}, err
					}
				}
				thread.inherited = false
			} else if status.StopSignal() == unix.SIGTRAP && status.TrapCause() == 0 {
				debugStatus, err := debugRegister(thread.tid, 6)
				if err != nil {
					return nil, unix.PtraceRegs{}, err
				}
				code, err := trapCode(thread.tid)
				if err != nil {
					return nil, unix.PtraceRegs{}, err
				}
				var registers unix.PtraceRegs
				if err := unix.PtraceGetRegs(thread.tid, &registers); err != nil {
					return nil, registers, err
				}
				ownBreakpoint := trace.breakpoint(registers.Rip, debugStatus, code)
				ownStep := trace.singleStep(thread.tid, registers.Rip, code)
				if ownBreakpoint || ownStep {
					thread.signal = 0
				}
				if (ownBreakpoint || ownStep) && (address == 0 || registers.Rip == address) && (only == 0 || only == thread.tid) {
					return thread, registers, nil
				}
			}
			if stoppingSignal(thread.signal) {
				return nil, unix.PtraceRegs{}, errors.New("python process was stopped during attachment")
			}
			if err := trace.resume(thread, thread.signal); err != nil && !errors.Is(err, unix.ESRCH) {
				return nil, unix.PtraceRegs{}, err
			}
			continue
		}
		if err := pauseAttachment(ctx); err != nil {
			return nil, unix.PtraceRegs{}, err
		}
	}
	return nil, unix.PtraceRegs{}, errors.Join(errors.New("python process exited during attachment"), trace.exitErr)
}

func (trace *pythonTrace) syscall(ctx context.Context, thread *tracedThread, address, number uint64, args ...uint64) (result uint64, resultErr error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var saved unix.PtraceRegs
	if err := unix.PtraceGetRegs(thread.tid, &saved); err != nil {
		return 0, err
	}
	defer func() {
		if !thread.stopped {
			resultErr = errors.Join(resultErr, trace.stopThread(thread))
		}
		if thread.stopped && !trace.replaced {
			resultErr = errors.Join(resultErr, unix.PtraceSetRegs(thread.tid, &saved))
		}
		trace.stepTID = 0
		trace.stepIP = 0
	}()
	registers := saved
	registers.Rip, registers.Rax, registers.Orig_rax = address, number, ^uint64(0)
	arguments := []*uint64{&registers.Rdi, &registers.Rsi, &registers.Rdx, &registers.R10, &registers.R8, &registers.R9}
	for index, value := range args {
		*arguments[index] = value
	}
	if err := unix.PtraceSetRegs(thread.tid, &registers); err != nil {
		return 0, err
	}
	trace.stepTID = thread.tid
	trace.stepIP = address + 2
	if err := unix.PtraceSingleStep(thread.tid); err != nil {
		return 0, err
	}
	thread.stopped = false
	_, registers, err := trace.waitAt(ctx, address+2, thread.tid)
	if err != nil {
		return 0, err
	}
	if value := int64(registers.Rax); value < 0 && value >= -4095 {
		return 0, unix.Errno(-value)
	}
	return registers.Rax, nil
}

func writeTarget(memory *os.File, address uint64, data []byte) error {
	n, err := memory.WriteAt(data, int64(address))
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func attach(ctx context.Context, process *procs.ProcessHandle) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	statusFile, err := process.Open("status", os.O_RDONLY)
	if err != nil {
		return err
	}
	processStatus, err := io.ReadAll(statusFile)
	_ = statusFile.Close()
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(string(processStatus), "\n") {
		if strings.HasPrefix(line, "State:") {
			fields := strings.Fields(line)
			if len(fields) > 1 && (fields[1] == "T" || fields[1] == "t") {
				return errors.New("python process is stopped")
			}
		}
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	trace := &pythonTrace{process: process, threads: map[int]*tracedThread{}}
	defer func() { resultErr = errors.Join(resultErr, trace.close()) }()
	if err := trace.seize(ctx); err != nil {
		return err
	}
	// Resolve while every thread is stopped, so exec cannot replace the ELF
	// between symbol validation and arming the execution breakpoint.
	entry, err := resolveRuntime(process)
	if err != nil {
		return err
	}
	if err := trace.arm(entry.frame, entry.alternate); err != nil {
		return err
	}
	thread, original, err := trace.waitAt(ctx, 0, 0)
	if err != nil {
		return err
	}
	memory, err := process.Open("mem", os.O_RDWR)
	if err != nil {
		return err
	}
	defer memory.Close()
	var instruction [2]byte
	if _, err := memory.ReadAt(instruction[:], int64(entry.syscall)); err != nil {
		return err
	}
	if instruction != [2]byte{0x0f, 0x05} {
		return errors.New("the target libc syscall instruction was modified")
	}
	page := uint64(os.Getpagesize())
	scriptBytes := append([]byte(Script()), 0)
	scriptSize := (uint64(len(scriptBytes)) + page - 1) & ^(page - 1)
	var stack uint64
	var allocations []struct{ address, size uint64 }
	started, returned, accepted := false, false, false
	defer func() {
		// After enqueue starts, the target owns these mappings until it returns.
		// Cancellation must not free code or stack that it can still execute.
		if accepted || (started && !returned) || trace.replaced || !thread.stopped {
			return
		}
		if err := unix.PtraceSetRegs(thread.tid, &original); err != nil {
			resultErr = errors.Join(resultErr, err)
			return
		}
		cleanup, cancelCleanup := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelCleanup()
		for _, allocation := range slices.Backward(allocations) {
			if returned && allocation.address == stack {
				continue // The enqueue trampoline released its own stack.
			}
			_, err := trace.syscall(cleanup, thread, entry.syscall, unix.SYS_MUNMAP, allocation.address, allocation.size)
			resultErr = errors.Join(resultErr, err)
		}
	}()
	allocate := func(size uint64) (uint64, error) {
		address, err := trace.syscall(ctx, thread, entry.syscall, unix.SYS_MMAP,
			0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uint64(0), 0)
		if err == nil {
			allocations = append(allocations, struct{ address, size uint64 }{address, size})
		}
		return address, err
	}
	script, err := allocate(scriptSize)
	if err != nil {
		return err
	}
	code, err := allocate(2 * page)
	if err != nil {
		return err
	}
	stack, err = allocate(attachmentStackSize)
	if err != nil {
		return err
	}
	status := code + page
	callback := pendingCallback(entry, script, scriptSize, status)
	callAddress := code + page/2
	call := enqueueCallback(entry, original, code, script, status, stack, attachmentStackSize)
	if uint64(len(callback)) > page/2 || uint64(len(call)) > page/2 {
		return errors.New("python attachment trampoline exceeds its code page")
	}
	for _, block := range []struct {
		address uint64
		data    []byte
	}{{script, scriptBytes}, {code, callback}, {callAddress, call}} {
		if err := writeTarget(memory, block.address, block.data); err != nil {
			return err
		}
	}
	if _, err := trace.syscall(ctx, thread, entry.syscall, unix.SYS_MPROTECT, code, page, unix.PROT_READ|unix.PROT_EXEC); err != nil {
		return err
	}
	registers := original
	registers.Rip, registers.Rsp = callAddress, stack+attachmentStackSize-16
	if err := unix.PtraceSetRegs(thread.tid, &registers); err != nil {
		return err
	}
	if err := trace.resume(thread, 0); err != nil {
		return err
	}
	started = true
	if _, _, err := trace.waitAt(ctx, original.Rip, thread.tid); err != nil {
		return err
	}
	returned = true
	var state [16]byte
	if _, err := memory.ReadAt(state[:], int64(status)); err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(state[:4]) != 1 || int32(binary.LittleEndian.Uint32(state[4:8])) != 0 {
		return errors.New("CPython pending-call queue did not accept the agent")
	}
	accepted = true
	if err := trace.close(); err != nil {
		return err
	}
	// The callback code and acknowledgement page remain mapped until process
	// exit; the callback can still be returning when its acknowledgement arrives.
	for {
		if _, err := memory.ReadAt(state[:], int64(status)); err != nil {
			return err
		}
		if binary.LittleEndian.Uint32(state[8:12]) == 1 {
			if int32(binary.LittleEndian.Uint32(state[12:])) != 0 {
				return errors.New("python requests agent installation failed")
			}
			return nil
		}
		if err := pauseAttachment(ctx); err != nil {
			return err
		}
	}
}
