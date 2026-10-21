// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package agent // import "go.opentelemetry.io/obi/pkg/internal/cpython/agent"

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const (
	remoteSize       = 256 * 1024
	codeSize         = 4096
	ackOffset        = codeSize
	scriptOffset     = ackOffset + 8
	ntX86Xstate      = 0x202
	ptraceGetSigmask = 0x420a
	ptraceSetSigmask = 0x420b
)

var errNotIdle = errors.New("main Python thread is not blocked in an event-loop syscall")

type addresses struct {
	pending     uint64
	run         uint64
	syscall     uint64
	initialized uint64
}

// Inject schedules the agent on CPython's main interpreter with the GIL held.
// Only the main thread is interrupted, and only at an idle event-loop syscall.
// No live application instructions or stack memory are overwritten.
func Inject(ctx context.Context, pid app.PID, startTime uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	handle, err := procs.OpenProcessHandle(pid, startTime)
	if err != nil {
		return err
	}
	defer handle.Close()
	functions, err := resolve(handle)
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var remote uint64
	err = whenIdle(ctx, handle, func(thread *stoppedThread) (resultErr error) {
		queued := false
		defer func() {
			if remote != 0 && !queued {
				_, cleanupErr := thread.syscall(functions.syscall, unix.SYS_MUNMAP, remote, remoteSize, 0, 0, 0, 0)
				resultErr = errors.Join(resultErr, cleanupErr)
			}
		}()
		remote, err = thread.syscall(functions.syscall, unix.SYS_MMAP,
			0, remoteSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS, ^uint64(0), 0)
		if err != nil {
			return fmt.Errorf("allocating agent memory: %w", err)
		}
		payload := append([]byte(bootstrap(remote+ackOffset)), 0)
		if len(payload) > remoteSize/2 {
			return errors.New("embedded Python agent exceeds remote allocation")
		}
		if _, err = unix.PtracePokeData(int(pid), uintptr(remote+scriptOffset), payload); err != nil {
			return err
		}
		// CALL uses the processor's normal return stack, including CET shadow stacks.
		if _, err = unix.PtracePokeData(int(pid), uintptr(remote), []byte{0xff, 0xd0, 0xcc}); err != nil {
			return err
		}
		if _, err = thread.syscall(functions.syscall, unix.SYS_MPROTECT, remote, codeSize, unix.PROT_READ|unix.PROT_EXEC, 0, 0, 0); err != nil {
			return err
		}
		initialized, err := thread.call(remote, remote+remoteSize, functions.initialized, 0, 0)
		if err != nil {
			return err
		}
		if initialized == 0 {
			return errors.New("CPython is not initialized")
		}
		result, err := thread.call(remote, remote+remoteSize, functions.pending, functions.run, remote+scriptOffset)
		if err != nil {
			return err
		}
		if int32(result) != 0 {
			return errors.New("CPython pending-call queue is full")
		}
		queued = true
		return nil
	})
	if err != nil {
		return fmt.Errorf("scheduling Python agent: %w", err)
	}
	// The callback is allowed to run on the next ordinary event-loop wakeup.
	// Its buffer must remain mapped if cancellation happens before that wakeup.
	status, err := awaitAck(ctx, handle, remote+ackOffset)
	if err != nil {
		return err
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = whenIdle(cleanupCtx, handle, func(thread *stoppedThread) error {
		_, err := thread.syscall(functions.syscall, unix.SYS_MUNMAP, remote, remoteSize, 0, 0, 0, 0)
		return err
	})
	if status != 1 {
		return fmt.Errorf("installing Python HTTPX agent failed (status %d)", status)
	}
	return nil
}

func awaitAck(ctx context.Context, handle *procs.ProcessHandle, address uint64) (byte, error) {
	mem, err := handle.Open("mem", unix.O_RDONLY)
	if err != nil {
		return 0, err
	}
	defer mem.Close()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var status [1]byte
		if _, err := mem.ReadAt(status[:], int64(address)); err != nil {
			return 0, err
		}
		if status[0] != 0 {
			return status[0], nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}
	}
}

func resolve(handle *procs.ProcessHandle) (addresses, error) {
	maps, err := procs.FindLibMaps(handle.PID())
	if err != nil {
		return addresses{}, err
	}
	var result addresses
	seen := map[uint64]bool{}
	for _, mapping := range maps {
		if !mapping.Perms.Execute || mapping.Inode == 0 || seen[mapping.Inode] {
			continue
		}
		seen[mapping.Inode] = true
		file, err := handle.Open("root"+mapping.Pathname, unix.O_RDONLY)
		if err != nil {
			continue
		}
		func() {
			defer file.Close()
			var stat unix.Stat_t
			if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Ino != mapping.Inode {
				return
			}
			image, err := elf.NewFile(file)
			if err != nil || image.Machine != elf.EM_X86_64 || image.Class != elf.ELFCLASS64 {
				return
			}
			syms, err := procs.FindExeSymbols(image, []string{"Py_AddPendingCall", "PyRun_SimpleString", "Py_IsInitialized", "syscall"})
			if err != nil {
				return
			}
			bias, err := procs.FindMappingLoadBias(maps, image.Progs, mapping.Dev, mapping.Inode)
			if err != nil {
				return
			}
			if pending, ok := syms["Py_AddPendingCall"]; ok && pending.Prog != nil {
				if run, ok := syms["PyRun_SimpleString"]; ok && run.Prog != nil {
					result.pending, result.run = bias+pending.Value, bias+run.Value
					if initialized, ok := syms["Py_IsInitialized"]; ok && initialized.Prog != nil {
						result.initialized = bias + initialized.Value
					}
				}
			}
			if symbol, ok := syms["syscall"]; ok && symbol.Len > 0 && symbol.Len <= 256 {
				data := make([]byte, symbol.Len)
				if _, err := file.ReadAt(data, int64(symbol.Off)); err != nil {
					return
				}
				for offset := 0; offset < len(data); {
					// x86asm versions predating CET do not decode ENDBR64.
					if offset+4 <= len(data) && string(data[offset:offset+4]) == "\xf3\x0f\x1e\xfa" {
						offset += 4
						continue
					}
					instruction, err := x86asm.Decode(data[offset:], 64)
					if err != nil || instruction.Len == 0 {
						break
					}
					if instruction.Op == x86asm.SYSCALL {
						result.syscall = bias + symbol.Value + uint64(offset)
						break
					}
					offset += instruction.Len
				}
			}
		}()
	}
	if result.pending == 0 || result.run == 0 || result.syscall == 0 || result.initialized == 0 {
		return result, fmt.Errorf("CPython pending-call API or native syscall instruction unavailable: pending=%#x run=%#x syscall=%#x", result.pending, result.run, result.syscall)
	}
	return result, handle.Alive()
}

type stoppedThread struct {
	pid    int
	regs   unix.PtraceRegs
	xstate []byte
}

func whenIdle(ctx context.Context, handle *procs.ProcessHandle, run func(*stoppedThread) error) error {
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := withIdleThread(handle, run)
		if !errors.Is(err, errNotIdle) {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", errNotIdle, ctx.Err())
		case <-ticker.C:
		}
	}
}

func withIdleThread(handle *procs.ProcessHandle, run func(*stoppedThread) error) (result error) {
	pid := int(handle.PID())
	file, err := handle.Open("syscall", unix.O_RDONLY)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(file)
	file.Close()
	if err != nil {
		return err
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 || !idleSyscall(fields[0]) {
		return errNotIdle
	}
	if err := handle.Alive(); err != nil {
		return err
	}
	if err := unix.PtraceSeize(pid); err != nil {
		return err
	}
	if err := unix.PtraceInterrupt(pid); err != nil {
		return err
	}
	status, err := waitStatus(pid)
	if err != nil {
		return err
	}
	if !status.Stopped() {
		return fmt.Errorf("selected Python process exited during attachment: %v", status)
	}
	detachSignal := 0
	defer func() {
		_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_DETACH, uintptr(pid), 0, uintptr(detachSignal), 0, 0)
		if errno != 0 {
			result = errors.Join(result, errno)
		}
	}()
	if status.StopSignal() != unix.SIGTRAP || status.TrapCause() != unix.PTRACE_EVENT_STOP {
		detachSignal = int(status.StopSignal())
		return errNotIdle
	}
	// Once stopped, recheck the identity before touching registers or memory.
	if err := handle.Alive(); err != nil {
		return err
	}
	thread := &stoppedThread{pid: pid}
	if err := unix.PtraceGetRegs(pid, &thread.regs); err != nil {
		return err
	}
	if !idleSyscall(strconv.FormatUint(thread.regs.Orig_rax, 10)) {
		return errNotIdle
	}
	thread.xstate = make([]byte, 64*1024)
	length, err := regset(pid, unix.PTRACE_GETREGSET, thread.xstate)
	if err != nil {
		return fmt.Errorf("saving extended registers: %w", err)
	}
	thread.xstate = thread.xstate[:length]
	var originalMask uint64
	if err := signalMask(pid, ptraceGetSigmask, &originalMask); err != nil {
		return fmt.Errorf("saving Python thread signal mask: %w", err)
	}
	mask := ^uint64(0)
	if err := signalMask(pid, ptraceSetSigmask, &mask); err != nil {
		return fmt.Errorf("blocking signals during Python pending call: %w", err)
	}
	defer func() {
		_, fpErr := regset(pid, unix.PTRACE_SETREGSET, thread.xstate)
		result = errors.Join(result, fpErr, unix.PtraceSetRegs(pid, &thread.regs), signalMask(pid, ptraceSetSigmask, &originalMask))
	}()
	return run(thread)
}

func signalMask(pid, operation int, mask *uint64) error {
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, uintptr(operation), uintptr(pid), unsafe.Sizeof(*mask), uintptr(unsafe.Pointer(mask)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func idleSyscall(number string) bool {
	switch number {
	case "7", "23", "232", "270", "271", "281", "441": // poll, select, epoll, pselect, ppoll
		return true
	default:
		return false
	}
}

func regset(pid, operation int, data []byte) (int, error) {
	iov := unix.Iovec{Base: &data[0], Len: uint64(len(data))}
	_, _, errno := unix.Syscall6(unix.SYS_PTRACE, uintptr(operation), uintptr(pid), ntX86Xstate, uintptr(unsafe.Pointer(&iov)), 0, 0)
	runtime.KeepAlive(data)
	if errno != 0 {
		return 0, errno
	}
	return int(iov.Len), nil
}

func waitStop(pid int) error {
	status, err := waitStatus(pid)
	if err != nil {
		return err
	}
	if !status.Stopped() || status.StopSignal() != unix.SIGTRAP {
		return fmt.Errorf("unexpected Python thread status: %v", status)
	}
	return nil
}

func waitStatus(pid int) (unix.WaitStatus, error) {
	var status unix.WaitStatus
	for {
		_, err := unix.Wait4(pid, &status, unix.WALL, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return status, err
	}
}

func (t *stoppedThread) syscall(instruction, number uint64, args ...uint64) (uint64, error) {
	var opcode [2]byte
	if _, err := unix.PtracePeekText(t.pid, uintptr(instruction), opcode[:]); err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint16(opcode[:]) != 0x050f {
		return 0, errors.New("native syscall instruction changed")
	}
	regs := t.regs
	regs.Rip, regs.Rax, regs.Orig_rax = instruction, number, ^uint64(0)
	regs.Rdi, regs.Rsi, regs.Rdx, regs.R10, regs.R8, regs.R9 = args[0], args[1], args[2], args[3], args[4], args[5]
	if err := unix.PtraceSetRegs(t.pid, &regs); err != nil {
		return 0, err
	}
	if err := unix.PtraceSingleStep(t.pid); err != nil {
		return 0, err
	}
	if err := waitStop(t.pid); err != nil {
		return 0, err
	}
	if err := unix.PtraceGetRegs(t.pid, &regs); err != nil {
		return 0, err
	}
	if int64(regs.Rax) < 0 && int64(regs.Rax) >= -4095 {
		return 0, unix.Errno(-int64(regs.Rax))
	}
	return regs.Rax, nil
}

func (t *stoppedThread) call(code, stack, function, first, second uint64) (uint64, error) {
	regs := t.regs
	regs.Rip, regs.Rsp, regs.Rax, regs.Orig_rax = code, stack&^15, function, ^uint64(0)
	regs.Rdi, regs.Rsi = first, second
	if err := unix.PtraceSetRegs(t.pid, &regs); err != nil {
		return 0, err
	}
	if err := unix.PtraceCont(t.pid, 0); err != nil {
		return 0, err
	}
	if err := waitStop(t.pid); err != nil {
		return 0, err
	}
	if err := unix.PtraceGetRegs(t.pid, &regs); err != nil {
		return 0, err
	}
	if regs.Rip != code+3 {
		return 0, fmt.Errorf("calling Python pending-call API missed its return trap: %#x", regs.Rip)
	}
	return regs.Rax, nil
}
