// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package pythonagent // import "go.opentelemetry.io/obi/pkg/internal/pythonagent"

import (
	"encoding/binary"
	"errors"

	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/unix"
)

const (
	xRAX = iota
	xRCX
	xRDX
	xRBX
	xRSP
	xRBP
	xRSI
	xRDI
	xR8
	xR9
	xR10
	xR11
	xR12
	xR13
)

type nativeCode []byte

func (c *nativeCode) immediate(register byte, value uint64) {
	*c = append(*c, 0x48|register>>3, 0xb8|register&7)
	*c = binary.LittleEndian.AppendUint64(*c, value)
}

func (c *nativeCode) move(destination, source byte) {
	*c = append(*c, 0x48|(source>>3)<<2|destination>>3, 0x89, 0xc0|(source&7)<<3|destination&7)
}

func (c *nativeCode) call(address uint64) {
	c.immediate(xRAX, address)
	*c = append(*c, 0xff, 0xd0)
}

func (c *nativeCode) push(register byte) {
	if register >= 8 {
		*c = append(*c, 0x41)
	}
	*c = append(*c, 0x50|register&7)
}

func (c *nativeCode) pop(register byte) {
	if register >= 8 {
		*c = append(*c, 0x41)
	}
	*c = append(*c, 0x58|register&7)
}

func (c *nativeCode) store(base, offset, source byte) {
	*c = append(*c, 0x40|(source>>3)<<2|base>>3, 0x89, 0x40|(source&7)<<3|base&7, offset)
}

func (c *nativeCode) jump(zero bool) int {
	if zero {
		*c = append(*c, 0x48, 0x85, 0xc0, 0x0f, 0x84)
	} else {
		*c = append(*c, 0xe9)
	}
	position := len(*c)
	*c = append(*c, 0, 0, 0, 0)
	return position
}

func (c *nativeCode) target(position int) {
	binary.LittleEndian.PutUint32((*c)[position:], uint32(len(*c)-position-4))
}

func (c *nativeCode) unmap(address, size uint64) {
	c.immediate(xRDI, address)
	c.immediate(xRSI, size)
	c.immediate(xRAX, unix.SYS_MUNMAP)
	*c = append(*c, 0x0f, 0x05)
}

// The callback runs under CPython's GIL. Its namespace is private, exceptions
// are cleared, and its return value never raises into the application.
func pendingCallback(runtime attachmentRuntime, script, scriptSize, status uint64) []byte {
	c := nativeCode{0xf3, 0x0f, 0x1e, 0xfa} // ENDBR64 for CET-enabled interpreters.
	c.push(xRBX)
	c.push(xR12)
	c.push(xR13)
	c = append(c, 0x48, 0x83, 0xec, 0x20) // Reserve three PyObject pointers, keeping stack alignment.
	c.move(xRDI, xRSP)
	c = append(c, 0x48, 0x8d, 0x74, 0x24, 0x08, 0x48, 0x8d, 0x54, 0x24, 0x10)
	c.call(runtime.fetch)
	c.immediate(xR13, status)
	c.immediate(xR12, 0)
	c.call(runtime.dict)
	allocationFailed := c.jump(true)
	c.move(xRBX, xRAX)
	c.immediate(xRDI, script)
	c.immediate(xRSI, 257) // Py_file_input, part of CPython's C API.
	c.move(xRDX, xRBX)
	c.move(xRCX, xRBX)
	c.immediate(xR8, 0)
	c.call(runtime.run)
	executionFailed := c.jump(true)
	c.move(xRDI, xRAX)
	c.call(runtime.decref)
	releaseNamespace := c.jump(false)
	c.target(executionFailed)
	c.immediate(xR12, ^uint64(0))
	c.target(releaseNamespace)
	c.move(xRDI, xRBX)
	c.call(runtime.decref)
	completed := c.jump(false)
	c.target(allocationFailed)
	c.immediate(xR12, ^uint64(0))
	c.target(completed)
	c.call(runtime.clear)
	c = append(c, 0x48, 0x8b, 0x3c, 0x24, 0x48, 0x8b, 0x74, 0x24, 0x08, 0x48, 0x8b, 0x54, 0x24, 0x10)
	c.call(runtime.restore)
	c.unmap(script, scriptSize)
	c.store(xR13, 12, xR12)
	c.immediate(xRAX, 1)
	c.store(xR13, 8, xRAX)
	c.immediate(xRAX, 0)
	c = append(c, 0x48, 0x83, 0xc4, 0x20)
	c.pop(xR13)
	c.pop(xR12)
	c.pop(xRBX)
	c = append(c, 0xc3)
	return c
}

// Enter only at the verified CPython boundary: its three integer arguments
// are restored, and callees preserve the SysV nonvolatile registers.
// Restoration happens in the target even if the tracer detaches on timeout.
func enqueueCallback(runtime attachmentRuntime, registers unix.PtraceRegs, callback, script, status, stack, stackSize uint64) []byte {
	c := nativeCode{0xf3, 0x0f, 0x1e, 0xfa}
	c.call(runtime.errno)
	c.push(xRAX)
	c = append(c, 0x8b, 0x08) // Save the target thread's errno.
	c.push(xRCX)
	c.immediate(xRDI, callback)
	c.immediate(xRSI, script)
	c.call(runtime.pending)
	c.immediate(xR10, status)
	c.store(xR10, 4, xRAX)
	c.pop(xRCX)
	c.pop(xRDX)
	c = append(c, 0x89, 0x0a)
	c.immediate(xRAX, 1)
	c.store(xR10, 0, xRAX)
	c.immediate(xRSP, registers.Rsp)
	c.unmap(stack, stackSize)
	c.immediate(xRDI, registers.Rdi)
	c.immediate(xRSI, registers.Rsi)
	c.immediate(xRDX, registers.Rdx)
	c = append(c, 0xff, 0x25, 0, 0, 0, 0)
	c = binary.LittleEndian.AppendUint64(c, registers.Rip)
	return c
}

func syscallInstruction(data []byte) (int, error) {
	position := 0
	// x86asm does not decode the CET landing pad used by current glibc.
	if len(data) >= 4 && binary.LittleEndian.Uint32(data[:4]) == 0xfa1e0ff3 {
		position = 4
	}
	for position < len(data) {
		instruction, err := x86asm.Decode(data[position:], 64)
		if err != nil || instruction.Len == 0 || instruction.Op == x86asm.RET {
			break
		}
		if instruction.Op == x86asm.SYSCALL {
			return position, nil
		}
		position += instruction.Len
	}
	return 0, errors.New("libc syscall instruction not found")
}
