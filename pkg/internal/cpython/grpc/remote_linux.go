// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package grpc // import "go.opentelemetry.io/obi/pkg/internal/cpython/grpc"

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// CPython 3.14's _Py_DebugOffsets bootstrap positions. All addresses used for
// remote execution come from this published table, not build-specific offsets.
// https://github.com/python/cpython/blob/v3.14.0/Include/internal/pycore_debug_offsets.h
const (
	debugWords    = 95
	debuggerWord  = 89
	pleaseStopBit = 1 << 5
)

type remoteLayout struct {
	interpreters, mainThread, enabled             uint64
	evalBreaker, support, pending, path, pathSize uint64
}

func readRemoteLayout(mem io.ReaderAt, address uint64) (remoteLayout, error) {
	var raw [debugWords * 8]byte
	if _, err := mem.ReadAt(raw[:], int64(address)); err != nil {
		return remoteLayout{}, err
	}
	word := func(index int) uint64 { return binary.LittleEndian.Uint64(raw[index*8:]) }
	version := word(1)
	if string(raw[:8]) != "xdebugpy" || version>>16 != 0x030e || version&0xff != 0xf0 || word(2) != 0 {
		return remoteLayout{}, errors.New("remote execution requires non-free-threaded CPython 3.14 final")
	}
	layout := remoteLayout{
		interpreters: word(5), mainThread: word(10),
		evalBreaker: word(debuggerWord), support: word(debuggerWord + 1),
		enabled: word(debuggerWord + 2), pending: word(debuggerWord + 3),
		path: word(debuggerWord + 4), pathSize: word(debuggerWord + 5),
	}
	within := func(size, offset, width uint64) bool {
		return size > 0 && size < 1<<30 && width <= size && offset <= size-width
	}
	threadSize := word(22)
	if !within(word(3), layout.interpreters, 8) ||
		!within(word(6), layout.mainThread, 8) || !within(word(6), layout.enabled, 4) ||
		!within(threadSize, layout.evalBreaker, 8) ||
		layout.pathSize == 0 || layout.pathSize > 4096 ||
		!within(threadSize, layout.support, 1) ||
		!within(threadSize-layout.support, layout.pending, 4) ||
		!within(threadSize-layout.support, layout.path, layout.pathSize) {
		return remoteLayout{}, errors.New("invalid CPython remote execution offsets")
	}
	return layout, nil
}

func readWord(mem io.ReaderAt, address uint64, width int) (uint64, error) {
	var data [8]byte
	if _, err := mem.ReadAt(data[:width], int64(address)); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data[:]), nil
}

func requestExec(mem *os.File, runtimeAddress uint64, layout remoteLayout, path string) (bool, error) {
	if uint64(len(path)+1) > layout.pathSize || strings.ContainsRune(path, '\x00') {
		return false, errors.New("invalid remote execution script path")
	}
	interpreter, err := readWord(mem, runtimeAddress+layout.interpreters, 8)
	if err != nil {
		return false, err
	}
	if interpreter == 0 {
		return false, errors.New("no running Python interpreter")
	}
	enabled, err := readWord(mem, interpreter+layout.enabled, 4)
	if err != nil {
		return false, err
	}
	if enabled != 1 {
		return false, errors.New("CPython remote execution is disabled")
	}
	thread, err := readWord(mem, interpreter+layout.mainThread, 8)
	if err != nil {
		return false, err
	}
	if thread == 0 {
		return false, errors.New("no Python main thread")
	}
	support := thread + layout.support
	pending, err := readWord(mem, support+layout.pending, 4)
	if err != nil {
		return false, err
	}
	if pending != 0 {
		return false, errors.New("another CPython remote execution is pending")
	}
	if _, err = mem.WriteAt(append([]byte(path), 0), int64(support+layout.path)); err != nil {
		return false, err
	}
	var data [8]byte
	binary.LittleEndian.PutUint32(data[:], 1)
	if _, err = mem.WriteAt(data[:4], int64(support+layout.pending)); err != nil {
		return true, err
	}
	breaker, err := readWord(mem, thread+layout.evalBreaker, 8)
	if err != nil {
		return true, err
	}
	binary.LittleEndian.PutUint64(data[:], breaker|pleaseStopBit)
	_, err = mem.WriteAt(data[:], int64(thread+layout.evalBreaker))
	return true, err
}

func (i *Injector) attach(ctx context.Context, target InjectionTarget) error {
	mem, err := target.Process.Open("mem", unix.O_RDWR)
	if err != nil {
		return err
	}
	defer mem.Close()
	runtime, err := i.resolver.Resolve(ctx, target.PID(), target.StartTime)
	if err != nil {
		return err
	}
	defer runtime.Close()
	layout, err := readRemoteLayout(mem, runtime.RuntimeAddress)
	if err != nil {
		return err
	}
	layout.interpreters = runtime.RuntimeInterpretersMain
	tmp, err := target.Process.Open("root/tmp", unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer tmp.Close()
	uid, gid, err := processCredentials(target)
	if err != nil {
		return err
	}
	name := fmt.Sprintf(".obi-python-%x", rand.Text())
	if err := unix.Mkdirat(int(tmp.Fd()), name, 0o700); err != nil {
		return err
	}
	fd, err := unix.Openat(int(tmp.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), name)
	defer directory.Close()
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Unlinkat(fd, "agent.py", 0)
			_ = unix.Unlinkat(fd, "result", 0)
			_ = unix.Unlinkat(int(tmp.Fd()), name, unix.AT_REMOVEDIR)
		}
	}()
	if err := directory.Chown(uid, gid); err != nil {
		return err
	}
	scriptFD, err := unix.Openat(fd, "agent.py", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return err
	}
	script := os.NewFile(uintptr(scriptFD), "agent.py")
	path := "/tmp/" + name + "/agent.py"
	source := fmt.Sprintf("import os\n_scope = {'__name__': '_obi_grpc'}\ntry:\n    exec(%s, _scope)\n    _result = 'ready' if _scope['install']() else 'grpc is not imported'\nexcept Exception as _error:\n    _result = str(_error)\nwith open(%s, 'w') as _file:\n    _file.write(_result)\n", strconv.Quote(agent), strconv.Quote("/tmp/"+name+"/result"))
	_, writeErr := script.WriteString(source)
	closeErr := script.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err := target.Process.Alive(); err != nil {
		return err
	}
	// Once published, retain the script until the interpreter acknowledges it.
	// A main thread blocked in native code may execute it after our deadline.
	if err := ctx.Err(); err != nil {
		return err
	}
	published, err := requestExec(mem, runtime.RuntimeAddress, layout, path)
	cleanup = !published
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		resultFD, openErr := unix.Openat(fd, "result", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if openErr == nil {
			resultFile := os.NewFile(uintptr(resultFD), "result")
			result, readErr := io.ReadAll(io.LimitReader(resultFile, 1024))
			_ = resultFile.Close()
			if readErr != nil {
				return readErr
			}
			if len(result) > 0 {
				cleanup = true
				if string(result) == "ready" {
					return nil
				}
				return fmt.Errorf("python agent: %s", result)
			}
		} else if !errors.Is(openErr, unix.ENOENT) {
			return openErr
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("python agent acknowledgement at %s: %w", path, ctx.Err())
		case <-ticker.C:
			if err := target.Process.Alive(); err != nil {
				cleanup = true
				return err
			}
		}
	}
}

func processCredentials(target InjectionTarget) (int, int, error) {
	status, err := target.Process.Open("status", unix.O_RDONLY)
	if err != nil {
		return 0, 0, err
	}
	defer status.Close()
	data, err := io.ReadAll(status)
	if err != nil {
		return 0, 0, err
	}
	uid, gid := -1, -1
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && (fields[0] == "Uid:" || fields[0] == "Gid:") {
			value, err := strconv.Atoi(fields[2])
			if err != nil {
				return 0, 0, err
			}
			if fields[0] == "Uid:" {
				uid = value
			} else {
				gid = value
			}
		}
	}
	if uid < 0 || gid < 0 {
		return 0, 0, errors.New("missing process credentials")
	}
	return uid, gid, nil
}
