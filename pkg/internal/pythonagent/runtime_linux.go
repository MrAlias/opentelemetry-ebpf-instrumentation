// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package pythonagent // import "go.opentelemetry.io/obi/pkg/internal/pythonagent"

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/prometheus/procfs"

	cpython "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type attachmentRuntime struct {
	frame     uint64
	alternate uint64
	pending   uint64
	run       uint64
	dict      uint64
	decref    uint64
	clear     uint64
	fetch     uint64
	restore   uint64
	errno     uint64
	syscall   uint64
}

func resolveRuntime(process *procs.ProcessHandle) (attachmentRuntime, error) {
	mappings, err := procs.FindLibMaps(process.PID())
	if err != nil {
		return attachmentRuntime{}, err
	}
	candidates, err := cpython.RuntimeObjectCandidates(process.PID(), mappings)
	if err != nil {
		return attachmentRuntime{}, err
	}
	for _, mapping := range mappings {
		base := filepath.Base(mapping.Pathname)
		if mapping.Perms.Execute && (strings.HasPrefix(base, "libc.") || strings.HasPrefix(base, "ld-musl-")) {
			candidates = append(candidates, mapping)
		}
	}
	var result attachmentRuntime
	seen := map[[2]uint64]bool{}
	for _, mapping := range candidates {
		key := [2]uint64{mapping.Dev, mapping.Inode}
		if seen[key] {
			continue
		}
		seen[key] = true
		if err := inspectObject(process, mappings, mapping, &result); err != nil {
			return attachmentRuntime{}, err
		}
	}
	if result.frame == 0 || result.pending == 0 || result.run == 0 || result.dict == 0 ||
		result.decref == 0 || result.clear == 0 || result.fetch == 0 || result.restore == 0 ||
		result.errno == 0 || result.syscall == 0 {
		return attachmentRuntime{}, errors.New("CPython attachment entry points are unavailable")
	}
	return result, process.Alive()
}

func inspectObject(process *procs.ProcessHandle, mappings []*procfs.ProcMap, mapping *procfs.ProcMap, result *attachmentRuntime) error {
	path := fmt.Sprintf("map_files/%x-%x", mapping.StartAddr, mapping.EndAddr)
	object, err := process.Open(path, os.O_RDONLY)
	if err != nil {
		return fmt.Errorf("open mapped runtime: %w", err)
	}
	defer object.Close()
	file, err := elf.NewFile(object)
	if err != nil {
		return err
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Machine != elf.EM_X86_64 || file.Data != elf.ELFDATA2LSB {
		return errors.New("CPython attachment requires a native x86-64 ELF")
	}
	bias, err := procs.FindMappingLoadBias(mappings, file.Progs, mapping.Dev, mapping.Inode)
	if err != nil {
		return err
	}
	symbols, err := procs.FindExeSymbols(file,
		[]string{"_PyEval_EvalFrameDefault", "PyObject_Call", "Py_AddPendingCall", "PyRun_StringFlags", "PyDict_New", "Py_DecRef", "PyErr_Clear", "PyErr_Fetch", "PyErr_Restore", "__errno_location", "syscall"}, elf.STT_FUNC)
	if err != nil {
		return err
	}
	// Imported symbols also appear in the ELF function table. Only definitions
	// in this mapped object provide callable addresses.
	for name, symbol := range symbols {
		if symbol.Value == 0 || symbol.Len == 0 {
			delete(symbols, name)
		}
	}
	if frame, ok := symbols["_PyEval_EvalFrameDefault"]; ok {
		version, freeThreaded, versionErr := cpython.ReadVersion(file)
		minor := version >> 16 & 0xff
		if versionErr != nil {
			return versionErr
		}
		if version>>24 != 3 || minor < 9 || minor > 14 || freeThreaded || (version>>4)&0xf != 0xf {
			return fmt.Errorf("unsupported CPython attachment build: %#x, free-threaded=%t", version, freeThreaded)
		}
		if result.frame != 0 && result.frame != bias+frame.Value {
			return errors.New("multiple CPython runtimes are mapped")
		}
		result.frame = bias + frame.Value
		// The tail-call interpreter can inline its frame-entry wrapper. The
		// public object-call boundary also takes three integer arguments.
		if minor == 14 {
			call, found := symbols["PyObject_Call"]
			if !found {
				return errors.New("CPython object-call entry point is unavailable")
			}
			result.alternate = bias + call.Value
		}
		if symbol, found := symbols["Py_AddPendingCall"]; found {
			result.pending = bias + symbol.Value
		}
		if symbol, found := symbols["PyRun_StringFlags"]; found {
			result.run = bias + symbol.Value
		}
		if symbol, found := symbols["PyDict_New"]; found {
			result.dict = bias + symbol.Value
		}
		if symbol, found := symbols["Py_DecRef"]; found {
			result.decref = bias + symbol.Value
		}
		if symbol, found := symbols["PyErr_Clear"]; found {
			result.clear = bias + symbol.Value
		}
		if symbol, found := symbols["PyErr_Fetch"]; found {
			result.fetch = bias + symbol.Value
		}
		if symbol, found := symbols["PyErr_Restore"]; found {
			result.restore = bias + symbol.Value
		}
	}
	if symbol, ok := symbols["__errno_location"]; ok {
		result.errno = bias + symbol.Value
	}
	if symbol, ok := symbols["syscall"]; ok {
		if symbol.Len == 0 || symbol.Len > 256 {
			return errors.New("unrecognized libc syscall wrapper")
		}
		data := make([]byte, symbol.Len)
		if _, err := object.ReadAt(data, int64(symbol.Off)); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		offset, err := syscallInstruction(data)
		if err != nil {
			return err
		}
		result.syscall = bias + symbol.Value + uint64(offset)
	}
	return nil
}
