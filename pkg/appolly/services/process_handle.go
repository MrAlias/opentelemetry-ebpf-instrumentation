// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services // import "go.opentelemetry.io/obi/pkg/appolly/services"

import (
	"errors"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
)

var nextProcessInstanceID atomic.Uint64

// NewProcessInstanceID returns a nonzero identifier for one discovery
// admission lifetime. The identifier follows ProcessInfo through executable
// inspection so a delayed deletion cannot be confused with a later admission
// of the same numeric PID, even when the kernel start tick collides.
func NewProcessInstanceID() uint64 {
	for {
		if id := nextProcessInstanceID.Add(1); id != 0 {
			return id
		}
	}
}

// ProcessHandle is a single-owner handoff for a stable process-directory file.
// The wrapper makes ProcessInfo copies safe: every alias observes the same
// take-or-close decision.
type ProcessHandle struct {
	mu   sync.Mutex
	file *os.File
}

func NewProcessHandle(file *os.File) *ProcessHandle {
	if file == nil {
		return nil
	}
	handle := &ProcessHandle{file: file}
	runtime.SetFinalizer(handle, func(handle *ProcessHandle) {
		_ = handle.Close()
	})
	return handle
}

func (handle *ProcessHandle) TakeFile() (*os.File, error) {
	if handle == nil {
		return nil, errors.New("stable process handle is unavailable")
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.file == nil {
		return nil, errors.New("stable process handle was already consumed")
	}
	file := handle.file
	handle.file = nil
	runtime.SetFinalizer(handle, nil)
	return file, nil
}

func (handle *ProcessHandle) Close() error {
	if handle == nil {
		return nil
	}
	handle.mu.Lock()
	file := handle.file
	handle.file = nil
	handle.mu.Unlock()
	runtime.SetFinalizer(handle, nil)
	if file == nil {
		return nil
	}
	return file.Close()
}

func (process *ProcessInfo) TakeProcessHandle() (*os.File, error) {
	if process == nil {
		return nil, errors.New("process information is nil")
	}
	return process.ProcessHandle.TakeFile()
}

func (process *ProcessInfo) CloseProcessHandle() error {
	if process == nil {
		return nil
	}
	return process.ProcessHandle.Close()
}
