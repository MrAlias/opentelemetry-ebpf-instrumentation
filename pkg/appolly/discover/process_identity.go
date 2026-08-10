// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"errors"
	"os"
	"runtime"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

// processIdentityState owns one stable process-directory descriptor. Leases let
// the watcher, metadata cache, and one in-flight discovery event share that
// descriptor without treating ordinary ProcessAttrs value copies as additional
// owners.
type processIdentityState struct {
	mu     sync.RWMutex
	handle *os.File
	refs   uint64

	pid    app.PID
	start  uint64
	device uint64
	inode  uint64
}

// processIdentityLease is one independently releasable reference. Copying a
// ProcessAttrs value copies the lease pointer and therefore remains one logical
// owner; code that stores or emits an independent copy must call retain.
type processIdentityLease struct {
	mu    sync.Mutex
	state *processIdentityState
}

func newProcessIdentityLease(
	handle *os.File,
	pid app.PID,
	start, device, inode uint64,
) *processIdentityLease {
	lease := &processIdentityLease{state: &processIdentityState{
		handle: handle,
		refs:   1,
		pid:    pid,
		start:  start,
		device: device,
		inode:  inode,
	}}
	runtime.SetFinalizer(lease, func(lease *processIdentityLease) {
		_ = lease.close()
	})
	return lease
}

func (lease *processIdentityLease) retain() *processIdentityLease {
	if lease == nil {
		return nil
	}
	lease.mu.Lock()
	state := lease.state
	if state != nil {
		current := state
		current.mu.Lock()
		if current.handle == nil {
			state = nil
		} else {
			current.refs++
		}
		current.mu.Unlock()
	}
	lease.mu.Unlock()
	if state == nil {
		return nil
	}
	retained := &processIdentityLease{state: state}
	runtime.SetFinalizer(retained, func(retained *processIdentityLease) {
		_ = retained.close()
	})
	return retained
}

func (lease *processIdentityLease) close() error {
	if lease == nil {
		return nil
	}
	lease.mu.Lock()
	state := lease.state
	lease.state = nil
	lease.mu.Unlock()
	runtime.SetFinalizer(lease, nil)
	if state == nil {
		return nil
	}

	state.mu.Lock()
	if state.refs == 0 {
		state.mu.Unlock()
		return errors.New("stable process identity reference count underflow")
	}
	state.refs--
	var handle *os.File
	if state.refs == 0 {
		handle = state.handle
		state.handle = nil
	}
	state.mu.Unlock()
	if handle == nil {
		return nil
	}
	return handle.Close()
}

func (lease *processIdentityLease) duplicateFile() (*os.File, error) {
	var duplicate *os.File
	err := lease.useFile(func(fd int) error {
		var err error
		duplicate, err = duplicateProcessHandleFD(uintptr(fd))
		return err
	})
	return duplicate, err
}

func (lease *processIdentityLease) useFile(use func(int) error) error {
	if lease == nil {
		return errors.New("stable process identity is unavailable")
	}
	if use == nil {
		return errors.New("stable process identity callback is nil")
	}
	lease.mu.Lock()
	state := lease.state
	if state == nil {
		lease.mu.Unlock()
		return errors.New("stable process identity is closed")
	}
	state.mu.RLock()
	lease.mu.Unlock()
	defer state.mu.RUnlock()
	if state.handle == nil {
		return errors.New("stable process identity is closed")
	}
	return use(int(state.handle.Fd()))
}

func (lease *processIdentityLease) metadata() (
	pid app.PID,
	start, device, inode uint64,
	ok bool,
) {
	if lease == nil {
		return 0, 0, 0, 0, false
	}
	lease.mu.Lock()
	state := lease.state
	lease.mu.Unlock()
	if state == nil {
		return 0, 0, 0, 0, false
	}
	return state.pid, state.start, state.device, state.inode, true
}

func sameProcessIdentity(left, right *processIdentityLease) bool {
	leftPID, leftStart, leftDevice, leftInode, leftOK := left.metadata()
	rightPID, rightStart, rightDevice, rightInode, rightOK := right.metadata()
	if !leftOK || !rightOK || leftPID != rightPID {
		return false
	}
	// Linux proc-directory inodes identify the particular procfs inode opened
	// for this process, unlike the clock-tick start token which can collide.
	if leftDevice != 0 && leftInode != 0 && rightDevice != 0 && rightInode != 0 {
		return leftDevice == rightDevice && leftInode == rightInode
	}
	return leftStart != 0 && leftStart == rightStart
}

func (attrs *ProcessAttrs) closeProcessIdentity() error {
	if attrs == nil {
		return nil
	}
	identity := attrs.processIdentity
	attrs.processIdentity = nil
	return identity.close()
}

func (attrs ProcessAttrs) retainProcessIdentity() (ProcessAttrs, bool) {
	if attrs.processIdentity == nil {
		return attrs, true
	}
	retained := attrs.processIdentity.retain()
	if retained == nil {
		return ProcessAttrs{}, false
	}
	attrs.processIdentity = retained
	return attrs, true
}

func (attrs ProcessAttrs) withoutProcessIdentity() ProcessAttrs {
	attrs.processIdentity = nil
	return attrs
}
