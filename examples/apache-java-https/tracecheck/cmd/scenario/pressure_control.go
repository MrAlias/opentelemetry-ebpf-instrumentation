// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	pressureSignalReady       = "ready"
	pressureReleaseTraffic    = "release"
	pressureControlPollPeriod = 10 * time.Millisecond
	pressureControlFileMode   = 0o600
	pressureControlDirMode    = 0o700
)

type pressureControl struct {
	directory string
	session   string
	device    uint64
	inode     uint64
	owner     uint32
}

func newPressureControl(directory, session string) (*pressureControl, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, fmt.Errorf("pressure control directory must be a clean absolute path: %q", directory)
	}
	if !canonicalPressureSession(session) {
		return nil, errors.New("pressure control session must be 32 lowercase hexadecimal characters")
	}
	metadata, err := openPressureControlDirectory(directory)
	if err != nil {
		return nil, err
	}
	if metadata.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("pressure control directory owner does not match the scenario user")
	}
	return &pressureControl{
		directory: directory,
		session:   session,
		device:    uint64(metadata.Dev),
		inode:     metadata.Ino,
		owner:     metadata.Uid,
	}, nil
}

func canonicalPressureSession(session string) bool {
	if len(session) != 32 {
		return false
	}
	decoded, err := hex.DecodeString(session)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == session
}

func (control *pressureControl) awaitRelease(ctx context.Context) error {
	if err := control.publish(pressureSignalReady); err != nil {
		return err
	}
	ticker := time.NewTicker(pressureControlPollPeriod)
	defer ticker.Stop()
	for {
		ready, err := control.fileReady(pressureReleaseTraffic, nil)
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for pressure release: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func (control *pressureControl) publish(name string) error {
	if name != pressureSignalReady {
		return fmt.Errorf("invalid pressure control signal %q", name)
	}
	directoryDescriptor, err := control.openDirectory()
	if err != nil {
		return err
	}
	defer syscall.Close(directoryDescriptor)

	randomSuffix := make([]byte, 16)
	if _, err := rand.Read(randomSuffix); err != nil {
		return fmt.Errorf("create pressure signal nonce: %w", err)
	}
	temporaryName := "." + name + "." + hex.EncodeToString(randomSuffix)
	descriptor, err := syscall.Openat(
		directoryDescriptor,
		temporaryName,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		pressureControlFileMode,
	)
	if err != nil {
		return fmt.Errorf("create pressure signal %s: %w", name, err)
	}
	file := os.NewFile(uintptr(descriptor), temporaryName)
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = unix.Unlinkat(directoryDescriptor, temporaryName, 0)
		}
	}()

	payload := pressureControlPayload(name, control.session)
	if _, err := io.WriteString(file, payload); err != nil {
		_ = file.Close()
		return fmt.Errorf("write pressure signal %s: %w", name, err)
	}
	if err := file.Chmod(pressureControlFileMode); err != nil {
		_ = file.Close()
		return fmt.Errorf("set pressure signal permissions %s: %w", name, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync pressure signal %s: %w", name, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close pressure signal %s: %w", name, err)
	}
	if err := unix.Renameat2(
		directoryDescriptor,
		temporaryName,
		directoryDescriptor,
		name,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return fmt.Errorf("publish pressure signal %s: %w", name, err)
	}
	removeTemporary = false
	if err := syscall.Fsync(directoryDescriptor); err != nil {
		return fmt.Errorf("sync pressure control directory: %w", err)
	}
	ready, err := control.fileReady(name, nil)
	if err != nil {
		return err
	}
	if !ready {
		return fmt.Errorf("published pressure signal %s is not present", name)
	}
	return nil
}

// fileReady opens the leaf relative to a freshly authenticated directory
// descriptor, then binds metadata and bytes to that descriptor. The optional
// hook exists only so tests can deterministically exercise a path replacement
// between the read and final path-identity check.
func (control *pressureControl) fileReady(name string, beforeFinalPathCheck func()) (bool, error) {
	if name != pressureSignalReady && name != pressureReleaseTraffic {
		return false, fmt.Errorf("invalid pressure control file %q", name)
	}
	if !canonicalPressureSession(control.session) {
		return false, errors.New("invalid pressure control session")
	}
	directoryDescriptor, err := control.openDirectory()
	if err != nil {
		return false, err
	}
	defer syscall.Close(directoryDescriptor)

	descriptor, err := syscall.Openat(
		directoryDescriptor,
		name,
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0,
	)
	if errors.Is(err, syscall.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open pressure control file %s: %w", name, err)
	}
	file := os.NewFile(uintptr(descriptor), name)
	defer file.Close()

	expected := pressureControlPayload(name, control.session)
	var before syscall.Stat_t
	if err := syscall.Fstat(descriptor, &before); err != nil {
		return false, fmt.Errorf("inspect pressure control file %s: %w", name, err)
	}
	if before.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		before.Mode&0o7777 != pressureControlFileMode ||
		uint64(before.Dev) != control.device || before.Uid != control.owner ||
		before.Nlink != 1 || before.Size != int64(len(expected)) {
		return false, fmt.Errorf("pressure control file %s has invalid metadata", name)
	}
	contents, err := io.ReadAll(io.LimitReader(file, int64(len(expected)+1)))
	if err != nil {
		return false, fmt.Errorf("read pressure control file %s: %w", name, err)
	}
	if string(contents) != expected {
		return false, fmt.Errorf("pressure control file %s has invalid contents", name)
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(descriptor, &after); err != nil || !samePressureControlFile(before, after) {
		return false, fmt.Errorf("pressure control file %s changed while read", name)
	}
	if beforeFinalPathCheck != nil {
		beforeFinalPathCheck()
	}
	var pathMetadata unix.Stat_t
	if err := unix.Fstatat(directoryDescriptor, name, &pathMetadata, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		uint64(pathMetadata.Dev) != uint64(before.Dev) || pathMetadata.Ino != before.Ino ||
		pathMetadata.Mode&syscall.S_IFMT != syscall.S_IFREG || pathMetadata.Nlink != 1 {
		return false, fmt.Errorf("pressure control file %s path identity changed", name)
	}
	if err := control.validateOpenDirectory(directoryDescriptor); err != nil {
		return false, err
	}
	return true, nil
}

func (control *pressureControl) openDirectory() (int, error) {
	descriptor, err := syscall.Open(
		control.directory,
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY,
		0,
	)
	if err != nil {
		return -1, fmt.Errorf("open pressure control directory: %w", err)
	}
	if err := control.validateOpenDirectory(descriptor); err != nil {
		_ = syscall.Close(descriptor)
		return -1, err
	}
	return descriptor, nil
}

func (control *pressureControl) validateOpenDirectory(descriptor int) error {
	var metadata syscall.Stat_t
	if err := syscall.Fstat(descriptor, &metadata); err != nil {
		return fmt.Errorf("inspect pressure control directory: %w", err)
	}
	if metadata.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		metadata.Mode&0o7777 != pressureControlDirMode ||
		uint64(metadata.Dev) != control.device || metadata.Ino != control.inode ||
		metadata.Uid != control.owner {
		return errors.New("pressure control directory identity changed")
	}
	return nil
}

func openPressureControlDirectory(path string) (syscall.Stat_t, error) {
	descriptor, err := syscall.Open(
		path,
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY,
		0,
	)
	if err != nil {
		return syscall.Stat_t{}, fmt.Errorf("open pressure control directory: %w", err)
	}
	defer syscall.Close(descriptor)
	var metadata syscall.Stat_t
	if err := syscall.Fstat(descriptor, &metadata); err != nil {
		return syscall.Stat_t{}, fmt.Errorf("inspect pressure control directory: %w", err)
	}
	if metadata.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		metadata.Mode&0o7777 != pressureControlDirMode {
		return syscall.Stat_t{}, errors.New("pressure control directory is not private")
	}
	return metadata, nil
}

func samePressureControlFile(first, second syscall.Stat_t) bool {
	return first.Dev == second.Dev && first.Ino == second.Ino &&
		first.Mode == second.Mode && first.Uid == second.Uid &&
		first.Gid == second.Gid && first.Nlink == second.Nlink &&
		first.Size == second.Size
}

func pressureControlPayload(name, session string) string {
	switch name {
	case pressureSignalReady:
		return "pressure-ready-v1:" + session + "\n"
	case pressureReleaseTraffic:
		return "pressure-release-v1:" + session + "\n"
	default:
		return ""
	}
}
