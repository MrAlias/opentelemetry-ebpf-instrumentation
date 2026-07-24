// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	restartSignalPreStopReady               = "pre-stop-ready"
	restartSignalStoppedTrafficComplete     = "stopped-traffic-complete"
	restartSignalPostRestartTrafficComplete = "post-restart-traffic-complete"
	restartReleaseOBIStopped                = "obi-stopped"
	restartReleaseOBIReady                  = "obi-ready"
	restartControlPollInterval              = 25 * time.Millisecond
)

type restartControl struct {
	directory string
}

func newRestartControl(directory string) (*restartControl, error) {
	if !filepath.IsAbs(directory) {
		return nil, fmt.Errorf("restart control directory must be absolute: %q", directory)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, fmt.Errorf("inspect restart control directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("restart control path is not a real directory: %s", directory)
	}
	return &restartControl{directory: directory}, nil
}

func (control *restartControl) checkpoint(ctx context.Context, signal, release string) error {
	if err := control.publish(signal); err != nil {
		return err
	}
	if err := control.wait(ctx, release); err != nil {
		return fmt.Errorf("wait for restart release %s: %w", release, err)
	}
	return nil
}

func (control *restartControl) publish(name string) error {
	if !validRestartControlName(name) {
		return fmt.Errorf("invalid restart control name %q", name)
	}
	target := filepath.Join(control.directory, name)
	temporary, err := os.CreateTemp(control.directory, "."+name+".")
	if err != nil {
		return fmt.Errorf("create restart signal %s: %w", name, err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)

	payload := []byte(name + "\n")
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write restart signal %s: %w", name, err)
	}
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set restart signal permissions %s: %w", name, err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync restart signal %s: %w", name, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close restart signal %s: %w", name, err)
	}
	if err := os.Link(temporaryName, target); err != nil {
		return fmt.Errorf("publish restart signal %s: %w", name, err)
	}
	return nil
}

func (control *restartControl) wait(ctx context.Context, name string) error {
	if !validRestartControlName(name) {
		return fmt.Errorf("invalid restart control name %q", name)
	}
	ticker := time.NewTicker(restartControlPollInterval)
	defer ticker.Stop()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		ready, err := restartControlFileReady(filepath.Join(control.directory, name), name)
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func restartControlFileReady(path, name string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect restart control file %s: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, fmt.Errorf("restart control file %s is not a regular file", name)
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read restart control file %s: %w", name, err)
	}
	if string(payload) != name+"\n" {
		return false, fmt.Errorf("restart control file %s has invalid contents", name)
	}
	return true, nil
}

func validRestartControlName(name string) bool {
	switch name {
	case restartSignalPreStopReady,
		restartSignalStoppedTrafficComplete,
		restartSignalPostRestartTrafficComplete,
		restartReleaseOBIStopped,
		restartReleaseOBIReady:
		return true
	default:
		return false
	}
}
