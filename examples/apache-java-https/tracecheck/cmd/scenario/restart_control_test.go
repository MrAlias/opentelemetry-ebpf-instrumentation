// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRestartControlCoordinatesTrafficPhases(t *testing.T) {
	control, err := newRestartControl(t.TempDir())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)

	go func() {
		if err := control.checkpoint(
			ctx,
			restartSignalPreStopReady,
			restartReleaseOBIStopped,
		); err != nil {
			done <- err
			return
		}
		if err := control.checkpoint(
			ctx,
			restartSignalStoppedTrafficComplete,
			restartReleaseOBIReady,
		); err != nil {
			done <- err
			return
		}
		done <- control.publish(restartSignalPostRestartTrafficComplete)
	}()

	requireControlFile(t, control.directory, restartSignalPreStopReady)
	require.NoError(t, control.publish(restartReleaseOBIStopped))
	requireControlFile(t, control.directory, restartSignalStoppedTrafficComplete)
	require.NoError(t, control.publish(restartReleaseOBIReady))
	require.NoError(t, <-done)
	requireControlFile(t, control.directory, restartSignalPostRestartTrafficComplete)
}

func TestRestartControlWaitHonorsContextCancellation(t *testing.T) {
	control, err := newRestartControl(t.TempDir())
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = control.checkpoint(ctx, restartSignalPreStopReady, restartReleaseOBIStopped)

	require.ErrorIs(t, err, context.Canceled)
	requireControlFile(t, control.directory, restartSignalPreStopReady)
}

func TestRestartControlRejectsMalformedRelease(t *testing.T) {
	directory := t.TempDir()
	control, err := newRestartControl(directory)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(
		filepath.Join(directory, restartReleaseOBIStopped),
		[]byte("wrong\n"),
		0o600,
	))

	err = control.wait(context.Background(), restartReleaseOBIStopped)

	require.ErrorContains(t, err, "invalid contents")
}

func TestRestartControlRejectsSymlinkRelease(t *testing.T) {
	directory := t.TempDir()
	control, err := newRestartControl(directory)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(directory, "target"), []byte("obi-stopped\n"), 0o600))
	require.NoError(t, os.Symlink("target", filepath.Join(directory, restartReleaseOBIStopped)))

	err = control.wait(context.Background(), restartReleaseOBIStopped)

	require.ErrorContains(t, err, "not a regular file")
}

func TestRestartControlPublishDoesNotReplaceExistingSignal(t *testing.T) {
	control, err := newRestartControl(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, control.publish(restartSignalPreStopReady))

	err = control.publish(restartSignalPreStopReady)

	require.Error(t, err)
	requireControlFile(t, control.directory, restartSignalPreStopReady)
}

func requireControlFile(t *testing.T, directory, name string) {
	t.Helper()
	path := filepath.Join(directory, name)
	require.Eventually(t, func() bool {
		ready, err := restartControlFileReady(path, name)
		return ready && err == nil
	}, time.Second, 10*time.Millisecond)
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, name+"\n", string(contents))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}
