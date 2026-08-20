// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPressureSession = "00112233445566778899aabbccddeeff"

func TestPressureControlCoordinatesOneShotRelease(t *testing.T) {
	control, err := newPressureControl(pressureControlTestDirectory(t), testPressureSession)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)

	go func() {
		done <- control.awaitRelease(ctx)
	}()

	requirePressureControlFile(t, control.directory, pressureSignalReady)
	select {
	case err := <-done:
		t.Fatalf("pressure control returned before release: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	publishPressureReleaseForTest(t, control.directory, testPressureSession)
	require.NoError(t, <-done)

	readyInfo, err := os.Stat(filepath.Join(control.directory, pressureSignalReady))
	require.NoError(t, err)
	stat, ok := readyInfo.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	assert.Equal(t, uint32(os.Geteuid()), stat.Uid)
}

func TestPressureControlWaitHonorsContextCancellation(t *testing.T) {
	control, err := newPressureControl(pressureControlTestDirectory(t), testPressureSession)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = control.awaitRelease(ctx)

	require.ErrorIs(t, err, context.Canceled)
	requirePressureControlFile(t, control.directory, pressureSignalReady)
}

func TestPressureControlRejectsMalformedOrSymlinkRelease(t *testing.T) {
	for _, test := range []struct {
		name  string
		write func(*testing.T, string)
		want  string
	}{
		{
			name: "malformed",
			write: func(t *testing.T, directory string) {
				require.NoError(t, os.WriteFile(
					filepath.Join(directory, pressureReleaseTraffic),
					[]byte("wrong\n"),
					0o600,
				))
			},
			want: "invalid metadata",
		},
		{
			name: "wrong mode",
			write: func(t *testing.T, directory string) {
				require.NoError(t, os.WriteFile(
					filepath.Join(directory, pressureReleaseTraffic),
					[]byte(pressureControlPayload(pressureReleaseTraffic, testPressureSession)),
					0o644,
				))
			},
			want: "invalid metadata",
		},
		{
			name: "symlink",
			write: func(t *testing.T, directory string) {
				target := filepath.Join(directory, "target")
				require.NoError(t, os.WriteFile(
					target,
					[]byte(pressureControlPayload(pressureReleaseTraffic, testPressureSession)),
					0o600,
				))
				require.NoError(t, os.Symlink(target, filepath.Join(directory, pressureReleaseTraffic)))
			},
			want: "open pressure control file release",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := pressureControlTestDirectory(t)
			control, err := newPressureControl(directory, testPressureSession)
			require.NoError(t, err)
			test.write(t, directory)

			err = control.awaitRelease(context.Background())

			require.ErrorContains(t, err, test.want)
		})
	}
}

func TestPressureControlRejectsHardLinkedRelease(t *testing.T) {
	directory := pressureControlTestDirectory(t)
	control, err := newPressureControl(directory, testPressureSession)
	require.NoError(t, err)
	publishPressureReleaseForTest(t, directory, testPressureSession)
	require.NoError(t, os.Link(
		filepath.Join(directory, pressureReleaseTraffic),
		filepath.Join(directory, "release-alias"),
	))

	ready, err := control.fileReady(pressureReleaseTraffic, nil)

	assert.False(t, ready)
	require.ErrorContains(t, err, "invalid metadata")
}

func TestPressureControlRejectsReleasePathReplacement(t *testing.T) {
	directory := pressureControlTestDirectory(t)
	control, err := newPressureControl(directory, testPressureSession)
	require.NoError(t, err)
	publishPressureReleaseForTest(t, directory, testPressureSession)
	replacement := filepath.Join(directory, "replacement")
	require.NoError(t, os.WriteFile(
		replacement,
		[]byte(pressureControlPayload(pressureReleaseTraffic, testPressureSession)),
		0o600,
	))

	ready, err := control.fileReady(pressureReleaseTraffic, func() {
		require.NoError(t, os.Rename(
			filepath.Join(directory, pressureReleaseTraffic),
			filepath.Join(directory, "original"),
		))
		require.NoError(t, os.Rename(replacement, filepath.Join(directory, pressureReleaseTraffic)))
	})

	assert.False(t, ready)
	require.ErrorContains(t, err, "path identity changed")
}

func TestPressureControlRejectsDirectoryReplacement(t *testing.T) {
	parent := t.TempDir()
	directory := filepath.Join(parent, "control")
	require.NoError(t, os.Mkdir(directory, 0o700))
	control, err := newPressureControl(directory, testPressureSession)
	require.NoError(t, err)
	require.NoError(t, os.Rename(directory, filepath.Join(parent, "original")))
	require.NoError(t, os.Mkdir(directory, 0o700))

	ready, err := control.fileReady(pressureReleaseTraffic, nil)

	assert.False(t, ready)
	require.ErrorContains(t, err, "identity changed")
}

func TestPressureControlReadyPublicationDoesNotReplaceExistingFile(t *testing.T) {
	control, err := newPressureControl(pressureControlTestDirectory(t), testPressureSession)
	require.NoError(t, err)
	require.NoError(t, control.publish(pressureSignalReady))

	err = control.publish(pressureSignalReady)

	require.Error(t, err)
	requirePressureControlFile(t, control.directory, pressureSignalReady)
}

func TestPressureControlRejectsUnsafeConfiguration(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o755))
	_, err := newPressureControl(directory, testPressureSession)
	require.ErrorContains(t, err, "not private")

	require.NoError(t, os.Chmod(directory, 0o700))
	_, err = newPressureControl(directory, "ABCDEF")
	require.ErrorContains(t, err, "32 lowercase hexadecimal")

	link := filepath.Join(t.TempDir(), "control")
	require.NoError(t, os.Symlink(directory, link))
	_, err = newPressureControl(link, testPressureSession)
	require.ErrorContains(t, err, "open pressure control directory")
}

func publishPressureReleaseForTest(t *testing.T, directory, session string) {
	t.Helper()
	temporary, err := os.CreateTemp(directory, ".release.")
	require.NoError(t, err)
	temporaryName := temporary.Name()
	t.Cleanup(func() { _ = os.Remove(temporaryName) })
	_, err = temporary.WriteString(pressureControlPayload(pressureReleaseTraffic, session))
	require.NoError(t, err)
	require.NoError(t, temporary.Chmod(0o600))
	require.NoError(t, temporary.Close())
	require.NoError(t, os.Link(temporaryName, filepath.Join(directory, pressureReleaseTraffic)))
	require.NoError(t, os.Remove(temporaryName))
}

func requirePressureControlFile(t *testing.T, directory, name string) {
	t.Helper()
	path := filepath.Join(directory, name)
	control, err := newPressureControl(directory, testPressureSession)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		ready, err := control.fileReady(name, nil)
		return ready && err == nil
	}, time.Second, 10*time.Millisecond)
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, pressureControlPayload(name, testPressureSession), string(contents))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestPressureControlDoesNotExposeHardLinkPublicationWindow(t *testing.T) {
	control, err := newPressureControl(pressureControlTestDirectory(t), testPressureSession)
	require.NoError(t, err)

	err = control.publish(pressureSignalReady)

	require.NoError(t, err)
	ready, err := control.fileReady(pressureSignalReady, nil)
	require.NoError(t, err)
	assert.True(t, ready)
	entries, err := os.ReadDir(control.directory)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, pressureSignalReady, entries[0].Name())
}

func TestPressureControlFileReadyRejectsInvalidName(t *testing.T) {
	control, err := newPressureControl(pressureControlTestDirectory(t), testPressureSession)
	require.NoError(t, err)

	ready, err := control.fileReady("../release", nil)

	assert.False(t, ready)
	require.ErrorContains(t, err, "invalid pressure control file")
}

func pressureControlTestDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, pressureControlDirMode))
	return directory
}
