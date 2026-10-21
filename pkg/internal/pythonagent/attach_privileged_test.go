// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64 && privileged_tests

package pythonagent

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// Exercise real interpreter scheduling and thread creation, without loading an
// agent from the application or importing an OpenTelemetry SDK.
func TestAttachRequestsSession(t *testing.T) {
	process, reader, _ := startPythonChild(t, `
import requests, threading, time

def work():
    return sum(range(10))

def churn():
    while True:
        thread = threading.Thread(target=work)
        thread.start()
        thread.join()
        time.sleep(0.01)

threading.Thread(target=churn, daemon=True).start()
print("ready", flush=True)
while not getattr(requests.Session.send, "_obi_requests_session", False):
    work()
    time.sleep(0.01)
print("installed", flush=True)
while True:
    work()
    time.sleep(0.01)
`)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	require.NoError(t, attach(ctx, process))
	require.True(t, reader.Scan(), "Python child exited before installation: %v", reader.Err())
	require.Equal(t, "installed", reader.Text())
	require.NoError(t, process.Alive())
}

const idlePythonChild = `
import select, sys
print("ready", flush=True)
while True:
    if select.select([sys.stdin], [], [], 0.05)[0]:
        print("pong:" + sys.stdin.readline().strip(), flush=True)
`

func TestAttachCancellationDetaches(t *testing.T) {
	process, output, input := startPythonChild(t, idlePythonChild)
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, attach(ctx, process), context.DeadlineExceeded)
	assertDetached(t, process)
	_, err := io.WriteString(input, "after-cancellation\n")
	require.NoError(t, err)
	require.True(t, output.Scan())
	require.Equal(t, "pong:after-cancellation", output.Text())
}

func TestAttachPreservesStoppedProcess(t *testing.T) {
	process, output, input := startPythonChild(t, idlePythonChild)
	require.NoError(t, process.SendSignal(unix.SIGSTOP))
	require.Eventually(t, func() bool {
		return pythonState(t, process) == "T"
	}, time.Second, time.Millisecond)
	require.ErrorContains(t, attach(t.Context(), process), "python process is stopped")
	assertDetached(t, process)
	require.Equal(t, "T", pythonState(t, process))
	require.NoError(t, process.SendSignal(unix.SIGCONT))
	_, err := io.WriteString(input, "after-resume\n")
	require.NoError(t, err)
	require.True(t, output.Scan())
	require.Equal(t, "pong:after-resume", output.Text())
}

func TestAttachForwardsApplicationSignal(t *testing.T) {
	process, output, _ := startPythonChild(t, `
import select, signal, sys
def received(number, frame):
    print("signal", flush=True)
signal.signal(signal.SIGUSR1, received)
print("ready", flush=True)
while True:
    select.select([sys.stdin], [], [], 0.05)
`)
	sent := make(chan error, 1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		sent <- process.SendSignal(unix.SIGUSR1)
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := attach(ctx, process); err != nil {
		require.ErrorIs(t, err, context.DeadlineExceeded)
	}
	require.NoError(t, <-sent)
	assertDetached(t, process)
	line := make(chan string, 1)
	go func() {
		if output.Scan() {
			line <- output.Text()
		} else {
			line <- ""
		}
	}()
	select {
	case message := <-line:
		require.Equal(t, "signal", message)
	case <-time.After(3 * time.Second):
		t.Fatal("application signal was not delivered")
	}
}

func pythonState(t *testing.T, process *procs.ProcessHandle) string {
	t.Helper()
	proc, err := procfs.NewProc(int(process.PID()))
	require.NoError(t, err)
	stat, err := proc.Stat()
	require.NoError(t, err)
	return stat.State
}

func assertDetached(t *testing.T, process *procs.ProcessHandle) {
	t.Helper()
	file, err := process.Open("status", os.O_RDONLY)
	require.NoError(t, err)
	defer file.Close()
	status, err := io.ReadAll(file)
	require.NoError(t, err)
	require.Contains(t, strings.Split(string(status), "\n"), "TracerPid:\t0")
}

func startPythonChild(t *testing.T, source string) (*procs.ProcessHandle, *bufio.Scanner, io.WriteCloser) {
	t.Helper()
	python := os.Getenv("OBI_PYTHON_TEST_EXECUTABLE")
	if python == "" {
		python = "python3"
	}
	child := exec.CommandContext(t.Context(), python, "-X", "faulthandler", "-u", "-c", source)
	input, err := child.StdinPipe()
	require.NoError(t, err)
	output, err := child.StdoutPipe()
	require.NoError(t, err)
	child.Stderr = os.Stderr
	require.NoError(t, child.Start())
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	reader := bufio.NewScanner(output)
	require.True(t, reader.Scan(), "Python child did not start: %v", reader.Err())
	require.Equal(t, "ready", reader.Text())
	proc, err := procfs.NewProc(child.Process.Pid)
	require.NoError(t, err)
	stat, err := proc.Stat()
	require.NoError(t, err)
	process, err := procs.OpenProcessHandle(app.PID(child.Process.Pid), stat.Starttime)
	require.NoError(t, err)
	t.Cleanup(func() { _ = process.Close() })
	return process, reader, input
}
