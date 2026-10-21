// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package agent

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	cpythonruntime "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"
)

func TestInjectLivePython(t *testing.T) {
	if os.Getenv("OBI_TEST_PYTHON_AGENT") != "1" {
		t.Skip("requires ptrace and a Python interpreter; set OBI_TEST_PYTHON_AGENT=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-u", "-c", `
import asyncio, signal, sys, types
async def send(*args): pass
class Client:
    _send_single_request = send
class Connection:
    _send_request_headers = send
sys.modules["httpx"] = types.SimpleNamespace(AsyncClient=Client)
sys.modules["httpcore._async.http11"] = types.SimpleNamespace(AsyncHTTP11Connection=Connection)
sys.modules["httpcore._models"] = types.SimpleNamespace()
async def main():
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
    print("ready")
    while not getattr(Client._send_single_request, "__obi_httpx__", False):
        await asyncio.sleep(.01)
    print("installed")
    assert signal.pthread_sigmask(signal.SIG_BLOCK, []) == mask
    while True:
        await asyncio.sleep(.01)
asyncio.run(main())
`)
	output, err := command.StdoutPipe()
	require.NoError(t, err)
	command.Stderr = os.Stderr
	require.NoError(t, command.Start())
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	scanner := bufio.NewScanner(output)
	require.True(t, scanner.Scan())
	require.Equal(t, "ready", scanner.Text())
	pid := app.PID(command.Process.Pid)
	start, err := cpythonruntime.ProcessStartTime(pid)
	require.NoError(t, err)
	require.NoError(t, Inject(ctx, pid, start))
	require.True(t, scanner.Scan())
	require.Equal(t, "installed", scanner.Text())
	require.NoError(t, Inject(ctx, pid, start))
}

func TestInjectRejectsReplacedProcess(t *testing.T) {
	pid := app.PID(os.Getpid())
	start, err := cpythonruntime.ProcessStartTime(pid)
	require.NoError(t, err)
	require.Error(t, Inject(t.Context(), pid, start+1))
}

func TestInjectBusyPythonCancellation(t *testing.T) {
	if os.Getenv("OBI_TEST_PYTHON_AGENT") != "1" {
		t.Skip("requires ptrace and a Python interpreter; set OBI_TEST_PYTHON_AGENT=1")
	}
	command := exec.CommandContext(t.Context(), "python3", "-u", "-c", "print('ready')\nwhile True: pass")
	output, err := command.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, command.Start())
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	scanner := bufio.NewScanner(output)
	require.True(t, scanner.Scan())
	pid := app.PID(command.Process.Pid)
	start, err := cpythonruntime.ProcessStartTime(pid)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	err = Inject(ctx, pid, start)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	require.NoError(t, err)
	require.Contains(t, string(status), "TracerPid:\t0\n")
}
