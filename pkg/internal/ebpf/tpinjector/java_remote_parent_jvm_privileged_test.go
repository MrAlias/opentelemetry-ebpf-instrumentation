// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/javabridge"
)

const (
	javaRemoteParentJVMProbeAgentEnv = "OBI_JAVA_REMOTE_PARENT_AGENT_JAR"
	javaRemoteParentJVMProbeClass    = "io.opentelemetry.obi.java.probe.RemoteParentPrimaryProbe"
	javaRemoteParentJVMProbeNonce    = uint64(1)
	javaRemoteParentJVMProbeTimeout  = 15 * time.Second

	javaRemoteParentJVMProbeTraceID      = "0102030405060708090a0b0c0d0e0f10"
	javaRemoteParentJVMProbeParentSpanID = "1112131415161718"
)

type javaRemoteParentJVMScenario struct {
	generation uint64
	name       string
	status     javabridge.Status
	stale      bool
	mutate     func(*BpfJavaRemoteParentJavaRemoteParentStateT)
}

type javaRemoteParentJVMProbeLog struct {
	mu     sync.Mutex
	output bytes.Buffer
}

func (log *javaRemoteParentJVMProbeLog) Write(value []byte) (int, error) {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.output.Write(value)
}

func (log *javaRemoteParentJVMProbeLog) String() string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.output.String()
}

// TestJavaRemoteParentPrimaryJVMFaults validates primary cgroup-sockopt delivery through the
// packaged JVM agent, JNI, and Java provider. It is VM-gated because it requires BPF privileges
// and a staged agent artifact.
func TestJavaRemoteParentPrimaryJVMFaults(t *testing.T) {
	agentPath, java := javaRemoteParentJVMProbeRuntime(t)
	requireJavaRemoteParentPrimarySockoptSupport(t)

	objects := loadJavaRemoteParentFixture(t)
	defer objects.Close()
	setJavaRemoteParentDataHookReadiness(t, objects.JavaRemoteParentDataHookReadiness, true)
	attachJavaRemoteParentFixture(t, &objects.BpfJavaRemoteParentPrograms)
	attachJavaRemoteParentSockopsFixture(t, objects.JavaRemoteParentSocketCookies)

	scenarios := []javaRemoteParentJVMScenario{
		{generation: 51, name: "valid", status: javabridge.StatusValid},
		{generation: 52, name: "stale", status: javabridge.StatusStale, stale: true},
		{
			generation: 53,
			name:       "version-mismatch",
			status:     javabridge.StatusVersionMismatch,
			mutate: func(state *BpfJavaRemoteParentJavaRemoteParentStateT) {
				state.Response.VersionLe = javabridge.Version + 1
			},
		},
		{
			generation: 54,
			name:       "malformed-trace-id",
			status:     javabridge.StatusMalformed,
			mutate: func(state *BpfJavaRemoteParentJavaRemoteParentStateT) {
				state.Response.TraceId = [16]uint8{}
			},
		},
		{
			generation: 55,
			name:       "malformed-parent-span-id",
			status:     javabridge.StatusMalformed,
			mutate: func(state *BpfJavaRemoteParentJavaRemoteParentStateT) {
				state.Response.SpanId = [8]uint8{}
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			runJavaRemoteParentJVMScenario(
				t,
				&objects.BpfJavaRemoteParentMaps,
				agentPath,
				java,
				scenario,
			)
		})
	}
}

func requireJavaRemoteParentPrimarySockoptSupport(t *testing.T) {
	t.Helper()

	if err := javabridge.HaveSockOpsNetnsCookie(); err != nil {
		t.Skipf("sockops network namespace cookies unsupported: %v", err)
	}
	if err := features.HaveProgramType(ebpf.CGroupSockopt); err != nil {
		t.Skipf("cgroup sockopt BPF programs unsupported: %v", err)
	}
	if err := features.HaveMapType(ebpf.SkStorage); err != nil {
		t.Skipf("BPF socket-local storage unsupported: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot remove the BPF memory lock limit: %v", err)
	}
}

func javaRemoteParentJVMProbeRuntime(t *testing.T) (string, string) {
	t.Helper()

	agentPath := os.Getenv(javaRemoteParentJVMProbeAgentEnv)
	if agentPath == "" {
		t.Skipf("set %s to run the primary JVM bridge fixture", javaRemoteParentJVMProbeAgentEnv)
	}
	agentPath, err := filepath.Abs(agentPath)
	require.NoError(t, err)
	info, err := os.Stat(agentPath)
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular(), "agent artifact must be a regular file")

	java, err := exec.LookPath("java")
	if err != nil {
		t.Skipf("Java runtime unavailable: %v", err)
	}
	return agentPath, java
}

func runJavaRemoteParentJVMScenario(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	agentPath string,
	java string,
	scenario javaRemoteParentJVMScenario,
) {
	t.Helper()

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), javaRemoteParentJVMProbeTimeout)
	defer cancel()

	capability := uint64(0x7f6e5d4c3b2a1908) + scenario.generation
	command := exec.CommandContext(
		ctx,
		"sh",
		"-c",
		`IFS= read -r _; exec "$@"`,
		"sh",
		java,
		"-javaagent:"+agentPath+"=remoteParentTransport=disabled",
		"-cp",
		agentPath,
		javaRemoteParentJVMProbeClass,
		"127.0.0.1",
		strconv.Itoa(listener.Addr().(*net.TCPAddr).Port),
		strconv.FormatUint(capability, 10),
	)
	stdin, err := command.StdinPipe()
	require.NoError(t, err)
	stdout, err := command.StdoutPipe()
	require.NoError(t, err)
	var stderr javaRemoteParentJVMProbeLog
	command.Stderr = &stderr
	require.NoError(t, command.Start())
	waited := false
	defer func() {
		if waited {
			return
		}
		_ = stdin.Close()
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	}()

	process := javaRemoteParentProcessKey(t, command.Process.Pid)
	require.NoError(t, maps.JavaAuthorizedProcesses.Update(process, capability, ebpf.UpdateAny))
	require.NoError(t, maps.JavaProcessIncarnations.Update(process, capability, ebpf.UpdateAny))
	_, err = io.WriteString(stdin, "\n")
	require.NoError(t, err)

	lines := javaRemoteParentJVMProbeLines(stdout)
	ready := waitForJavaRemoteParentJVMProbe(t, ctx, lines, "READY", &stderr)
	tid := javaRemoteParentJVMProbeUint32(t, ready, "tid")
	javaSocketFD := javaRemoteParentJVMProbeInt(t, ready, "fd")
	require.GreaterOrEqual(t, javaSocketFD, 0)
	pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	require.NoError(t, err)
	defer unix.Close(pidfd)
	javaSocketDuplicate, err := unix.PidfdGetfd(pidfd, javaSocketFD, 0)
	require.NoError(t, err)
	defer unix.Close(javaSocketDuplicate)
	javaSocketCookie := socketCookie(t, javaSocketDuplicate)
	var seededSocketCookie uint64
	require.NoError(t, maps.JavaRemoteParentSocketCookies.Lookup(
		uint32(javaSocketDuplicate), &seededSocketCookie,
	))
	require.Equal(t, javaSocketCookie, seededSocketCookie)
	owner := process
	owner.Tid = tid

	connection, err := listener.AcceptTCP()
	require.NoError(t, err)
	defer connection.Close()
	connectionInfo := javaRemoteParentJVMConnectionInfo(t, connection)
	netns := currentNamespaceID(t, fmt.Sprintf("/proc/%d/ns/net", command.Process.Pid))

	observed := monotonicNowNS(t)
	if scenario.stale {
		const staleAge = 31 * time.Second
		require.Greater(t, observed, uint64(staleAge.Nanoseconds()))
		observed -= uint64(staleAge.Nanoseconds())
	}
	stageRemoteParentAt(
		t,
		maps,
		process,
		owner,
		capability,
		connectionInfo,
		netns,
		javaSocketCookie,
		scenario.generation,
		javaRemoteParentJVMProbeNonce,
		observed,
	)
	if scenario.mutate != nil {
		key := BpfJavaRemoteParentJavaRemoteParentKeyT{
			Owner:      owner,
			Generation: scenario.generation,
		}
		var state BpfJavaRemoteParentJavaRemoteParentStateT
		require.NoError(t, maps.JavaRemoteParentState.Lookup(key, &state))
		scenario.mutate(&state)
		require.NoError(t, maps.JavaRemoteParentState.Update(key, state, ebpf.UpdateExist))
	}

	_, err = io.WriteString(stdin, "GO\n")
	require.NoError(t, err)
	result := waitForJavaRemoteParentJVMProbe(t, ctx, lines, "RESULT", &stderr)
	require.Equal(t, "1", result["emit"])
	assert.Equal(t, scenario.status, javabridge.Status(javaRemoteParentJVMProbeInt(t, result, "status")))
	if scenario.status == javabridge.StatusValid {
		assert.Equal(t, javaRemoteParentJVMProbeTraceID, result["trace"])
		assert.Equal(t, javaRemoteParentJVMProbeParentSpanID, result["span"])
	} else {
		assert.Equal(t, "-", result["trace"])
		assert.Equal(t, "-", result["span"])
	}
	assert.Equal(t, "-1", result["fdAfter"])

	err = command.Wait()
	waited = true
	if ctx.Err() != nil {
		t.Fatalf("primary JVM bridge probe timed out: %s", stderr.String())
	}
	require.NoErrorf(t, err, "primary JVM bridge probe failed:\n%s", stderr.String())
	assertGenerationMissing(t, maps.JavaRemoteParentState, owner, scenario.generation)
	assertJavaRemoteParentJVMDataAckMissing(t, maps.JavaRemoteParentDataAcks, process)
}

func javaRemoteParentJVMProbeLines(output io.Reader) <-chan string {
	lines := make(chan string, 8)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()
	return lines
}

func waitForJavaRemoteParentJVMProbe(
	t *testing.T,
	ctx context.Context,
	lines <-chan string,
	prefix string,
	stderr *javaRemoteParentJVMProbeLog,
) map[string]string {
	t.Helper()

	for {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatalf("primary JVM bridge probe ended before %s: %s", prefix, stderr.String())
			}
			fields := strings.Fields(line)
			if len(fields) == 0 || fields[0] != prefix {
				continue
			}
			return javaRemoteParentJVMProbeFields(t, fields)
		case <-ctx.Done():
			t.Fatalf("timed out waiting for JVM bridge probe %s: %s", prefix, stderr.String())
		}
	}
}

func javaRemoteParentJVMProbeFields(t *testing.T, fields []string) map[string]string {
	t.Helper()

	values := make(map[string]string, len(fields)-1)
	for _, field := range fields[1:] {
		key, value, ok := strings.Cut(field, "=")
		require.Truef(t, ok && key != "" && value != "", "invalid probe field %q", field)
		_, duplicate := values[key]
		require.Falsef(t, duplicate, "duplicate probe field %q", key)
		values[key] = value
	}
	return values
}

func javaRemoteParentJVMProbeUint32(t *testing.T, values map[string]string, key string) uint32 {
	t.Helper()

	value, ok := values[key]
	require.Truef(t, ok, "missing probe field %q", key)
	parsed, err := strconv.ParseUint(value, 10, 32)
	require.NoErrorf(t, err, "invalid probe field %q", key)
	require.NotZero(t, parsed, "probe field %q must be nonzero", key)
	return uint32(parsed)
}

func javaRemoteParentJVMProbeInt(t *testing.T, values map[string]string, key string) int {
	t.Helper()

	value, ok := values[key]
	require.Truef(t, ok, "missing probe field %q", key)
	parsed, err := strconv.Atoi(value)
	require.NoErrorf(t, err, "invalid probe field %q", key)
	return parsed
}

func javaRemoteParentJVMConnectionInfo(
	t *testing.T,
	connection *net.TCPConn,
) BpfJavaRemoteParentConnectionInfoT {
	t.Helper()

	local, ok := connection.LocalAddr().(*net.TCPAddr)
	require.True(t, ok)
	remote, ok := connection.RemoteAddr().(*net.TCPAddr)
	require.True(t, ok)
	source := remote.IP.To4()
	destination := local.IP.To4()
	require.NotNil(t, source)
	require.NotNil(t, destination)

	info := BpfJavaRemoteParentConnectionInfoT{
		S_addr: javaRemoteParentJVMIPv4Mapped(source),
		D_addr: javaRemoteParentJVMIPv4Mapped(destination),
		S_port: uint16(remote.Port),
		D_port: uint16(local.Port),
	}
	if (!javaRemoteParentJVMEphemeral(info.S_port) && javaRemoteParentJVMEphemeral(info.D_port)) ||
		info.D_port > info.S_port {
		info.S_addr, info.D_addr = info.D_addr, info.S_addr
		info.S_port, info.D_port = info.D_port, info.S_port
	}
	return info
}

func javaRemoteParentJVMIPv4Mapped(address net.IP) [16]uint8 {
	return [16]uint8{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
		address[0], address[1], address[2], address[3],
	}
}

func javaRemoteParentJVMEphemeral(port uint16) bool {
	return port >= 32768
}

func assertJavaRemoteParentJVMDataAckMissing(
	t *testing.T,
	dataAcks *ebpf.Map,
	process BpfJavaRemoteParentPidKeyT,
) {
	t.Helper()

	key := BpfJavaRemoteParentJavaRemoteParentDataSignalKeyT{
		Process: process,
		Nonce:   javaRemoteParentJVMProbeNonce,
	}
	var acknowledgement BpfJavaRemoteParentJavaRemoteParentDataAckT
	assert.ErrorIs(t, dataAcks.Lookup(key, &acknowledgement), ebpf.ErrKeyNotExist)
}
