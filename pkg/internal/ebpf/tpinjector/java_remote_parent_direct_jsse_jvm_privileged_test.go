// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/javabridge"
)

const (
	javaRemoteParentDirectJSSEProbeClass       = "io.opentelemetry.obi.java.probe.RemoteParentDirectSSLSocketProbe"
	javaRemoteParentDirectJSSEKeyStore         = "../../../../internal/test/integration/components/java_tls/jdk8/src/main/resources/server.p12"
	javaRemoteParentDirectJSSEKeyStorePassword = "1234567"
	javaRemoteParentDirectJSSEProtocol         = "TLSv1.2"
	javaRemoteParentDirectJSSERequest          = "GET /direct-jsse-bpf HTTP/1.1\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Connection: close\r\n\r\n"
	javaRemoteParentDirectJSSEGeneration        = uint64(61)
	javaRemoteParentDirectJSSENonce             = uint64(1)
	javaRemoteParentDirectJSSELifecycleConsumed = uint8(2)
	javaRemoteParentDirectJSSETimeout           = 20 * time.Second
)

// TestJavaRemoteParentPrimaryJVMDirectSSLSocket proves that a real, directly owned accepted
// SSLSocket application read reaches the packaged advice and JNI before consuming a cgroup BPF
// data acknowledgement and taking the staged remote parent. The generic HTTP parser is outside
// this fixture: it deliberately pre-stages the final BPF graph and ACK.
func TestJavaRemoteParentPrimaryJVMDirectSSLSocket(t *testing.T) {
	agentPath, java := javaRemoteParentJVMProbeRuntime(t)
	requireJavaRemoteParentPrimarySockoptSupport(t)
	keyStore := javaRemoteParentDirectJSSEKeyStorePath(t)

	objects := loadJavaRemoteParentFixture(t)
	defer objects.Close()
	setJavaRemoteParentDataHookReadiness(t, objects.JavaRemoteParentDataHookReadiness, true)
	attachJavaRemoteParentFixture(t, &objects.BpfJavaRemoteParentPrograms)
	attachJavaRemoteParentSockopsFixture(t, objects.JavaRemoteParentSocketCookies)

	runJavaRemoteParentDirectSSLSocketProbe(
		t,
		&objects.BpfJavaRemoteParentMaps,
		agentPath,
		java,
		keyStore,
	)
}

func javaRemoteParentDirectJSSEKeyStorePath(t *testing.T) string {
	t.Helper()

	path, err := filepath.Abs(javaRemoteParentDirectJSSEKeyStore)
	require.NoError(t, err)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular(), "direct JSSE key store must be a regular file")
	require.Positive(t, info.Size(), "direct JSSE key store must not be empty")
	return path
}

func runJavaRemoteParentDirectSSLSocketProbe(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	agentPath string,
	java string,
	keyStore string,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), javaRemoteParentDirectJSSETimeout)
	defer cancel()

	const capability = uint64(0x7f6e5d4c3b2a1961)
	agentOptions := fmt.Sprintf(
		"remoteParentTransport=getsockopt,remoteParentTimeoutMillis=1000,processCapability=%d",
		capability,
	)
	command := exec.CommandContext(
		ctx,
		"sh",
		"-c",
		`IFS= read -r _; exec "$@"`,
		"sh",
		java,
		"-javaagent:"+agentPath+"="+agentOptions,
		"-cp",
		agentPath,
		javaRemoteParentDirectJSSEProbeClass,
		javaRemoteParentDirectJSSEProtocol,
		keyStore,
		javaRemoteParentDirectJSSEKeyStorePassword,
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
	defer func() {
		_ = maps.JavaProcessIncarnations.Delete(process)
		_ = maps.JavaAuthorizedProcesses.Delete(process)
	}()
	_, err = io.WriteString(stdin, "\n")
	require.NoError(t, err)

	lines := javaRemoteParentJVMProbeLines(stdout)
	listen := waitForJavaRemoteParentJVMProbe(t, ctx, lines, "LISTEN", &stderr)
	require.Equal(t, javaRemoteParentDirectJSSEProtocol, listen["protocol"])
	require.Equal(
		t,
		strconv.Itoa(len(javaRemoteParentDirectJSSERequest)),
		listen["requestBytes"],
	)
	requestDigest := sha256.Sum256([]byte(javaRemoteParentDirectJSSERequest))
	require.Equal(t, hex.EncodeToString(requestDigest[:]), listen["requestSha256"])
	certificateDigest := javaRemoteParentDirectJSSEHexDigest(t, listen, "certSha256")
	port := javaRemoteParentJVMProbeInt(t, listen, "port")
	require.Greater(t, port, 0)
	require.LessOrEqual(t, port, 65535)

	rawConnection, err := net.DialTCP(
		"tcp4",
		nil,
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
	)
	require.NoError(t, err)
	defer rawConnection.Close()
	require.NoError(t, rawConnection.SetDeadline(time.Now().Add(javaRemoteParentDirectJSSETimeout)))
	tlsConnection := tls.Client(rawConnection, javaRemoteParentDirectJSSETLSConfig(certificateDigest))
	defer tlsConnection.Close()
	require.NoError(t, tlsConnection.HandshakeContext(ctx))
	require.Equal(t, uint16(tls.VersionTLS12), tlsConnection.ConnectionState().Version)

	ready := waitForJavaRemoteParentJVMProbe(t, ctx, lines, "READY", &stderr)
	tid := javaRemoteParentJVMProbeUint32(t, ready, "tid")
	javaSocketFD := javaRemoteParentJVMProbeInt(t, ready, "fd")
	require.GreaterOrEqual(t, javaSocketFD, 0)
	require.Equal(t, javaSocketFD, javaRemoteParentJVMProbeInt(t, ready, "directFd"))
	require.Equal(t, javaRemoteParentDirectJSSEProtocol, ready["protocol"])
	require.NotEmpty(t, ready["cipher"])

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
	assertSocketNegotiationMissing(t, maps.JavaRemoteParentNegotiations, javaSocketDuplicate)

	owner := process
	owner.Tid = tid
	connection := javaRemoteParentJVMConnectionInfo(t, rawConnection)
	netns := currentNamespaceID(t, fmt.Sprintf("/proc/%d/ns/net", command.Process.Pid))
	observed := monotonicNowNS(t)
	stageRemoteParentAt(
		t,
		maps,
		process,
		owner,
		capability,
		connection,
		netns,
		javaSocketCookie,
		javaRemoteParentDirectJSSEGeneration,
		javaRemoteParentDirectJSSENonce,
		observed,
	)
	javaRemoteParentDirectJSSEMoveSignalToOwner(t, maps, process, owner)
	javaRemoteParentDirectJSSEAssertStaged(
		t,
		maps,
		process,
		owner,
		capability,
		connection,
		netns,
		javaSocketCookie,
		observed,
	)

	_, err = io.WriteString(stdin, "READ\n")
	require.NoError(t, err)
	written, err := tlsConnection.Write([]byte(javaRemoteParentDirectJSSERequest))
	require.NoError(t, err)
	require.Equal(t, len(javaRemoteParentDirectJSSERequest), written)

	acknowledged := waitForJavaRemoteParentJVMProbe(t, ctx, lines, "ACK", &stderr)
	require.Equal(t, strconv.Itoa(javaSocketFD), acknowledged["fdBeforeTake"])
	require.Equal(t, "1", acknowledged["lookupSource"])
	require.Equal(
		t,
		strconv.Itoa(len(javaRemoteParentDirectJSSERequest)),
		acknowledged["bytes"],
	)
	reads := javaRemoteParentJVMProbeInt(t, acknowledged, "reads")
	require.Positive(t, reads)
	require.Equal(t, hex.EncodeToString(requestDigest[:]), acknowledged["requestSha256"])

	negotiation := socketNegotiation(t, maps.JavaRemoteParentNegotiations, javaSocketDuplicate)
	assert.Equal(t, process, negotiation.Process)
	assert.Equal(t, capability, negotiation.ProcessIncarnation)
	assert.Equal(t, connection, negotiation.Connection)
	assert.Equal(t, netns, negotiation.ConnectionNetns)
	assert.Equal(t, javaRemoteParentDirectJSSEGeneration, negotiation.Generation)
	javaRemoteParentDirectJSSEAssertDataAckMissing(t, maps.JavaRemoteParentDataAcks, process)
	javaRemoteParentDirectJSSEAssertSignalMissing(t, maps.JavaRemoteParentDataSignals, owner)
	javaRemoteParentDirectJSSEAssertActiveState(t, maps, owner, capability, connection, netns, observed)

	statsBeforeTake := javaRemoteParentStats(t, maps.JavaRemoteParentStats)
	_, err = io.WriteString(stdin, "TAKE\n")
	require.NoError(t, err)
	result := waitForJavaRemoteParentJVMProbe(t, ctx, lines, "RESULT", &stderr)
	assert.Equal(t, strconv.Itoa(int(javabridge.StatusValid)), result["status"])
	assert.Equal(t, "1", result["flags"])
	assert.Equal(t, javaRemoteParentJVMProbeTraceID, result["trace"])
	assert.Equal(t, javaRemoteParentJVMProbeParentSpanID, result["span"])
	assert.Equal(t, strconv.FormatUint(javaRemoteParentDirectJSSEGeneration, 10), result["generation"])
	assert.Equal(t, strconv.FormatUint(observed, 10), result["observed"])
	assert.Equal(t, "-1", result["fdAfter"])

	err = command.Wait()
	waited = true
	if ctx.Err() != nil {
		t.Fatalf("direct JSSE JVM bridge probe timed out: %s", stderr.String())
	}
	require.NoErrorf(t, err, "direct JSSE JVM bridge probe failed:\n%s", stderr.String())
	statsAfterTake := javaRemoteParentStats(t, maps.JavaRemoteParentStats)
	assert.Equal(
		t,
		statsBeforeTake[javaRemoteParentStatTakeValid]+1,
		statsAfterTake[javaRemoteParentStatTakeValid],
	)
	javaRemoteParentDirectJSSEAssertConsumed(
		t,
		maps,
		process,
		owner,
		capability,
		connection,
		netns,
		observed,
	)
}

func javaRemoteParentDirectJSSETLSConfig(certificateDigest [sha256.Size]byte) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // #nosec G402 -- VerifyConnection pins the local fixture certificate.
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return fmt.Errorf("expected one server certificate, got %d", len(state.PeerCertificates))
			}
			actual := sha256.Sum256(state.PeerCertificates[0].Raw)
			if actual != certificateDigest {
				return fmt.Errorf("server certificate fingerprint mismatch")
			}
			return nil
		},
	}
}

func javaRemoteParentDirectJSSEHexDigest(
	t *testing.T,
	values map[string]string,
	key string,
) [sha256.Size]byte {
	t.Helper()

	encoded, ok := values[key]
	require.Truef(t, ok, "missing probe field %q", key)
	decoded, err := hex.DecodeString(encoded)
	require.NoErrorf(t, err, "invalid probe field %q", key)
	require.Len(t, decoded, sha256.Size)
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	return digest
}

func javaRemoteParentDirectJSSEMoveSignalToOwner(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
) {
	t.Helper()

	if owner == process {
		return
	}
	var nonce uint64
	require.NoError(t, maps.JavaRemoteParentDataSignals.Lookup(process, &nonce))
	require.Equal(t, javaRemoteParentDirectJSSENonce, nonce)
	require.NoError(t, maps.JavaRemoteParentDataSignals.Delete(process))
	require.NoError(t, maps.JavaRemoteParentDataSignals.Update(owner, nonce, ebpf.UpdateNoExist))
}

func javaRemoteParentDirectJSSEAssertStaged(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	capability uint64,
	connection BpfJavaRemoteParentConnectionInfoT,
	netns uint32,
	socketCookie uint64,
	observed uint64,
) {
	t.Helper()

	javaRemoteParentDirectJSSEAssertActiveState(
		t, maps, owner, capability, connection, netns, observed,
	)
	var nonce uint64
	require.NoError(t, maps.JavaRemoteParentDataSignals.Lookup(owner, &nonce))
	require.Equal(t, javaRemoteParentDirectJSSENonce, nonce)
	key := BpfJavaRemoteParentJavaRemoteParentDataSignalKeyT{
		Process: process,
		Nonce:   javaRemoteParentDirectJSSENonce,
	}
	var acknowledgement BpfJavaRemoteParentJavaRemoteParentDataAckT
	require.NoError(t, maps.JavaRemoteParentDataAcks.Lookup(key, &acknowledgement))
	assert.Equal(t, owner, acknowledgement.Owner)
	assert.Equal(t, javaRemoteParentDirectJSSEGeneration, acknowledgement.Generation)
	assert.Equal(t, connection, acknowledgement.Connection)
	assert.Equal(t, netns, acknowledgement.ConnectionNetns)
	connectionKey := BpfJavaRemoteParentConnectionInfoNsT{
		Connection: connection,
		Netns:      netns,
	}
	var indexed BpfJavaRemoteParentJavaRemoteParentConnectionT
	require.NoError(t, maps.JavaRemoteParentConnections.Lookup(connectionKey, &indexed))
	assert.Equal(t, socketCookie, indexed.SocketCookie)
}

func javaRemoteParentDirectJSSEAssertActiveState(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	owner BpfJavaRemoteParentPidKeyT,
	capability uint64,
	connection BpfJavaRemoteParentConnectionInfoT,
	netns uint32,
	observed uint64,
) {
	t.Helper()

	key := BpfJavaRemoteParentJavaRemoteParentKeyT{
		Owner:      owner,
		Generation: javaRemoteParentDirectJSSEGeneration,
	}
	var state BpfJavaRemoteParentJavaRemoteParentStateT
	require.NoError(t, maps.JavaRemoteParentState.Lookup(key, &state))
	assert.Equal(t, bridgeLifecycleActive, state.Lifecycle)
	assert.Equal(t, observed, state.ObservedMonotimeNs)
	assert.Equal(t, connection, state.Connection)
	assert.Equal(t, netns, state.ConnectionNetns)
	assert.Equal(t, capability, state.ProcessIncarnation)
	assert.Equal(t, uint8(javabridge.StatusValid), state.Response.Status)
	assert.Equal(t, javaRemoteParentDirectJSSEGeneration, state.Response.GenerationLe)
	var indexedOwner BpfJavaRemoteParentJavaRemoteParentOwnerT
	require.NoError(t, maps.JavaRemoteParentOwners.Lookup(owner, &indexedOwner))
	assert.Equal(t, javaRemoteParentDirectJSSEGeneration, indexedOwner.Generation)
	assert.Equal(t, capability, indexedOwner.ProcessIncarnation)
	assert.Equal(t, bridgeLifecycleActive, indexedOwner.Lifecycle)
}

func javaRemoteParentDirectJSSEAssertSignalMissing(
	t *testing.T,
	signals *ebpf.Map,
	owner BpfJavaRemoteParentPidKeyT,
) {
	t.Helper()

	var nonce uint64
	assert.ErrorIs(t, signals.Lookup(owner, &nonce), ebpf.ErrKeyNotExist)
}

func javaRemoteParentDirectJSSEAssertDataAckMissing(
	t *testing.T,
	dataAcks *ebpf.Map,
	process BpfJavaRemoteParentPidKeyT,
) {
	t.Helper()

	key := BpfJavaRemoteParentJavaRemoteParentDataSignalKeyT{
		Process: process,
		Nonce:   javaRemoteParentDirectJSSENonce,
	}
	var acknowledgement BpfJavaRemoteParentJavaRemoteParentDataAckT
	assert.ErrorIs(t, dataAcks.Lookup(key, &acknowledgement), ebpf.ErrKeyNotExist)
}

func javaRemoteParentDirectJSSEAssertConsumed(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	capability uint64,
	connection BpfJavaRemoteParentConnectionInfoT,
	netns uint32,
	observed uint64,
) {
	t.Helper()

	key := BpfJavaRemoteParentJavaRemoteParentKeyT{
		Owner:      owner,
		Generation: javaRemoteParentDirectJSSEGeneration,
	}
	assertGenerationMissing(t, maps.JavaRemoteParentState, owner, javaRemoteParentDirectJSSEGeneration)
	var generationIndex BpfJavaRemoteParentJavaRemoteParentGenerationIndexT
	assert.ErrorIs(t, maps.JavaRemoteParentGenerationIndex.Lookup(key, &generationIndex), ebpf.ErrKeyNotExist)
	var indexedOwner BpfJavaRemoteParentJavaRemoteParentOwnerT
	assert.ErrorIs(t, maps.JavaRemoteParentOwners.Lookup(owner, &indexedOwner), ebpf.ErrKeyNotExist)
	var fallback BpfJavaRemoteParentJavaRemoteParentResponseT
	assert.ErrorIs(t, maps.JavaRemoteParentFallback.Lookup(owner, &fallback), ebpf.ErrKeyNotExist)
	connectionKey := BpfJavaRemoteParentConnectionInfoNsT{
		Connection: connection,
		Netns:      netns,
	}
	var indexed BpfJavaRemoteParentJavaRemoteParentConnectionT
	assert.ErrorIs(t, maps.JavaRemoteParentConnections.Lookup(connectionKey, &indexed), ebpf.ErrKeyNotExist)
	cookieConnectionKey := BpfJavaRemoteParentConnectionInfoNetnsCookieT{
		Connection: connection,
		NetnsCookie: remoteParentTestNetNSCookie(
			netns,
			javaRemoteParentDirectJSSEGeneration,
		),
	}
	assert.ErrorIs(
		t,
		maps.JavaRemoteParentCookieConnections.Lookup(cookieConnectionKey, &indexed),
		ebpf.ErrKeyNotExist,
	)
	var claim BpfJavaRemoteParentJavaRemoteParentClaimT
	assert.ErrorIs(t, maps.JavaRemoteParentClaims.Lookup(key, &claim), ebpf.ErrKeyNotExist)
	var ownerGuard BpfJavaRemoteParentJavaRemoteParentClaimT
	assert.ErrorIs(
		t,
		maps.JavaRemoteParentOwnerGuards.Lookup(owner, &ownerGuard),
		ebpf.ErrKeyNotExist,
	)
	var ambiguity uint64
	assert.ErrorIs(t, maps.JavaRemoteParentAmbiguity.Lookup(key, &ambiguity), ebpf.ErrKeyNotExist)
	javaRemoteParentDirectJSSEAssertDataAckMissing(t, maps.JavaRemoteParentDataAcks, process)
	javaRemoteParentDirectJSSEAssertSignalMissing(t, maps.JavaRemoteParentDataSignals, owner)

	var terminal BpfJavaRemoteParentJavaRemoteParentTerminalT
	require.NoError(t, maps.JavaRemoteParentTerminal.Lookup(owner, &terminal))
	assert.Equal(t, javaRemoteParentDirectJSSEGeneration, terminal.Generation)
	assert.Equal(t, observed, terminal.ObservedMonotimeNs)
	assert.Equal(t, capability, terminal.ProcessIncarnation)
	assert.Equal(t, javaRemoteParentDirectJSSELifecycleConsumed, terminal.Lifecycle)
	assert.Zero(t, terminal.Reserved)
	require.NoError(t, maps.JavaRemoteParentTerminal.Delete(owner))
}
