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
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/javabridge"
)

const (
	javaRemoteParentGenericDirectJSSEIncomingGeneration = uint64(61)
	javaRemoteParentGenericDirectJSSETCPSequence        = uint32(0x10203040)
	javaRemoteParentGenericDirectJSSECursorValid        = uint32(0)
)

// TestJavaRemoteParentGenericJVMDirectSSLSocket proves that the production generictracer HTTP/1
// parser claims a strict incoming TCP candidate, allocates a fresh bridge generation, publishes
// an exact data ACK, and drives the primary JNI sockopt path for an ordinary accepted JSSE read.
// The JVM remains alive after explicitly closing the accepted socket so the dedicated tcp_close
// hook's receive-cursor and incoming-candidate cleanup is observed before process exit.
func TestJavaRemoteParentGenericJVMDirectSSLSocket(t *testing.T) {
	agentPath, java := javaRemoteParentJVMProbeRuntime(t)
	requireJavaRemoteParentGenericDirectJSSEJava21(t, java)
	requireJavaRemoteParentPrimarySockoptSupport(t)
	keyStore := javaRemoteParentDirectJSSEKeyStorePath(t)

	primary := loadJavaRemoteParentFixture(t)
	t.Cleanup(func() { require.NoError(t, primary.Close()) })
	setJavaRemoteParentDataHookReadiness(
		t, primary.JavaRemoteParentDataHookReadiness, false,
	)
	attachJavaRemoteParentFixture(t, &primary.BpfJavaRemoteParentPrograms)
	attachJavaRemoteParentSockopsFixture(t, primary.JavaRemoteParentSocketCookies)

	parser := loadJavaRemoteParentGenericDirectJSSEFixture(
		t, &primary.BpfJavaRemoteParentMaps,
	)
	parser.attach(t, primary.JavaRemoteParentDataHookReadiness)

	runJavaRemoteParentGenericDirectSSLSocketProbe(
		t,
		&primary.BpfJavaRemoteParentMaps,
		agentPath,
		java,
		keyStore,
	)
}

func requireJavaRemoteParentGenericDirectJSSEJava21(t *testing.T, java string) {
	t.Helper()

	output, err := exec.Command(java, "-XshowSettings:properties", "-version").CombinedOutput()
	require.NoErrorf(t, err, "inspect Java runtime:\n%s", output)
	const property = "java.specification.version = "
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, property) {
			continue
		}
		value := strings.TrimPrefix(line, property)
		version, parseErr := strconv.Atoi(value)
		if parseErr != nil || version < 21 {
			t.Skipf("generic direct JSSE raw-close fixture requires Java 21+, got %q", value)
		}
		return
	}
	require.FailNow(t, "Java runtime did not report java.specification.version")
}

func runJavaRemoteParentGenericDirectSSLSocketProbe(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	agentPath string,
	java string,
	keyStore string,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), javaRemoteParentDirectJSSETimeout)
	defer cancel()

	const capability = uint64(0x6f5e4d3c2b1a0978)
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
		"--add-opens=java.base/java.io=ALL-UNNAMED",
		"--add-opens=java.base/java.net=ALL-UNNAMED",
		"-javaagent:"+agentPath+"="+agentOptions,
		"-cp",
		agentPath,
		javaRemoteParentDirectJSSEProbeClass,
		javaRemoteParentDirectJSSEProtocol,
		keyStore,
		javaRemoteParentDirectJSSEKeyStorePassword,
		"await-close",
	)
	stdin, err := command.StdinPipe()
	require.NoError(t, err)
	stdout, err := command.StdoutPipe()
	require.NoError(t, err)
	var stderr javaRemoteParentJVMProbeLog
	command.Stderr = &stderr
	require.NoError(t, command.Start())

	process := javaRemoteParentProcessKey(t, command.Process.Pid)
	waited := false
	javaSocketDuplicate := -1
	defer func() {
		if javaSocketDuplicate >= 0 {
			_ = unix.Close(javaSocketDuplicate)
		}
		if !waited {
			_ = stdin.Close()
			if command.Process != nil {
				_ = command.Process.Kill()
			}
			_ = command.Wait()
		}
		_ = maps.JavaProcessIncarnations.Delete(process)
		_ = maps.JavaAuthorizedProcesses.Delete(process)
	}()

	require.NoError(t, maps.JavaAuthorizedProcesses.Update(
		process, capability, ebpf.UpdateNoExist,
	))
	var processIncarnation uint64
	require.ErrorIs(
		t,
		maps.JavaProcessIncarnations.Lookup(process, &processIncarnation),
		ebpf.ErrKeyNotExist,
	)
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
	require.NoError(t, rawConnection.SetDeadline(
		time.Now().Add(javaRemoteParentDirectJSSETimeout),
	))
	tlsConnection := tlsClientForJavaRemoteParentGenericDirectJSSE(
		rawConnection, certificateDigest,
	)
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

	var authorization uint64
	require.NoError(t, maps.JavaAuthorizedProcesses.Lookup(process, &authorization))
	require.Equal(t, capability, authorization)
	require.NoError(t, maps.JavaProcessIncarnations.Lookup(process, &processIncarnation))
	require.Equal(t, capability, processIncarnation)

	pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	require.NoError(t, err)
	defer unix.Close(pidfd)
	javaSocketDuplicate, err = unix.PidfdGetfd(pidfd, javaSocketFD, 0)
	require.NoError(t, err)
	javaSocketCookie := socketCookie(t, javaSocketDuplicate)
	netnsCookie, err := unix.GetsockoptUint64(
		javaSocketDuplicate, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE,
	)
	require.NoError(t, err)
	require.NotZero(t, netnsCookie)
	var seededSocketCookie uint64
	require.NoError(t, maps.JavaRemoteParentSocketCookies.Lookup(
		uint32(javaSocketDuplicate), &seededSocketCookie,
	))
	require.Equal(t, javaSocketCookie, seededSocketCookie)
	assertSocketNegotiationMissing(
		t, maps.JavaRemoteParentNegotiations, javaSocketDuplicate,
	)

	owner := process
	owner.Tid = tid
	connection := javaRemoteParentJVMConnectionInfo(t, rawConnection)
	netns := currentNamespaceID(t, fmt.Sprintf("/proc/%d/ns/net", command.Process.Pid))
	observed := monotonicNowNS(t)
	incomingKey := BpfJavaRemoteParentConnectionInfoNetnsCookieT{
		Connection:  connection,
		NetnsCookie: netnsCookie,
	}
	incoming := javaRemoteParentGenericDirectJSSEIncomingCandidate(observed)
	javaRemoteParentGenericDirectJSSEAssertBeforeRead(
		t,
		maps,
		process,
		owner,
		connection,
		netns,
		netnsCookie,
		javaSocketCookie,
	)
	require.NoError(t, maps.IncomingTraceCandidates.Update(
		javaRemoteParentGenericDirectJSSEIncomingGeneration,
		incoming,
		ebpf.UpdateNoExist,
	))
	require.NoError(t, maps.IncomingTraceHeads.Update(
		incomingKey,
		javaRemoteParentGenericDirectJSSEIncomingGeneration,
		ebpf.UpdateNoExist,
	))
	javaRemoteParentGenericDirectJSSEAssertIncoming(
		t, maps, incomingKey, incoming, false,
	)
	statsBeforeStage := javaRemoteParentStats(t, maps.JavaRemoteParentStats)

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
	require.Positive(t, javaRemoteParentJVMProbeInt(t, acknowledged, "reads"))
	require.Equal(t, hex.EncodeToString(requestDigest[:]), acknowledged["requestSha256"])
	lifecycleID := javaRemoteParentGenericDirectJSSEProbeUint64(
		t, acknowledged, "lifecycleId",
	)

	negotiation := socketNegotiation(
		t, maps.JavaRemoteParentNegotiations, javaSocketDuplicate,
	)
	require.Equal(t, process, negotiation.Process)
	require.Zero(t, negotiation.Reserved)
	require.Equal(t, capability, negotiation.ProcessIncarnation)
	require.Equal(t, connection, negotiation.Connection)
	require.Equal(t, netns, negotiation.ConnectionNetns)
	require.NotZero(t, negotiation.Generation)
	generation := negotiation.Generation

	cursor := javaRemoteParentGenericDirectJSSEAssertActive(
		t,
		maps,
		process,
		owner,
		capability,
		connection,
		netns,
		netnsCookie,
		javaSocketCookie,
		incomingKey,
		incoming,
		generation,
		observed,
		lifecycleID,
	)
	statsAfterStage := javaRemoteParentStats(t, maps.JavaRemoteParentStats)
	require.Equal(
		t,
		statsBeforeStage[javaRemoteParentStatStageValid]+1,
		statsAfterStage[javaRemoteParentStatStageValid],
	)

	statsBeforeTake := statsAfterStage
	_, err = io.WriteString(stdin, "TAKE\n")
	require.NoError(t, err)
	result := waitForJavaRemoteParentJVMProbe(t, ctx, lines, "RESULT", &stderr)
	require.Equal(t, strconv.Itoa(int(javabridge.StatusValid)), result["status"])
	require.Equal(t, "1", result["flags"])
	require.Equal(t, javaRemoteParentJVMProbeTraceID, result["trace"])
	require.Equal(t, javaRemoteParentJVMProbeParentSpanID, result["span"])
	require.Equal(t, strconv.FormatUint(generation, 10), result["generation"])
	require.Equal(t, strconv.FormatUint(observed, 10), result["observed"])
	require.Equal(t, "-1", result["fdAfter"])

	statsAfterTake := javaRemoteParentStats(t, maps.JavaRemoteParentStats)
	require.Equal(
		t,
		statsBeforeTake[javaRemoteParentStatTakeValid]+1,
		statsAfterTake[javaRemoteParentStatTakeValid],
	)
	javaRemoteParentGenericDirectJSSEAssertConsumedWhileOpen(
		t,
		maps,
		process,
		owner,
		capability,
		connection,
		netns,
		netnsCookie,
		javaSocketCookie,
		incomingKey,
		incoming,
		negotiation,
		cursor,
		observed,
	)
	require.Equal(t, negotiation, socketNegotiation(
		t, maps.JavaRemoteParentNegotiations, javaSocketDuplicate,
	))

	require.NoError(t, unix.Close(javaSocketDuplicate))
	javaSocketDuplicate = -1
	_, err = io.WriteString(stdin, "CLOSE\n")
	require.NoError(t, err)
	closed := waitForJavaRemoteParentJVMProbe(t, ctx, lines, "CLOSED", &stderr)
	require.Equal(t, strconv.Itoa(javaSocketFD), closed["fd"])
	javaRemoteParentGenericDirectJSSEAssertClosed(
		t,
		maps,
		process,
		owner,
		capability,
		connection,
		netns,
		netnsCookie,
		javaSocketCookie,
		incomingKey,
		generation,
		observed,
		cursor,
	)
	require.Equal(t, statsAfterTake, javaRemoteParentStats(t, maps.JavaRemoteParentStats))

	_, err = io.WriteString(stdin, "EXIT\n")
	require.NoError(t, err)
	err = command.Wait()
	waited = true
	if ctx.Err() != nil {
		t.Fatalf("generic direct JSSE JVM bridge probe timed out: %s", stderr.String())
	}
	require.NoErrorf(t, err, "generic direct JSSE JVM bridge probe failed:\n%s", stderr.String())
}

func tlsClientForJavaRemoteParentGenericDirectJSSE(
	connection net.Conn,
	certificateDigest [sha256.Size]byte,
) *tls.Conn {
	return tls.Client(connection, javaRemoteParentDirectJSSETLSConfig(certificateDigest))
}

func javaRemoteParentGenericDirectJSSEProbeUint64(
	t *testing.T,
	values map[string]string,
	key string,
) uint64 {
	t.Helper()

	value, ok := values[key]
	require.Truef(t, ok, "missing probe field %q", key)
	parsed, err := strconv.ParseUint(value, 10, 64)
	require.NoErrorf(t, err, "invalid probe field %q", key)
	require.NotZero(t, parsed, "probe field %q must be nonzero", key)
	return parsed
}

func javaRemoteParentGenericDirectJSSEIncomingCandidate(
	observed uint64,
) BpfJavaRemoteParentIncomingTraceCandidateT {
	candidate := BpfJavaRemoteParentIncomingTraceCandidateT{
		TcpSequence: javaRemoteParentGenericDirectJSSETCPSequence,
	}
	candidate.Candidate.Tp.TraceId = [16]uint8{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	}
	candidate.Candidate.Tp.SpanId = [8]uint8{17, 18, 19, 20, 21, 22, 23, 24}
	candidate.Candidate.Tp.Ts = observed
	candidate.Candidate.Tp.Flags = 1
	candidate.Candidate.Valid = 1
	candidate.Candidate.State = 2 // k_tp_provenance_tcp_exact_flags
	return candidate
}

func javaRemoteParentGenericDirectJSSEAssertBeforeRead(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	connection BpfJavaRemoteParentConnectionInfoT,
	netns uint32,
	netnsCookie uint64,
	socketCookie uint64,
) {
	t.Helper()

	var indexedOwner BpfJavaRemoteParentJavaRemoteParentOwnerT
	require.ErrorIs(t, maps.JavaRemoteParentOwners.Lookup(owner, &indexedOwner), ebpf.ErrKeyNotExist)
	var fallback BpfJavaRemoteParentJavaRemoteParentResponseT
	require.ErrorIs(t, maps.JavaRemoteParentFallback.Lookup(owner, &fallback), ebpf.ErrKeyNotExist)
	var terminal BpfJavaRemoteParentJavaRemoteParentTerminalT
	require.ErrorIs(t, maps.JavaRemoteParentTerminal.Lookup(owner, &terminal), ebpf.ErrKeyNotExist)
	javaRemoteParentGenericDirectJSSEAssertConnectionIndexesMissing(
		t, maps, connection, netns, netnsCookie,
	)
	var cursor BpfJavaRemoteParentJavaRemoteParentReceiveCursorT
	require.ErrorIs(t, maps.JrpRecvCur.Lookup(socketCookie, &cursor), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, maps.JrpRecvGuard.Lookup(socketCookie, &cursor), ebpf.ErrKeyNotExist)
	javaRemoteParentGenericDirectJSSEAssertSignalMissing(t, maps.JavaRemoteParentDataSignals, owner)
	javaRemoteParentGenericDirectJSSEAssertSignalMissing(t, maps.JavaRemoteParentDataSignals, process)
	javaRemoteParentGenericDirectJSSEAssertDataAckMissing(
		t, maps.JavaRemoteParentDataAcks, process, javaRemoteParentDirectJSSENonce,
	)
	assertJavaRemoteParentGenericDirectJSSEReadiness(
		t, maps.JavaRemoteParentDataHookReadiness, 1,
	)
}

func javaRemoteParentGenericDirectJSSEAssertIncoming(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	key BpfJavaRemoteParentConnectionInfoNetnsCookieT,
	want BpfJavaRemoteParentIncomingTraceCandidateT,
	claimed bool,
) {
	t.Helper()

	var generation uint64
	require.NoError(t, maps.IncomingTraceHeads.Lookup(key, &generation))
	require.Equal(t, javaRemoteParentGenericDirectJSSEIncomingGeneration, generation)
	var candidate BpfJavaRemoteParentIncomingTraceCandidateT
	require.NoError(t, maps.IncomingTraceCandidates.Lookup(generation, &candidate))
	require.Equal(t, want, candidate)
	var claim uint8
	if claimed {
		require.NoError(t, maps.IncomingTraceClaims.Lookup(generation, &claim))
		require.Equal(t, uint8(1), claim)
	} else {
		require.ErrorIs(
			t, maps.IncomingTraceClaims.Lookup(generation, &claim), ebpf.ErrKeyNotExist,
		)
	}
	var ambiguity uint8
	require.ErrorIs(
		t, maps.IncomingTraceAmbiguity.Lookup(generation, &ambiguity), ebpf.ErrKeyNotExist,
	)
}

func javaRemoteParentGenericDirectJSSEAssertActive(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	capability uint64,
	connection BpfJavaRemoteParentConnectionInfoT,
	netns uint32,
	netnsCookie uint64,
	socketCookie uint64,
	incomingKey BpfJavaRemoteParentConnectionInfoNetnsCookieT,
	incoming BpfJavaRemoteParentIncomingTraceCandidateT,
	generation uint64,
	observed uint64,
	lifecycleID uint64,
) BpfJavaRemoteParentJavaRemoteParentReceiveCursorT {
	t.Helper()

	key := BpfJavaRemoteParentJavaRemoteParentKeyT{Owner: owner, Generation: generation}
	wantResponse := javaRemoteParentGenericDirectJSSEResponse(generation, observed)
	var state BpfJavaRemoteParentJavaRemoteParentStateT
	require.NoError(t, maps.JavaRemoteParentState.Lookup(key, &state))
	require.Equal(t, bridgeLifecycleActive, state.Lifecycle)
	require.Zero(t, state.Reserved)
	require.Zero(t, state.Aliases)
	require.Equal(t, observed, state.ObservedMonotimeNs)
	require.Equal(t, connection, state.Connection)
	require.Equal(t, netns, state.ConnectionNetns)
	require.Equal(t, capability, state.ProcessIncarnation)
	require.Equal(t, wantResponse, state.Response)

	var generationIndex BpfJavaRemoteParentJavaRemoteParentGenerationIndexT
	require.NoError(t, maps.JavaRemoteParentGenerationIndex.Lookup(key, &generationIndex))
	require.Equal(t, process, generationIndex.Process)
	require.Zero(t, generationIndex.Reserved)
	require.Equal(t, capability, generationIndex.ProcessIncarnation)
	require.Equal(t, observed, generationIndex.ObservedMonotimeNs)
	var indexedOwner BpfJavaRemoteParentJavaRemoteParentOwnerT
	require.NoError(t, maps.JavaRemoteParentOwners.Lookup(owner, &indexedOwner))
	require.Equal(t, generation, indexedOwner.Generation)
	require.Equal(t, capability, indexedOwner.ProcessIncarnation)
	require.Equal(t, bridgeLifecycleActive, indexedOwner.Lifecycle)
	require.Zero(t, indexedOwner.Reserved)
	var fallback BpfJavaRemoteParentJavaRemoteParentResponseT
	require.NoError(t, maps.JavaRemoteParentFallback.Lookup(owner, &fallback))
	require.Equal(t, wantResponse, fallback)

	connectionValue := BpfJavaRemoteParentJavaRemoteParentConnectionT{
		Owner:              owner,
		Generation:         generation,
		NetnsCookie:        netnsCookie,
		IncomingGeneration: javaRemoteParentGenericDirectJSSEIncomingGeneration,
		SocketCookie:       socketCookie,
		Netns:              netns,
	}
	connectionKey := BpfJavaRemoteParentConnectionInfoNsT{
		Connection: connection,
		Netns:      netns,
	}
	var indexedConnection BpfJavaRemoteParentJavaRemoteParentConnectionT
	require.NoError(t, maps.JavaRemoteParentConnections.Lookup(
		connectionKey, &indexedConnection,
	))
	require.Equal(t, connectionValue, indexedConnection)
	cookieConnectionKey := BpfJavaRemoteParentConnectionInfoNetnsCookieT{
		Connection:  connection,
		NetnsCookie: netnsCookie,
	}
	require.NoError(t, maps.JavaRemoteParentCookieConnections.Lookup(
		cookieConnectionKey, &indexedConnection,
	))
	require.Equal(t, connectionValue, indexedConnection)

	var reservation uint64
	require.NoError(t, maps.JavaRemoteParentAmbiguity.Lookup(key, &reservation))
	require.Zero(t, reservation)
	var claim BpfJavaRemoteParentJavaRemoteParentClaimT
	require.ErrorIs(t, maps.JavaRemoteParentClaims.Lookup(key, &claim), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, maps.JavaRemoteParentOwnerGuards.Lookup(owner, &claim), ebpf.ErrKeyNotExist)
	var terminal BpfJavaRemoteParentJavaRemoteParentTerminalT
	require.ErrorIs(t, maps.JavaRemoteParentTerminal.Lookup(owner, &terminal), ebpf.ErrKeyNotExist)

	var cursor BpfJavaRemoteParentJavaRemoteParentReceiveCursorT
	require.NoError(t, maps.JrpRecvCur.Lookup(socketCookie, &cursor))
	require.Equal(t, owner, cursor.Owner)
	require.Equal(t, javaRemoteParentGenericDirectJSSECursorValid, cursor.State)
	require.Equal(t, capability, cursor.ProcessIncarnation)
	require.Equal(t, lifecycleID, cursor.LifecycleId)
	require.Equal(t, uint64(1), cursor.RequestSequence)
	require.Equal(t, javaRemoteParentDirectJSSENonce, cursor.DataSignalNonce)
	require.Equal(t, generation, cursor.Generation)
	var guard BpfJavaRemoteParentJavaRemoteParentReceiveCursorT
	require.ErrorIs(t, maps.JrpRecvGuard.Lookup(socketCookie, &guard), ebpf.ErrKeyNotExist)

	javaRemoteParentGenericDirectJSSEAssertIncoming(t, maps, incomingKey, incoming, true)
	javaRemoteParentGenericDirectJSSEAssertSignalMissing(t, maps.JavaRemoteParentDataSignals, owner)
	javaRemoteParentGenericDirectJSSEAssertSignalMissing(t, maps.JavaRemoteParentDataSignals, process)
	javaRemoteParentGenericDirectJSSEAssertDataAckMissing(
		t, maps.JavaRemoteParentDataAcks, process, cursor.DataSignalNonce,
	)
	assertJavaRemoteParentGenericDirectJSSEReadiness(
		t, maps.JavaRemoteParentDataHookReadiness, 1,
	)
	return cursor
}

func javaRemoteParentGenericDirectJSSEAssertConsumedWhileOpen(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	capability uint64,
	connection BpfJavaRemoteParentConnectionInfoT,
	netns uint32,
	netnsCookie uint64,
	socketCookie uint64,
	incomingKey BpfJavaRemoteParentConnectionInfoNetnsCookieT,
	incoming BpfJavaRemoteParentIncomingTraceCandidateT,
	negotiation BpfJavaRemoteParentJavaRemoteParentNegotiationT,
	cursor BpfJavaRemoteParentJavaRemoteParentReceiveCursorT,
	observed uint64,
) {
	t.Helper()

	javaRemoteParentGenericDirectJSSEAssertGraphMissing(
		t, maps, process, owner, connection, netns, netnsCookie, cursor,
	)
	var storedCursor BpfJavaRemoteParentJavaRemoteParentReceiveCursorT
	require.NoError(t, maps.JrpRecvCur.Lookup(socketCookie, &storedCursor))
	require.Equal(t, cursor, storedCursor)
	require.ErrorIs(
		t, maps.JrpRecvGuard.Lookup(socketCookie, &storedCursor), ebpf.ErrKeyNotExist,
	)
	javaRemoteParentGenericDirectJSSEAssertIncoming(t, maps, incomingKey, incoming, true)
	javaRemoteParentGenericDirectJSSEAssertTerminal(
		t, maps.JavaRemoteParentTerminal, owner, capability, cursor.Generation, observed,
	)
	require.Equal(t, cursor.Generation, negotiation.Generation)
	var authorization uint64
	require.NoError(t, maps.JavaAuthorizedProcesses.Lookup(process, &authorization))
	require.Equal(t, capability, authorization)
	var incarnation uint64
	require.NoError(t, maps.JavaProcessIncarnations.Lookup(process, &incarnation))
	require.Equal(t, capability, incarnation)
	assertJavaRemoteParentGenericDirectJSSEReadiness(
		t, maps.JavaRemoteParentDataHookReadiness, 1,
	)
}

func javaRemoteParentGenericDirectJSSEAssertClosed(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	capability uint64,
	connection BpfJavaRemoteParentConnectionInfoT,
	netns uint32,
	netnsCookie uint64,
	socketCookie uint64,
	incomingKey BpfJavaRemoteParentConnectionInfoNetnsCookieT,
	generation uint64,
	observed uint64,
	cursor BpfJavaRemoteParentJavaRemoteParentReceiveCursorT,
) {
	t.Helper()

	var storedCursor BpfJavaRemoteParentJavaRemoteParentReceiveCursorT
	require.ErrorIs(t, maps.JrpRecvCur.Lookup(socketCookie, &storedCursor), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, maps.JrpRecvGuard.Lookup(socketCookie, &storedCursor), ebpf.ErrKeyNotExist)
	javaRemoteParentGenericDirectJSSEAssertIncomingMissing(
		t, maps, incomingKey,
	)
	javaRemoteParentGenericDirectJSSEAssertGraphMissing(
		t, maps, process, owner, connection, netns, netnsCookie, cursor,
	)
	javaRemoteParentGenericDirectJSSEAssertTerminal(
		t, maps.JavaRemoteParentTerminal, owner, capability, generation, observed,
	)
	var authorization uint64
	require.NoError(t, maps.JavaAuthorizedProcesses.Lookup(process, &authorization))
	require.Equal(t, capability, authorization)
	var incarnation uint64
	require.NoError(t, maps.JavaProcessIncarnations.Lookup(process, &incarnation))
	require.Equal(t, capability, incarnation)
	assertJavaRemoteParentGenericDirectJSSEReadiness(
		t, maps.JavaRemoteParentDataHookReadiness, 1,
	)
}

func javaRemoteParentGenericDirectJSSEAssertGraphMissing(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	connection BpfJavaRemoteParentConnectionInfoT,
	netns uint32,
	netnsCookie uint64,
	cursor BpfJavaRemoteParentJavaRemoteParentReceiveCursorT,
) {
	t.Helper()

	key := BpfJavaRemoteParentJavaRemoteParentKeyT{
		Owner:      owner,
		Generation: cursor.Generation,
	}
	var state BpfJavaRemoteParentJavaRemoteParentStateT
	require.ErrorIs(t, maps.JavaRemoteParentState.Lookup(key, &state), ebpf.ErrKeyNotExist)
	var generationIndex BpfJavaRemoteParentJavaRemoteParentGenerationIndexT
	require.ErrorIs(
		t, maps.JavaRemoteParentGenerationIndex.Lookup(key, &generationIndex), ebpf.ErrKeyNotExist,
	)
	var indexedOwner BpfJavaRemoteParentJavaRemoteParentOwnerT
	require.ErrorIs(t, maps.JavaRemoteParentOwners.Lookup(owner, &indexedOwner), ebpf.ErrKeyNotExist)
	var fallback BpfJavaRemoteParentJavaRemoteParentResponseT
	require.ErrorIs(t, maps.JavaRemoteParentFallback.Lookup(owner, &fallback), ebpf.ErrKeyNotExist)
	javaRemoteParentGenericDirectJSSEAssertConnectionIndexesMissing(
		t, maps, connection, netns, netnsCookie,
	)
	var claim BpfJavaRemoteParentJavaRemoteParentClaimT
	require.ErrorIs(t, maps.JavaRemoteParentClaims.Lookup(key, &claim), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, maps.JavaRemoteParentOwnerGuards.Lookup(owner, &claim), ebpf.ErrKeyNotExist)
	var ambiguity uint64
	require.ErrorIs(t, maps.JavaRemoteParentAmbiguity.Lookup(key, &ambiguity), ebpf.ErrKeyNotExist)
	javaRemoteParentGenericDirectJSSEAssertSignalMissing(t, maps.JavaRemoteParentDataSignals, owner)
	javaRemoteParentGenericDirectJSSEAssertSignalMissing(t, maps.JavaRemoteParentDataSignals, process)
	javaRemoteParentGenericDirectJSSEAssertDataAckMissing(
		t, maps.JavaRemoteParentDataAcks, process, cursor.DataSignalNonce,
	)
}

func javaRemoteParentGenericDirectJSSEAssertConnectionIndexesMissing(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	connection BpfJavaRemoteParentConnectionInfoT,
	netns uint32,
	netnsCookie uint64,
) {
	t.Helper()

	connectionKey := BpfJavaRemoteParentConnectionInfoNsT{
		Connection: connection,
		Netns:      netns,
	}
	var indexed BpfJavaRemoteParentJavaRemoteParentConnectionT
	require.ErrorIs(
		t, maps.JavaRemoteParentConnections.Lookup(connectionKey, &indexed), ebpf.ErrKeyNotExist,
	)
	cookieConnectionKey := BpfJavaRemoteParentConnectionInfoNetnsCookieT{
		Connection:  connection,
		NetnsCookie: netnsCookie,
	}
	require.ErrorIs(
		t,
		maps.JavaRemoteParentCookieConnections.Lookup(cookieConnectionKey, &indexed),
		ebpf.ErrKeyNotExist,
	)
}

func javaRemoteParentGenericDirectJSSEAssertIncomingMissing(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	key BpfJavaRemoteParentConnectionInfoNetnsCookieT,
) {
	t.Helper()

	var generation uint64
	require.ErrorIs(t, maps.IncomingTraceHeads.Lookup(key, &generation), ebpf.ErrKeyNotExist)
	generation = javaRemoteParentGenericDirectJSSEIncomingGeneration
	var candidate BpfJavaRemoteParentIncomingTraceCandidateT
	require.ErrorIs(
		t, maps.IncomingTraceCandidates.Lookup(generation, &candidate), ebpf.ErrKeyNotExist,
	)
	var marker uint8
	require.ErrorIs(t, maps.IncomingTraceClaims.Lookup(generation, &marker), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, maps.IncomingTraceAmbiguity.Lookup(generation, &marker), ebpf.ErrKeyNotExist)
}

func javaRemoteParentGenericDirectJSSEAssertTerminal(
	t *testing.T,
	terminals *ebpf.Map,
	owner BpfJavaRemoteParentPidKeyT,
	capability uint64,
	generation uint64,
	observed uint64,
) {
	t.Helper()

	var terminal BpfJavaRemoteParentJavaRemoteParentTerminalT
	require.NoError(t, terminals.Lookup(owner, &terminal))
	require.Equal(t, generation, terminal.Generation)
	require.Equal(t, observed, terminal.ObservedMonotimeNs)
	require.Equal(t, capability, terminal.ProcessIncarnation)
	require.Equal(t, javaRemoteParentDirectJSSELifecycleConsumed, terminal.Lifecycle)
	require.Zero(t, terminal.Reserved)
}

func javaRemoteParentGenericDirectJSSEAssertSignalMissing(
	t *testing.T,
	signals *ebpf.Map,
	owner BpfJavaRemoteParentPidKeyT,
) {
	t.Helper()

	var nonce uint64
	require.ErrorIs(t, signals.Lookup(owner, &nonce), ebpf.ErrKeyNotExist)
}

func javaRemoteParentGenericDirectJSSEAssertDataAckMissing(
	t *testing.T,
	acks *ebpf.Map,
	process BpfJavaRemoteParentPidKeyT,
	nonce uint64,
) {
	t.Helper()

	key := BpfJavaRemoteParentJavaRemoteParentDataSignalKeyT{
		Process: process,
		Nonce:   nonce,
	}
	var acknowledgement BpfJavaRemoteParentJavaRemoteParentDataAckT
	require.ErrorIs(t, acks.Lookup(key, &acknowledgement), ebpf.ErrKeyNotExist)
}

func javaRemoteParentGenericDirectJSSEResponse(
	generation uint64,
	observed uint64,
) BpfJavaRemoteParentJavaRemoteParentResponseT {
	return BpfJavaRemoteParentJavaRemoteParentResponseT{
		Magic:                [4]uint8{'O', 'B', 'I', 'J'},
		VersionLe:            javabridge.Version,
		SizeLe:               javabridge.RecordSize,
		Status:               uint8(javabridge.StatusValid),
		Flags:                1,
		TraceId:              [16]uint8{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanId:               [8]uint8{17, 18, 19, 20, 21, 22, 23, 24},
		GenerationLe:         generation,
		ObservedMonotimeNsLe: observed,
	}
}
