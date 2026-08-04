// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/javabridge"
)

const (
	javaRemoteParentUnknown  = 0x4aff
	bridgeLifecycleActive    = uint8(1)
	bridgeLifecycleDiscarded = uint8(3)
	unauthorizedCallCount    = 512
	unauthorizedHelperEnv    = "OBI_JAVA_REMOTE_PARENT_UNAUTHORIZED_HELPER"
)

// TestJavaRemoteParentPrimarySocketAuthority exercises the cgroup sockopt
// programs against real TCP sockets. It is intentionally privileged and
// reports missing kernel features or capabilities as unsupported rather than
// treating an unexecuted security scenario as a pass.
func TestJavaRemoteParentPrimarySocketAuthority(t *testing.T) {
	requireJavaRemoteParentPrimarySockoptSupport(t)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	objects := loadJavaRemoteParentFixture(t)
	defer objects.Close()
	setJavaRemoteParentDataHookReadiness(t, objects.JavaRemoteParentDataHookReadiness, true)
	attachJavaRemoteParentFixture(t, &objects.BpfJavaRemoteParentPrograms)

	process, owner := currentBridgeIdentities(t)
	const capability = uint64(0x7f6e5d4c3b2a1908)
	require.NoError(t, objects.JavaAuthorizedProcesses.Update(process, capability, ebpf.UpdateAny))
	require.NoError(t, objects.JavaProcessIncarnations.Update(process, capability, ebpf.UpdateAny))

	listener := newTCPListener(t)
	defer unix.Close(listener)
	first := connectTCP(t, listener)
	defer first.close()
	second := connectTCP(t, listener)
	defer second.close()

	assertStandardSockoptPassThrough(t, first.client)
	assertNativeSockoptMiss(t, first.client, javabridge.SocketLevel, javaRemoteParentUnknown)
	requireNativeSockoptUnsupported(t, rawSetsockoptUint64(
		first.client, javabridge.SocketLevel, javabridge.SocketNegotiate, capability,
	))
	assertSocketNegotiationMissing(t, objects.JavaRemoteParentNegotiations, first.client)

	firstSocketCookie := seedJavaRemoteParentSocketCookie(
		t, objects.JavaRemoteParentSocketCookies, first.client,
	)
	seedJavaRemoteParentSocketCookie(t, objects.JavaRemoteParentSocketCookies, second.client)

	for range unauthorizedCallCount {
		require.ErrorIs(t,
			rawSetsockoptUint64(
				first.client, javabridge.SocketLevel, javabridge.SocketNegotiate, capability+1,
			),
			unix.ENOPROTOOPT,
		)
	}
	assertSocketNegotiationMissing(t, objects.JavaRemoteParentNegotiations, first.client)

	require.NoError(t, rawSetsockoptUint64(
		first.client, javabridge.SocketLevel, javabridge.SocketNegotiate, capability,
	))
	assert.Equal(t, capability, javaRemoteParentHealthValue(t, first.client))
	firstNegotiation := socketNegotiation(t, objects.JavaRemoteParentNegotiations, first.client)
	assert.Equal(t, process, firstNegotiation.Process)
	assert.Equal(t, capability, firstNegotiation.ProcessIncarnation)
	assert.NotZero(t, firstNegotiation.Connection.S_port)
	assert.NotZero(t, firstNegotiation.Connection.D_port)
	assert.NotZero(t, firstNegotiation.ConnectionNetns)

	for range unauthorizedCallCount {
		require.ErrorIs(t,
			rawSetsockoptUint64(
				first.client, javabridge.SocketLevel, javabridge.SocketNegotiate, capability+1,
			),
			unix.ENOPROTOOPT,
		)
	}
	assertNativeSockoptMiss(t, first.client, javabridge.SocketLevel, javaRemoteParentUnknown)
	assert.Equal(
		t,
		firstNegotiation,
		socketNegotiation(t, objects.JavaRemoteParentNegotiations, first.client),
		"unauthorized and unrelated sockopts must not replace socket-local authority",
	)

	require.NoError(t, rawSetsockoptUint64(
		second.client, javabridge.SocketLevel, javabridge.SocketNegotiate, capability,
	))
	assert.NotEqual(t,
		firstNegotiation.Connection,
		socketNegotiation(t, objects.JavaRemoteParentNegotiations, second.client).Connection,
	)

	netns := firstNegotiation.ConnectionNetns
	const firstGeneration = uint64(41)
	const firstNonce = uint64(0x1020304050607080)
	stageRemoteParent(t,
		&objects.BpfJavaRemoteParentMaps,
		process,
		owner,
		capability,
		firstNegotiation.Connection,
		netns,
		firstSocketCookie,
		firstGeneration,
		firstNonce,
	)
	if err := acknowledgeRemoteParentData(first.client, firstNonce); err != nil {
		t.Fatalf("valid data ACK failed: %v; negotiation: %+v",
			err,
			socketNegotiation(t, objects.JavaRemoteParentNegotiations, first.client),
		)
	}
	updateDataAck(t,
		objects.JavaRemoteParentDataAcks,
		process,
		owner,
		firstNegotiation.Connection,
		netns,
		firstGeneration,
		firstNonce,
	)

	assertNativeDataAckMiss(t, second.client, firstNonce)
	assertGenerationPresent(t, objects.JavaRemoteParentState, owner, firstGeneration)

	wrongNetns := netns + 1
	if wrongNetns == 0 {
		wrongNetns = 1
	}
	updateDataAck(t,
		objects.JavaRemoteParentDataAcks,
		process,
		owner,
		firstNegotiation.Connection,
		wrongNetns,
		firstGeneration,
		firstNonce,
	)
	assertNativeDataAckMiss(t, first.client, firstNonce)
	assertGenerationPresent(t, objects.JavaRemoteParentState, owner, firstGeneration)

	updateDataAck(t,
		objects.JavaRemoteParentDataAcks,
		process,
		owner,
		firstNegotiation.Connection,
		netns,
		firstGeneration,
		firstNonce,
	)
	if ackErr, err := acknowledgeFromNewNetworkNamespace(first.client, firstNonce); err != nil {
		t.Logf("cross-network-namespace runtime scenario unsupported: %v", err)
	} else {
		requireNativeSockoptUnsupported(t, ackErr)
		assertGenerationPresent(t, objects.JavaRemoteParentState, owner, firstGeneration)
	}

	require.NoError(t, acknowledgeRemoteParentData(first.client, firstNonce))
	assertInvalidRecordSizesPreserveGeneration(
		t, first.client, objects.JavaRemoteParentState, owner, firstGeneration,
	)
	statsBeforeUnauthorized := javaRemoteParentStats(t, objects.JavaRemoteParentStats)
	assertUnrelatedProcessCannotRetrieve(t, first.client)
	statsAfterUnauthorized := javaRemoteParentStats(t, objects.JavaRemoteParentStats)
	assert.Equal(t,
		statsBeforeUnauthorized[javaRemoteParentStatTakeUnauthorized]+unauthorizedCallCount,
		statsAfterUnauthorized[javaRemoteParentStatTakeUnauthorized],
	)
	assert.Equal(t,
		statsBeforeUnauthorized[javaRemoteParentStatDiscardUnauthorized]+unauthorizedCallCount,
		statsAfterUnauthorized[javaRemoteParentStatDiscardUnauthorized],
	)
	assertNativeTakeMiss(t, second.client)
	assertGenerationPresent(t, objects.JavaRemoteParentState, owner, firstGeneration)

	record := takeRemoteParent(t, first.client)
	assert.Equal(t, javabridge.StatusValid, record.Status)
	assert.Equal(t, firstGeneration, record.Generation)
	assert.False(t, record.TraceID == [javabridge.TraceIDSize]byte{})
	assert.False(t, record.SpanID == [javabridge.SpanIDSize]byte{})
	assertGenerationMissing(t, objects.JavaRemoteParentState, owner, firstGeneration)
	assertValidDiscard(
		t,
		&objects.BpfJavaRemoteParentMaps,
		process,
		owner,
		capability,
		firstNegotiation,
		first.client,
	)

	assertStaleRemoteParent(
		t,
		&objects.BpfJavaRemoteParentMaps,
		process,
		owner,
		capability,
		firstNegotiation,
		first.client,
	)
	assertVersionMismatchedRemoteParent(
		t,
		&objects.BpfJavaRemoteParentMaps,
		process,
		owner,
		capability,
		firstNegotiation,
		first.client,
	)
	assertConcurrentTakeIsOneShot(
		t,
		&objects.BpfJavaRemoteParentMaps,
		process,
		owner,
		capability,
		firstNegotiation,
		first.client,
	)

	third := connectTCP(t, listener)
	thirdClosed := false
	defer func() {
		if !thirdClosed {
			third.close()
		}
	}()
	thirdSocketCookie := seedJavaRemoteParentSocketCookie(
		t, objects.JavaRemoteParentSocketCookies, third.client,
	)
	require.NoError(t, rawSetsockoptUint64(
		third.client, javabridge.SocketLevel, javabridge.SocketNegotiate, capability,
	))
	thirdNegotiation := socketNegotiation(t, objects.JavaRemoteParentNegotiations, third.client)
	assert.NotZero(t, thirdNegotiation.ConnectionNetns)

	reusedFD := third.client
	require.NoError(t, unix.Close(third.client))
	require.NoError(t, unix.Close(third.server))
	thirdClosed = true

	replacement := connectTCPAtFD(t, listener, reusedFD)
	defer replacement.close()
	assert.Equal(t, reusedFD, replacement.client)
	assertSocketNegotiationMissing(t, objects.JavaRemoteParentNegotiations, replacement.client)
	assertNativeTakeMiss(t, replacement.client)
	var missingReplacementCookie uint64
	assert.ErrorIs(t, objects.JavaRemoteParentSocketCookies.Lookup(
		uint32(replacement.client), &missingReplacementCookie,
	), ebpf.ErrKeyNotExist)
	replacementSocketCookie := seedJavaRemoteParentSocketCookie(
		t, objects.JavaRemoteParentSocketCookies, replacement.client,
	)
	require.NotEqual(t, thirdSocketCookie, replacementSocketCookie)
	require.NoError(t, rawSetsockoptUint64(
		replacement.client, javabridge.SocketLevel, javabridge.SocketNegotiate, capability,
	))
	replacementNegotiation := socketNegotiation(
		t, objects.JavaRemoteParentNegotiations, replacement.client,
	)
	const reuseGeneration = uint64(46)
	const secondNonce = uint64(0x8877665544332211)
	stageRemoteParent(t,
		&objects.BpfJavaRemoteParentMaps,
		process,
		owner,
		capability,
		replacementNegotiation.Connection,
		replacementNegotiation.ConnectionNetns,
		thirdSocketCookie,
		reuseGeneration,
		secondNonce,
	)
	assertNativeDataAckMiss(t, replacement.client, secondNonce)
	assertGenerationPresent(t, objects.JavaRemoteParentState, owner, reuseGeneration)
	assert.Zero(t,
		socketNegotiation(t, objects.JavaRemoteParentNegotiations, replacement.client).Generation,
	)
	var preservedAck BpfJavaRemoteParentJavaRemoteParentDataAckT
	require.NoError(t, objects.JavaRemoteParentDataAcks.Lookup(
		BpfJavaRemoteParentJavaRemoteParentDataSignalKeyT{
			Process: process,
			Nonce:   secondNonce,
		},
		&preservedAck,
	))
	assert.Equal(t, reuseGeneration, preservedAck.Generation)
	var preservedSignal uint64
	require.NoError(t, objects.JavaRemoteParentDataSignals.Lookup(process, &preservedSignal))
	assert.Equal(t, secondNonce, preservedSignal)
}

func TestJavaRemoteParentUnauthorizedProcessHelper(t *testing.T) {
	if os.Getenv(unauthorizedHelperEnv) != "1" {
		t.Skip("subprocess helper")
	}

	for range unauthorizedCallCount {
		assertNativeTakeMiss(t, 3)
		assertNativeDiscardMiss(t, 3)
	}
}

func TestJavaRemoteParentPrimaryRequiresAuthoritativeDataHook(t *testing.T) {
	requireJavaRemoteParentPrimarySockoptSupport(t)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	objects := loadJavaRemoteParentFixture(t)
	defer objects.Close()
	attachJavaRemoteParentFixture(t, &objects.BpfJavaRemoteParentPrograms)

	process, _ := currentBridgeIdentities(t)
	const capability = uint64(0x1122334455667788)
	require.NoError(t, objects.JavaAuthorizedProcesses.Update(process, capability, ebpf.UpdateAny))
	require.NoError(t, objects.JavaProcessIncarnations.Update(process, capability, ebpf.UpdateAny))

	listener := newTCPListener(t)
	defer unix.Close(listener)
	pair := connectTCP(t, listener)
	defer pair.close()
	seedJavaRemoteParentSocketCookie(
		t, objects.JavaRemoteParentSocketCookies, pair.client,
	)

	requireNativeSockoptUnsupported(t, rawSetsockoptUint64(
		pair.client, javabridge.SocketLevel, javabridge.SocketNegotiate, capability,
	))
	assertSocketNegotiationMissing(t, objects.JavaRemoteParentNegotiations, pair.client)
	assertNativeSockoptMiss(t, pair.client, javabridge.SocketLevel, javabridge.SocketHealth)
}

func loadJavaRemoteParentFixture(t *testing.T) BpfJavaRemoteParentObjects {
	t.Helper()

	spec := javaRemoteParentFixtureSpec(t)

	var objects BpfJavaRemoteParentObjects
	if err := spec.LoadAndAssign(&objects, nil); err != nil {
		if errors.Is(err, unix.EPERM) {
			t.Skipf("insufficient capability to load Java bridge BPF programs: %v", err)
		}
		require.NoError(t, err)
	}
	return objects
}

func javaRemoteParentFixtureSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()

	spec, err := LoadBpfJavaRemoteParent()
	require.NoError(t, err)
	for _, mapSpec := range spec.Maps {
		mapSpec.Pinning = ebpf.PinNone
	}
	require.NoError(t, ebpfconvenience.RewriteConstants(spec, map[string]any{
		"filter_pids":                   int32(0),
		"g_bpf_debug":                   false,
		"java_remote_parent_enabled":    true,
		"java_remote_parent_max_age_ns": uint64((30 * time.Second).Nanoseconds()),
	}))

	return spec
}

func attachJavaRemoteParentFixture(t *testing.T, programs *BpfJavaRemoteParentPrograms) {
	t.Helper()

	path := currentCgroupV2Path(t)
	setsockoptLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    path,
		Attach:  ebpf.AttachCGroupSetsockopt,
		Program: programs.ObiJavaRemoteParentSetsockopt,
	})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("insufficient capability to attach cgroup setsockopt BPF program: %v", err)
		}
		require.NoError(t, err)
	}
	t.Cleanup(func() { require.NoError(t, setsockoptLink.Close()) })

	getsockoptLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    path,
		Attach:  ebpf.AttachCGroupGetsockopt,
		Program: programs.ObiJavaRemoteParentGetsockopt,
	})
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("insufficient capability to attach cgroup getsockopt BPF program: %v", err)
		}
		require.NoError(t, err)
	}
	t.Cleanup(func() { require.NoError(t, getsockoptLink.Close()) })
}

func attachJavaRemoteParentSockopsFixture(t *testing.T, socketCookies *ebpf.Map) {
	t.Helper()

	spec, err := LoadBpf()
	require.NoError(t, err)
	for _, mapSpec := range spec.Maps {
		mapSpec.Pinning = ebpf.PinNone
	}
	require.NoError(t, ebpfconvenience.RewriteConstants(spec, map[string]any{
		"filter_pids":                int32(0),
		"g_bpf_debug":                false,
		"inject_flags":               uint32(0),
		"java_remote_parent_enabled": true,
	}))

	programs := struct {
		ObiSockmapTracker *ebpf.Program `ebpf:"obi_sockmap_tracker"`
	}{}
	require.NoError(t, spec.LoadAndAssign(&programs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"java_remote_parent_socket_cookies": socketCookies,
		},
	}))
	t.Cleanup(func() { require.NoError(t, programs.ObiSockmapTracker.Close()) })

	path := currentCgroupV2Path(t)
	sockopsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    path,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: programs.ObiSockmapTracker,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, sockopsLink.Close()) })
}

func currentCgroupV2Path(t *testing.T) string {
	t.Helper()

	contents, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	for line := range strings.SplitSeq(strings.TrimSpace(string(contents)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] != "0" || parts[1] != "" {
			continue
		}
		relative := filepath.Clean("/" + strings.TrimPrefix(parts[2], "/"))
		return filepath.Join("/sys/fs/cgroup", relative)
	}
	t.Skip("unified cgroup v2 membership unavailable")
	return ""
}

func currentBridgeIdentities(t *testing.T) (
	BpfJavaRemoteParentPidKeyT,
	BpfJavaRemoteParentPidKeyT,
) {
	t.Helper()

	namespace := currentNamespaceID(t, "/proc/thread-self/ns/pid_for_children")
	pid := uint32(os.Getpid())
	return BpfJavaRemoteParentPidKeyT{Tid: pid, Pid: pid, Ns: namespace},
		BpfJavaRemoteParentPidKeyT{Tid: uint32(unix.Gettid()), Pid: pid, Ns: namespace}
}

func currentNamespaceID(t *testing.T, path string) uint32 {
	t.Helper()

	var stat unix.Stat_t
	require.NoError(t, unix.Stat(path, &stat))
	require.LessOrEqual(t, stat.Ino, uint64(^uint32(0)))
	return uint32(stat.Ino)
}

type tcpPair struct {
	client int
	server int
}

func (p tcpPair) close() {
	_ = unix.Close(p.client)
	_ = unix.Close(p.server)
}

func newTCPListener(t *testing.T) int {
	t.Helper()

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		_ = unix.Close(fd)
		require.NoError(t, err)
	}
	if err := unix.Listen(fd, 8); err != nil {
		_ = unix.Close(fd)
		require.NoError(t, err)
	}
	return fd
}

func connectTCP(t *testing.T, listener int) tcpPair {
	t.Helper()

	client, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	return connectTCPFD(t, listener, client)
}

func connectTCPAtFD(t *testing.T, listener, targetFD int) tcpPair {
	t.Helper()

	client, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	if client != targetFD {
		require.NoError(t, unix.Dup3(client, targetFD, unix.O_CLOEXEC))
		require.NoError(t, unix.Close(client))
		client = targetFD
	}
	return connectTCPFD(t, listener, client)
}

func connectTCPFD(t *testing.T, listener, client int) tcpPair {
	t.Helper()

	address, err := unix.Getsockname(listener)
	if err != nil {
		_ = unix.Close(client)
		require.NoError(t, err)
	}
	if err := unix.Connect(client, address); err != nil {
		_ = unix.Close(client)
		require.NoError(t, err)
	}
	server, _, err := unix.Accept4(listener, unix.SOCK_CLOEXEC)
	if err != nil {
		_ = unix.Close(client)
		require.NoError(t, err)
	}
	return tcpPair{client: client, server: server}
}

func assertStandardSockoptPassThrough(t *testing.T, fd int) {
	t.Helper()

	require.NoError(t, unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_KEEPALIVE, 1))
	value, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_KEEPALIVE)
	require.NoError(t, err)
	assert.Equal(t, 1, value)
}

func assertNativeSockoptMiss(t *testing.T, fd, level, option int) {
	t.Helper()

	_, err := rawGetsockopt(fd, level, option, make([]byte, 8))
	requireNativeSockoptUnsupported(t, err)
}

func assertNativeDataAckMiss(t *testing.T, fd int, nonce uint64) {
	t.Helper()

	requireNativeSockoptUnsupported(t, acknowledgeRemoteParentData(fd, nonce))
}

func assertNativeTakeMiss(t *testing.T, fd int) {
	t.Helper()

	_, err := rawGetsockopt(
		fd, javabridge.SocketLevel, javabridge.SocketTake, make([]byte, javabridge.RecordSize),
	)
	requireNativeSockoptUnsupported(t, err)
}

func assertNativeDiscardMiss(t *testing.T, fd int) {
	t.Helper()

	_, err := rawGetsockopt(
		fd, javabridge.SocketLevel, javabridge.SocketDiscard, make([]byte, javabridge.RecordSize),
	)
	requireNativeSockoptUnsupported(t, err)
}

func requireNativeSockoptUnsupported(t *testing.T, err error) {
	t.Helper()

	require.True(t,
		errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EOPNOTSUPP),
		"expected native socket-option unsupported error, got %v",
		err,
	)
}

func rawSetsockoptUint64(fd, level, option int, value uint64) error {
	encoded := make([]byte, 8)
	binary.LittleEndian.PutUint64(encoded, value)
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(option),
		uintptr(unsafe.Pointer(&encoded[0])),
		uintptr(len(encoded)),
		0,
	)
	runtime.KeepAlive(encoded)
	if errno != 0 {
		return errno
	}
	return nil
}

func rawGetsockopt(fd, level, option int, value []byte) (int, error) {
	length := uint32(len(value))
	var valuePointer unsafe.Pointer
	if len(value) != 0 {
		valuePointer = unsafe.Pointer(&value[0])
	}
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(option),
		uintptr(valuePointer),
		uintptr(unsafe.Pointer(&length)),
		0,
	)
	runtime.KeepAlive(value)
	if errno != 0 {
		return int(length), errno
	}
	return int(length), nil
}

func assertInvalidRecordSizesPreserveGeneration(
	t *testing.T,
	fd int,
	states *ebpf.Map,
	owner BpfJavaRemoteParentPidKeyT,
	generation uint64,
) {
	t.Helper()

	for _, option := range []int{javabridge.SocketTake, javabridge.SocketDiscard} {
		for _, size := range []int{int(javabridge.RecordSize) - 1, int(javabridge.RecordSize) + 1} {
			_, err := rawGetsockopt(fd, javabridge.SocketLevel, option, make([]byte, size))
			requireNativeSockoptUnsupported(t, err)
			assertGenerationPresent(t, states, owner, generation)
		}
	}
}

func assertUnrelatedProcessCannotRetrieve(t *testing.T, fd int) {
	t.Helper()

	duplicate, err := unix.Dup(fd)
	require.NoError(t, err)
	extraFile := os.NewFile(uintptr(duplicate), "java-remote-parent-socket")
	require.NotNil(t, extraFile)

	command := exec.Command(
		os.Args[0], "-test.run=^TestJavaRemoteParentUnauthorizedProcessHelper$", "-test.v",
	)
	command.Env = append(os.Environ(), unauthorizedHelperEnv+"=1")
	command.ExtraFiles = []*os.File{extraFile}
	output, commandErr := command.CombinedOutput()
	closeErr := extraFile.Close()
	require.NoError(t, closeErr)
	require.NoErrorf(t, commandErr, "unrelated-process helper failed:\n%s", output)
}

func assertValidDiscard(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	capability uint64,
	negotiation BpfJavaRemoteParentJavaRemoteParentNegotiationT,
	fd int,
) {
	t.Helper()

	const generation = uint64(42)
	const nonce = uint64(0x2132435465768798)
	stageRemoteParent(t,
		maps,
		process,
		owner,
		capability,
		negotiation.Connection,
		negotiation.ConnectionNetns,
		socketCookie(t, fd),
		generation,
		nonce,
	)
	require.NoError(t, acknowledgeRemoteParentData(fd, nonce))

	statsBefore := javaRemoteParentStats(t, maps.JavaRemoteParentStats)
	value := make([]byte, javabridge.RecordSize)
	length, err := rawGetsockopt(fd, javabridge.SocketLevel, javabridge.SocketDiscard, value)
	require.NoError(t, err)
	require.Equal(t, len(value), length)
	record, err := javabridge.UnmarshalRecord(value)
	require.NoError(t, err)
	assert.Equal(t, javabridge.StatusMissing, record.Status)
	assert.Equal(t, generation, record.Generation)
	assertGenerationMissing(t, maps.JavaRemoteParentState, owner, generation)

	var terminal BpfJavaRemoteParentJavaRemoteParentTerminalT
	require.NoError(t, maps.JavaRemoteParentTerminal.Lookup(owner, &terminal))
	assert.Equal(t, generation, terminal.Generation)
	assert.Equal(t, bridgeLifecycleDiscarded, terminal.Lifecycle)

	statsAfter := javaRemoteParentStats(t, maps.JavaRemoteParentStats)
	assert.Equal(t,
		statsBefore[javaRemoteParentStatDiscardValid]+1,
		statsAfter[javaRemoteParentStatDiscardValid],
	)
}

func javaRemoteParentStats(t *testing.T, stats *ebpf.Map) [javaRemoteParentStatCount]uint64 {
	t.Helper()

	values, err := readJavaRemoteParentStats(stats)
	require.NoError(t, err)
	return values
}

func assertStaleRemoteParent(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	capability uint64,
	negotiation BpfJavaRemoteParentJavaRemoteParentNegotiationT,
	fd int,
) {
	t.Helper()

	const generation = uint64(43)
	const nonce = uint64(0x0011223344556677)
	const staleAge = 31 * time.Second
	now := monotonicNowNS(t)
	require.Greater(t, now, uint64(staleAge.Nanoseconds()))
	stageRemoteParentAt(t,
		maps,
		process,
		owner,
		capability,
		negotiation.Connection,
		negotiation.ConnectionNetns,
		socketCookie(t, fd),
		generation,
		nonce,
		now-uint64(staleAge.Nanoseconds()),
	)
	require.NoError(t, acknowledgeRemoteParentData(fd, nonce))

	record := takeRemoteParent(t, fd)
	assert.Equal(t, javabridge.StatusStale, record.Status)
	assert.Equal(t, generation, record.Generation)
	assertGenerationMissing(t, maps.JavaRemoteParentState, owner, generation)
}

func assertVersionMismatchedRemoteParent(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	capability uint64,
	negotiation BpfJavaRemoteParentJavaRemoteParentNegotiationT,
	fd int,
) {
	t.Helper()

	const generation = uint64(44)
	const nonce = uint64(0x1021324354657687)
	stageRemoteParent(t,
		maps,
		process,
		owner,
		capability,
		negotiation.Connection,
		negotiation.ConnectionNetns,
		socketCookie(t, fd),
		generation,
		nonce,
	)
	require.NoError(t, acknowledgeRemoteParentData(fd, nonce))

	key := BpfJavaRemoteParentJavaRemoteParentKeyT{Owner: owner, Generation: generation}
	var state BpfJavaRemoteParentJavaRemoteParentStateT
	require.NoError(t, maps.JavaRemoteParentState.Lookup(key, &state))
	state.Response.VersionLe = javabridge.Version + 1
	require.NoError(t, maps.JavaRemoteParentState.Update(key, state, ebpf.UpdateExist))

	value := takeRemoteParentBytes(t, fd)
	_, err := javabridge.UnmarshalRecord(value)
	require.ErrorIs(t, err, javabridge.ErrVersionMismatch)
	assertGenerationMissing(t, maps.JavaRemoteParentState, owner, generation)
}

func assertConcurrentTakeIsOneShot(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	capability uint64,
	negotiation BpfJavaRemoteParentJavaRemoteParentNegotiationT,
	fd int,
) {
	t.Helper()

	const (
		concurrentTakeWorkers = 2
		generation            = uint64(45)
		nonce                 = uint64(0x98a9bacbdcedfe0f)
	)
	stageRemoteParent(t,
		maps,
		process,
		owner,
		capability,
		negotiation.Connection,
		negotiation.ConnectionNetns,
		socketCookie(t, fd),
		generation,
		nonce,
	)
	require.NoError(t, acknowledgeRemoteParentData(fd, nonce))
	statsBefore := javaRemoteParentStats(t, maps.JavaRemoteParentStats)

	type takeResult struct {
		value  []byte
		length int
		err    error
	}
	ready := make(chan uint32, concurrentTakeWorkers)
	start := make(chan struct{})
	results := make(chan takeResult, concurrentTakeWorkers)
	for range concurrentTakeWorkers {
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ready <- uint32(unix.Gettid())
			<-start

			value := make([]byte, javabridge.RecordSize)
			length, err := rawGetsockopt(
				fd, javabridge.SocketLevel, javabridge.SocketTaskTake, value,
			)
			results <- takeResult{value: value, length: length, err: err}
		}()
	}

	observed := monotonicNowNS(t)
	workerKeys := make([]BpfJavaRemoteParentPidKeyT, 0, concurrentTakeWorkers)
	for range concurrentTakeWorkers {
		worker := BpfJavaRemoteParentPidKeyT{
			Tid: <-ready,
			Pid: process.Pid,
			Ns:  process.Ns,
		}
		workerKeys = append(workerKeys, worker)
	}

	stateKey := BpfJavaRemoteParentJavaRemoteParentKeyT{
		Owner:      owner,
		Generation: generation,
	}
	var state BpfJavaRemoteParentJavaRemoteParentStateT
	require.NoError(t, maps.JavaRemoteParentState.Lookup(stateKey, &state))
	state.Aliases = uint32(len(workerKeys))
	require.NoError(t, maps.JavaRemoteParentState.Update(stateKey, state, ebpf.UpdateExist))

	for _, worker := range workerKeys {
		require.NoError(t, maps.JavaRemoteParentTasks.Update(worker,
			BpfJavaRemoteParentJavaRemoteParentTaskT{
				Owner:              owner,
				Generation:         generation,
				ObservedMonotimeNs: observed,
			}, ebpf.UpdateAny))
	}
	close(start)

	valid := 0
	for range concurrentTakeWorkers {
		result := <-results
		require.NoError(t, result.err)
		require.Equal(t, int(javabridge.RecordSize), result.length)
		record, err := javabridge.UnmarshalRecord(result.value)
		require.NoError(t, err)
		if record.Status == javabridge.StatusValid {
			valid++
			continue
		}
		require.Contains(t,
			[]javabridge.Status{javabridge.StatusAlreadyConsumed, javabridge.StatusMissing},
			record.Status,
		)
	}
	require.Equal(t, 1, valid)
	statsAfter := javaRemoteParentStats(t, maps.JavaRemoteParentStats)
	assert.Equal(t,
		statsBefore[javaRemoteParentStatHandoffValid]+1,
		statsAfter[javaRemoteParentStatHandoffValid],
	)
	for _, worker := range workerKeys {
		require.NoError(t, maps.JavaRemoteParentTasks.Delete(worker))
	}
	assertGenerationMissing(t, maps.JavaRemoteParentState, owner, generation)
}

func setJavaRemoteParentDataHookReadiness(t *testing.T, readiness *ebpf.Map, ready bool) {
	t.Helper()

	key := uint32(0)
	state := uint32(0)
	if ready {
		state = 1
	}
	require.NoError(t, readiness.Update(&key, &state, ebpf.UpdateAny))
}

func javaRemoteParentHealthValue(t *testing.T, fd int) uint64 {
	t.Helper()

	value := make([]byte, 8)
	length, err := rawGetsockopt(fd, javabridge.SocketLevel, javabridge.SocketHealth, value)
	require.NoError(t, err)
	require.Equal(t, len(value), length)
	return binary.LittleEndian.Uint64(value)
}

func socketNegotiation(
	t *testing.T,
	storage *ebpf.Map,
	fd int,
) BpfJavaRemoteParentJavaRemoteParentNegotiationT {
	t.Helper()

	var negotiation BpfJavaRemoteParentJavaRemoteParentNegotiationT
	require.NoError(t, storage.Lookup(uint32(fd), &negotiation))
	return negotiation
}

func socketCookie(t *testing.T, fd int) uint64 {
	t.Helper()

	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	require.NoError(t, err)
	require.NotZero(t, cookie)
	return cookie
}

func seedJavaRemoteParentSocketCookie(t *testing.T, storage *ebpf.Map, fd int) uint64 {
	t.Helper()

	cookie := socketCookie(t, fd)
	require.NoError(t, storage.Update(uint32(fd), cookie, ebpf.UpdateAny))
	var stored uint64
	require.NoError(t, storage.Lookup(uint32(fd), &stored))
	require.Equal(t, cookie, stored)
	return cookie
}

func assertSocketNegotiationMissing(t *testing.T, storage *ebpf.Map, fd int) {
	t.Helper()

	var negotiation BpfJavaRemoteParentJavaRemoteParentNegotiationT
	assert.ErrorIs(t, storage.Lookup(uint32(fd), &negotiation), ebpf.ErrKeyNotExist)
}

func acknowledgeFromNewNetworkNamespace(fd int, nonce uint64) (error, error) {
	type acknowledgementResult struct {
		acknowledgement error
		setup           error
	}
	results := make(chan acknowledgementResult, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			results <- acknowledgementResult{setup: err}
			return
		}

		results <- acknowledgementResult{acknowledgement: acknowledgeRemoteParentData(fd, nonce)}
		// Leave the goroutine locked so the runtime discards its isolated OS
		// thread, including the new network namespace, when it returns.
	}()

	acknowledgement := <-results
	return acknowledgement.acknowledgement, acknowledgement.setup
}

func stageRemoteParent(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	capability uint64,
	connection BpfJavaRemoteParentConnectionInfoT,
	netns uint32,
	socketCookie uint64,
	generation uint64,
	nonce uint64,
) {
	t.Helper()

	stageRemoteParentAt(t,
		maps,
		process,
		owner,
		capability,
		connection,
		netns,
		socketCookie,
		generation,
		nonce,
		monotonicNowNS(t),
	)
}

func stageRemoteParentAt(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	capability uint64,
	connection BpfJavaRemoteParentConnectionInfoT,
	netns uint32,
	socketCookie uint64,
	generation uint64,
	nonce uint64,
	observed uint64,
) {
	t.Helper()
	require.NotZero(t, socketCookie)

	record := BpfJavaRemoteParentJavaRemoteParentResponseT{
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
	key := BpfJavaRemoteParentJavaRemoteParentKeyT{Owner: owner, Generation: generation}
	connectionKey := BpfJavaRemoteParentConnectionInfoNsT{
		Connection: connection,
		Netns:      netns,
	}
	netnsCookie := remoteParentTestNetNSCookie(netns, generation)
	cookieConnectionKey := BpfJavaRemoteParentConnectionInfoNetnsCookieT{
		Connection:  connection,
		NetnsCookie: netnsCookie,
	}
	connectionValue := BpfJavaRemoteParentJavaRemoteParentConnectionT{
		Owner:              owner,
		Generation:         generation,
		NetnsCookie:        netnsCookie,
		IncomingGeneration: generation,
		SocketCookie:       socketCookie,
		Netns:              netns,
	}

	require.NoError(t, maps.JavaRemoteParentState.Update(key,
		BpfJavaRemoteParentJavaRemoteParentStateT{
			Lifecycle:          bridgeLifecycleActive,
			ObservedMonotimeNs: observed,
			Connection:         connection,
			ConnectionNetns:    netns,
			ProcessIncarnation: capability,
			Response:           record,
		}, ebpf.UpdateNoExist))
	require.NoError(t, maps.JavaRemoteParentGenerationIndex.Update(key,
		BpfJavaRemoteParentJavaRemoteParentGenerationIndexT{
			Process:            process,
			ProcessIncarnation: capability,
			ObservedMonotimeNs: observed,
		}, ebpf.UpdateNoExist))
	require.NoError(t, maps.JavaRemoteParentConnections.Update(
		connectionKey, connectionValue, ebpf.UpdateNoExist))
	require.NoError(t, maps.JavaRemoteParentCookieConnections.Update(
		cookieConnectionKey, connectionValue, ebpf.UpdateNoExist))
	require.NoError(t, maps.JavaRemoteParentFallback.Update(owner, record, ebpf.UpdateNoExist))
	require.NoError(t, maps.JavaRemoteParentOwners.Update(owner,
		BpfJavaRemoteParentJavaRemoteParentOwnerT{
			Generation:         generation,
			ProcessIncarnation: capability,
			Lifecycle:          bridgeLifecycleActive,
		}, ebpf.UpdateNoExist))
	require.NoError(t, maps.JavaRemoteParentDataSignals.Update(
		process, nonce, ebpf.UpdateAny,
	))

	updateDataAck(t,
		maps.JavaRemoteParentDataAcks,
		process,
		owner,
		connection,
		netns,
		generation,
		nonce,
	)
}

func remoteParentTestNetNSCookie(netns uint32, generation uint64) uint64 {
	cookie := uint64(netns)<<32 ^ generation
	if cookie == 0 {
		return 1
	}

	return cookie
}

func monotonicNowNS(t *testing.T) uint64 {
	t.Helper()

	var monotonic unix.Timespec
	require.NoError(t, unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic))
	return uint64(monotonic.Nano())
}

func updateDataAck(
	t *testing.T,
	dataAcks *ebpf.Map,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	connection BpfJavaRemoteParentConnectionInfoT,
	netns uint32,
	generation uint64,
	nonce uint64,
) {
	t.Helper()

	key := BpfJavaRemoteParentJavaRemoteParentDataSignalKeyT{
		Process: process,
		Nonce:   nonce,
	}
	value := BpfJavaRemoteParentJavaRemoteParentDataAckT{
		Owner:           owner,
		Generation:      generation,
		Connection:      connection,
		ConnectionNetns: netns,
	}
	require.NoError(t, dataAcks.Update(key, value, ebpf.UpdateAny))
}

func acknowledgeRemoteParentData(fd int, nonce uint64) error {
	return rawSetsockoptUint64(fd, javabridge.SocketLevel, javabridge.SocketDataAck, nonce)
}

func takeRemoteParent(t *testing.T, fd int) javabridge.Record {
	t.Helper()

	value := takeRemoteParentBytes(t, fd)
	record, err := javabridge.UnmarshalRecord(value)
	require.NoError(t, err)
	return record
}

func takeRemoteParentBytes(t *testing.T, fd int) []byte {
	t.Helper()

	value := make([]byte, javabridge.RecordSize)
	length, err := rawGetsockopt(fd, javabridge.SocketLevel, javabridge.SocketTake, value)
	require.NoError(t, err)
	require.Equal(t, len(value), length)
	return value
}

func assertGenerationPresent(
	t *testing.T,
	states *ebpf.Map,
	owner BpfJavaRemoteParentPidKeyT,
	generation uint64,
) {
	t.Helper()

	key := BpfJavaRemoteParentJavaRemoteParentKeyT{Owner: owner, Generation: generation}
	var state BpfJavaRemoteParentJavaRemoteParentStateT
	require.NoError(t, states.Lookup(key, &state))
}

func assertGenerationMissing(
	t *testing.T,
	states *ebpf.Map,
	owner BpfJavaRemoteParentPidKeyT,
	generation uint64,
) {
	t.Helper()

	key := BpfJavaRemoteParentJavaRemoteParentKeyT{Owner: owner, Generation: generation}
	var state BpfJavaRemoteParentJavaRemoteParentStateT
	assert.ErrorIs(t, states.Lookup(key, &state), ebpf.ErrKeyNotExist)
}
