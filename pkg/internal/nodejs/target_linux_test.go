// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs

import (
	"debug/elf"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	execpkg "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
)

func exactNodeTestInjector() *NodeInjector {
	cfg := obi.DefaultConfig
	cfg.NodeJS.Enabled = true
	cfg.TracePrinter = debug.TracePrinterText
	return NewNodeInjector(&cfg)
}

func testNodeOwner(t *testing.T, pid app.PID) *execpkg.FileInfo {
	t.Helper()
	handle, err := os.Open(t.TempDir())
	require.NoError(t, err)
	owner := execpkg.New(execpkg.Init{
		Pid:           pid,
		Dev:           11,
		Ino:           22,
		ProcessStart:  33,
		ProcessHandle: handle,
	})
	t.Cleanup(func() { require.NoError(t, owner.CloseProcessHandle()) })
	return owner
}

func duplicateTestFile(t *testing.T, file *os.File) int {
	t.Helper()
	fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	require.NoError(t, err)
	return fd
}

func TestPrepareExactNodeTargetUsesEventOwnerAndBindingOrder(t *testing.T) {
	previous := nodeTargetOps
	t.Cleanup(func() { nodeTargetOps = previous })

	anchor, err := os.Open("/dev/null")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, anchor.Close()) })

	const (
		parentPID = app.PID(101)
		eventPID  = app.PID(202)
	)
	parent := execpkg.New(execpkg.Init{Pid: parentPID, Dev: 44, Ino: 55})
	owner := testNodeOwner(t, eventPID)
	var sequence []string
	var pidfdPID int
	var closed []int
	nodeTargetOps = exactNodeTargetOps{
		duplicateProcFD: func(int) (int, error) {
			sequence = append(sequence, "duplicate-procfd")
			return duplicateTestFile(t, anchor), nil
		},
		validateProc: func(_ int, pid app.PID, start, dev, ino uint64) error {
			sequence = append(sequence, "validate-proc")
			assert.Equal(t, eventPID, pid)
			assert.Equal(t, uint64(33), start)
			assert.Equal(t, uint64(11), dev)
			assert.Equal(t, uint64(22), ino)
			return nil
		},
		openPIDFD: func(pid, _ int) (int, error) {
			sequence = append(sequence, "pidfd-open")
			pidfdPID = pid
			return duplicateTestFile(t, anchor), nil
		},
		openNetNS: func(int) (int, error) {
			sequence = append(sequence, "open-netns-from-procfd")
			return duplicateTestFile(t, anchor), nil
		},
		validateNetNS: func(int, int) error {
			sequence = append(sequence, "validate-netns")
			return nil
		},
		validatePIDFD: func(int) error {
			sequence = append(sequence, "validate-pidfd")
			return nil
		},
		openExecutable: func(int, uint64, uint64) (*elf.File, *os.File, error) {
			sequence = append(sequence, "open-executable-from-procfd")
			return nil, nil, nil
		},
		withNetNS: func(_ int, fn func() error) error { return fn() },
		closeFD: func(fd int) error {
			closed = append(closed, fd)
			return unix.Close(fd)
		},
	}

	prepared, err := exactNodeTestInjector().PrepareExecutable(&ebpf.Instrumentable{
		Type:     svc.InstrumentableNodejs,
		FileInfo: parent,
		PIDOwner: owner,
	})
	require.NoError(t, err)
	require.NotNil(t, prepared)
	assert.Equal(t, int(eventPID), pidfdPID)
	assert.Equal(t, []string{
		"duplicate-procfd",
		"validate-proc",
		"pidfd-open",
		"open-netns-from-procfd",
		"validate-proc",
		"validate-netns",
		"validate-pidfd",
		"open-executable-from-procfd",
		"validate-proc",
		"validate-netns",
		"validate-pidfd",
		"validate-proc",
	}, sequence)

	require.NoError(t, prepared.Close())
	require.NoError(t, prepared.Close(), "prepared cleanup must be idempotent")
	assert.Len(t, closed, 3, "procfd, pidfd, and netns fd must each close exactly once")
	require.NoError(t, owner.UseProcessHandle(func(int) error { return nil }),
		"closing the prepared operation must not retire the discovery owner's handle")
}

func TestPrepareExactNodeTargetRejectsPIDReuseAndClosesEveryPinnedFD(t *testing.T) {
	previous := nodeTargetOps
	t.Cleanup(func() { nodeTargetOps = previous })

	anchor, err := os.Open("/dev/null")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, anchor.Close()) })
	owner := testNodeOwner(t, 303)
	validation := 0
	var opened []int
	duplicate := func() int {
		fd := duplicateTestFile(t, anchor)
		opened = append(opened, fd)
		return fd
	}
	nodeTargetOps = exactNodeTargetOps{
		duplicateProcFD: func(int) (int, error) { return duplicate(), nil },
		validateProc: func(int, app.PID, uint64, uint64, uint64) error {
			validation++
			if validation == 2 {
				return errors.New("original procfd is no longer live after PID reuse")
			}
			return nil
		},
		openPIDFD:     func(int, int) (int, error) { return duplicate(), nil },
		openNetNS:     func(int) (int, error) { return duplicate(), nil },
		validateNetNS: func(int, int) error { return nil },
		validatePIDFD: func(int) error { return nil },
		openExecutable: func(int, uint64, uint64) (*elf.File, *os.File, error) {
			t.Fatal("executable must not open after the post-pidfd owner check fails")
			return nil, nil, nil
		},
		closeFD: unix.Close,
	}

	prepared, err := exactNodeTestInjector().PrepareExecutable(&ebpf.Instrumentable{
		Type:     svc.InstrumentableNodejs,
		FileInfo: owner,
		PIDOwner: owner,
	})
	require.ErrorContains(t, err, "no longer live after PID reuse")
	assert.Nil(t, prepared)
	require.Len(t, opened, 3)
	for _, fd := range opened {
		_, fdErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		assert.ErrorIs(t, fdErr, unix.EBADF, "failed preparation leaked fd %d", fd)
	}
}

func TestExactNodeExecutableRealFileHasOneIdempotentCloseOwner(t *testing.T) {
	procDir, err := os.Open("/proc/self")
	require.NoError(t, err)
	defer procDir.Close()
	dev, ino, err := procs.ExecutableIdentityFromProcFD(int(procDir.Fd()))
	require.NoError(t, err)
	elfFile, exeFile, err := openExactNodeExecutable(int(procDir.Fd()), dev, ino)
	require.NoError(t, err)
	require.NotNil(t, elfFile)
	require.NotNil(t, exeFile)

	operation := &exactNodeExecutable{
		ops:     nodeTargetOps,
		procFD:  -1,
		pidFD:   -1,
		netNSFD: -1,
		elfFile: elfFile,
		exeFile: exeFile,
	}
	require.NoError(t, operation.Close())
	require.NoError(t, operation.Close())
	_, err = exeFile.Stat()
	assert.ErrorIs(t, err, os.ErrClosed)
}

func TestInspectorSocketOwnershipRequiresExactRosterAndConnectionTuple(t *testing.T) {
	loopback := netip.MustParseAddr("127.0.0.1")
	unspecified := netip.MustParseAddr("0.0.0.0")
	client := tcpEndpoint{address: loopback, port: 45123}
	server := tcpEndpoint{address: loopback, port: nodeInspectorPort}
	listener := procTCPSocket{
		local: tcpEndpoint{address: unspecified, port: nodeInspectorPort},
		state: 0x0a,
		inode: 77,
	}
	accepted := procTCPSocket{
		local:  server,
		remote: client,
		state:  0x01,
		inode:  88,
	}

	assert.False(t, inspectorSocketOwned(
		map[uint64]struct{}{99: {}},
		[]procTCPSocket{listener, accepted},
		client,
		server,
		false,
	), "a listener in the same netns but outside the exact fd roster is not authorized")
	assert.True(t, inspectorSocketOwned(
		map[uint64]struct{}{77: {}},
		[]procTCPSocket{listener},
		client,
		server,
		false,
	), "the exact target's listener authorizes only pre-CDP inspector discovery")
	assert.False(t, inspectorSocketOwned(
		map[uint64]struct{}{77: {}},
		[]procTCPSocket{listener},
		client,
		server,
		true,
	), "Runtime.evaluate requires the accepted connection, not merely a listener")
	assert.True(t, inspectorSocketOwned(
		map[uint64]struct{}{88: {}},
		[]procTCPSocket{accepted},
		client,
		server,
		true,
	))
	accepted.remote.port++
	assert.False(t, inspectorSocketOwned(
		map[uint64]struct{}{88: {}},
		[]procTCPSocket{accepted},
		client,
		server,
		true,
	), "an exact target socket for a different connection cannot authorize CDP")
}

func TestParseProcNetTCPPreservesIPv4TupleAndInode(t *testing.T) {
	sockets, err := parseProcNetTCP(strings.NewReader(
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
			"   0: 0100007F:240D 0100007F:B043 01 00000000:00000000 00:00000000 00000000  1000 0 4242 1\n",
	))
	require.NoError(t, err)
	require.Len(t, sockets, 1)
	assert.Equal(t, tcpEndpoint{address: netip.MustParseAddr("127.0.0.1"), port: 9229}, sockets[0].local)
	assert.Equal(t, tcpEndpoint{address: netip.MustParseAddr("127.0.0.1"), port: 45123}, sockets[0].remote)
	assert.Equal(t, uint8(1), sockets[0].state)
	assert.Equal(t, uint64(4242), sockets[0].inode)
}

func TestExactTargetSocketProofUsesLiveProcFDRoster(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, listener.Close()) })

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	var server net.Conn
	select {
	case err := <-acceptErr:
		require.NoError(t, err)
	case server = <-accepted:
		t.Cleanup(func() { require.NoError(t, server.Close()) })
	case <-time.After(time.Second):
		t.Fatal("timed out accepting local exact-owner test connection")
	}

	procDir, err := os.Open("/proc/self")
	require.NoError(t, err)
	defer procDir.Close()
	expectedRemote, err := tcpEndpointFromAddr(client.RemoteAddr())
	require.NoError(t, err)
	owned, err := exactTargetOwnsSocket(int(procDir.Fd()), client, true, expectedRemote)
	require.NoError(t, err)
	assert.True(t, owned,
		"the server-side accepted socket must be found in the exact procfd roster and netns table")
}
