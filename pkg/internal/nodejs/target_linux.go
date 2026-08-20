// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	discexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/netns"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const (
	nodeInspectorAddress = "127.0.0.1"
	nodeInspectorPort    = 9229
	nodeInspectorWait    = 5 * time.Second
	nodeInspectorPoll    = 200 * time.Millisecond
	linuxTaskFlagExiting = 0x00000004
)

type exactNodeTargetOps struct {
	duplicateProcFD func(int) (int, error)
	validateProc    func(int, app.PID, uint64, uint64, uint64) error
	openPIDFD       func(int, int) (int, error)
	openNetNS       func(int) (int, error)
	validateNetNS   func(int, int) error
	validatePIDFD   func(int) error
	openExecutable  func(int, uint64, uint64) (*elf.File, *os.File, error)
	withNetNS       func(int, func() error) error
	sendSignal      func(int, syscall.Signal, *unix.Siginfo, int) error
	closeFD         func(int) error
}

var nodeTargetOps = exactNodeTargetOps{
	duplicateProcFD: duplicateNodeProcFD,
	validateProc:    validateExactNodeProc,
	openPIDFD:       unix.PidfdOpen,
	openNetNS:       openExactNodeNetNS,
	validateNetNS:   validateExactNodeNetNS,
	validatePIDFD:   validateExactNodePIDFD,
	openExecutable:  openExactNodeExecutable,
	withNetNS:       netns.WithNetNSFD,
	sendSignal:      unix.PidfdSendSignal,
	closeFD:         unix.Close,
}

type exactNodeExecutable struct {
	mu sync.Mutex

	injector *NodeInjector
	ops      exactNodeTargetOps
	pid      app.PID
	start    uint64
	dev      uint64
	ino      uint64
	procFD   int
	pidFD    int
	netNSFD  int
	elfFile  *elf.File
	exeFile  *os.File
	closed   bool
}

func (i *NodeInjector) prepareExactExecutable(
	_ *ebpf.Instrumentable,
	owner *discexec.FileInfo,
) (PreparedExecutable, error) {
	if owner == nil || owner.Pid() <= 0 || owner.ProcessStartTime() == 0 ||
		owner.Dev() == 0 || owner.Ino() == 0 {
		return nil, errors.New(
			"exact Node.js target requires PID, process start time, and executable identity",
		)
	}

	operation := &exactNodeExecutable{
		injector: i,
		ops:      nodeTargetOps,
		pid:      owner.Pid(),
		start:    owner.ProcessStartTime(),
		dev:      owner.Dev(),
		ino:      owner.Ino(),
		procFD:   -1,
		pidFD:    -1,
		netNSFD:  -1,
	}

	if err := owner.UseProcessHandle(func(sourceFD int) error {
		duplicate, err := operation.ops.duplicateProcFD(sourceFD)
		if err != nil {
			return fmt.Errorf("duplicate exact Node.js proc directory: %w", err)
		}
		operation.procFD = duplicate
		return nil
	}); err != nil {
		return nil, fmt.Errorf("pin exact Node.js proc directory: %w", err)
	}

	fail := func(err error) (PreparedExecutable, error) {
		return nil, errors.Join(err, operation.Close())
	}
	if err := operation.validateProc(); err != nil {
		return fail(err)
	}

	pidfd, err := operation.ops.openPIDFD(int(operation.pid), 0)
	if err != nil {
		return fail(fmt.Errorf(
			"exact Node.js injection requires pidfd_open support: %w",
			err,
		))
	}
	operation.pidFD = pidfd

	// Open the namespace through the already pinned proc directory. Resolving
	// /proc/<pid>/ns/net here would let a recycled numeric PID redirect it.
	netnsfd, err := operation.ops.openNetNS(operation.procFD)
	if err != nil {
		return fail(fmt.Errorf("open exact Node.js network namespace: %w", err))
	}
	operation.netNSFD = netnsfd

	// The second proc validation closes the pidfd_open race: if the original
	// owner exited and the numeric PID was recycled, its pinned proc directory
	// is no longer live even though pidfd_open may have found the replacement.
	if err := operation.validateProc(); err != nil {
		return fail(err)
	}
	if err := operation.validateNetNS(); err != nil {
		return fail(err)
	}
	if err := operation.validatePIDFD(); err != nil {
		return fail(err)
	}

	elfFile, exeFile, err := operation.ops.openExecutable(
		operation.procFD,
		operation.dev,
		operation.ino,
	)
	if err != nil {
		return fail(fmt.Errorf("open exact Node.js executable: %w", err))
	}
	operation.elfFile = elfFile
	operation.exeFile = exeFile

	if err := operation.validate(); err != nil {
		return fail(err)
	}
	return operation, nil
}

func duplicateNodeProcFD(sourceFD int) (int, error) {
	return unix.FcntlInt(uintptr(sourceFD), unix.F_DUPFD_CLOEXEC, 0)
}

func openExactNodeNetNS(procFD int) (int, error) {
	return unix.Openat(procFD, "ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
}

func validateExactNodeProc(procFD int, pid app.PID, start, dev, ino uint64) error {
	currentPID, _, currentStart, state, flags, err := procs.ProcessStatWithFlagsFromProcFD(procFD)
	if err != nil {
		return fmt.Errorf("read exact Node.js process identity: %w", err)
	}
	if currentPID != pid || currentStart != start || state == 'Z' || state == 'X' ||
		state == 'x' || flags&linuxTaskFlagExiting != 0 {
		return fmt.Errorf(
			"exact Node.js process changed: got PID %d start %d state %q flags %#x, expected PID %d start %d",
			currentPID,
			currentStart,
			state,
			flags,
			pid,
			start,
		)
	}
	currentDev, currentIno, err := procs.ExecutableIdentityFromProcFD(procFD)
	if err != nil {
		return fmt.Errorf("read exact Node.js executable identity: %w", err)
	}
	if currentDev != dev || currentIno != ino {
		return fmt.Errorf(
			"exact Node.js executable changed: got dev %d inode %d, expected dev %d inode %d",
			currentDev,
			currentIno,
			dev,
			ino,
		)
	}
	return nil
}

func validateExactNodePIDFD(pidfd int) error {
	if pidfd < 0 {
		return errors.New("exact Node.js pidfd is unavailable")
	}
	pollFD := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	if _, err := unix.Poll(pollFD, 0); err != nil {
		return fmt.Errorf("poll exact Node.js pidfd: %w", err)
	}
	if pollFD[0].Revents&unix.POLLNVAL != 0 {
		return syscall.EBADF
	}
	if pollFD[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 {
		return errors.New("exact Node.js target exited")
	}
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		return fmt.Errorf(
			"exact Node.js injection requires pidfd_send_signal support: %w",
			err,
		)
	}
	return nil
}

func validateExactNodeNetNS(procFD, netNSFD int) error {
	var current, pinned unix.Stat_t
	if err := unix.Fstatat(procFD, "ns/net", &current, 0); err != nil {
		return fmt.Errorf("stat current exact Node.js netns: %w", err)
	}
	if err := unix.Fstat(netNSFD, &pinned); err != nil {
		return fmt.Errorf("stat pinned exact Node.js netns: %w", err)
	}
	if current.Dev != pinned.Dev || current.Ino != pinned.Ino {
		return errors.New("exact Node.js target changed network namespaces")
	}
	return nil
}

func openExactNodeExecutable(
	procFD int,
	expectedDev, expectedIno uint64,
) (*elf.File, *os.File, error) {
	fd, err := unix.Openat(procFD, "exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), "exact-node-executable")
	if file == nil {
		_ = unix.Close(fd)
		return nil, nil, errors.New("create exact Node.js executable file")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	if stat.Dev != expectedDev || stat.Ino != expectedIno {
		return nil, nil, errors.Join(fmt.Errorf(
			"opened Node.js executable is dev %d inode %d, expected dev %d inode %d",
			stat.Dev,
			stat.Ino,
			expectedDev,
			expectedIno,
		), file.Close())
	}
	elfFile, err := elf.NewFile(file)
	if err != nil {
		return nil, nil, errors.Join(err, file.Close())
	}
	return elfFile, file, nil
}

func (p *exactNodeExecutable) validateProc() error {
	return p.ops.validateProc(p.procFD, p.pid, p.start, p.dev, p.ino)
}

func (p *exactNodeExecutable) validatePIDFD() error {
	return p.ops.validatePIDFD(p.pidFD)
}

func (p *exactNodeExecutable) validateNetNS() error {
	return p.ops.validateNetNS(p.procFD, p.netNSFD)
}

func (p *exactNodeExecutable) validate() error {
	if err := p.validateProc(); err != nil {
		return err
	}
	if err := p.validateNetNS(); err != nil {
		return err
	}
	if err := p.validatePIDFD(); err != nil {
		return err
	}
	return p.validateProc()
}

func (p *exactNodeExecutable) NewExecutable() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("exact Node.js target is closed")
	}
	return p.ops.withNetNS(p.netNSFD, func() error {
		if err := p.validate(); err != nil {
			return err
		}
		return p.injectFile()
	})
}

func (p *exactNodeExecutable) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true

	var closeErr error
	// openExactNodeExecutable builds elfFile with elf.NewFile, which does not
	// own or close its ReaderAt. exeFile is the sole close owner.
	p.elfFile = nil
	if p.exeFile != nil {
		closeErr = errors.Join(closeErr, p.exeFile.Close())
		p.exeFile = nil
	}
	for _, fd := range []*int{&p.netNSFD, &p.pidFD, &p.procFD} {
		if *fd < 0 {
			continue
		}
		closeErr = errors.Join(closeErr, p.ops.closeFD(*fd))
		*fd = -1
	}
	return closeErr
}

// injectFile first considers an existing inspector. It does not send even a
// version request until the port is proven to belong to this exact target.
// Before Runtime.evaluate, the accepted TCP socket itself must be present in
// the target's procfd-anchored descriptor roster and netns socket table.
func (p *exactNodeExecutable) injectFile() error {
	conn, err := connect(nodeInspectorAddress, nodeInspectorPort)
	if err == nil {
		if ownershipErr := p.verifyInspectorConnection(conn, false); ownershipErr == nil &&
			p.injector.isNodeInspector(conn) {
			p.injector.log.Debug(
				"Node.js inspector already open, injecting directly",
				"pid",
				p.pid,
			)
			return p.injectViaConn(conn)
		}
		_ = conn.Close()
	}

	switch hasUserSIGUSR1Handler(p.procFD, p.dev, p.ino, p.elfFile) {
	case signalCheckFound:
		p.injector.log.Warn("Node.js process has a custom SIGUSR1 handler, skipping agent injection. "+
			"Node.js trace correlation will not work", "pid", p.pid)
		return nil
	case signalCheckFailed:
		if sourceHasSIGUSR1Reference(p.procFD) {
			p.injector.log.Warn("Node.js source files reference SIGUSR1, skipping agent injection. "+
				"Node.js trace correlation will not work", "pid", p.pid)
			return nil
		}
	case signalCheckNotFound:
	}

	if err := p.validate(); err != nil {
		return err
	}
	// A pidfd pins the task lifetime and prevents numeric PID reuse, but Linux
	// does not let pidfd_send_signal condition delivery on an exec generation.
	// A same-task, same-inode re-exec between validation and this call remains
	// outside the guarantee provided by this primitive.
	if err := p.ops.sendSignal(p.pidFD, syscall.SIGUSR1, nil, 0); err != nil {
		return fmt.Errorf("enable Node.js inspector through exact pidfd: %w", err)
	}

	conn, err = p.connectInspectorWait(nodeInspectorWait, nodeInspectorPoll)
	if err != nil {
		return fmt.Errorf("connect to exact Node.js inspector after SIGUSR1: %w", err)
	}
	if !p.injector.isNodeInspector(conn) {
		_ = conn.Close()
		return errors.New("exact target's port 9229 is not a Node.js inspector")
	}
	return p.injectViaConn(conn)
}

func (p *exactNodeExecutable) connectInspectorWait(timeout, interval time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		if err := p.validate(); err != nil {
			return nil, err
		}
		conn, err := connect(nodeInspectorAddress, nodeInspectorPort)
		if err == nil {
			if err = p.verifyInspectorConnection(conn, false); err == nil {
				return conn, nil
			}
			_ = conn.Close()
		}
		lastErr = err
		if time.Now().After(deadline) {
			if lastErr == nil {
				lastErr = errors.New("inspector socket ownership was not established")
			}
			return nil, errors.Join(fmt.Errorf(
				"timed out waiting for %s:%d",
				nodeInspectorAddress,
				nodeInspectorPort,
			), lastErr)
		}
		time.Sleep(interval)
	}
}

func (p *exactNodeExecutable) injectViaConn(conn net.Conn) error {
	return p.injector.injectViaConnValidated(conn, func(activeConn net.Conn) error {
		return p.verifyInspectorConnection(activeConn, true)
	})
}

func (p *exactNodeExecutable) verifyInspectorConnection(
	conn net.Conn,
	requireConnectedSocket bool,
) error {
	if err := p.validate(); err != nil {
		return err
	}
	owned, err := exactTargetOwnsInspectorSocket(p.procFD, conn, requireConnectedSocket)
	if err != nil {
		return err
	}
	if !owned {
		if requireConnectedSocket {
			return errors.New("exact Node.js target does not own the connected inspector socket")
		}
		return errors.New("exact Node.js target does not own the inspector listener or socket")
	}
	return p.validate()
}

type tcpEndpoint struct {
	address netip.Addr
	port    uint16
}

type procTCPSocket struct {
	local  tcpEndpoint
	remote tcpEndpoint
	state  uint8
	inode  uint64
}

func exactTargetOwnsInspectorSocket(
	procFD int,
	conn net.Conn,
	requireConnectedSocket bool,
) (bool, error) {
	return exactTargetOwnsSocket(
		procFD,
		conn,
		requireConnectedSocket,
		tcpEndpoint{
			address: netip.MustParseAddr(nodeInspectorAddress),
			port:    uint16(nodeInspectorPort),
		},
	)
}

func exactTargetOwnsSocket(
	procFD int,
	conn net.Conn,
	requireConnectedSocket bool,
	expectedRemote tcpEndpoint,
) (bool, error) {
	local, err := tcpEndpointFromAddr(conn.LocalAddr())
	if err != nil {
		return false, err
	}
	remote, err := tcpEndpointFromAddr(conn.RemoteAddr())
	if err != nil {
		return false, err
	}
	if remote != expectedRemote {
		return false, errors.New("connection is not to the expected socket endpoint")
	}

	ownedInodes, err := exactTargetSocketInodes(procFD)
	if err != nil {
		return false, fmt.Errorf("read exact Node.js socket descriptors: %w", err)
	}
	table, err := os.Open("/proc/thread-self/net/tcp")
	if err != nil {
		return false, fmt.Errorf("open exact Node.js netns TCP table: %w", err)
	}
	sockets, parseErr := parseProcNetTCP(table)
	closeErr := table.Close()
	if parseErr != nil || closeErr != nil {
		return false, errors.Join(parseErr, closeErr)
	}

	return inspectorSocketOwned(ownedInodes, sockets, local, remote, requireConnectedSocket), nil
}

func inspectorSocketOwned(
	ownedInodes map[uint64]struct{},
	sockets []procTCPSocket,
	local, remote tcpEndpoint,
	requireConnectedSocket bool,
) bool {
	for _, socket := range sockets {
		if _, owned := ownedInodes[socket.inode]; !owned {
			continue
		}
		if socket.state == 0x01 && socket.local == remote && socket.remote == local {
			return true
		}
		if !requireConnectedSocket && socket.state == 0x0a &&
			socket.local.port == uint16(nodeInspectorPort) &&
			(socket.local.address.IsUnspecified() || socket.local.address == remote.address) {
			return true
		}
	}
	return false
}

func exactTargetSocketInodes(procFD int) (map[uint64]struct{}, error) {
	fd, err := unix.Openat(procFD, "fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), "exact-node-fds")
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("create exact Node.js fd directory")
	}
	entries, readErr := directory.ReadDir(-1)
	if readErr != nil {
		return nil, errors.Join(readErr, directory.Close())
	}

	inodes := make(map[uint64]struct{})
	buffer := make([]byte, unix.PathMax)
	for _, entry := range entries {
		n, linkErr := unix.Readlinkat(fd, entry.Name(), buffer)
		if linkErr != nil {
			continue
		}
		link := string(buffer[:n])
		if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
			continue
		}
		inode, parseErr := strconv.ParseUint(link[len("socket:["):len(link)-1], 10, 64)
		if parseErr == nil && inode != 0 {
			inodes[inode] = struct{}{}
		}
	}
	return inodes, directory.Close()
}

func parseProcNetTCP(reader io.Reader) ([]procTCPSocket, error) {
	var sockets []procTCPSocket
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || fields[0] == "sl" || strings.HasPrefix(fields[0], "sl") {
			continue
		}
		if len(fields) < 10 {
			return nil, errors.New("truncated netns TCP socket row")
		}
		local, err := parseProcTCPEndpoint(fields[1])
		if err != nil {
			return nil, fmt.Errorf("parse local TCP endpoint: %w", err)
		}
		remote, err := parseProcTCPEndpoint(fields[2])
		if err != nil {
			return nil, fmt.Errorf("parse remote TCP endpoint: %w", err)
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("parse TCP state: %w", err)
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse TCP inode: %w", err)
		}
		sockets = append(sockets, procTCPSocket{
			local:  local,
			remote: remote,
			state:  uint8(state),
			inode:  inode,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sockets, nil
}

func parseProcTCPEndpoint(value string) (tcpEndpoint, error) {
	addressText, portText, ok := strings.Cut(value, ":")
	if !ok || len(addressText) != 8 {
		return tcpEndpoint{}, fmt.Errorf("invalid IPv4 endpoint %q", value)
	}
	addressValue, err := strconv.ParseUint(addressText, 16, 32)
	if err != nil {
		return tcpEndpoint{}, err
	}
	port, err := strconv.ParseUint(portText, 16, 16)
	if err != nil {
		return tcpEndpoint{}, err
	}
	var addressBytes [4]byte
	binary.LittleEndian.PutUint32(addressBytes[:], uint32(addressValue))
	return tcpEndpoint{
		address: netip.AddrFrom4(addressBytes),
		port:    uint16(port),
	}, nil
}

func tcpEndpointFromAddr(address net.Addr) (tcpEndpoint, error) {
	host, portText, err := net.SplitHostPort(address.String())
	if err != nil {
		return tcpEndpoint{}, fmt.Errorf("parse TCP address %q: %w", address, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return tcpEndpoint{}, fmt.Errorf("parse TCP IP %q: %w", host, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return tcpEndpoint{}, fmt.Errorf("parse TCP port %q: %w", portText, err)
	}
	return tcpEndpoint{address: ip.Unmap(), port: uint16(port)}, nil
}
