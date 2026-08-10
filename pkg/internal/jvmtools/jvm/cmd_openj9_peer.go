// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvm"

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maxOpenJ9PeerScanEntries       = 1 << 20
	openJ9TCPStateEstablished      = 1
	openJ9SocketDiagnosticTimeout  = time.Second
	openJ9SocketDiagnosticBufBytes = 4096
	inetDiagRequestBytes           = 56
	inetDiagResponseBytes          = 72
)

var (
	duplicateJVMTargetFD    = unix.PidfdGetfd
	diagnoseOpenJ9TCPSocket = currentOpenJ9TCPSocketDiagnostic
	openJ9DiagnosticSeq     atomic.Uint32
)

var (
	errOpenJ9PeerMismatch                = errors.New("OpenJ9 client is not owned by the exact JVM")
	errOpenJ9PeerVerificationUnavailable = errors.New("exact OpenJ9 peer verification is unavailable")
	errNotINETSocket                     = errors.New("socket is not an INET endpoint")
)

type inetEndpoint struct {
	family  int
	address [16]byte
	port    uint16
}

type openJ9TCPSocketDiagnostic struct {
	local  inetEndpoint
	peer   inetEndpoint
	state  uint8
	cookie uint64
}

func endpointFromIP(family int, address net.IP, port uint16) (inetEndpoint, error) {
	var endpoint inetEndpoint
	endpoint.family = family
	endpoint.port = port
	switch family {
	case unix.AF_INET:
		ipv4 := address.To4()
		if ipv4 == nil {
			return endpoint, errors.New("invalid IPv4 socket diagnostic address")
		}
		copy(endpoint.address[:4], ipv4)
	case unix.AF_INET6:
		ipv6 := address.To16()
		if ipv6 == nil {
			return endpoint, errors.New("invalid IPv6 socket diagnostic address")
		}
		copy(endpoint.address[:], ipv6)
	default:
		return endpoint, fmt.Errorf("unsupported socket diagnostic family %d", family)
	}
	return endpoint, nil
}

func serializeOpenJ9SocketDiagnosticRequest(
	sequence uint32,
	local, peer inetEndpoint,
	cookie uint64,
) ([]byte, error) {
	if local.family != peer.family ||
		(local.family != unix.AF_INET && local.family != unix.AF_INET6) {
		return nil, errors.New("invalid TCP socket diagnostic endpoint families")
	}
	request := make([]byte, unix.SizeofNlMsghdr+inetDiagRequestBytes)
	order := binary.NativeEndian
	order.PutUint32(request[0:4], uint32(len(request)))
	order.PutUint16(request[4:6], unix.SOCK_DIAG_BY_FAMILY)
	order.PutUint16(request[6:8], unix.NLM_F_REQUEST)
	order.PutUint32(request[8:12], sequence)
	request[16] = byte(local.family)
	request[17] = unix.IPPROTO_TCP
	order.PutUint32(request[20:24], 1<<(openJ9TCPStateEstablished-1))
	binary.BigEndian.PutUint16(request[24:26], local.port)
	binary.BigEndian.PutUint16(request[26:28], peer.port)
	if local.family == unix.AF_INET {
		copy(request[28:32], local.address[:4])
		copy(request[44:48], peer.address[:4])
	} else {
		copy(request[28:44], local.address[:])
		copy(request[44:60], peer.address[:])
	}
	order.PutUint32(request[64:68], uint32(cookie))
	order.PutUint32(request[68:72], uint32(cookie>>32))
	return request, nil
}

func parseOpenJ9SocketDiagnostic(
	data []byte,
) (openJ9TCPSocketDiagnostic, error) {
	var diagnostic openJ9TCPSocketDiagnostic
	if len(data) < inetDiagResponseBytes {
		return diagnostic, fmt.Errorf(
			"short TCP socket diagnostic response: got %d bytes", len(data),
		)
	}
	family := int(data[0])
	localIP := net.IP(data[8:24])
	peerIP := net.IP(data[24:40])
	if family == unix.AF_INET {
		localIP = localIP[:4]
		peerIP = peerIP[:4]
	}
	local, err := endpointFromIP(
		family, localIP, binary.BigEndian.Uint16(data[4:6]),
	)
	if err != nil {
		return diagnostic, err
	}
	peer, err := endpointFromIP(
		family, peerIP, binary.BigEndian.Uint16(data[6:8]),
	)
	if err != nil {
		return diagnostic, err
	}
	order := binary.NativeEndian
	return openJ9TCPSocketDiagnostic{
		local: local,
		peer:  peer,
		state: data[1],
		cookie: uint64(order.Uint32(data[44:48])) |
			uint64(order.Uint32(data[48:52]))<<32,
	}, nil
}

func sendOpenJ9SocketDiagnosticRequest(
	ctx context.Context, fd int, request []byte,
) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			if err := waitFD(ctx, fd, unix.POLLOUT); err != nil {
				return err
			}
			continue
		}
		return err
	}
}

func currentOpenJ9TCPSocketDiagnostic(
	ctx context.Context,
	local, peer inetEndpoint,
	cookie uint64,
) (bool, error) {
	diagnosticCtx, cancel := context.WithTimeout(ctx, openJ9SocketDiagnosticTimeout)
	defer cancel()
	sequence := openJ9DiagnosticSeq.Add(1)
	request, err := serializeOpenJ9SocketDiagnosticRequest(
		sequence, local, peer, cookie,
	)
	if err != nil {
		return false, err
	}
	fd, err := unix.Socket(
		unix.AF_NETLINK,
		unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK,
		unix.NETLINK_INET_DIAG,
	)
	if err != nil {
		return false, err
	}
	defer unix.Close(fd)
	if err := sendOpenJ9SocketDiagnosticRequest(diagnosticCtx, fd, request); err != nil {
		return false, err
	}

	buffer := make([]byte, openJ9SocketDiagnosticBufBytes)
	for {
		if err := waitFD(diagnosticCtx, fd, unix.POLLIN); err != nil {
			return false, err
		}
		n, _, flags, from, err := unix.Recvmsg(fd, buffer, nil, 0)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) ||
			errors.Is(err, unix.EWOULDBLOCK) {
			continue
		}
		if err != nil {
			return false, err
		}
		if flags&unix.MSG_TRUNC != 0 {
			return false, errors.New("truncated TCP socket diagnostic response")
		}
		netlinkSource, ok := from.(*unix.SockaddrNetlink)
		if !ok || netlinkSource.Pid != 0 {
			return false, errors.New("TCP socket diagnostic response was not sent by the kernel")
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return false, err
		}
		for _, message := range messages {
			if message.Header.Seq != sequence {
				continue
			}
			switch message.Header.Type {
			case unix.NLMSG_ERROR:
				if len(message.Data) < 4 {
					return false, errors.New("short TCP socket diagnostic error")
				}
				code := int32(binary.NativeEndian.Uint32(message.Data[:4]))
				if code == 0 {
					continue
				}
				errno := unix.Errno(-code)
				if errors.Is(errno, unix.ENOENT) {
					return false, nil
				}
				return false, errno
			case unix.SOCK_DIAG_BY_FAMILY:
				diagnostic, err := parseOpenJ9SocketDiagnostic(message.Data)
				if err != nil {
					return false, err
				}
				return diagnostic.state == openJ9TCPStateEstablished &&
					diagnostic.local == local && diagnostic.peer == peer &&
					diagnostic.cookie == cookie, nil
			default:
				return false, fmt.Errorf(
					"unexpected TCP socket diagnostic message type %d",
					message.Header.Type,
				)
			}
		}
	}
}

func endpointFromSockaddr(address unix.Sockaddr) (inetEndpoint, error) {
	switch current := address.(type) {
	case *unix.SockaddrInet4:
		var endpoint inetEndpoint
		endpoint.family = unix.AF_INET
		copy(endpoint.address[:4], current.Addr[:])
		endpoint.port = uint16(current.Port)
		return endpoint, nil
	case *unix.SockaddrInet6:
		// A dual-stack listener reports IPv4 clients as mapped IPv6. Normalize
		// them to the AF_INET tuple exposed by the client's own descriptor.
		if current.Addr[0] == 0 && current.Addr[1] == 0 &&
			current.Addr[2] == 0 && current.Addr[3] == 0 &&
			current.Addr[4] == 0 && current.Addr[5] == 0 &&
			current.Addr[6] == 0 && current.Addr[7] == 0 &&
			current.Addr[8] == 0 && current.Addr[9] == 0 &&
			current.Addr[10] == 0xff && current.Addr[11] == 0xff {
			var endpoint inetEndpoint
			endpoint.family = unix.AF_INET
			copy(endpoint.address[:4], current.Addr[12:])
			endpoint.port = uint16(current.Port)
			return endpoint, nil
		}
		return inetEndpoint{
			family:  unix.AF_INET6,
			address: current.Addr,
			port:    uint16(current.Port),
		}, nil
	default:
		return inetEndpoint{}, fmt.Errorf("%w: %T", errNotINETSocket, address)
	}
}

func openJ9SocketEndpoints(fd int) (local, peer inetEndpoint, err error) {
	localAddress, err := unix.Getsockname(fd)
	if err != nil {
		return local, peer, fmt.Errorf("reading OpenJ9 local socket address: %w", err)
	}
	peerAddress, err := unix.Getpeername(fd)
	if err != nil {
		return local, peer, fmt.Errorf("reading OpenJ9 peer socket address: %w", err)
	}
	local, err = endpointFromSockaddr(localAddress)
	if err != nil {
		return local, peer, err
	}
	peer, err = endpointFromSockaddr(peerAddress)
	if err != nil {
		return local, peer, err
	}
	if local.family != peer.family {
		return local, peer, errors.New("OpenJ9 socket endpoints use different address families")
	}
	return local, peer, nil
}

func endpointLoopback(endpoint inetEndpoint) bool {
	length := 4
	if endpoint.family == unix.AF_INET6 {
		length = 16
	}
	return net.IP(endpoint.address[:length]).IsLoopback()
}

func openJ9ConnectionLoopback(fd int) (bool, error) {
	local, peer, err := openJ9SocketEndpoints(fd)
	if err != nil {
		return false, err
	}
	return endpointLoopback(local) && endpointLoopback(peer), nil
}

func openJ9TCPStream(fd int) (bool, error) {
	socketType, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil {
		return false, err
	}
	protocol, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL)
	if err != nil {
		return false, err
	}
	return socketType == unix.SOCK_STREAM && protocol == unix.IPPROTO_TCP, nil
}

func reverseOpenJ9Tuple(serverFD, candidateFD int) (bool, error) {
	serverLocal, serverPeer, err := openJ9SocketEndpoints(serverFD)
	if err != nil {
		return false, err
	}
	if !endpointLoopback(serverLocal) || !endpointLoopback(serverPeer) {
		return false, nil
	}
	candidateLocal, candidatePeer, err := openJ9SocketEndpoints(candidateFD)
	if err != nil {
		if errors.Is(err, unix.ENOTSOCK) || errors.Is(err, unix.ENOTCONN) ||
			errors.Is(err, errNotINETSocket) {
			return false, nil
		}
		return false, err
	}
	tcpStream, err := openJ9TCPStream(candidateFD)
	if err != nil {
		return false, err
	}
	return tcpStream &&
		candidateLocal == serverPeer && candidatePeer == serverLocal, nil
}

func endpointWithNativeFamily(endpoint inetEndpoint, family int) (inetEndpoint, error) {
	if endpoint.family == family {
		return endpoint, nil
	}
	if endpoint.family != unix.AF_INET || family != unix.AF_INET6 {
		return endpoint, fmt.Errorf(
			"socket address family %d cannot be represented as native family %d",
			endpoint.family, family,
		)
	}
	address := endpoint.address
	clear(endpoint.address[:])
	endpoint.family = unix.AF_INET6
	endpoint.address[10] = 0xff
	endpoint.address[11] = 0xff
	copy(endpoint.address[12:], address[:4])
	return endpoint, nil
}

func verifyOpenJ9CandidateInCurrentNetNS(
	ctx context.Context,
	serverFD, candidateFD int,
) (bool, error) {
	matched, err := reverseOpenJ9Tuple(serverFD, candidateFD)
	if err != nil || !matched {
		return matched, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	domain, err := unix.GetsockoptInt(candidateFD, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		return false, fmt.Errorf(
			"%w: reading duplicated JVM socket family: %w",
			errOpenJ9PeerVerificationUnavailable, err,
		)
	}
	if domain != unix.AF_INET && domain != unix.AF_INET6 {
		return false, nil
	}
	candidateLocal, candidatePeer, err := openJ9SocketEndpoints(candidateFD)
	if err != nil {
		return false, err
	}
	// Keep the native socket family for the diagnostic lookup. An AF_INET6
	// socket can expose IPv4-mapped endpoints that endpointFromSockaddr
	// normalizes to AF_INET for tuple comparison.
	candidateLocal, err = endpointWithNativeFamily(candidateLocal, domain)
	if err != nil {
		return false, err
	}
	candidatePeer, err = endpointWithNativeFamily(candidatePeer, domain)
	if err != nil {
		return false, err
	}
	candidateCookie, err := unix.GetsockoptUint64(
		candidateFD, unix.SOL_SOCKET, unix.SO_COOKIE,
	)
	if err != nil {
		return false, fmt.Errorf(
			"%w: reading duplicated JVM socket cookie: %w",
			errOpenJ9PeerVerificationUnavailable, err,
		)
	}

	matched, err = diagnoseOpenJ9TCPSocket(
		ctx, candidateLocal, candidatePeer, candidateCookie,
	)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return false, ctxErr
		}
		return false, fmt.Errorf(
			"%w: querying target network namespace TCP socket: %w",
			errOpenJ9PeerVerificationUnavailable, err,
		)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return matched, nil
}

func targetFDNumbers(ctx context.Context, procfd int) ([]int, error) {
	fd, err := unix.Openat(
		procfd, "fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0,
	)
	if err != nil {
		return nil, fmt.Errorf("opening exact JVM descriptor table: %w", err)
	}
	directory := os.NewFile(uintptr(fd), "exact-jvm-fds")
	if directory == nil {
		_ = unix.Close(fd)
		return nil, errors.New("creating exact JVM descriptor-table handle")
	}
	defer directory.Close()

	fdNumbers := make([]int, 0, 64)
	for scanned := 0; ; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		names, readErr := directory.Readdirnames(256)
		scanned += len(names)
		if scanned > maxOpenJ9PeerScanEntries {
			return nil, errors.New("exact JVM descriptor table exceeds bounded scan")
		}
		for _, name := range names {
			fdNumber, err := strconv.Atoi(name)
			if err == nil && fdNumber >= 0 {
				fdNumbers = append(fdNumbers, fdNumber)
			}
		}
		if errors.Is(readErr, io.EOF) {
			return fdNumbers, nil
		}
		if readErr != nil {
			return nil, fmt.Errorf("scanning exact JVM descriptor table: %w", readErr)
		}
	}
}

func (j *JAttacher) validateOpenJ9Peer(ctx context.Context, fd int) error {
	if err := j.ValidateTarget(); err != nil {
		return err
	}
	if j.targetPIDFD < 0 {
		return fmt.Errorf(
			"%w: pidfd_getfd requires an anonymous pidfd",
			errOpenJ9PeerVerificationUnavailable,
		)
	}
	if j.targetProcFD < 0 {
		return errors.New("exact JVM proc directory is not bound")
	}
	fdNumbers, err := targetFDNumbers(ctx, j.targetProcFD)
	if err != nil {
		return err
	}
	for _, fdNumber := range fdNumbers {
		if err := ctx.Err(); err != nil {
			return err
		}
		candidate, err := duplicateJVMTargetFD(j.targetPIDFD, fdNumber, 0)
		if errors.Is(err, unix.EBADF) {
			continue
		}
		if err != nil {
			if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) ||
				errors.Is(err, unix.EACCES) || errors.Is(err, unix.EINVAL) {
				return fmt.Errorf("%w: pidfd_getfd: %w", errOpenJ9PeerVerificationUnavailable, err)
			}
			return fmt.Errorf("duplicating exact JVM descriptor %d: %w", fdNumber, err)
		}
		matched, matchErr := verifyOpenJ9CandidateInCurrentNetNS(ctx, fd, candidate)
		closeErr := unix.Close(candidate)
		if matchErr != nil {
			return errors.Join(matchErr, closeErr)
		}
		if matched {
			if err := j.ValidateTarget(); err != nil {
				return errors.Join(err, closeErr)
			}
			return closeErr
		}
	}
	return errOpenJ9PeerMismatch
}
