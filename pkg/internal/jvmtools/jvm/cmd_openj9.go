// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Converted from C code from the jattach project
package jvm // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvm"

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	MaxNotifyFiles          = 256
	maxNotifyScanEntries    = MaxNotifyFiles * 16
	notifyDirectoryReadSize = 64
)

type j9Attacher struct {
	notifyLock [MaxNotifyFiles]int
	logger     *slog.Logger
	mu         sync.Mutex
	ioMu       sync.Mutex
	fd         int
}

func newJ9Attacher(logger *slog.Logger) *j9Attacher {
	if logger == nil {
		logger = slog.Default()
	}

	j := &j9Attacher{
		logger: logger,
		fd:     -1,
	}

	return j
}

// Translate HotSpot command to OpenJ9 equivalent
func translateCommand(argv []string) string {
	if len(argv) == 0 {
		return ""
	}

	argc := len(argv)
	cmd := argv[0]
	var result string

	switch cmd {
	case "load":
		if argc >= 2 {
			arg3 := ""
			if argc > 3 {
				arg3 = argv[3]
			}
			if argc > 2 && argv[2] == "true" {
				result = fmt.Sprintf("ATTACH_LOADAGENTPATH(%s,%s)", argv[1], arg3)
			} else {
				result = fmt.Sprintf("ATTACH_LOADAGENT(%s,%s)", argv[1], arg3)
			}
		}

	case "jcmd":
		arg1 := "help"
		if argc > 1 {
			arg1 = argv[1]
		}
		result = "ATTACH_DIAGNOSTICS:" + strings.Join(append([]string{arg1}, argv[2:]...), ",")

	case "threaddump":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = "ATTACH_DIAGNOSTICS:Thread.print," + arg1

	case "dumpheap":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = "ATTACH_DIAGNOSTICS:Dump.heap," + arg1

	case "inspectheap":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = "ATTACH_DIAGNOSTICS:GC.class_histogram," + arg1

	case "datadump":
		arg1 := ""
		if argc > 1 {
			arg1 = argv[1]
		}
		result = "ATTACH_DIAGNOSTICS:Dump.java," + arg1

	case "properties":
		result = "ATTACH_GETSYSTEMPROPERTIES"

	case "agentProperties":
		result = "ATTACH_GETAGENTPROPERTIES"

	default:
		result = cmd
	}

	return result
}

// Send command with arguments to socket
func writeCommand(fd int, cmd string) error {
	return writeCommandContext(context.Background(), fd, cmd)
}

func writeCommandContext(ctx context.Context, fd int, cmd string) error {
	data := []byte(cmd)
	data = append(data, 0) // null terminator

	off := 0
	for off < len(data) {
		n, err := syscall.Write(fd, data[off:])
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			if err := waitFD(ctx, fd, unix.POLLOUT); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return fmt.Errorf("write failed: %w", err)
		}
		if n <= 0 {
			return fmt.Errorf("write failed: %w", io.ErrShortWrite)
		}
		off += n
	}
	return nil
}

func waitFD(ctx context.Context, fd int, events int16) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		timeoutMillis := 100
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return context.DeadlineExceeded
			}
			timeoutMillis = min(timeoutMillis, max(1, int((remaining+time.Millisecond-1)/time.Millisecond)))
		}

		pollFD := []unix.PollFd{{Fd: int32(fd), Events: events}}
		_, err := unix.Poll(pollFD, timeoutMillis)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if pollFD[0].Revents&(events|unix.POLLERR|unix.POLLHUP) != 0 {
			return nil
		}
		if pollFD[0].Revents&unix.POLLNVAL != 0 {
			return syscall.EBADF
		}
	}
}

func readContext(ctx context.Context, fd int, buffer []byte) (int, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}

		n, err := syscall.Read(fd, buffer)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			if err := waitFD(ctx, fd, unix.POLLIN); err != nil {
				return 0, err
			}
			continue
		}
		return n, err
	}
}

func closeWithErrno(fd int) {
	_ = syscall.Close(fd)
}

func acquireLock(ctx context.Context, tmpPath, subdir, filename string) (int, error) {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", subdir, filename)

	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT, 0o666)
	if err != nil {
		return -1, err
	}

	for {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, syscall.EINTR) && !errors.Is(err, syscall.EAGAIN) && !errors.Is(err, syscall.EWOULDBLOCK) {
			return -1, errors.Join(err, syscall.Close(fd))
		}
		if err := sleepContext(ctx, 10*time.Millisecond); err != nil {
			return -1, errors.Join(err, syscall.Close(fd))
		}
	}
}

func releaseLock(lockFd int) error {
	return errors.Join(
		syscall.Flock(lockFd, syscall.LOCK_UN),
		syscall.Close(lockFd),
	)
}

func createAttachSocket() (int, int, error) {
	// Try IPv6 socket first, then fall back to IPv4
	s, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
	if err == nil {
		addr := &syscall.SockaddrInet6{}
		if err := syscall.Bind(s, addr); err == nil {
			if err := syscall.Listen(s, 0); err == nil {
				sa, err := syscall.Getsockname(s)
				if err == nil {
					if sa6, ok := sa.(*syscall.SockaddrInet6); ok {
						return s, sa6.Port, nil
					}
				}
			}
		}
		closeWithErrno(s)
	}

	// Fall back to IPv4
	s, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return -1, 0, err
	}

	addr := &syscall.SockaddrInet4{}
	if err := syscall.Bind(s, addr); err != nil {
		closeWithErrno(s)
		return -1, 0, err
	}

	if err := syscall.Listen(s, 0); err != nil {
		closeWithErrno(s)
		return -1, 0, err
	}

	sa, err := syscall.Getsockname(s)
	if err != nil {
		closeWithErrno(s)
		return -1, 0, err
	}

	if sa4, ok := sa.(*syscall.SockaddrInet4); ok {
		return s, sa4.Port, nil
	}

	closeWithErrno(s)
	return -1, 0, errors.New("failed to get socket port")
}

func closeAttachSocket(tmpPath string, s, pid int) error {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", strconv.Itoa(pid), "replyInfo")
	var err error
	if unlinkErr := syscall.Unlink(path); unlinkErr != nil && !errors.Is(unlinkErr, syscall.ENOENT) {
		err = errors.Join(err, unlinkErr)
	}

	return errors.Join(err, syscall.Close(s))
}

func randomKey() uint64 {
	key := uint64(time.Now().Unix()) * 0xc6a4a7935bd1e995

	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return key
	}

	for i, b := range buf {
		key ^= uint64(b) << (uint(i) * 8)
	}

	return key
}

func writeReplyInfo(tmpPath string, pid, port int, key uint64) error {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", strconv.Itoa(pid), "replyInfo")

	content := fmt.Sprintf("%016x\n%d\n", key, port)
	return os.WriteFile(path, []byte(content), 0o600)
}

func notifySemaphore(ctx context.Context, tmpPath string, value, notifyCount int) error {
	if notifyCount <= 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", "_notifier")

	semKey, err := ftok(path, 0xa1)
	if err != nil {
		return err
	}

	semID, err := semget(semKey, 1, unix.IPC_CREAT|0o666)
	if err != nil {
		return err
	}

	sb := createSembuf(0, int16(value), unix.IPC_NOWAIT)

	for range notifyCount {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := semop(semID, []sembuf{sb}); err != nil {
			// The restore path decrements with IPC_NOWAIT. The JVMs we notified
			// consume the posts themselves as they wake up, so the semaphore is
			// frequently already at zero by the time we try to take our posts
			// back. EAGAIN ("resource temporarily unavailable") is the kernel
			// signaling there is nothing left to decrement. The original C code
			// was handling this, but it was missed in translation.
			if value < 0 && errors.Is(err, unix.EAGAIN) {
				return nil
			}
			return fmt.Errorf("semop failed: %w", err)
		}
	}

	return nil
}

func acceptClient(ctx context.Context, s int, key uint64) (int, error) {
	if err := unix.SetNonblock(s, true); err != nil {
		return -1, fmt.Errorf("could not make JVM response socket nonblocking: %w", err)
	}

	var nfd int
	for {
		if err := waitFD(ctx, s, unix.POLLIN); err != nil {
			return -1, fmt.Errorf("jvm did not respond: %w", err)
		}
		var err error
		nfd, _, err = syscall.Accept(s)
		if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			continue
		}
		if err != nil {
			return -1, fmt.Errorf("jvm did not respond: %w", err)
		}
		break
	}
	if err := unix.SetNonblock(nfd, true); err != nil {
		_ = syscall.Close(nfd)
		return -1, fmt.Errorf("could not make JVM connection nonblocking: %w", err)
	}

	buf := make([]byte, 35)
	off := 0
	for off < len(buf) {
		n, err := readContext(ctx, nfd, buf[off:])
		if err != nil {
			_ = syscall.Close(nfd)
			return -1, fmt.Errorf("the JVM connection was prematurely closed: %w", err)
		}
		if n <= 0 {
			_ = syscall.Close(nfd)
			return -1, fmt.Errorf("the JVM connection was prematurely closed: %w", io.ErrUnexpectedEOF)
		}
		off += n
	}

	expected := fmt.Sprintf("ATTACH_CONNECTED %016x ", key)
	if !bytes.Equal(buf[:len(expected)], []byte(expected)) {
		_ = syscall.Close(nfd)
		return -1, fmt.Errorf("unexpected JVM response %s", buf[:len(expected)])
	}

	return nfd, nil
}

func (j *j9Attacher) lockNotificationFiles(ctx context.Context, tmpPath string) (int, error) {
	count := 0
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach")

	dir, err := os.Open(path)
	if err != nil {
		return 0, nil
	}
	defer dir.Close()

	for scanned := 0; scanned < maxNotifyScanEntries && count < MaxNotifyFiles; {
		if err := ctx.Err(); err != nil {
			return count, err
		}

		readSize := min(notifyDirectoryReadSize, maxNotifyScanEntries-scanned)
		entries, readErr := dir.Readdir(readSize)
		scanned += len(entries)

		for _, entry := range entries {
			name := entry.Name()
			if len(name) == 0 || name[0] < '1' || name[0] > '9' || !entry.IsDir() {
				continue
			}

			fd, err := acquireLock(ctx, tmpPath, name, "attachNotificationSync")
			if err != nil {
				return count, err
			}
			if fd >= 0 {
				j.notifyLock[count] = fd
				count++
				if count == MaxNotifyFiles {
					break
				}
			}
		}

		if errors.Is(readErr, io.EOF) {
			return count, nil
		}
		if readErr != nil {
			return count, fmt.Errorf("could not scan OpenJ9 notification directory: %w", readErr)
		}
	}

	if count < MaxNotifyFiles {
		return count, fmt.Errorf(
			"OpenJ9 notification directory exceeds the %d-entry scan limit",
			maxNotifyScanEntries,
		)
	}

	return count, nil
}

func (j *j9Attacher) unlockNotificationFiles(count int) error {
	var err error

	for i := range count {
		if j.notifyLock[i] >= 0 {
			err = errors.Join(err, releaseLock(j.notifyLock[i]))
			j.notifyLock[i] = -1
		}
	}

	return err
}

func (j *j9Attacher) releaseNotificationFiles(tmpPath string, count int) error {
	return errors.Join(
		j.unlockNotificationFiles(count),
		notifySemaphore(context.Background(), tmpPath, -1, count),
	)
}

func isOpenJ9Process(tmpPath string, pid int) bool {
	path := filepath.Join(tmpPath, ".com_ibm_tools_attach", strconv.Itoa(pid), "attachInfo")
	_, err := os.Stat(path)
	return err == nil
}

type j9Reader struct {
	attacher *j9Attacher
	ctx      context.Context
}

func (r *j9Reader) Read(p []byte) (int, error) {
	r.attacher.ioMu.Lock()
	defer r.attacher.ioMu.Unlock()

	r.attacher.mu.Lock()
	fd := r.attacher.fd
	r.attacher.mu.Unlock()
	if fd < 0 {
		return 0, os.ErrClosed
	}

	ctx := r.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	n, err := readContext(ctx, fd, p)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.EOF
	}

	return n, nil
}

func (r *j9Reader) Close() error {
	ctx := r.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return r.attacher.closeFD()
	}
	return r.attacher.detachContext(ctx)
}

func (j *j9Attacher) closeFD() error {
	j.mu.Lock()
	fd := j.fd
	if fd < 0 {
		j.mu.Unlock()
		return nil
	}
	j.fd = -1
	_ = syscall.Shutdown(fd, syscall.SHUT_RDWR)
	j.mu.Unlock()

	j.ioMu.Lock()
	defer j.ioMu.Unlock()
	return syscall.Close(fd)
}

func (j *j9Attacher) detach() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return j.detachContext(ctx)
}

func (j *j9Attacher) detachContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return j.closeFD()
	}

	j.ioMu.Lock()
	defer j.ioMu.Unlock()

	j.mu.Lock()
	fd := j.fd
	if fd < 0 {
		j.mu.Unlock()
		return nil
	}
	j.fd = -1
	j.mu.Unlock()

	var detachErr error
	if err := writeCommandContext(ctx, fd, "ATTACH_DETACHED"); err != nil {
		detachErr = errors.Join(detachErr, err)
	}

	buf := make([]byte, 256)
	if detachErr == nil {
		for {
			n, err := readContext(ctx, fd, buf)
			if err != nil || n <= 0 || buf[n-1] == 0 {
				detachErr = errors.Join(detachErr, err)
				break
			}
		}
	}

	return errors.Join(detachErr, syscall.Close(fd))
}

func (j *j9Attacher) jattachOpenJ9(ctx context.Context, tmpPath string, nspid int, argv []string) (reader io.ReadCloser, err error) {
	attachLock, err := acquireLock(ctx, tmpPath, "", "_attachlock")
	if err != nil {
		return nil, fmt.Errorf("could not acquire attach lock: %w", err)
	}

	notifyCount := 0
	s := -1
	var port int

	defer func() {
		var cleanupErr error
		if s >= 0 {
			cleanupErr = errors.Join(cleanupErr, closeAttachSocket(tmpPath, s, nspid))
		}
		if notifyCount > 0 {
			cleanupErr = errors.Join(cleanupErr, j.releaseNotificationFiles(tmpPath, notifyCount))
		}
		if attachLock >= 0 {
			cleanupErr = errors.Join(cleanupErr, releaseLock(attachLock))
		}
		if err != nil {
			cleanupErr = errors.Join(cleanupErr, j.closeFD())
		}
		if cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
		}
	}()

	s, port, err = createAttachSocket()
	if err != nil {
		return nil, fmt.Errorf("failed to listen to attach socket: %w", err)
	}

	key := randomKey()
	if err := writeReplyInfo(tmpPath, nspid, port, key); err != nil {
		return nil, fmt.Errorf("could not write replyInfo: %w", err)
	}

	notifyCount, err = j.lockNotificationFiles(ctx, tmpPath)
	if err != nil {
		return nil, fmt.Errorf("could not lock OpenJ9 notification files: %w", err)
	}
	if err := notifySemaphore(ctx, tmpPath, 1, notifyCount); err != nil {
		return nil, fmt.Errorf("could not notify semaphore: %w", err)
	}

	fd, err := acceptClient(ctx, s, key)
	if err != nil {
		return nil, err
	}

	j.mu.Lock()
	j.fd = fd
	j.mu.Unlock()

	closeErr := closeAttachSocket(tmpPath, s, nspid)
	s = -1
	if closeErr != nil {
		return nil, fmt.Errorf("could not close attach socket: %w", closeErr)
	}

	notifyErr := j.releaseNotificationFiles(tmpPath, notifyCount)
	notifyCount = 0
	if notifyErr != nil {
		return nil, fmt.Errorf("could not release OpenJ9 notification files: %w", notifyErr)
	}

	releaseErr := releaseLock(attachLock)
	attachLock = -1
	if releaseErr != nil {
		return nil, fmt.Errorf("could not release OpenJ9 attach lock: %w", releaseErr)
	}

	j.logger.Info("connected to remote JVM")

	cmd := translateCommand(argv)

	if writeErr := writeCommandContext(ctx, fd, cmd); writeErr != nil {
		return nil, errors.Join(fmt.Errorf("error writing to socket: %w", writeErr), j.closeFD())
	}

	return &j9Reader{attacher: j, ctx: ctx}, nil
}
