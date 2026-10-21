// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package generictracer

import (
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kprobe"
)

type pythonRequestsPacket struct {
	Version     uint32
	Operation   uint32
	Conn        BpfConnectionInfoT
	Traceparent [56]byte
}

func TestPythonRequestsContextBridge(t *testing.T) {
	require.NoError(t, rlimit.RemoveMemlock())
	for _, enabled := range []bool{true, false} {
		name := "enabled"
		if !enabled {
			name = "disabled"
		}
		t.Run(name, func(t *testing.T) {
			spec, err := LoadBpf()
			require.NoError(t, err)
			for _, m := range spec.Maps {
				m.Pinning = ebpf.PinNone
				switch m.Type {
				case ebpf.Hash, ebpf.LRUHash:
					m.MaxEntries = 16
				case ebpf.RingBuf:
					m.MaxEntries = uint32(os.Getpagesize())
				}
			}
			require.NoError(t, ebpfconvenience.RewriteConstants(spec, map[string]any{
				"filter_pids":                    int32(0),
				"max_transaction_time":           uint64(time.Minute),
				"g_bpf_header_propagation":       enabled,
				"g_bpf_probe_write_user_enabled": true,
			}))
			var objects struct {
				Ioctl     *ebpf.Program `ebpf:"obi_kprobe_sys_ioctl"`
				Requests  *ebpf.Map     `ebpf:"python_requests"`
				Servers   *ebpf.Map     `ebpf:"server_traces"`
				JumpTable *ebpf.Map     `ebpf:"jump_table"`
			}
			err = spec.LoadAndAssign(&objects, nil)
			if err != nil {
				var verifier *ebpf.VerifierError
				if errors.As(err, &verifier) {
					t.Logf("%+v", verifier)
				}
			}
			require.NoError(t, err)
			t.Cleanup(func() {
				objects.Ioctl.Close()
				objects.Requests.Close()
				objects.Servers.Close()
				objects.JumpTable.Close()
			})
			probe, err := kprobe.Attach("sys_ioctl", objects.Ioctl, false)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, probe.Close()) })

			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			pid, tid := uint32(os.Getpid()), uint32(unix.Gettid())
			var namespace unix.Stat_t
			require.NoError(t, unix.Stat("/proc/self/ns/pid", &namespace))
			var now unix.Timespec
			require.NoError(t, unix.ClockGettime(unix.CLOCK_MONOTONIC, &now))
			serverKey := BpfTraceKeyT{P_key: BpfPidKeyT{Tid: tid, Pid: pid, Ns: uint32(namespace.Ino)}}
			server := BpfTpInfoPidT{
				Tp:  BpfTpInfoT{TraceId: [16]uint8{1}, SpanId: [8]uint8{2}, Ts: uint64(now.Nano()), Flags: 1},
				Pid: pid, Valid: 1, ReqType: ebpfcommon.EventTypeHTTPRequest,
			}
			require.NoError(t, objects.Servers.Put(serverKey, server))

			connection := BpfConnectionInfoT{S_port: 40000, D_port: 443}
			connection.S_addr = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1}
			connection.D_addr = [16]uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 2}
			key := BpfPidConnectionInfoT{Pid: pid, Conn: connection}
			packet := pythonRequestsPacket{Version: 1, Conn: connection}
			require.Equal(t, uintptr(100), unsafe.Sizeof(packet))

			spans := map[string]bool{}
			for range 3 {
				packet.Operation = 1
				clear(packet.Traceparent[:])
				pythonRequestsIoctl(&packet)
				var context BpfPythonRequestContextT
				err := objects.Requests.Lookup(key, &context)
				if !enabled {
					require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
					require.Equal(t, [56]byte{}, packet.Traceparent)
					continue
				}
				require.NoError(t, err)
				require.Equal(t, uint64(pid)<<32|uint64(tid), context.ThreadId)
				require.NotZero(t, context.ThreadStartTime)
				require.Equal(t, server.Tp.TraceId, context.Trace.Tp.TraceId)
				require.Equal(t, server.Tp.SpanId, context.Trace.Tp.ParentId)
				span := hex.EncodeToString(context.Trace.Tp.SpanId[:])
				require.False(t, spans[span], "connection reuse must allocate a new client span")
				spans[span] = true
				require.Equal(t, "00-"+hex.EncodeToString(server.Tp.TraceId[:])+"-"+span+"-01", string(packet.Traceparent[:55]))
				packet.Operation = 2
				pythonRequestsIoctl(&packet)
				require.ErrorIs(t, objects.Requests.Lookup(key, &context), ebpf.ErrKeyNotExist)
			}
		})
	}
}

func pythonRequestsIoctl(packet *pythonRequestsPacket) {
	_, _, _ = unix.Syscall(unix.SYS_IOCTL, 0, 0x0b10b2, uintptr(unsafe.Pointer(packet)))
	runtime.KeepAlive(packet)
}
