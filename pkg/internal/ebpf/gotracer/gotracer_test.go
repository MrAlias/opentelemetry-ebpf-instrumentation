// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gotracer

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

func TestGoChannelLinkProbesRequireChannelOffsets(t *testing.T) {
	disableContextPropagationForTest(t)

	tracer := &Tracer{
		log:                   slog.New(slog.NewTextHandler(io.Discard, nil)),
		goChannelOffsetsByIno: map[uint64]bool{},
	}

	assertNoGoChannelLinkProbes(t, tracer.GoProbes())

	tracer.recordGoChannelOffsetAvailability(
		exec.New(exec.Init{Ino: 1}),
		&goexec.Offsets{Field: goexec.FieldOffsets{
			goexec.HchanQcountPos:   uint64(0),
			goexec.HchanDataqsizPos: uint64(8),
			goexec.HchanSendxPos:    uint64(48),
		}},
	)
	assertNoGoChannelLinkProbes(t, tracer.GoProbes())

	tracer.recordGoChannelOffsetAvailability(exec.New(exec.Init{Ino: 2}), goChannelOffsets())
	probes := tracer.GoProbes()
	for _, symbol := range GoChannelLinkProbeSymbols() {
		require.Contains(t, probes, symbol)
	}
}

func TestMissingGoChannelOffsetsUseSentinel(t *testing.T) {
	var offTable BpfOffTableT

	initMissingGoChannelOffsets(&offTable)

	for _, field := range goChannelOffsetFields {
		assert.Equal(t, missingGoOffset, offTable.Table[field])
	}
	assert.Zero(t, offTable.Table[goexec.ConnFdPos])
}

func TestProcessBinarySelectsRecordedChannelOffsetState(t *testing.T) {
	tracer := &Tracer{
		goChannelOffsetsByIno: map[uint64]bool{
			1: true,
			2: false,
		},
	}

	tracer.ProcessBinary(exec.New(exec.Init{Ino: 1}))
	assert.True(t, tracer.goChannelLinkProbesEnabled())

	tracer.ProcessBinary(exec.New(exec.Init{Ino: 2}))
	assert.False(t, tracer.goChannelLinkProbesEnabled())

	tracer.ProcessBinary(nil)
	assert.False(t, tracer.goChannelLinkProbesEnabled())
}

func TestJavaRemoteParentModeSelectsConsumerProtocolAndMapSizes(t *testing.T) {
	disableContextPropagationForTest(t)

	unsupported := errors.New("network namespace cookie helper unavailable")
	for _, tt := range []struct {
		configured    bool
		probeErr      error
		expected      bool
		expectedCalls int
	}{
		{configured: false, expected: false},
		{configured: true, expected: true, expectedCalls: 1},
		{configured: true, probeErr: unsupported, expected: false, expectedCalls: 1},
	} {
		name := fmt.Sprintf("configured=%t/supported=%t", tt.configured, tt.probeErr == nil)
		t.Run(name, func(t *testing.T) {
			probeCalls := 0
			tracer := &Tracer{
				log:                        slog.New(slog.NewTextHandler(io.Discard, nil)),
				cfg:                        &config.EBPFTracer{},
				javaRemoteParentConfigured: tt.configured,
				haveSockOpsNetnsCookie: func() error {
					probeCalls++
					return tt.probeErr
				},
			}

			bundles, err := tracer.LoadSpecs()
			require.NoError(t, err)
			require.Len(t, bundles, 1)
			assert.Equal(t, tt.expectedCalls, probeCalls)
			assert.Equal(t, tt.expected, bundles[0].Constants["java_remote_parent_enabled"])
			writeArgs := bundles[0].Spec.Maps["active_ssl_write_args"]
			require.NotNil(t, writeArgs)
			assert.Equal(t, uint32(16), writeArgs.KeySize)
			assert.Equal(t, uint32(64), writeArgs.ValueSize)
			assert.Equal(t, ebpf.LRUHash, writeArgs.Type)

			for _, name := range []string{"incoming_trace_heads", "incoming_trace_candidates"} {
				mapSpec := bundles[0].Spec.Maps[name]
				require.NotNil(t, mapSpec, name)
				if tt.expected {
					assert.Greater(t, mapSpec.MaxEntries, uint32(1), name)
				} else {
					assert.Equal(t, uint32(1), mapSpec.MaxEntries, name)
				}
			}
		})
	}
}

func goChannelOffsets() *goexec.Offsets {
	return &goexec.Offsets{Field: goexec.FieldOffsets{
		goexec.HchanQcountPos:   uint64(0),
		goexec.HchanDataqsizPos: uint64(8),
		goexec.HchanSendxPos:    uint64(48),
		goexec.HchanRecvxPos:    uint64(56),
	}}
}

func assertNoGoChannelLinkProbes(t *testing.T, probes map[string][]*ebpfcommon.ProbeDesc) {
	t.Helper()

	for _, symbol := range GoChannelLinkProbeSymbols() {
		assert.NotContains(t, probes, symbol)
	}
}

func disableContextPropagationForTest(t *testing.T) {
	t.Helper()

	previous := ebpfcommon.IntegrityModeOverride
	ebpfcommon.IntegrityModeOverride = true
	t.Cleanup(func() {
		ebpfcommon.IntegrityModeOverride = previous
	})
}
