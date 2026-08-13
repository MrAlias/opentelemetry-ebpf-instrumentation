// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

var spanSet = []request.Span{
	{Pid: request.PidInfo{UserPID: 33, HostPID: 123, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 66, HostPID: 456, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 1000, HostPID: 1234, Namespace: 44}},
}

var spanSetWithPaths = []request.Span{
	{Pid: request.PidInfo{UserPID: 33, HostPID: 123, Namespace: 33}, Path: "/something"},
	{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}, Path: "/v1/traces"},
	{Pid: request.PidInfo{UserPID: 66, HostPID: 456, Namespace: 33}, Path: "/v1/metrics"},
	{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 1000, HostPID: 1234, Namespace: 44}},
}

type avoidedServiceRecord struct {
	name      string
	namespace string
	instance  string
}

type avoidedServiceRecordingReporter struct {
	imetrics.NoopReporter
	metrics []avoidedServiceRecord
	traces  []avoidedServiceRecord
}

func (r *avoidedServiceRecordingReporter) AvoidInstrumentationMetrics(name, namespace, instance string) {
	r.metrics = append(r.metrics, avoidedServiceRecord{name: name, namespace: namespace, instance: instance})
}

func (r *avoidedServiceRecordingReporter) AvoidInstrumentationTraces(name, namespace, instance string) {
	r.traces = append(r.traces, avoidedServiceRecord{name: name, namespace: namespace, instance: instance})
}

func allowTestPID(pf *PIDsFilter, pid app.PID, ns uint32, fi *exec.FileInfo, pidType PIDType) {
	pf.AllowPID(pid, ns, fi, fi, pidType)
}

func TestFilter_SameNS(t *testing.T) {
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid}, nil
	}
	pf := NewPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})
	allowTestPID(pf, 123, 33, exec.New(exec.Init{}), PIDTypeGo)
	allowTestPID(pf, 456, 33, exec.New(exec.Init{}), PIDTypeGo)
	allowTestPID(pf, 789, 33, exec.New(exec.Init{}), PIDTypeGo)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by OBI's process discovery
	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	}, resetTraceContext(pf.Filter(spanSet)))
}

func TestFilter_DifferentNS(t *testing.T) {
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid}, nil
	}
	pf := NewPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})
	allowTestPID(pf, 123, 22, exec.New(exec.Init{}), PIDTypeGo)
	allowTestPID(pf, 456, 22, exec.New(exec.Init{}), PIDTypeGo)
	allowTestPID(pf, 666, 22, exec.New(exec.Init{}), PIDTypeGo)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by OBI's process discovery
	assert.Equal(t, []request.Span{}, resetTraceContext(pf.Filter(spanSet)))
}

func TestFilter_Block(t *testing.T) {
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid}, nil
	}
	pf := NewPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})
	allowTestPID(pf, 123, 33, exec.New(exec.Init{}), PIDTypeGo)
	allowTestPID(pf, 456, 33, exec.New(exec.Init{}), PIDTypeGo)
	pf.BlockPID(123, 33, nil, nil)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by OBI's process discovery
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, []request.Span{
			{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		}, resetTraceContext(pf.Filter(spanSet)))
	}, 10*time.Second, 10*time.Millisecond, "still haven't seen pid 123 as blocked")
}

func TestFilter_StaleLifetimeDeletionPreservesReplacement(t *testing.T) {
	originalReadNamespacePIDs := readNamespacePIDs
	t.Cleanup(func() { readNamespacePIDs = originalReadNamespacePIDs })
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid}, nil
	}

	const pid = app.PID(123)
	const ns = uint32(33)
	predecessor := exec.New(exec.Init{Pid: pid})
	replacement := exec.New(exec.Init{Pid: pid})
	filter := NewPIDsFilter(
		&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{},
	)
	filter.AllowPID(pid, ns, predecessor, predecessor, PIDTypeKProbes)
	filter.AllowPID(pid, ns, replacement, replacement, PIDTypeKProbes)

	filter.BlockPID(pid, ns, predecessor, predecessor)
	assert.True(t, filter.ValidPID(pid, ns, PIDTypeKProbes))

	filter.BlockPID(pid, ns, replacement, replacement)
	assert.False(t, filter.ValidPID(pid, ns, PIDTypeKProbes))
}

func TestFilter_ParentSubstitutedChildDeletionUsesAdmissionOwner(t *testing.T) {
	originalReadNamespacePIDs := readNamespacePIDs
	t.Cleanup(func() { readNamespacePIDs = originalReadNamespacePIDs })
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid}, nil
	}

	const childPID = app.PID(123)
	const ns = uint32(33)
	parentService := exec.New(exec.Init{Pid: 122})
	childOwner := exec.New(exec.Init{Pid: childPID})
	filter := NewPIDsFilter(
		&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{},
	)
	filter.AllowPID(childPID, ns, parentService, childOwner, PIDTypeKProbes)
	require.True(t, filter.ValidPID(childPID, ns, PIDTypeKProbes))

	filter.BlockPID(childPID, ns, parentService, childOwner)
	require.False(t, filter.ValidPID(childPID, ns, PIDTypeKProbes))
}

func TestFilter_ParentSubstitutedChildStaleDeletionPreservesReplacement(t *testing.T) {
	originalReadNamespacePIDs := readNamespacePIDs
	t.Cleanup(func() { readNamespacePIDs = originalReadNamespacePIDs })
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid}, nil
	}

	const childPID = app.PID(123)
	const ns = uint32(33)
	parentService := exec.New(exec.Init{Pid: 122})
	predecessorOwner := exec.New(exec.Init{Pid: childPID})
	replacementOwner := exec.New(exec.Init{Pid: childPID})
	filter := NewPIDsFilter(
		&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{},
	)

	filter.AllowPID(childPID, ns, parentService, predecessorOwner, PIDTypeKProbes)
	filter.AllowPID(childPID, ns, parentService, replacementOwner, PIDTypeKProbes)

	filter.BlockPID(childPID, ns, parentService, predecessorOwner)
	assert.True(t, filter.ValidPID(childPID, ns, PIDTypeKProbes))
	require.Same(t, parentService, filter.current[ns][childPID].fileInfo)
	require.Same(t, replacementOwner, filter.current[ns][childPID].owner)

	filter.BlockPID(childPID, ns, parentService, replacementOwner)
	assert.False(t, filter.ValidPID(childPID, ns, PIDTypeKProbes))
}

func TestFilter_AliasReplacementResetsTypesAndSurvivesOldOwnerDeletion(t *testing.T) {
	originalReadNamespacePIDs := readNamespacePIDs
	t.Cleanup(func() { readNamespacePIDs = originalReadNamespacePIDs })
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		switch pid {
		case 123:
			return []app.PID{123, 7}, nil
		case 456:
			return []app.PID{456, 7}, nil
		default:
			return []app.PID{pid}, nil
		}
	}

	const ns = uint32(33)
	oldOwner := exec.New(exec.Init{Pid: 123})
	newOwner := exec.New(exec.Init{Pid: 456})
	filter := NewPIDsFilter(
		&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{},
	)
	filter.AllowPID(123, ns, oldOwner, oldOwner, PIDTypeGo)
	filter.AllowPID(456, ns, newOwner, newOwner, PIDTypeKProbes)

	assert.True(t, filter.ValidPID(7, ns, PIDTypeKProbes))
	assert.False(t, filter.ValidPID(7, ns, PIDTypeGo),
		"a replacement alias must not inherit predecessor PIDType bits")
	require.Same(t, newOwner, filter.current[ns][7].owner)

	filter.BlockPID(123, ns, oldOwner, oldOwner)
	assert.True(t, filter.ValidPID(7, ns, PIDTypeKProbes),
		"deleting the old owner must preserve an alias reassigned to the replacement")
	require.Same(t, newOwner, filter.current[ns][7].owner)
}

func TestFilter_InnermostAliasOutranksOuterCollisionAndDeletionRestores(t *testing.T) {
	originalReadNamespacePIDs := readNamespacePIDs
	t.Cleanup(func() { readNamespacePIDs = originalReadNamespacePIDs })
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		switch pid {
		case 2000:
			// PID 1000 is this process's innermost alias and is the value BPF
			// emits together with ns.
			return []app.PID{2000, 1000}, nil
		case 1000:
			// The same number is only this process's outer alias.
			return []app.PID{1000, 7}, nil
		default:
			return []app.PID{pid}, nil
		}
	}

	const ns = uint32(33)
	innerOwner := exec.New(exec.Init{
		Pid:     2000,
		Service: svc.Attrs{UID: svc.UID{Name: "inner-winner"}},
	})
	outerOwner := exec.New(exec.Init{
		Pid:     1000,
		Service: svc.Attrs{UID: svc.UID{Name: "outer-fallback"}},
	})
	filter := NewPIDsFilter(
		&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{},
	)

	// Admit B before A: last-writer order must not let A's outer alias steal
	// attribution from B's innermost alias.
	filter.AllowPID(2000, ns, innerOwner, innerOwner, PIDTypeGo)
	filter.AllowPID(1000, ns, outerOwner, outerOwner, PIDTypeKProbes)

	require.Same(t, innerOwner, filter.current[ns][1000].owner)
	assert.True(t, filter.ValidPID(1000, ns, PIDTypeGo))
	assert.False(t, filter.ValidPID(1000, ns, PIDTypeKProbes))
	spans := filter.Filter([]request.Span{{
		Pid: request.PidInfo{UserPID: 1000, HostPID: 2000, Namespace: ns},
	}})
	require.Len(t, spans, 1)
	assert.Equal(t, "inner-winner", spans[0].Service.UID.Name)

	filter.BlockPID(2000, ns, innerOwner, innerOwner)

	// Removing the winner reveals the still-live lower-ranked candidate rather
	// than losing the colliding key entirely.
	require.Same(t, outerOwner, filter.current[ns][1000].owner)
	assert.False(t, filter.ValidPID(1000, ns, PIDTypeGo))
	assert.True(t, filter.ValidPID(1000, ns, PIDTypeKProbes))
	spans = filter.Filter([]request.Span{{
		Pid: request.PidInfo{UserPID: 1000, HostPID: 1000, Namespace: ns},
	}})
	require.Len(t, spans, 1)
	assert.Equal(t, "outer-fallback", spans[0].Service.UID.Name)
}

func TestFilter_SameHostReplacementRetiresHiddenPredecessorCandidates(t *testing.T) {
	originalReadNamespacePIDs := readNamespacePIDs
	t.Cleanup(func() { readNamespacePIDs = originalReadNamespacePIDs })
	replacementLookups := 0
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		switch pid {
		case 1000:
			replacementLookups++
			if replacementLookups == 1 {
				return []app.PID{1000, 7}, nil
			}
			return []app.PID{1000, 8}, nil
		case 2000:
			return []app.PID{2000, 1000}, nil
		default:
			return []app.PID{pid}, nil
		}
	}

	const ns = uint32(33)
	predecessor := exec.New(exec.Init{Pid: 1000})
	competitor := exec.New(exec.Init{Pid: 2000})
	replacement := exec.New(exec.Init{Pid: 1000})
	filter := NewPIDsFilter(
		&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{},
	)

	filter.AllowPID(1000, ns, predecessor, predecessor, PIDTypeGo)
	filter.AllowPID(2000, ns, competitor, competitor, PIDTypeKProbes)
	require.Same(t, competitor, filter.current[ns][1000].owner,
		"the competitor hides the predecessor's outer alias")

	filter.AllowPID(1000, ns, replacement, replacement, PIDTypeGo)

	assert.False(t, filter.ValidPID(7, ns, PIDTypeGo),
		"same-host replacement must retire even a hidden predecessor alias")
	assert.True(t, filter.ValidPID(8, ns, PIDTypeGo))
	require.Same(t, competitor, filter.current[ns][1000].owner)

	filter.BlockPID(1000, ns, predecessor, predecessor)
	assert.True(t, filter.ValidPID(8, ns, PIDTypeGo),
		"a delayed predecessor deletion must preserve the replacement")

	filter.BlockPID(2000, ns, competitor, competitor)
	require.Same(t, replacement, filter.current[ns][1000].owner,
		"deleting the innermost winner must restore the replacement candidate")
}

func TestFilter_SameHostReplacementRetiresPredecessorAcrossNamespaces(t *testing.T) {
	originalReadNamespacePIDs := readNamespacePIDs
	t.Cleanup(func() { readNamespacePIDs = originalReadNamespacePIDs })
	lookups := 0
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		lookups++
		if lookups == 1 {
			return []app.PID{pid, 7}, nil
		}
		return []app.PID{pid, 8}, nil
	}

	const pid = app.PID(1000)
	const predecessorNS = uint32(33)
	const replacementNS = uint32(44)
	predecessor := exec.New(exec.Init{Pid: pid})
	replacement := exec.New(exec.Init{Pid: pid})
	filter := NewPIDsFilter(
		&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{},
	)

	filter.AllowPID(pid, predecessorNS, predecessor, predecessor, PIDTypeGo)
	filter.AllowPID(pid, replacementNS, replacement, replacement, PIDTypeKProbes)

	assert.False(t, filter.ValidPID(7, predecessorNS, PIDTypeGo))
	assert.False(t, filter.ValidPID(pid, predecessorNS, PIDTypeGo))
	assert.True(t, filter.ValidPID(8, replacementNS, PIDTypeKProbes))
	require.Same(t, replacement, filter.current[replacementNS][pid].owner)

	filter.BlockPID(pid, predecessorNS, predecessor, predecessor)
	assert.True(t, filter.ValidPID(8, replacementNS, PIDTypeKProbes),
		"a stale predecessor deletion must preserve a replacement in another namespace")
}

func TestFilter_PostPublishOwnerValidationFailureRestoresCollisionWinner(t *testing.T) {
	originalReadNamespacePIDs := readNamespacePIDs
	t.Cleanup(func() { readNamespacePIDs = originalReadNamespacePIDs })
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid, 7}, nil
	}

	const ns = uint32(33)
	incumbent := exec.New(exec.Init{
		Pid:     2000,
		Service: svc.Attrs{UID: svc.UID{Name: "incumbent"}},
	})
	rejected := exec.New(exec.Init{
		Pid:     3000,
		Service: svc.Attrs{UID: svc.UID{Name: "rejected"}},
	})
	filter := NewPIDsFilter(
		&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{},
	)
	filter.AllowPID(incumbent.Pid(), ns, incumbent, incumbent, PIDTypeGo)

	validationCalls := 0
	filter.validatePublishedOwner = func(pid app.PID, owner *exec.FileInfo) error {
		validationCalls++
		require.Equal(t, rejected.Pid(), pid)
		require.Same(t, rejected, owner)
		key := pidCandidateKey{hostPID: rejected.Pid(), owner: rejected}
		require.Contains(t, filter.candidates[ns][7], key,
			"the exact-owner check must run after candidate publication")
		require.Same(t, rejected, filter.current[ns][7].owner,
			"the later equal-rank candidate should be the transient winner")
		return errors.New("owner exited after alias lookup")
	}

	filter.AllowPID(rejected.Pid(), ns, rejected, rejected, PIDTypeKProbes)

	require.Equal(t, 1, validationCalls)
	assert.NotContains(t, filter.admissions, rejected.Pid())
	assert.False(t, filter.ValidPID(rejected.Pid(), ns, PIDTypeKProbes))
	require.Same(t, incumbent, filter.current[ns][7].owner)
	assert.True(t, filter.ValidPID(7, ns, PIDTypeGo))
	assert.False(t, filter.ValidPID(7, ns, PIDTypeKProbes))
	require.Len(t, filter.candidates[ns][7], 1)
}

func TestFilter_NewNSLater(t *testing.T) {
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid}, nil
	}
	pf := NewPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})
	allowTestPID(pf, 123, 33, exec.New(exec.Init{}), PIDTypeGo)
	allowTestPID(pf, 456, 33, exec.New(exec.Init{}), PIDTypeGo)
	allowTestPID(pf, 789, 33, exec.New(exec.Init{}), PIDTypeGo)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by OBI's process discovery
	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	}, resetTraceContext(pf.Filter(spanSet)))

	allowTestPID(pf, 1000, 44, exec.New(exec.Init{}), PIDTypeGo)

	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 1000, HostPID: 1234, Namespace: 44}},
	}, resetTraceContext(pf.Filter(spanSet)))

	pf.BlockPID(456, 33, nil, nil)

	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 1000, HostPID: 1234, Namespace: 44}},
	}, resetTraceContext(pf.Filter(spanSet)))

	pf.BlockPID(1000, 44, nil, nil)

	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	}, resetTraceContext(pf.Filter(spanSet)))
}

func TestFilter_ExportsOTelDetection(t *testing.T) {
	const defaultOtlpPort = 4317
	pf := NewPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})

	fi := exec.New(exec.Init{})
	span := request.Span{Type: request.EventTypeHTTP, Method: "GET", Path: "/random/server/span", RequestStart: 100, End: 200, Status: 200}

	pf.checkIfExportsOTel(fi, &span, defaultOtlpPort)
	assert.False(t, fi.ExportsOTelMetricsSpan())
	assert.False(t, fi.ExportsOTelMetrics())
	assert.False(t, fi.ExportsOTelTraces())

	fi = exec.New(exec.Init{})
	span = request.Span{Type: request.EventTypeHTTPClient, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 200}

	pf.checkIfExportsOTel(fi, &span, defaultOtlpPort)
	assert.False(t, fi.ExportsOTelMetricsSpan())
	assert.True(t, fi.ExportsOTelMetrics())
	assert.False(t, fi.ExportsOTelTraces())

	fi = exec.New(exec.Init{})
	span = request.Span{Type: request.EventTypeHTTPClient, Method: "GET", Path: "/v1/traces", RequestStart: 100, End: 200, Status: 200}

	pf.checkIfExportsOTel(fi, &span, defaultOtlpPort)
	assert.False(t, fi.ExportsOTelMetricsSpan())
	assert.False(t, fi.ExportsOTelMetrics())
	assert.True(t, fi.ExportsOTelTraces())
}

func TestFilter_ExportsOTelDetectionReportsAvoidedTraceServiceOnce(t *testing.T) {
	const defaultOtlpPort = 4317
	reporter := &avoidedServiceRecordingReporter{}
	pf := NewPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), reporter)

	expected := avoidedServiceRecord{
		name:      "java-backend",
		namespace: "apache-java-https",
		instance:  "java-1",
	}
	fi := exec.New(exec.Init{Service: svc.Attrs{UID: svc.UID{
		Name:      expected.name,
		Namespace: expected.namespace,
		Instance:  expected.instance,
	}}})
	span := request.Span{
		Type:         request.EventTypeHTTPClient,
		Method:       "POST",
		Path:         "/v1/traces",
		RequestStart: 100,
		End:          200,
		Status:       200,
	}

	pf.checkIfExportsOTel(fi, &span, defaultOtlpPort)
	pf.checkIfExportsOTel(fi, &span, defaultOtlpPort)

	assert.True(t, fi.ExportsOTelTraces())
	assert.Empty(t, reporter.metrics)
	assert.Equal(t, []avoidedServiceRecord{expected}, reporter.traces)
}

func TestFilter_ExportsOTelSpanDetection(t *testing.T) {
	const defaultOtlpPort = 4317
	pf := NewPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})

	fi := exec.New(exec.Init{})
	span := request.Span{Type: request.EventTypeHTTP, Method: "GET", Path: "/random/server/span", RequestStart: 100, End: 200, Status: 200}

	pf.checkIfExportsOTelSpanMetrics(fi, &span, defaultOtlpPort)
	assert.False(t, fi.ExportsOTelMetricsSpan())
	assert.False(t, fi.ExportsOTelMetrics())
	assert.False(t, fi.ExportsOTelTraces())

	fi = exec.New(exec.Init{})
	span = request.Span{Type: request.EventTypeHTTPClient, Method: "GET", Path: "/v1/metrics", RequestStart: 100, End: 200, Status: 200}

	pf.checkIfExportsOTelSpanMetrics(fi, &span, defaultOtlpPort)
	assert.False(t, fi.ExportsOTelMetricsSpan())
	assert.False(t, fi.ExportsOTelMetrics())
	assert.False(t, fi.ExportsOTelTraces())

	fi = exec.New(exec.Init{})
	span = request.Span{Type: request.EventTypeHTTPClient, Method: "GET", Path: "/v1/traces", RequestStart: 100, End: 200, Status: 200}

	pf.checkIfExportsOTelSpanMetrics(fi, &span, defaultOtlpPort)
	assert.False(t, fi.ExportsOTelMetrics())
	assert.True(t, fi.ExportsOTelMetricsSpan())
	assert.False(t, fi.ExportsOTelTraces())
	pf.checkIfExportsOTel(fi, &span, defaultOtlpPort)
	assert.True(t, fi.ExportsOTelTraces())
}

func TestFilter_TriggersOTelFiltering(t *testing.T) {
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid}, nil
	}
	pf := NewPIDsFilter(&services.DiscoveryConfig{ExcludeOTelInstrumentedServices: true, ExcludeOTelInstrumentedServicesSpanMetrics: true}, slog.With("env", "testing"), &imetrics.NoopReporter{})

	commonSvc := exec.New(exec.Init{})
	allowTestPID(pf, 33, 33, commonSvc, PIDTypeGo)
	allowTestPID(pf, 123, 33, commonSvc, PIDTypeGo)
	allowTestPID(pf, 456, 33, commonSvc, PIDTypeGo)
	allowTestPID(pf, 66, 33, commonSvc, PIDTypeGo)
	allowTestPID(pf, 789, 33, commonSvc, PIDTypeGo)

	testSpans := make([]request.Span, len(spanSetWithPaths))

	service := svc.Attrs{}

	for i := range spanSetWithPaths {
		testSpans[i] = spanSetWithPaths[i]
		testSpans[i].Service = service
		testSpans[i].Status = 200
		testSpans[i].Type = request.EventTypeHTTPClient
	}

	filtered := filterService(pf.Filter(testSpans))
	assert.Len(t, filtered, 5)

	// the first one didn't see any of the /v1/metrics, /v1/traces URLs in traffic
	assert.False(t, filtered[0].ExportsOTelMetrics())
	assert.False(t, filtered[0].ExportsOTelMetricsSpan())
	assert.False(t, filtered[0].ExportsOTelTraces())

	// second one saw /v1/traces so we marked both traces and span metrics as exported
	assert.False(t, filtered[1].ExportsOTelMetrics())
	assert.True(t, filtered[1].ExportsOTelMetricsSpan())
	assert.True(t, filtered[1].ExportsOTelTraces())

	// after the third, which has url /v1/metrics, we detected everything exported
	for i := 2; i < 5; i++ {
		assert.True(t, filtered[i].ExportsOTelMetrics())
		assert.True(t, filtered[i].ExportsOTelMetricsSpan())
		assert.True(t, filtered[i].ExportsOTelTraces())
	}
}

func TestFilter_TriggersOTelSpanFiltering(t *testing.T) {
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid}, nil
	}
	pf := NewPIDsFilter(&services.DiscoveryConfig{ExcludeOTelInstrumentedServices: true}, slog.With("env", "testing"), &imetrics.NoopReporter{})

	commonSvc := exec.New(exec.Init{})
	allowTestPID(pf, 33, 33, commonSvc, PIDTypeGo)
	allowTestPID(pf, 123, 33, commonSvc, PIDTypeGo)
	allowTestPID(pf, 456, 33, commonSvc, PIDTypeGo)
	allowTestPID(pf, 66, 33, commonSvc, PIDTypeGo)
	allowTestPID(pf, 789, 33, commonSvc, PIDTypeGo)

	testSpans := make([]request.Span, len(spanSetWithPaths))

	service := svc.Attrs{}

	for i := range spanSetWithPaths {
		testSpans[i] = spanSetWithPaths[i]
		testSpans[i].Service = service
		testSpans[i].Status = 200
		testSpans[i].Type = request.EventTypeHTTPClient
	}

	filtered := filterService(pf.Filter(testSpans))
	assert.Len(t, filtered, 5)

	// the first one didn't see any of the /v1/metrics, /v1/traces URLs in traffic
	assert.False(t, filtered[0].ExportsOTelMetrics())
	assert.False(t, filtered[0].ExportsOTelMetricsSpan())
	assert.False(t, filtered[0].ExportsOTelTraces())

	// second one saw /v1/traces so we marked traces as exported, but not span metrics because the default config is false
	assert.False(t, filtered[1].ExportsOTelMetrics())
	assert.False(t, filtered[1].ExportsOTelMetricsSpan())
	assert.True(t, filtered[1].ExportsOTelTraces())

	// after the third, which has url /v1/metrics, we detected everything exported, but not span metrics
	for i := 2; i < 5; i++ {
		assert.True(t, filtered[i].ExportsOTelMetrics())
		assert.False(t, filtered[i].ExportsOTelMetricsSpan())
		assert.True(t, filtered[i].ExportsOTelTraces())
	}
}

func TestFilter_OTelDetectionKeepsKProbeCaptureEligibleForUncoveredProtocol(t *testing.T) {
	previousReadNamespacePIDs := readNamespacePIDs
	t.Cleanup(func() {
		readNamespacePIDs = previousReadNamespacePIDs
	})
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid}, nil
	}

	const (
		pid       = app.PID(123)
		namespace = uint32(33)
	)
	fileInfo := exec.New(exec.Init{
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableJava},
		Pid:     pid,
		Ns:      namespace,
	})
	pf := NewPIDsFilter(
		&services.DiscoveryConfig{ExcludeOTelInstrumentedServices: true},
		slog.With("env", "testing"),
		&imetrics.NoopReporter{},
	)
	allowTestPID(pf, pid, namespace, fileInfo, PIDTypeKProbes)

	exportSpans := pf.Filter([]request.Span{{
		Pid: request.PidInfo{
			UserPID:   pid,
			HostPID:   pid,
			Namespace: namespace,
		},
		Type:   request.EventTypeHTTPClient,
		Method: "POST",
		Path:   "/v1/traces",
		Status: 200,
	}})
	require.Len(t, exportSpans, 1)
	require.True(t, fileInfo.ExportsOTelTraces())
	require.True(t, pf.ValidPID(pid, namespace, PIDTypeKProbes))
	currentNamespace, namespaceExists := pf.CurrentPIDs(PIDTypeKProbes)[namespace]
	require.True(t, namespaceExists)
	_, pidExists := currentNamespace[pid]
	require.True(t, pidExists)

	event := makeRedisTCPEvent(directionSend)
	event.EventSource = GenericEventSourceTypeKProbes
	event.Pid.UserPid = uint32(pid)
	event.Pid.HostPid = uint32(pid)
	event.Pid.Ns = namespace
	requestBytes := respArray("GET", "cache-key")
	responseBytes := []byte("$5\r\nvalue\r\n")
	event.Len = uint32(len(requestBytes))
	event.RespLen = uint32(len(responseBytes))
	copy(event.Buf[:], requestBytes)
	copy(event.Rbuf[:], responseBytes)

	var raw bytes.Buffer
	require.NoError(t, binary.Write(&raw, binary.LittleEndian, event))
	ebpfConfig := config.EBPFTracer{}
	span, ignore, err := ReadTCPRequestIntoSpan(
		NewEBPFParseContext(&ebpfConfig, nil, nil),
		&ebpfConfig,
		&ringbuf.Record{RawSample: raw.Bytes()},
		pf,
	)
	require.NoError(t, err)
	require.False(t, ignore)
	require.Equal(t, request.EventTypeRedisClient, span.Type)
	require.Equal(t, "GET", span.Method)

	capturedSpans := pf.Filter([]request.Span{span})
	require.Len(t, capturedSpans, 1)
	assert.True(t, capturedSpans[0].Service.ExportsOTelTraces())
}

func TestFilter_Cleanup(t *testing.T) {
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		switch pid {
		case 123:
			return []app.PID{pid, 1}, nil
		case 456:
			return []app.PID{pid, 2}, nil
		case 789:
			return []app.PID{pid, 3}, nil
		}
		assert.Fail(t, "fix your test, unknown pid")
		return nil, nil
	}
	pf := NewPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})
	allowTestPID(pf, 123, 33, exec.New(exec.Init{}), PIDTypeGo)
	allowTestPID(pf, 456, 33, exec.New(exec.Init{}), PIDTypeGo)
	allowTestPID(pf, 789, 33, exec.New(exec.Init{}), PIDTypeGo)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by OBI's process discovery
	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	}, resetTraceContext(pf.Filter(spanSet)))

	// We should be able to filter on the other namespaced pids: 1, 2 and 3
	anotherSpanSet := []request.Span{
		{Pid: request.PidInfo{UserPID: 33, HostPID: 123, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 1, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 66, HostPID: 456, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 2, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 3, HostPID: 234, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 1000, HostPID: 1234, Namespace: 44}},
	}

	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 1, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 2, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 3, HostPID: 234, Namespace: 33}},
	}, resetTraceContext(pf.Filter(anotherSpanSet)))

	// We clean-up the first namespaced pids: 123, 456, 789. This should
	// also clean up: 1, 2, 3.
	pf.BlockPID(123, 33, nil, nil)
	pf.BlockPID(456, 33, nil, nil)
	pf.BlockPID(789, 33, nil, nil)

	assert.False(t, pf.ValidPID(1, 33, PIDTypeGo))
	assert.False(t, pf.ValidPID(2, 33, PIDTypeGo))
	assert.False(t, pf.ValidPID(3, 33, PIDTypeGo))
	assert.False(t, pf.ValidPID(333, 33, PIDTypeGo))
	assert.False(t, pf.ValidPID(666, 33, PIDTypeGo))
	assert.False(t, pf.ValidPID(234, 33, PIDTypeGo))
}

func TestFilter_PreservesMultiplePIDTypes(t *testing.T) {
	readNamespacePIDs = func(pid app.PID) ([]app.PID, error) {
		return []app.PID{pid, pid + 1000}, nil
	}
	pf := NewPIDsFilter(&services.DiscoveryConfig{}, slog.With("env", "testing"), &imetrics.NoopReporter{})

	fileInfo := exec.New(exec.Init{})
	allowTestPID(pf, 123, 33, fileInfo, PIDTypeGo)
	allowTestPID(pf, 123, 33, fileInfo, PIDTypeKProbes)

	assert.True(t, pf.ValidPID(123, 33, PIDTypeGo))
	assert.True(t, pf.ValidPID(123, 33, PIDTypeKProbes))
	assert.True(t, pf.ValidPID(1123, 33, PIDTypeGo))
	assert.True(t, pf.ValidPID(1123, 33, PIDTypeKProbes))

	goPIDs := pf.CurrentPIDs(PIDTypeGo)
	goNamespacePIDs, goNamespaceOK := goPIDs[33]
	if assert.True(t, goNamespaceOK) {
		_, goOK := goNamespacePIDs[123]
		assert.True(t, goOK)
	}

	kprobePIDs := pf.CurrentPIDs(PIDTypeKProbes)
	kprobeNamespacePIDs, kprobeNamespaceOK := kprobePIDs[33]
	if assert.True(t, kprobeNamespaceOK) {
		_, kprobeOK := kprobeNamespacePIDs[123]
		assert.True(t, kprobeOK)
	}

	pf.BlockPID(123, 33, nil, nil)

	assert.False(t, pf.ValidPID(123, 33, PIDTypeGo))
	assert.False(t, pf.ValidPID(123, 33, PIDTypeKProbes))
	assert.False(t, pf.ValidPID(1123, 33, PIDTypeGo))
	assert.False(t, pf.ValidPID(1123, 33, PIDTypeKProbes))
}

func resetTraceContext(spans []request.Span) []request.Span {
	for i := range spans {
		spans[i].TraceID = trace.TraceID{0}
		spans[i].SpanID = trace.SpanID{0}
		spans[i].TraceFlags = 0
	}

	return spans
}

func filterService(spans []request.Span) []svc.Attrs {
	result := []svc.Attrs{}
	for i := range spans {
		result = append(result, spans[i].Service)
	}

	return result
}
