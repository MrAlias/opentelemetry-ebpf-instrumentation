// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/selection"
)

// pidMultisetEqual reports whether a and b contain the same PIDs with the same multiplicity.
func pidMultisetEqual(a, b []app.PID) bool {
	if len(a) != len(b) {
		return false
	}
	sa := slices.Clone(a)
	sb := slices.Clone(b)
	slices.Sort(sa)
	slices.Sort(sb)
	return slices.Equal(sa, sb)
}

// readPIDNotifyBatchesUntil reads from ch until the concatenation of batches matches want
// as a multiset (order of batches and within batches does not matter).
func readPIDNotifyBatchesUntil(t *testing.T, ch <-chan []app.PID, want []app.PID) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	var got []app.PID
	for !pidMultisetEqual(got, want) {
		if len(got) > len(want) {
			t.Fatalf("unexpected extra PID notify batches: got %v want %v", got, want)
		}
		select {
		case b := <-ch:
			got = append(got, b...)
		case <-ctx.Done():
			t.Fatalf("timeout reading notify batches: got %v want %v", got, want)
		}
	}
}

func TestDynamicPIDSelector_AddPIDs_RemovePIDs_GetPIDs(t *testing.T) {
	d := NewDynamicPIDSelector()
	pids, ok := d.GetPIDs()
	assert.False(t, ok)
	assert.Nil(t, pids)

	d.AddPIDs(1, 2, 3)
	pids, ok = d.GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{1, 2, 3}, pids)

	d.AddPIDs(2, 3, 4)
	pids, ok = d.GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{1, 2, 3, 4}, pids)

	d.RemovePIDs(2, 4)
	pids, ok = d.GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{1, 3}, pids)

	d.RemovePIDs(1, 3)
	pids, ok = d.GetPIDs()
	assert.False(t, ok)
	assert.Nil(t, pids)
}

func TestDynamicPIDSelector_Subviews(t *testing.T) {
	d := NewDynamicPIDSelector()

	d.Traces().AddPIDs(1, 2)
	d.AppMetrics().AddPIDs(2, 3)
	d.NetworkMetrics().AddPIDs(4)
	d.StatsMetrics().AddPIDs(5)

	rootPIDs, ok := d.GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{1, 2, 3, 4, 5}, rootPIDs)

	tracesPIDs, ok := d.Traces().GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{1, 2}, tracesPIDs)

	appMetricPIDs, ok := d.AppMetrics().GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{2, 3}, appMetricPIDs)

	appSignalPIDs, ok := d.appSignals().GetPIDs()
	require.True(t, ok)
	assert.Equal(t, []app.PID{1, 2, 3}, appSignalPIDs)

	assert.True(t, d.Traces().IncludesPID(1))
	assert.False(t, d.Traces().IncludesPID(3))
	assert.True(t, d.AppMetrics().IncludesPID(3))
	assert.False(t, d.NetworkMetrics().IncludesPID(3))
}

func TestDynamicPIDSelector_AppUnionNotifications(t *testing.T) {
	d := NewDynamicPIDSelector()
	tracesAdded := d.Traces().AddedPIDsNotify()
	metricsAdded := d.AppMetrics().AddedPIDsNotify()
	appAdded := d.appSignals().AddedPIDsNotify()
	rootAdded := d.AddedPIDsNotify()

	d.Traces().AddPIDs(42)
	assert.Equal(t, []app.PID{42}, <-tracesAdded)
	assert.Equal(t, []app.PID{42}, <-appAdded)
	assert.Equal(t, []app.PID{42}, <-rootAdded)

	d.AppMetrics().AddPIDs(42)
	assert.Equal(t, []app.PID{42}, <-metricsAdded)
	select {
	case <-appAdded:
		t.Fatal("expected no app-union add when PID already selected for traces")
	default:
	}
	select {
	case <-rootAdded:
		t.Fatal("expected no root add when PID already selected by another signal")
	default:
	}

	tracesRemoved := d.Traces().RemovedNotify()
	metricsRemoved := d.AppMetrics().RemovedNotify()
	appRemoved := d.appSignals().RemovedNotify()
	rootRemoved := d.RemovedNotify()

	d.Traces().RemovePIDs(42)
	assert.Equal(t, []app.PID{42}, <-tracesRemoved)
	select {
	case <-appRemoved:
		t.Fatal("expected no app-union remove while metrics still selected")
	default:
	}
	select {
	case <-rootRemoved:
		t.Fatal("expected no root remove while another signal still selected")
	default:
	}

	d.AppMetrics().RemovePIDs(42)
	assert.Equal(t, []app.PID{42}, <-metricsRemoved)
	assert.Equal(t, []app.PID{42}, <-appRemoved)
	assert.Equal(t, []app.PID{42}, <-rootRemoved)
}

func TestDynamicPIDSelector_NotifyBroadcastsToAllSubscribers(t *testing.T) {
	d := NewDynamicPIDSelector()
	addedOne := d.AddedPIDsNotify()
	addedTwo := d.AddedPIDsNotify()
	removedOne := d.RemovedNotify()
	removedTwo := d.RemovedNotify()

	d.AddPIDs(42)
	assert.Equal(t, []app.PID{42}, <-addedOne)
	assert.Equal(t, []app.PID{42}, <-addedTwo)

	d.RemovePIDs(42)
	assert.Equal(t, []app.PID{42}, <-removedOne)
	assert.Equal(t, []app.PID{42}, <-removedTwo)
}

func waitNotifyBufferLen(t *testing.T, ch <-chan []app.PID, want int) {
	t.Helper()
	require.Eventually(t, func() bool {
		return len(ch) == want
	}, 2*time.Second, 10*time.Millisecond)
}

func readPIDNotifyBatch(t *testing.T, ch <-chan []app.PID) []app.PID {
	t.Helper()
	select {
	case batch := <-ch:
		return batch
	case <-time.After(2 * time.Second):
		t.Fatal("timeout reading notify batch")
	}
	return nil
}

func TestDynamicPIDSelector_AddedNotifyDoesNotBlockBehindFullSubscriber(t *testing.T) {
	d := NewDynamicPIDSelector()
	stale := d.AddedPIDsNotify()

	for pid := uint32(1); pid <= dynamicPIDNotifyBufferSize; pid++ {
		d.AddPIDs(pid)
		waitNotifyBufferLen(t, stale, int(pid))
	}

	active := d.AddedPIDsNotify()
	d.AddPIDs(dynamicPIDNotifyBufferSize + 1)
	assert.Equal(t, []app.PID{dynamicPIDNotifyBufferSize + 1}, readPIDNotifyBatch(t, active))

	for pid := app.PID(1); pid <= dynamicPIDNotifyBufferSize; pid++ {
		assert.Equal(t, []app.PID{pid}, readPIDNotifyBatch(t, stale))
	}
	assert.Equal(t, []app.PID{dynamicPIDNotifyBufferSize + 1}, readPIDNotifyBatch(t, stale))
}

func TestDynamicPIDSelector_RemovedNotifyDoesNotBlockBehindFullSubscriber(t *testing.T) {
	d := NewDynamicPIDSelector()
	for pid := uint32(1); pid <= dynamicPIDNotifyBufferSize+1; pid++ {
		d.AddPIDs(pid)
	}
	stale := d.RemovedNotify()

	for pid := uint32(1); pid <= dynamicPIDNotifyBufferSize; pid++ {
		d.RemovePIDs(pid)
		waitNotifyBufferLen(t, stale, int(pid))
	}

	active := d.RemovedNotify()
	d.RemovePIDs(dynamicPIDNotifyBufferSize + 1)
	assert.Equal(t, []app.PID{dynamicPIDNotifyBufferSize + 1}, readPIDNotifyBatch(t, active))

	for pid := app.PID(1); pid <= dynamicPIDNotifyBufferSize; pid++ {
		assert.Equal(t, []app.PID{pid}, readPIDNotifyBatch(t, stale))
	}
	assert.Equal(t, []app.PID{dynamicPIDNotifyBufferSize + 1}, readPIDNotifyBatch(t, stale))
}

func TestDynamicPIDSubscriber_BoundsLegacyFullSubscriberBacklog(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	subscriber := newDynamicPIDSubscriber(ctx, dynamicPIDNotifyPendingMax)

	for pid := app.PID(1); pid <= dynamicPIDNotifyBufferSize; pid++ {
		subscriber.ch <- []app.PID{pid}
	}
	subscriber.notify([]app.PID{dynamicPIDNotifyBufferSize + 1})

	require.Eventually(t, func() bool {
		subscriber.mu.Lock()
		defer subscriber.mu.Unlock()
		return len(subscriber.pending) == 0
	}, 2*time.Second, 10*time.Millisecond)

	var batch []app.PID
	for pid := app.PID(dynamicPIDNotifyBufferSize + 2); pid <= dynamicPIDNotifyBufferSize+dynamicPIDNotifyPendingMax+20; pid++ {
		batch = append(batch, pid)
	}
	subscriber.notify(batch)

	subscriber.mu.Lock()
	assert.Len(t, subscriber.pending, dynamicPIDNotifyPendingMax)
	subscriber.mu.Unlock()

	cancel()
	<-subscriber.done
}

func TestDynamicPIDSubscriber_ContextSubscriberQueuesBeyondLegacyLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	subscriber := newDynamicPIDSubscriber(ctx, 0)

	for pid := app.PID(1); pid <= dynamicPIDNotifyBufferSize; pid++ {
		subscriber.ch <- []app.PID{pid}
	}
	subscriber.notify([]app.PID{dynamicPIDNotifyBufferSize + 1})

	require.Eventually(t, func() bool {
		subscriber.mu.Lock()
		defer subscriber.mu.Unlock()
		return len(subscriber.pending) == 0
	}, 2*time.Second, 10*time.Millisecond)

	var batch []app.PID
	for pid := app.PID(dynamicPIDNotifyBufferSize + 2); pid <= dynamicPIDNotifyBufferSize+dynamicPIDNotifyPendingMax+20; pid++ {
		batch = append(batch, pid)
	}
	subscriber.notify(batch)

	subscriber.mu.Lock()
	assert.Equal(t, batch, subscriber.pending)
	subscriber.mu.Unlock()

	cancel()
	<-subscriber.done
}

func TestDynamicPIDSubscriber_PreservesDuplicatePendingPIDEdges(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	subscriber := newDynamicPIDSubscriber(ctx, 0)

	for pid := app.PID(1); pid <= dynamicPIDNotifyBufferSize; pid++ {
		subscriber.ch <- []app.PID{pid}
	}
	subscriber.notify([]app.PID{dynamicPIDNotifyBufferSize + 1})

	require.Eventually(t, func() bool {
		subscriber.mu.Lock()
		defer subscriber.mu.Unlock()
		return len(subscriber.pending) == 0
	}, 2*time.Second, 10*time.Millisecond)

	batch := []app.PID{
		dynamicPIDNotifyBufferSize + 2,
		dynamicPIDNotifyBufferSize + 2,
		dynamicPIDNotifyBufferSize + 3,
	}
	subscriber.notify(batch)

	subscriber.mu.Lock()
	assert.Equal(t, batch, subscriber.pending)
	subscriber.mu.Unlock()

	cancel()
	<-subscriber.done
}

func TestDynamicPIDSelector_NotifyContextRemovesSubscriberOnCancel(t *testing.T) {
	d := NewDynamicPIDSelector()
	ctx, cancel := context.WithCancel(t.Context())
	added := d.AddedPIDsNotifyContext(ctx)
	removed := d.RemovedNotifyContext(ctx)

	cancel()

	require.Eventually(t, func() bool {
		d.rootView.notifier.addedMu.Lock()
		defer d.rootView.notifier.addedMu.Unlock()
		return len(d.rootView.notifier.addedSubscribers) == 0
	}, 2*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		d.rootView.notifier.removedMu.Lock()
		defer d.rootView.notifier.removedMu.Unlock()
		return len(d.rootView.notifier.removedSubscribers) == 0
	}, 2*time.Second, 10*time.Millisecond)

	_, ok := <-added
	assert.False(t, ok)
	_, ok = <-removed
	assert.False(t, ok)
}

func TestDynamicPIDSelector_RemovePIDs_Notify(t *testing.T) {
	d := NewDynamicPIDSelector()
	d.AddPIDs(42, 100)
	ch := d.RemovedNotify()

	d.RemovePIDs(100)
	got := <-ch
	assert.Equal(t, []app.PID{100}, got)

	d.RemovePIDs(42)
	got = <-ch
	assert.Equal(t, []app.PID{42}, got)
}

func TestDynamicPIDSelector_AddPIDs_Notify(t *testing.T) {
	d := NewDynamicPIDSelector()
	ch := d.AddedPIDsNotify()

	d.AddPIDs(42, 100)
	got := <-ch
	assert.Equal(t, []app.PID{42, 100}, got)

	// Adding already-present PIDs does not notify
	d.AddPIDs(42)
	select {
	case <-ch:
		t.Fatal("expected no send when adding existing PID")
	default:
	}
	// New PIDs only
	d.AddPIDs(42, 99)
	got = <-ch
	assert.Equal(t, []app.PID{99}, got)
}

// TestDynamicPIDSelector_QueueNoDrop verifies that rapid AddPIDs/RemovePIDs are all delivered
// on the notify channels (nothing dropped). With a buffered notify channel, one logical burst can
// span multiple receives; the consumer must drain until the expected multiset is complete.
func TestDynamicPIDSelector_QueueNoDrop(t *testing.T) {
	d := NewDynamicPIDSelector()
	d.AddPIDs(1, 2, 3, 4)
	removedCh := d.RemovedNotify()
	addedCh := d.AddedPIDsNotify()

	<-addedCh

	d.RemovePIDs(1)
	d.RemovePIDs(2, 3)
	readPIDNotifyBatchesUntil(t, removedCh, []app.PID{1, 2, 3})

	d.AddPIDs(10, 20)
	d.AddPIDs(30)
	readPIDNotifyBatchesUntil(t, addedCh, []app.PID{10, 20, 30})
}

func TestDynamicPIDSelector_AddPID_WithOptions(t *testing.T) {
	d := NewDynamicPIDSelector()
	d.Traces().AddPID(42, selection.DynamicPIDOptions{
		ServiceName:      "custom-svc",
		ServiceNamespace: "custom-ns",
		ResourceAttributes: map[string]string{
			"deployment.environment": "staging",
		},
	})

	entry, ok := d.GetPID(42)
	require.True(t, ok)
	assert.Equal(t, app.PID(42), entry.PID)
	assert.Equal(t, "custom-svc", entry.ServiceName)
	assert.Equal(t, "custom-ns", entry.ServiceNamespace)
	assert.Equal(t, "staging", entry.ResourceAttributes["deployment.environment"])
	assert.True(t, d.Traces().IncludesPID(42))
	assert.False(t, d.AppMetrics().IncludesPID(42))

	selector := d.appSignals().SelectorForPID(42)
	require.NotNil(t, selector)
	assert.Equal(t, "custom-svc", selector.GetName())
	attrs := ResourceAttributesFromSelector(selector)
	assert.Equal(t, "staging", attrs[attr.Name("deployment.environment")])
}

func TestDynamicPIDSelector_GetPID_SetPID(t *testing.T) {
	d := NewDynamicPIDSelector()
	d.AddPIDs(42)

	entry, ok := d.GetPID(42)
	require.True(t, ok)
	assert.Equal(t, app.PID(42), entry.PID)
	assert.Empty(t, entry.ServiceName)

	entry.ServiceName = "my app"
	entry.ResourceAttributes = map[string]string{"team": "platform"}
	require.True(t, d.SetPID(entry))

	updated, ok := d.GetPID(42)
	require.True(t, ok)
	assert.Equal(t, "my app", updated.ServiceName)
	assert.Equal(t, "platform", updated.ResourceAttributes["team"])

	assert.False(t, d.SetPID(selection.DynamicPIDEntry{PID: 99, ServiceName: "missing"}))
}

func TestDynamicPIDSelector_AddPID_UpdatesExistingAttributes(t *testing.T) {
	d := NewDynamicPIDSelector()
	d.Traces().AddPID(42, selection.DynamicPIDOptions{ServiceName: "first"})
	d.Traces().AddPID(42, selection.DynamicPIDOptions{ServiceName: "updated"})

	entry, ok := d.GetPID(42)
	require.True(t, ok)
	assert.Equal(t, "updated", entry.ServiceName)
}

func TestDynamicPIDSelector_AttributesSharedAcrossSignals(t *testing.T) {
	d := NewDynamicPIDSelector()
	d.Traces().AddPID(42, selection.DynamicPIDOptions{ServiceName: "shared-svc"})

	d.AppMetrics().AddPIDs(42)
	entry, ok := d.GetPID(42)
	require.True(t, ok)
	assert.Equal(t, "shared-svc", entry.ServiceName)
	assert.True(t, d.Traces().IncludesPID(42))
	assert.True(t, d.AppMetrics().IncludesPID(42))
}

func TestDynamicPIDSelector_SetPID_UpdatesFileInfo(t *testing.T) {
	d := NewDynamicPIDSelector()
	d.AddPIDs(42)

	fi := exec.New(exec.Init{
		Pid: 42,
		Service: svc.Attrs{
			UID:                svc.UID{Name: "old"},
			DynamicSelectorPID: 42,
		},
	})
	d.RegisterFileInfo(42, fi, fi)

	entry := selection.DynamicPIDEntry{
		PID:         42,
		ServiceName: "live-svc",
		ResourceAttributes: map[string]string{
			"team": "payments",
		},
	}
	require.True(t, d.SetPID(entry))

	snap := fi.ServiceAttrs()
	assert.Equal(t, "live-svc", snap.UID.Name)
	assert.Equal(t, "payments", snap.Metadata["team"])
}

func TestApplyDynamicPIDAttributesDoesNotResurrectRolledBackAdmission(t *testing.T) {
	const versionKey = attr.Name("service.version")
	fi := exec.New(exec.Init{})
	receipt := fi.BeginServiceMetadataAdmission("derived", versionKey, "1.2.3")
	require.NotNil(t, receipt)

	// Capture the exact stale snapshot that the former read-modify-write path
	// could publish after rollback. The updater now captures only field intent.
	stale := fi.ServiceAttrs()
	require.Equal(t, "derived", stale.UID.Name)
	require.Equal(t, "1.2.3", stale.Metadata[versionKey])
	update := dynamicPIDAttributes{
		serviceNamespace: "runtime-ns",
		resourceAttributes: map[string]string{
			"deployment.environment": "production",
		},
	}
	ready := make(chan struct{})
	release := make(chan struct{})
	done := make(chan bool, 1)
	go func() {
		close(ready)
		<-release
		done <- applyDynamicPIDAttributes(fi, update)
	}()
	<-ready

	receipt.Rollback()
	close(release)
	require.True(t, <-done)

	got := fi.ServiceAttrs()
	assert.Empty(t, got.UID.Name)
	assert.Equal(t, "runtime-ns", got.UID.Namespace)
	assert.NotContains(t, got.Metadata, versionKey)
	assert.Equal(t, "production", got.Metadata["deployment.environment"])
}

func TestApplyDynamicPIDAttributesExplicitFieldsSupersedeAdmission(t *testing.T) {
	const versionKey = attr.Name("service.version")
	fi := exec.New(exec.Init{})
	receipt := fi.BeginServiceMetadataAdmission("derived", versionKey, "1.2.3")
	require.NotNil(t, receipt)

	require.True(t, applyDynamicPIDAttributes(fi, dynamicPIDAttributes{
		serviceName: "derived",
		resourceAttributes: map[string]string{
			string(versionKey): "1.2.3",
		},
	}))
	receipt.Rollback()

	got := fi.ServiceAttrs()
	assert.Equal(t, "derived", got.UID.Name,
		"an explicit same-value name must supersede the provisional receipt")
	assert.Equal(t, "1.2.3", got.Metadata[versionKey],
		"an explicit same-value version must supersede the provisional receipt")
	assert.False(t, fi.AutoName())
}

func TestDynamicPIDSelector_RegisterReconcilesSetPIDCommittedAfterDiscoverySnapshot(t *testing.T) {
	const (
		ownerPID = app.PID(42)
		childPID = app.PID(43)
	)
	d := NewDynamicPIDSelector()
	d.AddPID(uint32(ownerPID), selection.DynamicPIDOptions{
		ServiceName:      "discovery-snapshot",
		ServiceNamespace: "old-namespace",
		ResourceAttributes: map[string]string{
			"generation": "old",
		},
	})

	// Simulate a FileInfo built from the selector snapshot above. SetPID wins
	// the race before the attacher registers this exact process lifetime.
	staleService := exec.New(exec.Init{Pid: childPID, Service: svc.Attrs{
		UID: svc.UID{
			Name:      "discovery-snapshot",
			Namespace: "old-namespace",
		},
		Metadata: map[attr.Name]string{
			"generation": "old",
			"preserved":  "yes",
		},
		DynamicSelectorPID: ownerPID,
	}})
	lifetime := exec.New(exec.Init{Pid: childPID})
	require.True(t, d.SetPID(selection.DynamicPIDEntry{
		PID:              ownerPID,
		ServiceName:      "committed-service",
		ServiceNamespace: "committed-namespace",
		ResourceAttributes: map[string]string{
			"generation": "new",
			"team":       "platform",
		},
	}))

	d.RegisterFileInfo(childPID, staleService, lifetime)

	snap := staleService.ServiceAttrs()
	assert.Equal(t, "committed-service", snap.UID.Name)
	assert.Equal(t, "committed-namespace", snap.UID.Namespace)
	assert.Equal(t, "new", snap.Metadata["generation"])
	assert.Equal(t, "platform", snap.Metadata["team"])
	assert.Equal(t, "yes", snap.Metadata["preserved"])
	assert.Same(t, staleService, d.fileInfoByPID[childPID])
	assert.Same(t, lifetime, d.lifetimeOwnerByPID[childPID])
}

func TestDynamicPIDSelector_SetPIDRegisterOverlapCannotMissCommittedAttributes(t *testing.T) {
	const (
		ownerPID = app.PID(42)
		childPID = app.PID(43)
	)
	d := NewDynamicPIDSelector()
	d.AddPID(uint32(ownerPID), selection.DynamicPIDOptions{ServiceName: "old"})

	existing := exec.New(exec.Init{Pid: ownerPID, Service: svc.Attrs{
		UID:                svc.UID{Name: "old"},
		DynamicSelectorPID: ownerPID,
	}})
	d.RegisterFileInfo(ownerPID, existing, existing)

	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	d.SetOnFileInfoUpdated(func(fi *exec.FileInfo) {
		if fi == existing {
			close(callbackStarted)
			<-releaseCallback
		}
	})
	setDone := make(chan bool, 1)
	go func() {
		setDone <- d.SetPID(selection.DynamicPIDEntry{
			PID:         ownerPID,
			ServiceName: "committed",
			ResourceAttributes: map[string]string{
				"generation": "new",
			},
		})
	}()

	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		t.Fatal("SetPID did not reach its update callback")
	}

	// SetPID has committed its selector state and completed the FileInfo set it
	// observed. Register a stale discovery result while its callback is paused;
	// registration must reconcile the committed state itself.
	late := exec.New(exec.Init{Pid: childPID, Service: svc.Attrs{
		UID:                svc.UID{Name: "old"},
		DynamicSelectorPID: ownerPID,
	}})
	lifetime := exec.New(exec.Init{Pid: childPID})
	registered := make(chan struct{})
	go func() {
		d.RegisterFileInfo(childPID, late, lifetime)
		close(registered)
	}()
	select {
	case <-registered:
	case <-time.After(time.Second):
		close(releaseCallback)
		t.Fatal("RegisterFileInfo blocked behind an update callback")
	}
	close(releaseCallback)
	assert.True(t, <-setDone)

	snap := late.ServiceAttrs()
	assert.Equal(t, "committed", snap.UID.Name)
	assert.Equal(t, "new", snap.Metadata["generation"])
}

func TestDynamicPIDSelector_SetPID_NotifiesFileInfoUpdate(t *testing.T) {
	d := NewDynamicPIDSelector()
	d.AddPIDs(42)

	fi := exec.New(exec.Init{Pid: 42, Service: svc.Attrs{DynamicSelectorPID: 42}})
	d.RegisterFileInfo(42, fi, fi)

	var notified *exec.FileInfo
	d.SetOnFileInfoUpdated(func(updated *exec.FileInfo) { notified = updated })

	require.True(t, d.SetPID(selection.DynamicPIDEntry{
		PID:         42,
		ServiceName: "metrics-svc",
	}))
	assert.Same(t, fi, notified)
}

func TestDynamicPIDSelector_SetPID_FansOutToOwnerAndDistinctChildren(t *testing.T) {
	const (
		ownerPID = app.PID(42)
		childOne = app.PID(43)
		childTwo = app.PID(44)
	)
	d := NewDynamicPIDSelector()
	d.AddPIDs(uint32(ownerPID))

	owner := exec.New(exec.Init{Pid: ownerPID, Service: svc.Attrs{
		UID:                svc.UID{Name: "owner"},
		DynamicSelectorPID: ownerPID,
	}})
	firstChild := exec.New(exec.Init{Pid: childOne, Service: svc.Attrs{
		UID:                svc.UID{Name: "first-child"},
		DynamicSelectorPID: ownerPID,
	}})
	secondChild := exec.New(exec.Init{Pid: childTwo, Service: svc.Attrs{
		UID:                svc.UID{Name: "second-child"},
		Metadata:           map[attr.Name]string{"existing": "preserved"},
		DynamicSelectorPID: ownerPID,
	}})
	d.RegisterFileInfo(ownerPID, owner, owner)
	d.RegisterFileInfo(childOne, firstChild, firstChild)
	d.RegisterFileInfo(childTwo, secondChild, secondChild)

	notified := map[*exec.FileInfo]int{}
	d.SetOnFileInfoUpdated(func(fi *exec.FileInfo) { notified[fi]++ })
	require.True(t, d.SetPID(selection.DynamicPIDEntry{
		PID:              ownerPID,
		ServiceName:      "updated-service",
		ServiceNamespace: "updated-namespace",
		ResourceAttributes: map[string]string{
			"team": "platform",
		},
	}))

	for _, fi := range []*exec.FileInfo{owner, firstChild, secondChild} {
		snap := fi.ServiceAttrs()
		assert.Equal(t, "updated-service", snap.UID.Name)
		assert.Equal(t, "updated-namespace", snap.UID.Namespace)
		assert.Equal(t, "platform", snap.Metadata["team"])
		assert.Equal(t, 1, notified[fi], "each distinct FileInfo must be notified exactly once")
		assert.Equal(t, 1, d.fileInfosByOwner[ownerPID][fi])
	}
	assert.Equal(t, "preserved", secondChild.ServiceAttrs().Metadata["existing"])
	assert.Len(t, notified, 3)
}

func TestDynamicPIDSelector_SharedServiceFileInfoReferencesAreIdempotentAndKeyScoped(t *testing.T) {
	const (
		ownerPID = app.PID(42)
		childOne = app.PID(43)
		childTwo = app.PID(44)
	)
	d := NewDynamicPIDSelector()
	d.AddPIDs(uint32(ownerPID))

	shared := exec.New(exec.Init{Pid: ownerPID, Service: svc.Attrs{
		UID:                svc.UID{Name: "shared"},
		DynamicSelectorPID: ownerPID,
	}})
	firstChildLifetime := exec.New(exec.Init{Pid: childOne})
	secondChildLifetime := exec.New(exec.Init{Pid: childTwo})
	d.RegisterFileInfo(ownerPID, shared, shared)
	d.RegisterFileInfo(ownerPID, shared, shared)
	d.RegisterFileInfo(childOne, shared, firstChildLifetime)
	d.RegisterFileInfo(childOne, shared, firstChildLifetime)
	d.RegisterFileInfo(childTwo, shared, secondChildLifetime)

	assert.Equal(t, 3, d.fileInfosByOwner[ownerPID][shared],
		"duplicate registrations for the same PID, service, and lifetime must be idempotent")

	notified := 0
	d.SetOnFileInfoUpdated(func(fi *exec.FileInfo) {
		assert.Same(t, shared, fi)
		notified++
	})
	require.True(t, d.SetPID(selection.DynamicPIDEntry{PID: ownerPID, ServiceName: "before-exit"}))
	assert.Equal(t, 1, notified, "one shared FileInfo must receive one callback")

	d.UnregisterFileInfo(childOne, firstChildLifetime)
	d.UnregisterFileInfo(childOne, firstChildLifetime)
	assert.NotContains(t, d.fileInfoByPID, childOne)
	assert.NotContains(t, d.lifetimeOwnerByPID, childOne)
	assert.Same(t, shared, d.fileInfoByPID[ownerPID])
	assert.Same(t, shared, d.fileInfoByPID[childTwo])
	assert.Same(t, secondChildLifetime, d.lifetimeOwnerByPID[childTwo])
	assert.Equal(t, 2, d.fileInfosByOwner[ownerPID][shared],
		"retiring one child must preserve the parent and sibling references")

	require.True(t, d.SetPID(selection.DynamicPIDEntry{PID: ownerPID, ServiceName: "after-exit"}))
	assert.Equal(t, "after-exit", shared.ServiceAttrs().UID.Name)
	assert.Equal(t, 2, notified)
}

func TestDynamicPIDSelector_LifetimeReplacementRejectsDelayedUnregister(t *testing.T) {
	const (
		ownerPID = app.PID(42)
		childPID = app.PID(43)
	)
	d := NewDynamicPIDSelector()
	d.AddPIDs(uint32(ownerPID))

	sharedService := exec.New(exec.Init{Pid: ownerPID, Service: svc.Attrs{
		UID:                svc.UID{Name: "shared-service"},
		DynamicSelectorPID: ownerPID,
	}})
	oldLifetime := exec.New(exec.Init{Pid: childPID})
	replacementLifetime := exec.New(exec.Init{Pid: childPID})
	d.RegisterFileInfo(ownerPID, sharedService, sharedService)
	d.RegisterFileInfo(childPID, sharedService, oldLifetime)
	d.RegisterFileInfo(childPID, sharedService, replacementLifetime)
	d.RegisterFileInfo(childPID, sharedService, replacementLifetime)

	assert.Same(t, sharedService, d.fileInfoByPID[childPID])
	assert.Same(t, replacementLifetime, d.lifetimeOwnerByPID[childPID])
	assert.Equal(t, 2, d.fileInfosByOwner[ownerPID][sharedService],
		"replacing only the lifetime token must not duplicate the shared service reference")

	d.UnregisterFileInfo(childPID, oldLifetime)
	assert.Same(t, sharedService, d.fileInfoByPID[childPID],
		"a delayed old-lifetime retirement must preserve its replacement")
	assert.Same(t, replacementLifetime, d.lifetimeOwnerByPID[childPID])
	assert.Equal(t, 2, d.fileInfosByOwner[ownerPID][sharedService])

	notified := 0
	d.SetOnFileInfoUpdated(func(fi *exec.FileInfo) {
		assert.Same(t, sharedService, fi)
		notified++
	})
	require.True(t, d.SetPID(selection.DynamicPIDEntry{
		PID:         ownerPID,
		ServiceName: "replacement-live",
		ResourceAttributes: map[string]string{
			"generation": "new",
		},
	}))

	snap := sharedService.ServiceAttrs()
	assert.Equal(t, "replacement-live", snap.UID.Name)
	assert.Equal(t, "new", snap.Metadata["generation"])
	assert.Equal(t, 1, notified, "one shared service FileInfo must receive one callback")
}

func TestDynamicPIDSelector_SetPID_NotifiesAttrsUpdated(t *testing.T) {
	d := NewDynamicPIDSelector()
	d.AddPIDs(7)

	ch := d.AttrsUpdatedNotify()
	require.True(t, d.SetPID(selection.DynamicPIDEntry{PID: 7, ServiceName: "net-svc"}))

	select {
	case pid := <-ch:
		assert.Equal(t, app.PID(7), pid)
	default:
		t.Fatal("expected attrs updated notification")
	}
}
