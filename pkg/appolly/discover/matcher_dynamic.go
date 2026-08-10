// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"log/slog"
	"slices"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

type DynamicMatcher struct {
	Log                *slog.Logger
	DynamicPIDSelector *dynamicPIDSignalView
	Input              <-chan []Event[ProcessAttrs]
	Output             *msg.Queue[[]Event[ProcessMatch]]
	ProcessHistory     map[app.PID]ProcessMatch
	// RediscoverPIDsNotify feeds selected PIDs back to ProcessWatcher. On an owner
	// re-add, the batch contains both the owner and the still-live descendants
	// retired with it, so the watcher forgets and re-emits all of them.
	RediscoverPIDsNotify chan<- []app.PID
	// AddedPIDsNotify can be injected by tests. Production subscribes to the
	// dynamic selector with a context owned by Run.
	AddedPIDsNotify <-chan []app.PID
	// RemovedPIDsNotify, when set, carries owner PIDs removed from the dynamic
	// selector so the matcher can retire every history entry tagged to an owner.
	RemovedPIDsNotify <-chan []app.PID
	// removedDescendants holds only descendants retired by a selector-owner
	// removal. An owner re-add transfers and clears its set exactly once.
	removedDescendants map[app.PID]map[app.PID]struct{}
	// disabledTreeOwners retains the removed-owner lineage of currently observed
	// PIDs. Removed owner PIDs remain as ancestry roots while disabled; descendant
	// entries are dropped when they exit. A replacement or new child can inherit
	// lineage from its actual parent, and entries are cleared when the owner is
	// re-added.
	disabledTreeOwners map[app.PID]map[app.PID]struct{}
	// activeAddedOwners suppresses duplicate feedback when the independent add
	// and remove notification streams are observed in the opposite order from
	// the selector mutations. A removal edge clears the owner's marker.
	activeAddedOwners map[app.PID]struct{}
}

func dynamicMatcherProvider(
	input *msg.Queue[[]Event[ProcessAttrs]],
	output *msg.Queue[[]Event[ProcessMatch]],
	dynamicPIDs *dynamicPIDSignalView,
	rediscoverPIDsNotify chan<- []app.PID,
) swarm.InstanceFunc {
	if dynamicPIDs == nil {
		emptyFunc, _ := swarm.EmptyRunFunc()
		return swarm.DirectInstance(emptyFunc)
	}

	dynamicMatcher := &DynamicMatcher{
		Log:                  slog.With("component", "discover.DynamicMatcher"),
		DynamicPIDSelector:   dynamicPIDs,
		Input:                input.Subscribe(msg.SubscriberName("discover.DynamicMatcher")),
		Output:               output,
		ProcessHistory:       map[app.PID]ProcessMatch{},
		RediscoverPIDsNotify: rediscoverPIDsNotify,
		removedDescendants:   map[app.PID]map[app.PID]struct{}{},
		disabledTreeOwners:   map[app.PID]map[app.PID]struct{}{},
		activeAddedOwners:    map[app.PID]struct{}{},
	}
	return swarm.DirectInstance(dynamicMatcher.Run)
}

func (m *DynamicMatcher) Run(ctx context.Context) {
	defer m.Output.Close()
	m.Log.Debug("starting dynamic matcher node")

	notifyCtx, cancelNotify := context.WithCancel(ctx)
	defer cancelNotify()

	addedPIDsNotify := m.AddedPIDsNotify
	if addedPIDsNotify == nil && m.DynamicPIDSelector != nil && m.RediscoverPIDsNotify != nil {
		addedPIDsNotify = m.DynamicPIDSelector.AddedPIDsNotifyContext(notifyCtx)
	}
	removedPIDsNotify := m.RemovedPIDsNotify
	if removedPIDsNotify == nil && m.DynamicPIDSelector != nil {
		removedPIDsNotify = m.DynamicPIDSelector.RemovedNotifyContext(notifyCtx)
	}

	for {
		select {
		case <-ctx.Done():
			m.Log.Debug("context done, stopping node")
			return
		case i, ok := <-m.Input:
			if !ok {
				m.Log.Debug("input channel closed, stopping node")
				return
			}
			m.Log.Debug("filtering processes", "len", len(i))
			o := m.filter(i)
			m.Log.Debug("processes matching selection criteria", "len", len(o))
			if len(o) > 0 {
				m.Output.SendCtx(ctx, o)
			}
		case addedPIDs, ok := <-addedPIDsNotify:
			if !ok {
				addedPIDsNotify = nil
				continue
			}
			// An inherited child that is selected independently changes lifecycle
			// owner. Retire the inherited admission before asking the watcher to
			// re-emit it, otherwise ProcessHistory suppresses the promotion and a
			// later removal of the old parent deletes the child incorrectly.
			if m.RediscoverPIDsNotify != nil {
				promoted := m.syntheticDeletesForPromotedPIDs(addedPIDs)
				if len(promoted) > 0 {
					m.Log.Debug("synthetic deletes for independently selected descendants", "len", len(promoted))
					m.Output.SendCtx(ctx, promoted)
				}
			}
			rediscoverPIDs := m.rediscoveryPIDsForAddedOwners(addedPIDs)
			if len(rediscoverPIDs) == 0 {
				continue
			}
			select {
			case m.RediscoverPIDsNotify <- rediscoverPIDs:
				m.Log.Debug("requesting dynamic PID rediscovery", "pids", rediscoverPIDs)
			case <-ctx.Done():
				return
			}
		case removedPIDs, ok := <-removedPIDsNotify:
			if !ok {
				removedPIDsNotify = nil
				continue
			}
			m.noteRemovedOwners(removedPIDs)
			o := m.syntheticDeletesForRemovedPIDs(removedPIDs)
			if len(o) > 0 {
				m.Log.Debug("synthetic deletes for removed PIDs", "len", len(o))
				m.Output.SendCtx(ctx, o)
			}
			// Added and removed notifications use independent subscribers. If a
			// fast re-add reached the selector before this removal edge was
			// observed, reconcile from the current level and request rediscovery
			// after the synthetic deletes have been queued.
			var readdedOwners []app.PID
			for _, owner := range removedPIDs {
				if m.DynamicPIDSelector != nil && m.DynamicPIDSelector.IncludesPID(owner) {
					readdedOwners = append(readdedOwners, owner)
				}
			}
			rediscoverPIDs := m.rediscoveryPIDsForAddedOwners(readdedOwners)
			if len(rediscoverPIDs) > 0 {
				select {
				case m.RediscoverPIDsNotify <- rediscoverPIDs:
					m.Log.Debug("requesting dynamic PID rediscovery after reordered notifications", "pids", rediscoverPIDs)
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (m *DynamicMatcher) filter(events []Event[ProcessAttrs]) []Event[ProcessMatch] {
	var matches []Event[ProcessMatch]
	for start := 0; start < len(events); {
		if events[start].Type == EventDeleted {
			if ev, ok := m.filterDeleted(events[start].Obj); ok {
				matches = append(matches, ev)
			}
			_ = events[start].Obj.closeProcessIdentity()
			start++
			continue
		}

		// Watcher rediscovery can emit an owner and its descendants in arbitrary
		// map order. Resolve this contiguous creation run as a dependency tree so
		// an owner (then child, then grandchild) is admitted before descendants.
		end := start + 1
		for end < len(events) && events[end].Type != EventDeleted {
			end++
		}
		matches = append(matches, m.filterCreatedBatch(events[start:end])...)
		for i := start; i < end; i++ {
			_ = events[i].Obj.closeProcessIdentity()
		}
		start = end
	}
	return matches
}

type dynamicCreateCandidate struct {
	obj ProcessAttrs
}

func (m *DynamicMatcher) filterCreatedBatch(events []Event[ProcessAttrs]) []Event[ProcessMatch] {
	var matches []Event[ProcessMatch]
	pendingByParent := map[app.PID][]dynamicCreateCandidate{}
	admitted := make([]app.PID, 0, len(events))
	for _, candidate := range events {
		event, parent, matched, retryable := m.filterCreatedCandidate(candidate.Obj)
		if matched {
			matches = append(matches, event)
			admitted = append(admitted, candidate.Obj.pid)
			continue
		}
		if retryable {
			pendingByParent[parent] = append(pendingByParent[parent], dynamicCreateCandidate{obj: candidate.Obj})
		}
	}

	// Resolve inherited processes breadth-first from every admission made in
	// this batch. This is linear in the batch size even for deep process trees.
	for len(admitted) > 0 {
		parent := admitted[0]
		admitted = admitted[1:]
		children := pendingByParent[parent]
		delete(pendingByParent, parent)
		for _, child := range children {
			if event, _, matched, _ := m.filterCreatedCandidate(child.obj); matched {
				matches = append(matches, event)
				admitted = append(admitted, child.obj.pid)
			}
		}
	}

	// No process in a disabled tree can be admitted until its selector owner is
	// re-added, but the watcher will still cache every observation in this batch.
	// Propagate the retained owner lineage through the remaining dependency tree
	// so unordered new children and grandchildren are all included in the next
	// rediscovery request.
	m.propagateDisabledTree(pendingByParent)
	return matches
}

func (m *DynamicMatcher) propagateDisabledTree(pendingByParent map[app.PID][]dynamicCreateCandidate) {
	if len(m.disabledTreeOwners) == 0 || len(pendingByParent) == 0 {
		return
	}
	queue := make([]app.PID, 0, len(m.disabledTreeOwners))
	for pid := range m.disabledTreeOwners {
		queue = append(queue, pid)
	}
	visited := make(map[app.PID]struct{}, len(queue))
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		if _, ok := visited[parent]; ok {
			continue
		}
		visited[parent] = struct{}{}
		for _, child := range pendingByParent[parent] {
			m.rememberDisabledCandidate(child.obj.pid, parent)
			if len(m.disabledTreeOwners[child.obj.pid]) > 0 {
				queue = append(queue, child.obj.pid)
			}
		}
	}
}

func (m *DynamicMatcher) filterCreatedCandidate(obj ProcessAttrs) (Event[ProcessMatch], app.PID, bool, bool) {
	if _, ok := m.ProcessHistory[obj.pid]; ok {
		return Event[ProcessMatch]{}, 0, false, false
	}

	proc, err := processInfo(obj)
	if err != nil {
		// If this PID belonged to a disabled tree, keep it eligible for
		// rediscovery even when the replacement cannot be inspected yet.
		m.rememberDisabledCandidate(obj.pid, 0)
		m.Log.Debug("can't get information for process", "pid", obj.pid, "error", err)
		return Event[ProcessMatch]{}, 0, false, false
	}
	event, matched := m.filterCreatedProcess(obj, proc)
	if matched {
		m.clearDisabledPID(obj.pid)
	} else {
		m.rememberDisabledCandidate(obj.pid, proc.PPid)
		_ = proc.CloseProcessHandle()
	}
	return event, proc.PPid, matched, !matched
}

func (m *DynamicMatcher) filterCreatedProcess(obj ProcessAttrs, proc *services.ProcessInfo) (Event[ProcessMatch], bool) {
	if _, ok := m.ProcessHistory[obj.pid]; ok {
		return Event[ProcessMatch]{}, false
	}
	if processMatch := m.matchDynamicCriteria(obj, proc); processMatch != nil {
		m.ProcessHistory[obj.pid] = processMatchForHistory(*processMatch)

		return Event[ProcessMatch]{
			Type: EventCreated,
			Obj:  *processMatch,
		}, true
	}

	// We didn't match the process, but let's see if the parent PID is tracked, it might be the child hasn't opened the port yet
	if procMatch, ok := m.ProcessHistory[proc.PPid]; ok {
		m.Log.Debug("found process by matching the process parent id", "pid", proc.Pid, "ppid", proc.PPid, "comm", proc.ExePath, "metadata", obj.metadata)

		procMatch.Process = proc

		m.ProcessHistory[obj.pid] = processMatchForHistory(procMatch)

		return Event[ProcessMatch]{
			Type: EventCreated,
			Obj:  procMatch,
		}, true
	}

	return Event[ProcessMatch]{}, false
}

func (m *DynamicMatcher) rediscoveryPIDsForAddedOwners(addedPIDs []app.PID) []app.PID {
	if len(addedPIDs) == 0 || m.RediscoverPIDsNotify == nil {
		return nil
	}
	if m.activeAddedOwners == nil {
		m.activeAddedOwners = map[app.PID]struct{}{}
	}
	requested := make(map[app.PID]struct{}, len(addedPIDs))
	for _, owner := range addedPIDs {
		if m.DynamicPIDSelector != nil && !m.DynamicPIDSelector.IncludesPID(owner) {
			// A later removal can overtake this edge on the independent
			// notification stream. Keep saved descendants for the next real add.
			continue
		}
		if _, active := m.activeAddedOwners[owner]; active {
			continue
		}
		m.activeAddedOwners[owner] = struct{}{}
		descendants := m.removedDescendants[owner]
		if m.hasOwnerAdmission(owner) && len(descendants) == 0 {
			// The owner was naturally discovered before its asynchronous initial
			// add notification. It is already in the desired watcher/matcher state.
			continue
		}
		requested[owner] = struct{}{}
		for descendant := range descendants {
			requested[descendant] = struct{}{}
		}
		delete(m.removedDescendants, owner)
		m.clearDisabledOwner(owner)
	}
	rediscoverPIDs := make([]app.PID, 0, len(requested))
	for pid := range requested {
		rediscoverPIDs = append(rediscoverPIDs, pid)
	}
	slices.Sort(rediscoverPIDs)
	return rediscoverPIDs
}

func (m *DynamicMatcher) hasOwnerAdmission(owner app.PID) bool {
	for _, processMatch := range m.ProcessHistory {
		if processMatch.DynamicSelectorPID == owner {
			return true
		}
	}
	return false
}

func (m *DynamicMatcher) noteRemovedOwners(removedPIDs []app.PID) {
	for _, owner := range removedPIDs {
		delete(m.activeAddedOwners, owner)
	}
}

func (m *DynamicMatcher) matchDynamicCriteria(obj ProcessAttrs, proc *services.ProcessInfo) *ProcessMatch {
	if !m.DynamicPIDSelector.IncludesPID(proc.Pid) {
		return nil
	}

	selector := m.DynamicPIDSelector.SelectorForPID(proc.Pid)
	if selector == nil {
		return nil
	}

	m.Log.Debug("found process", "pid", proc.Pid, "comm", proc.ExePath, "metadata",
		obj.metadata, "podLabels", obj.podLabels, "criteria", []services.Selector{selector})

	return &ProcessMatch{
		Criteria:           []services.Selector{selector},
		Process:            proc,
		DynamicSelectorPID: proc.Pid,
	}
}

func (m *DynamicMatcher) filterDeleted(obj ProcessAttrs) (Event[ProcessMatch], bool) {
	m.dropRemovedProcess(obj.pid)
	procMatch, ok := m.ProcessHistory[obj.pid]
	if !ok {
		m.Log.Debug("deleted untracked process. Ignoring", "pid", obj.pid)
		return Event[ProcessMatch]{}, false
	}
	delete(m.ProcessHistory, obj.pid)
	m.Log.Debug("stopped process", "pid", procMatch.Process.Pid, "comm", procMatch.Process.ExePath)
	return Event[ProcessMatch]{Type: EventDeleted, Obj: procMatch}, true
}

func (m *DynamicMatcher) dropRemovedProcess(pid app.PID) {
	// A real process deletion while its selector owner is disabled removes the
	// PID from the live rediscovery set and lineage cache. Keep only a self-owned
	// root: numeric selector owners must remain ancestry roots while disabled.
	for owner, descendants := range m.removedDescendants {
		delete(descendants, pid)
		if len(descendants) == 0 {
			delete(m.removedDescendants, owner)
		}
	}
	owners := m.disabledTreeOwners[pid]
	for owner := range owners {
		if owner != pid {
			delete(owners, owner)
		}
	}
	if len(owners) == 0 {
		delete(m.disabledTreeOwners, pid)
	}
}

func (m *DynamicMatcher) rememberDisabledPID(owner, pid app.PID) {
	if m.disabledTreeOwners == nil {
		m.disabledTreeOwners = map[app.PID]map[app.PID]struct{}{}
	}
	owners := m.disabledTreeOwners[pid]
	if owners == nil {
		owners = map[app.PID]struct{}{}
		m.disabledTreeOwners[pid] = owners
	}
	owners[owner] = struct{}{}
}

func (m *DynamicMatcher) rememberDisabledCandidate(pid, parent app.PID) {
	if len(m.disabledTreeOwners) == 0 {
		return
	}
	owners := map[app.PID]struct{}{}
	for owner := range m.disabledTreeOwners[pid] {
		owners[owner] = struct{}{}
	}
	for owner := range m.disabledTreeOwners[parent] {
		owners[owner] = struct{}{}
	}
	for owner := range owners {
		m.rememberDisabledPID(owner, pid)
		if pid == owner {
			continue
		}
		if m.removedDescendants == nil {
			m.removedDescendants = map[app.PID]map[app.PID]struct{}{}
		}
		descendants := m.removedDescendants[owner]
		if descendants == nil {
			descendants = map[app.PID]struct{}{}
			m.removedDescendants[owner] = descendants
		}
		descendants[pid] = struct{}{}
	}
}

func (m *DynamicMatcher) clearDisabledPID(pid app.PID) {
	delete(m.disabledTreeOwners, pid)
	for owner, descendants := range m.removedDescendants {
		delete(descendants, pid)
		if len(descendants) == 0 {
			delete(m.removedDescendants, owner)
		}
	}
}

func (m *DynamicMatcher) clearDisabledOwner(owner app.PID) {
	for pid, owners := range m.disabledTreeOwners {
		delete(owners, owner)
		if len(owners) == 0 {
			delete(m.disabledTreeOwners, pid)
		}
	}
}

// syntheticDeletesForPromotedPIDs retires inherited admissions whose PID was
// independently selected. The watcher rediscovery requested immediately after
// these deletes recreates them with DynamicSelectorPID equal to their own PID.
func (m *DynamicMatcher) syntheticDeletesForPromotedPIDs(addedPIDs []app.PID) []Event[ProcessMatch] {
	added := make(map[app.PID]struct{}, len(addedPIDs))
	for _, pid := range addedPIDs {
		if m.DynamicPIDSelector == nil || m.DynamicPIDSelector.IncludesPID(pid) {
			added[pid] = struct{}{}
		}
	}
	pids := make([]app.PID, 0, len(added))
	for pid := range added {
		pids = append(pids, pid)
	}
	slices.Sort(pids)

	var out []Event[ProcessMatch]
	for _, pid := range pids {
		procMatch, admitted := m.ProcessHistory[pid]
		if !admitted || procMatch.DynamicSelectorPID == pid {
			continue
		}
		delete(m.ProcessHistory, pid)
		m.clearDisabledPID(pid)
		m.Log.Debug("promoting inherited process to independent dynamic owner",
			"pid", pid, "previousOwnerPid", procMatch.DynamicSelectorPID)
		out = append(out, Event[ProcessMatch]{Type: EventDeleted, Obj: procMatch})
	}
	return out
}

// syntheticDeletesForRemovedPIDs returns EventDeleted for every admission owned by a PID removed
// from the dynamic selector. DynamicSelectorPID is the ownership key, so one history scan retires
// the owner and all inherited descendants while naturally deduplicating overlapping removed PIDs.
func (m *DynamicMatcher) syntheticDeletesForRemovedPIDs(removedPIDs []app.PID) []Event[ProcessMatch] {
	if len(removedPIDs) == 0 {
		return nil
	}
	removedOwners := make(map[app.PID]struct{}, len(removedPIDs))
	for _, pid := range removedPIDs {
		removedOwners[pid] = struct{}{}
		// Keep the owner PID as an ancestry root even when it was not admitted
		// (or exits) while disabled, so newly observed children are rediscovered.
		m.rememberDisabledPID(pid, pid)
	}
	historyPIDs := make([]app.PID, 0, len(m.ProcessHistory))
	for pid := range m.ProcessHistory {
		historyPIDs = append(historyPIDs, pid)
	}
	slices.Sort(historyPIDs)
	if m.removedDescendants == nil {
		m.removedDescendants = map[app.PID]map[app.PID]struct{}{}
	}

	var out []Event[ProcessMatch]
	for _, pid := range historyPIDs {
		procMatch := m.ProcessHistory[pid]
		owner := procMatch.DynamicSelectorPID
		if _, removed := removedOwners[owner]; !removed {
			continue
		}
		delete(m.ProcessHistory, pid)
		m.rememberDisabledPID(owner, pid)
		if pid != owner {
			descendants := m.removedDescendants[owner]
			if descendants == nil {
				descendants = map[app.PID]struct{}{}
				m.removedDescendants[owner] = descendants
			}
			descendants[pid] = struct{}{}
		}
		m.Log.Debug("dynamic selector owner removed, uninstrumenting process", "ownerPid", owner, "pid", pid, "comm", procMatch.Process.ExePath)
		out = append(out, Event[ProcessMatch]{Type: EventDeleted, Obj: procMatch})
	}
	return out
}
