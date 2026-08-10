// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"fmt"
	"log/slog"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/idgen"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

type PIDType uint8

const (
	PIDTypeKProbes PIDType = 1 << iota
	PIDTypeGo
)

// injectable functions (can be replaced in tests). It reads the
// current process namespace from the /proc filesystem. It is required to
// choose to filter traces using whether the User-space or Host-space PIDs
var readNamespacePIDs = procs.FindNamespacedPids

// NamespacedPIDsForOwner resolves namespace aliases from the exact process
// lifetime whenever a stable owner is available. Zero-start owners retain the
// injectable numeric-PID path used by legacy callers and unit tests.
func NamespacedPIDsForOwner(pid app.PID, owner *exec.FileInfo) ([]app.PID, error) {
	if owner != nil && owner.Pid() != 0 && owner.Pid() != pid {
		return nil, fmt.Errorf("exact process owner PID %d does not match %d", owner.Pid(), pid)
	}
	return namespacedPIDsForOwner(pid, owner)
}

// ValidateProcessOwner verifies that owner still represents pid's exact live
// process lifetime before any per-PID tracer state is published.
func ValidateProcessOwner(pid app.PID, owner *exec.FileInfo) error {
	if owner == nil {
		return fmt.Errorf("exact process owner for PID %d is unavailable", pid)
	}
	if owner.Pid() != 0 && owner.Pid() != pid {
		return fmt.Errorf("exact process owner PID %d does not match %d", owner.Pid(), pid)
	}
	return validateProcessOwner(pid, owner)
}

type PIDInfo struct {
	fileInfo       *exec.FileInfo
	owner          *exec.FileInfo
	pidTypes       PIDType
	otherKnownPids []app.PID
}

// pidAdmission is one exact host-PID lifetime. NSpid aliases are ordered from
// the outermost namespace to the innermost namespace, so rank zero is always
// the alias that BPF emits together with the admission's PID namespace.
type pidAdmission struct {
	nsid     uint32
	hostPID  app.PID
	fileInfo *exec.FileInfo
	owner    *exec.FileInfo
	pidTypes PIDType
	aliases  map[app.PID]int
	sequence uint64
}

type pidCandidateKey struct {
	hostPID app.PID
	owner   *exec.FileInfo
}

type pidAliasCandidate struct {
	admission *pidAdmission
	rank      int
}

type ServiceFilter interface {
	AllowPID(app.PID, uint32, *exec.FileInfo, *exec.FileInfo, PIDType)
	BlockPID(app.PID, uint32, *exec.FileInfo, *exec.FileInfo)
	ValidPID(app.PID, uint32, PIDType) bool
	Filter(inputSpans []request.Span) []request.Span
	CurrentPIDs(PIDType) map[uint32]map[app.PID]svc.Attrs
}

// PIDsFilter keeps a thread-safe copy of the PIDs whose traces are allowed to
// be forwarded. Its Filter method filters the request.Span instances whose
// PIDs are not in the allowed list.
type PIDsFilter struct {
	log     *slog.Logger
	current map[uint32]map[app.PID]PIDInfo
	// candidates retains colliding aliases instead of destructively replacing
	// them. current contains only the highest-ranked live candidate for the
	// existing filtering and service-attribution API.
	candidates map[uint32]map[app.PID]map[pidCandidateKey]pidAliasCandidate
	// admissions is keyed by the host PID presented to AllowPID. It lets a
	// same-host-PID replacement retire every predecessor alias even when a
	// different process currently wins one of the colliding alias keys.
	admissions map[app.PID]*pidAdmission
	// validatePublishedOwner is injectable so tests can deterministically model
	// an exact owner exiting or being reused after its aliases were read but
	// before the admission is allowed to remain published.
	validatePublishedOwner func(app.PID, *exec.FileInfo) error
	admissionSequence      uint64
	mux                    *sync.RWMutex
	ignoreOtel             bool
	ignoreOtelSpan         bool
	defaultOtlpGRPCPort    int
	metrics                imetrics.Reporter
}

func NewPIDsFilter(c *services.DiscoveryConfig, log *slog.Logger, metrics imetrics.Reporter) *PIDsFilter {
	return &PIDsFilter{
		log:                    log,
		current:                map[uint32]map[app.PID]PIDInfo{},
		candidates:             map[uint32]map[app.PID]map[pidCandidateKey]pidAliasCandidate{},
		admissions:             map[app.PID]*pidAdmission{},
		validatePublishedOwner: validatePublishedPIDOwner,
		mux:                    &sync.RWMutex{},
		ignoreOtel:             c.ExcludeOTelInstrumentedServices,
		ignoreOtelSpan:         c.ExcludeOTelInstrumentedServicesSpanMetrics,
		defaultOtlpGRPCPort:    c.DefaultOtlpGRPCPort,
		metrics:                metrics,
	}
}

func (pf *PIDsFilter) AllowPID(
	pid app.PID,
	ns uint32,
	fi *exec.FileInfo,
	owner *exec.FileInfo,
	pidType PIDType,
) {
	pf.mux.Lock()
	defer pf.mux.Unlock()
	pf.addPID(pid, ns, fi, owner, pidType)
}

func (pf *PIDsFilter) BlockPID(
	pid app.PID,
	ns uint32,
	_ *exec.FileInfo,
	owner *exec.FileInfo,
) {
	pf.mux.Lock()
	defer pf.mux.Unlock()
	pf.removePID(pid, ns, owner)
}

func (pf *PIDsFilter) ValidPID(userPID app.PID, ns uint32, pidType PIDType) bool {
	pf.mux.RLock()
	defer pf.mux.RUnlock()

	if ns, nsExists := pf.current[ns]; nsExists {
		if info, pidExists := ns[userPID]; pidExists {
			return info.pidTypes&pidType != 0
		}
	}

	return false
}

func (pf *PIDsFilter) CurrentPIDs(t PIDType) map[uint32]map[app.PID]svc.Attrs {
	pf.mux.RLock()
	defer pf.mux.RUnlock()
	cp := map[uint32]map[app.PID]svc.Attrs{}

	for k, v := range pf.current {
		cVal := map[app.PID]svc.Attrs{}
		for kv, vv := range v {
			if vv.pidTypes&t != 0 {
				cVal[kv] = vv.fileInfo.ServiceAttrs()
			}
		}
		cp[k] = cVal
	}

	return cp
}

func (pf *PIDsFilter) normalizeTraceContext(span *request.Span) {
	if !span.TraceID.IsValid() {
		span.TraceID = idgen.RandomTraceID()
		span.TraceFlags = 1
	}
	if !span.SpanID.IsValid() {
		span.SpanID = idgen.RandomSpanID()
	}
}

func (pf *PIDsFilter) Filter(inputSpans []request.Span) []request.Span {
	pf.mux.RLock()
	defer pf.mux.RUnlock()
	// todo: adaptive presizing as a function of the historical percentage
	// of filtered spans
	outputSpans := make([]request.Span, 0, len(inputSpans))
	for i := range inputSpans {
		span := &inputSpans[i]

		// We first confirm that the current namespace seen by BPF is tracked by OBI
		ns, nsExists := pf.current[span.Pid.Namespace]

		if !nsExists {
			continue
		}

		// If the namespace exist, we confirm that we are tracking the user PID that OBI
		// saw. We don't check for the host pid, because we can't be sure of the number
		// of container layers. The Host PID is always the outer most layer.
		if info, pidExists := ns[span.Pid.UserPID]; pidExists {
			if pf.ignoreOtel {
				pf.checkIfExportsOTel(info.fileInfo, span, pf.defaultOtlpGRPCPort)
			}
			if pf.ignoreOtelSpan {
				pf.checkIfExportsOTelSpanMetrics(info.fileInfo, span, pf.defaultOtlpGRPCPort)
			}
			inputSpans[i].Service = info.fileInfo.ServiceAttrs()
			pf.normalizeTraceContext(&inputSpans[i])
			outputSpans = append(outputSpans, inputSpans[i])
		}
	}

	if len(outputSpans) != len(inputSpans) {
		pf.log.Debug("filtered spans from processes that did not match discovery",
			"function", "PIDsFilter.Filter", "inLen", len(inputSpans), "outLen", len(outputSpans),
			"pids", pf.current,
		)
	}
	return outputSpans
}

func (pf *PIDsFilter) addPID(
	pid app.PID,
	nsid uint32,
	fi *exec.FileInfo,
	owner *exec.FileInfo,
	t PIDType,
) {
	if owner == nil {
		owner = fi
	}
	allPids, err := NamespacedPIDsForOwner(pid, owner)
	if err != nil {
		pf.log.Debug("Error looking up namespaced pids", "pid", pid, "error", err)
		return
	}

	aliases := rankedPIDAliases(allPids)
	pf.ensurePIDCandidateState()

	admission := pf.admissions[pid]
	var predecessor *pidAdmission
	if admission != nil && admission.owner != owner {
		// Keep the predecessor as a transactional fallback until the replacement
		// passes its post-publication exact-owner check. A successful replacement
		// retires its complete candidate set, including hidden aliases.
		predecessor = admission
		admission = nil
	}

	if admission == nil {
		pf.admissionSequence++
		if pf.admissionSequence == 0 {
			pf.admissionSequence++
		}
		admission = &pidAdmission{
			nsid:     nsid,
			hostPID:  pid,
			owner:    owner,
			sequence: pf.admissionSequence,
		}
	} else {
		// Repeated notifications for one exact lifetime merge tracer types, but
		// do not refresh its sequence and jump ahead of an equally ranked newer
		// process. Remove the old alias set before publishing the refreshed one.
		pf.removeAdmissionCandidates(admission)
	}

	admission.nsid = nsid
	admission.fileInfo = fi
	admission.pidTypes |= t
	admission.aliases = aliases
	pf.admissions[pid] = admission
	pf.addAdmissionCandidates(admission)

	if err := pf.revalidatePublishedOwner(pid, owner); err != nil {
		// The lock makes the pointer check invariant today; retain it so this
		// cleanup stays owner-conditional if validation is later moved outside the
		// critical section.
		if current := pf.admissions[pid]; current == admission && current.owner == owner {
			delete(pf.admissions, pid)
			pf.removeAdmissionCandidates(admission)
			if predecessor != nil {
				pf.admissions[pid] = predecessor
			}
		}
		pf.log.Debug("Exact process owner changed after publishing PID aliases",
			"pid", pid, "error", err)
		return
	}

	if predecessor != nil {
		pf.removeAdmissionCandidates(predecessor)
	}
}

func (pf *PIDsFilter) removePID(pid app.PID, nsid uint32, owner *exec.FileInfo) {
	if admission := pf.admissions[pid]; admission != nil {
		if owner != nil && admission.owner != owner {
			return
		}
		if owner == nil && admission.nsid != nsid {
			return
		}
		delete(pf.admissions, pid)
		pf.removeAdmissionCandidates(admission)
		return
	}

	// Preserve compatibility with state assembled before ranked candidate
	// accounting (including narrow tests that seed current directly).
	ns := pf.current[nsid]
	pidInfo, exists := ns[pid]
	if !exists || (owner != nil && pidInfo.owner != owner) {
		return
	}
	for _, alias := range pidInfo.otherKnownPids {
		if current, ok := ns[alias]; ok && current.owner == pidInfo.owner {
			delete(ns, alias)
		}
	}
	delete(ns, pid)
	if len(ns) == 0 {
		delete(pf.current, nsid)
	}
}

// rankedPIDAliases converts the kernel's outermost-to-innermost NSpid list to
// per-key ranks. Duplicate numeric aliases retain their strongest (innermost)
// rank.
func rankedPIDAliases(pids []app.PID) map[app.PID]int {
	aliases := make(map[app.PID]int, len(pids))
	for index, pid := range pids {
		rank := len(pids) - index - 1
		if current, exists := aliases[pid]; !exists || rank < current {
			aliases[pid] = rank
		}
	}
	return aliases
}

func (pf *PIDsFilter) ensurePIDCandidateState() {
	if pf.current == nil {
		pf.current = make(map[uint32]map[app.PID]PIDInfo)
	}
	if pf.candidates == nil {
		pf.candidates = make(
			map[uint32]map[app.PID]map[pidCandidateKey]pidAliasCandidate,
		)
	}
	if pf.admissions == nil {
		pf.admissions = make(map[app.PID]*pidAdmission)
	}
}

func (pf *PIDsFilter) addAdmissionCandidates(admission *pidAdmission) {
	if admission == nil {
		return
	}
	pf.ensurePIDCandidateState()
	nsid := admission.nsid
	nsCandidates := pf.candidates[nsid]
	if nsCandidates == nil {
		nsCandidates = make(map[app.PID]map[pidCandidateKey]pidAliasCandidate)
		pf.candidates[nsid] = nsCandidates
	}
	key := pidCandidateKey{hostPID: admission.hostPID, owner: admission.owner}
	for alias, rank := range admission.aliases {
		aliasCandidates := nsCandidates[alias]
		if aliasCandidates == nil {
			aliasCandidates = make(map[pidCandidateKey]pidAliasCandidate)
			nsCandidates[alias] = aliasCandidates
		}
		aliasCandidates[key] = pidAliasCandidate{admission: admission, rank: rank}
		pf.refreshPIDWinner(nsid, alias)
	}
}

func (pf *PIDsFilter) removeAdmissionCandidates(admission *pidAdmission) {
	if admission == nil {
		return
	}
	nsid := admission.nsid
	nsCandidates := pf.candidates[nsid]
	key := pidCandidateKey{hostPID: admission.hostPID, owner: admission.owner}
	for alias := range admission.aliases {
		aliasCandidates := nsCandidates[alias]
		delete(aliasCandidates, key)
		if len(aliasCandidates) == 0 {
			delete(nsCandidates, alias)
		}
		pf.refreshPIDWinner(nsid, alias)
	}
	if len(nsCandidates) == 0 {
		delete(pf.candidates, nsid)
	}
}

func (pf *PIDsFilter) revalidatePublishedOwner(pid app.PID, owner *exec.FileInfo) error {
	if pf.validatePublishedOwner != nil {
		return pf.validatePublishedOwner(pid, owner)
	}
	return validatePublishedPIDOwner(pid, owner)
}

func validatePublishedPIDOwner(pid app.PID, owner *exec.FileInfo) error {
	// A zero start time is the explicit legacy/test seam: there is no stable
	// lifetime token to revalidate, so retain the injectable numeric-PID path.
	if owner != nil && owner.ProcessStartTime() == 0 {
		return nil
	}
	return ValidateProcessOwner(pid, owner)
}

func (pf *PIDsFilter) refreshPIDWinner(nsid uint32, pid app.PID) {
	aliasCandidates := pf.candidates[nsid][pid]
	var winner pidAliasCandidate
	hasWinner := false
	for _, candidate := range aliasCandidates {
		if !hasWinner || pidAliasCandidateOutranks(candidate, winner) {
			winner = candidate
			hasWinner = true
		}
	}
	if !hasWinner {
		if ns := pf.current[nsid]; ns != nil {
			delete(ns, pid)
			if len(ns) == 0 {
				delete(pf.current, nsid)
			}
		}
		return
	}

	ns := pf.current[nsid]
	if ns == nil {
		ns = make(map[app.PID]PIDInfo)
		pf.current[nsid] = ns
	}
	admission := winner.admission
	aliases := make([]app.PID, 0, len(admission.aliases))
	for alias := range admission.aliases {
		aliases = append(aliases, alias)
	}
	ns[pid] = PIDInfo{
		fileInfo:       admission.fileInfo,
		owner:          admission.owner,
		pidTypes:       admission.pidTypes,
		otherKnownPids: aliases,
	}
}

func pidAliasCandidateOutranks(candidate, current pidAliasCandidate) bool {
	if candidate.rank != current.rank {
		return candidate.rank < current.rank
	}
	return candidate.admission.sequence > current.admission.sequence
}

// IdentityPidsFilter is a PIDsFilter that does not filter anything. It is feasible
// for concrete cases like GPU tracer
type IdentityPidsFilter struct{}

func (pf *IdentityPidsFilter) AllowPID(
	_ app.PID,
	_ uint32,
	_ *exec.FileInfo,
	_ *exec.FileInfo,
	_ PIDType,
) {
}

func (pf *IdentityPidsFilter) BlockPID(
	_ app.PID,
	_ uint32,
	_ *exec.FileInfo,
	_ *exec.FileInfo,
) {
}

func (pf *IdentityPidsFilter) ValidPID(_ app.PID, _ uint32, _ PIDType) bool {
	return true
}

func (pf *IdentityPidsFilter) CurrentPIDs(_ PIDType) map[uint32]map[app.PID]svc.Attrs {
	return nil
}

func (pf *IdentityPidsFilter) Filter(inputSpans []request.Span) []request.Span {
	return inputSpans
}

func (pf *PIDsFilter) checkIfExportsOTel(fi *exec.FileInfo, span *request.Span, defaultOtlpGRPCPort int) {
	if span.IsExportMetricsSpan(defaultOtlpGRPCPort) && fi.EnsureExportsOTelMetrics() {
		pf.reportAvoidedService(fi, "metrics")
	} else if span.IsExportTracesSpan(defaultOtlpGRPCPort) && fi.EnsureExportsOTelTraces() {
		pf.reportAvoidedService(fi, "traces")
	}
}

func (pf *PIDsFilter) checkIfExportsOTelSpanMetrics(fi *exec.FileInfo, span *request.Span, defaultOtlpGRPCPort int) {
	if span.IsExportTracesSpan(defaultOtlpGRPCPort) && fi.EnsureExportsOTelMetricsSpan() {
		pf.reportAvoidedService(fi, "metrics_span")
	}
}

func (pf *PIDsFilter) reportAvoidedService(fi *exec.FileInfo, telemetryType string) {
	if pf.metrics == nil || imetrics.IsBuiltinNoopReporter(pf.metrics) {
		return
	}

	snap := fi.ServiceAttrs()
	serviceName := snap.UID.Name
	serviceNamespace := snap.UID.Namespace
	serviceInstance := snap.UID.Instance

	switch telemetryType {
	case "metrics", "metrics_span":
		pf.metrics.AvoidInstrumentationMetrics(serviceName, serviceNamespace, serviceInstance)
	case "traces":
		pf.metrics.AvoidInstrumentationTraces(serviceName, serviceNamespace, serviceInstance)
	}
}
