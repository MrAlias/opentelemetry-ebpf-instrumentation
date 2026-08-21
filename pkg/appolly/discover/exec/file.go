// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package exec provides the utilities to analyze the executable code
package exec // import "go.opentelemetry.io/obi/pkg/appolly/discover/exec"

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"maps"
	"os"
	"strings"
	"sync"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/transform/route"
)

const (
	envServiceName      = "OTEL_SERVICE_NAME"
	envResourceAttrs    = "OTEL_RESOURCE_ATTRIBUTES"
	serviceNameKey      = "service.name"
	serviceNamespaceKey = "service.namespace"
)

// FileID identifies a file by its device and inode numbers.
type FileID struct {
	Dev uint64
	Ino uint64
}

type Init struct {
	Service           svc.Attrs
	CmdExePath        string
	ProExeLinkPath    string
	ELF               *elf.File
	Pid               app.PID
	Ppid              app.PID
	Dev               uint64
	Ino               uint64
	Ns                uint32
	ProcessStart      uint64
	ProcessInstanceID uint64
	// ProcessHandle ownership transfers to the returned FileInfo. On Linux it
	// must be a stable /proc/<pid> directory descriptor for ProcessStart.
	ProcessHandle *os.File
}

type FileInfo struct {
	mu                     sync.RWMutex
	processHandleMu        sync.RWMutex
	service                svc.Attrs
	runtimeGen             map[app.PID]uint64
	cmdExePath             string
	proExeLinkPath         string
	elfFile                *elf.File
	pid                    app.PID
	ppid                   app.PID
	dev                    uint64
	ino                    uint64
	ns                     uint32
	processStart           uint64
	processInstanceID      uint64
	processHandle          *os.File
	javaCapability         uint64
	javaAuthSeq            uint64
	javaAuth               *javaAuthorizationState
	serviceAdmissionSeq    uint64
	provisionalServiceName *provisionalServiceNameState
	provisionalServiceMeta *provisionalServiceMetadataState
}

type javaAuthorizationState struct {
	sequence   uint64
	done       chan struct{}
	capability uint64
	completed  bool
}

type provisionalServiceNameState struct {
	token    uint64
	previous string
	value    string
}

type provisionalServiceMetadataState struct {
	token          uint64
	key            attr.Name
	previous       string
	previousExists bool
	mapWasNil      bool
	value          string
}

// ServiceMetadataAdmission is an opaque receipt for provisional service name
// and resource metadata fields. Commit and Rollback affect a field only while
// this receipt remains its exact owner.
type ServiceMetadataAdmission struct {
	fileInfo *FileInfo
	token    uint64
	name     bool
	metadata bool
}

// ServiceAttrsUpdate describes which receipt-relevant fields a decorator
// explicitly publishes. Declaring a field preserves same-value setter intent;
// actual name/version changes are detected even when omitted here.
type ServiceAttrsUpdate struct {
	Publish      bool
	ServiceName  bool
	MetadataKeys []attr.Name
}

func New(init Init) *FileInfo {
	return &FileInfo{
		service:           init.Service,
		runtimeGen:        map[app.PID]uint64{},
		cmdExePath:        init.CmdExePath,
		proExeLinkPath:    init.ProExeLinkPath,
		elfFile:           init.ELF,
		pid:               init.Pid,
		ppid:              init.Ppid,
		dev:               init.Dev,
		ino:               init.Ino,
		ns:                init.Ns,
		processStart:      init.ProcessStart,
		processInstanceID: init.ProcessInstanceID,
		processHandle:     init.ProcessHandle,
	}
}

func (fi *FileInfo) RuntimeMetricGeneration(pid app.PID) uint64 {
	fi.mu.RLock()
	defer fi.mu.RUnlock()

	return fi.runtimeGen[pid]
}

func (fi *FileInfo) SetRuntimeMetricGeneration(pid app.PID, generation uint64) {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	if fi.runtimeGen == nil {
		fi.runtimeGen = map[app.PID]uint64{}
	}
	fi.runtimeGen[pid] = generation
}

// Identity getters. Fields are set at construction and never mutated, so
// no locking is required.

func (fi *FileInfo) Pid() app.PID              { return fi.pid }
func (fi *FileInfo) Ppid() app.PID             { return fi.ppid }
func (fi *FileInfo) Dev() uint64               { return fi.dev }
func (fi *FileInfo) Ino() uint64               { return fi.ino }
func (fi *FileInfo) ID() FileID                { return FileID{Dev: fi.dev, Ino: fi.ino} }
func (fi *FileInfo) Ns() uint32                { return fi.ns }
func (fi *FileInfo) ProcessStartTime() uint64  { return fi.processStart }
func (fi *FileInfo) ProcessInstanceID() uint64 { return fi.processInstanceID }
func (fi *FileInfo) CmdExePath() string        { return fi.cmdExePath }
func (fi *FileInfo) ProExeLinkPath() string    { return fi.proExeLinkPath }
func (fi *FileInfo) ELF() *elf.File            { return fi.elfFile }

// UseProcessHandle runs use while the stable process descriptor remains open.
// Callers that retain access after use returns must duplicate the descriptor.
func (fi *FileInfo) UseProcessHandle(use func(int) error) error {
	if use == nil {
		return errors.New("stable process-handle callback is nil")
	}
	fi.processHandleMu.RLock()
	defer fi.processHandleMu.RUnlock()
	if fi.processHandle == nil {
		return errors.New("stable process handle is unavailable")
	}
	return use(int(fi.processHandle.Fd()))
}

// CloseProcessHandle retires FileInfo's stable process descriptor. Prepared
// operations own independent duplicates, so closing the discovery handle does
// not race an already-started attachment.
func (fi *FileInfo) CloseProcessHandle() error {
	fi.processHandleMu.Lock()
	handle := fi.processHandle
	fi.processHandle = nil
	fi.processHandleMu.Unlock()
	if handle == nil {
		return nil
	}
	return handle.Close()
}

func (fi *FileInfo) ExecutableName() string {
	parts := strings.Split(fi.cmdExePath, "/")
	return parts[len(parts)-1]
}

func (fi *FileInfo) ServiceAttrs() svc.Attrs {
	fi.mu.RLock()
	defer fi.mu.RUnlock()

	return cloneServiceAttrs(fi.service)
}

func cloneServiceAttrs(service svc.Attrs) svc.Attrs {
	out := service
	out.Metadata = maps.Clone(service.Metadata)
	out.EnvVars = maps.Clone(service.EnvVars)

	// No need to clone the other fields as they are immutable.
	return out
}

// UpdateServiceAttrs atomically decorates a private clone of the current
// service attributes. update must only mutate the supplied clone and describes
// whether it should be published and any explicit name/metadata-key writes. A
// true second argument identifies a provisional derived name that decorators
// should treat as logically automatic. A decorator supersedes provisional
// service metadata only when it declares or actually changes the owned field;
// unrelated updates preserve the receipt.
func (fi *FileInfo) UpdateServiceAttrs(
	update func(*svc.Attrs, bool) ServiceAttrsUpdate,
) bool {
	if update == nil {
		return false
	}

	fi.mu.Lock()
	defer fi.mu.Unlock()

	updated := cloneServiceAttrs(fi.service)
	provisionalAutoName := fi.provisionalServiceName != nil &&
		fi.service.UID.Name == fi.provisionalServiceName.value
	result := update(&updated, provisionalAutoName)
	if !result.Publish {
		return false
	}

	if fi.provisionalServiceName != nil &&
		(result.ServiceName || updated.UID.Name != fi.service.UID.Name ||
			updated.AutoName() != fi.service.AutoName()) {
		fi.provisionalServiceName = nil
	}
	if state := fi.provisionalServiceMeta; state != nil {
		before, beforeExists := fi.service.Metadata[state.key]
		after, afterExists := updated.Metadata[state.key]
		if containsMetadataKey(result.MetadataKeys, state.key) ||
			beforeExists != afterExists || before != after {
			fi.provisionalServiceMeta = nil
		}
	}
	fi.service = updated
	return true
}

func containsMetadataKey(keys []attr.Name, wanted attr.Name) bool {
	for _, key := range keys {
		if key == wanted {
			return true
		}
	}
	return false
}

// EnsureServiceMetadataMap records the independent requirement that Metadata
// remain non-nil without adopting an owned provisional metadata key. If the
// admission later rolls that key back, it restores an empty map rather than
// the receipt's original nil map.
func (fi *FileInfo) EnsureServiceMetadataMap() {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	if fi.service.Metadata == nil {
		fi.service.Metadata = map[attr.Name]string{}
	}
	if state := fi.provisionalServiceMeta; state != nil {
		state.mapWasNil = false
	}
}

// ApplyDynamicServiceAttrs atomically applies only the fields present in a
// dynamic PID update. An explicit name or metadata key supersedes a matching
// provisional admission field; namespace and unrelated metadata updates leave
// provisional ownership intact.
func (fi *FileInfo) ApplyDynamicServiceAttrs(
	name string,
	namespace string,
	metadata map[attr.Name]string,
) {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	if name != "" {
		fi.provisionalServiceName = nil
		fi.service.UID.Name = name
	}
	if namespace != "" {
		fi.service.UID.Namespace = namespace
	}
	fi.applyServiceMetadataLocked(metadata)
}

// ApplyProcessContextAttribute atomically merges one process-context metadata
// key and, for service identity keys, fills only a logically missing UID field.
// A provisional name is logically missing, so an explicit service.name value
// supersedes it. Namespace and unrelated metadata never adopt provisional
// name or metadata fields.
func (fi *FileInfo) ApplyProcessContextAttribute(key attr.Name, value string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	fi.applyServiceMetadataLocked(map[attr.Name]string{key: value})
	switch key {
	case attr.ServiceName:
		if fi.provisionalServiceName != nil || fi.service.UID.Name == "" {
			fi.provisionalServiceName = nil
			fi.service.UID.Name = value
		}
	case attr.ServiceNamespace:
		if fi.service.UID.Namespace == "" {
			fi.service.UID.Namespace = value
		}
	}
}

func (fi *FileInfo) applyServiceMetadataLocked(metadata map[attr.Name]string) {
	if len(metadata) == 0 {
		return
	}

	updated := maps.Clone(fi.service.Metadata)
	if updated == nil {
		updated = make(map[attr.Name]string, len(metadata))
	}
	for key, value := range metadata {
		if state := fi.provisionalServiceMeta; state != nil && state.key == key {
			// The explicit key owns even a same-value write.
			fi.provisionalServiceMeta = nil
		}
		updated[key] = value
	}
	fi.service.Metadata = updated
}

// BeginServiceMetadataAdmission atomically applies missing derived service
// fields and returns their ownership receipt. Starting a new transaction first
// supersedes and rolls back any still-provisional fields from an older one.
func (fi *FileInfo) BeginServiceMetadataAdmission(
	name string,
	metadataKey attr.Name,
	metadataValue string,
) *ServiceMetadataAdmission {
	fi.mu.Lock()
	defer fi.mu.Unlock()

	fi.rollbackProvisionalServiceNameLocked(fi.provisionalServiceName)
	fi.rollbackProvisionalServiceMetadataLocked(fi.provisionalServiceMeta)
	fi.serviceAdmissionSeq++
	if fi.serviceAdmissionSeq == 0 {
		fi.serviceAdmissionSeq++
	}
	token := fi.serviceAdmissionSeq
	receipt := &ServiceMetadataAdmission{fileInfo: fi, token: token}

	if name != "" && fi.service.UID.Name == "" {
		fi.provisionalServiceName = &provisionalServiceNameState{
			token:    token,
			previous: fi.service.UID.Name,
			value:    name,
		}
		fi.service.UID.Name = name
		receipt.name = true
	}
	if metadataValue != "" && fi.service.Metadata[metadataKey] == "" {
		previous, previousExists := fi.service.Metadata[metadataKey]
		state := &provisionalServiceMetadataState{
			token:          token,
			key:            metadataKey,
			previous:       previous,
			previousExists: previousExists,
			mapWasNil:      fi.service.Metadata == nil,
			value:          metadataValue,
		}
		metadata := maps.Clone(fi.service.Metadata)
		if metadata == nil {
			metadata = map[attr.Name]string{}
		}
		metadata[metadataKey] = metadataValue
		fi.service.Metadata = metadata
		fi.provisionalServiceMeta = state
		receipt.metadata = true
	}
	if !receipt.name && !receipt.metadata {
		return nil
	}
	return receipt
}

// Commit makes receipt-owned fields permanent. The derived name's auto-name
// flag is set in the same critical section that verifies exact ownership and
// value, eliminating a read-then-set race with independent identity updates.
func (a *ServiceMetadataAdmission) Commit() {
	if a == nil || a.fileInfo == nil {
		return
	}
	fi := a.fileInfo
	fi.mu.Lock()
	defer fi.mu.Unlock()

	if state := fi.provisionalServiceName; a.name &&
		state != nil && state.token == a.token {
		if fi.service.UID.Name == state.value {
			fi.service.SetAutoName()
		}
		fi.provisionalServiceName = nil
	}
	if state := fi.provisionalServiceMeta; a.metadata &&
		state != nil && state.token == a.token {
		fi.provisionalServiceMeta = nil
	}
}

// Rollback restores only fields still owned by this receipt. Independent
// setters invalidate ownership, including same-value writes, so their intent
// and every unrelated service field remain untouched.
func (a *ServiceMetadataAdmission) Rollback() {
	if a == nil || a.fileInfo == nil {
		return
	}
	fi := a.fileInfo
	fi.mu.Lock()
	defer fi.mu.Unlock()

	if state := fi.provisionalServiceName; a.name &&
		state != nil && state.token == a.token {
		fi.rollbackProvisionalServiceNameLocked(state)
	}
	if state := fi.provisionalServiceMeta; a.metadata &&
		state != nil && state.token == a.token {
		fi.rollbackProvisionalServiceMetadataLocked(state)
	}
}

func (fi *FileInfo) rollbackProvisionalServiceNameLocked(
	state *provisionalServiceNameState,
) {
	if state == nil {
		return
	}
	if fi.service.UID.Name == state.value {
		fi.service.UID.Name = state.previous
	}
	if fi.provisionalServiceName == state {
		fi.provisionalServiceName = nil
	}
}

func (fi *FileInfo) rollbackProvisionalServiceMetadataLocked(
	state *provisionalServiceMetadataState,
) {
	if state == nil {
		return
	}
	if current, exists := fi.service.Metadata[state.key]; exists && current == state.value {
		metadata := maps.Clone(fi.service.Metadata)
		if state.previousExists {
			metadata[state.key] = state.previous
		} else {
			delete(metadata, state.key)
		}
		if state.mapWasNil && len(metadata) == 0 {
			metadata = nil
		}
		fi.service.Metadata = metadata
	}
	if fi.provisionalServiceMeta == state {
		fi.provisionalServiceMeta = nil
	}
}

func (fi *FileInfo) SDKLanguage() svc.InstrumentableType {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	return fi.service.SDKLanguage
}

func (fi *FileInfo) JavaAgentCapability() uint64 {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	return fi.javaCapability
}

func (fi *FileInfo) SetJavaAgentCapability(capability uint64) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.javaCapability = capability
}

// SetJavaAgentCapabilityForGeneration publishes a prepared capability only if
// the caller still owns the current readiness generation. This prevents a slow
// preparation from overwriting the capability of a newer operation.
func (fi *FileInfo) SetJavaAgentCapabilityForGeneration(
	sequence uint64,
	capability uint64,
) bool {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if fi.javaAuth == nil || fi.javaAuth.sequence != sequence || fi.javaAuth.completed {
		return false
	}
	fi.javaCapability = capability
	return true
}

// PrepareJavaAgentCapability starts one attachment-authorization generation.
// Any waiter for an unexpectedly superseded generation is released fail-closed.
func (fi *FileInfo) PrepareJavaAgentCapability(capability uint64) uint64 {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if fi.javaAuth != nil && !fi.javaAuth.completed {
		fi.javaAuth.completed = true
		fi.javaAuth.capability = 0
		close(fi.javaAuth.done)
	}
	fi.javaAuthSeq++
	if fi.javaAuthSeq == 0 {
		fi.javaAuthSeq++
	}
	fi.javaCapability = capability
	fi.javaAuth = &javaAuthorizationState{
		sequence: fi.javaAuthSeq,
		done:     make(chan struct{}),
	}
	return fi.javaAuthSeq
}

// BeginJavaAgentAuthorization snapshots and closes the attachment gate for the
// current prepared generation. A zero sequence denotes legacy/test setup that
// did not create a readiness waiter.
func (fi *FileInfo) BeginJavaAgentAuthorization() (capability, sequence uint64) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	capability = fi.javaCapability
	fi.javaCapability = 0
	if fi.javaAuth != nil && !fi.javaAuth.completed {
		sequence = fi.javaAuth.sequence
	}
	return capability, sequence
}

// CompleteJavaAgentAuthorization publishes the exact generation's result and
// wakes its Java attachment waiter. Stale completions are ignored.
func (fi *FileInfo) CompleteJavaAgentAuthorization(sequence, capability uint64) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if sequence == 0 {
		if fi.javaAuth == nil {
			fi.javaCapability = capability
		}
		return
	}
	state := fi.javaAuth
	if state == nil || state.sequence != sequence || state.completed {
		return
	}
	state.capability = capability
	state.completed = true
	fi.javaCapability = capability
	close(state.done)
}

// WaitJavaAgentAuthorization waits for the prepared generation captured at
// call time. Its result cannot be confused with a later generation.
func (fi *FileInfo) WaitJavaAgentAuthorization(ctx context.Context) (uint64, error) {
	fi.mu.RLock()
	state := fi.javaAuth
	if state == nil {
		capability := fi.javaCapability
		fi.mu.RUnlock()
		return capability, nil
	}
	fi.mu.RUnlock()
	return fi.waitJavaAgentAuthorizationState(ctx, state)
}

// WaitJavaAgentAuthorizationGeneration waits only for the prepared generation
// owned by one exact attachment operation. A replacement preparation cannot
// make an older operation consume the replacement's capability or target.
func (fi *FileInfo) WaitJavaAgentAuthorizationGeneration(
	ctx context.Context,
	sequence uint64,
) (uint64, error) {
	fi.mu.RLock()
	state := fi.javaAuth
	if state == nil || state.sequence != sequence {
		fi.mu.RUnlock()
		return 0, fmt.Errorf("java authorization generation %d was superseded", sequence)
	}
	fi.mu.RUnlock()
	return fi.waitJavaAgentAuthorizationState(ctx, state)
}

func (fi *FileInfo) waitJavaAgentAuthorizationState(
	ctx context.Context,
	state *javaAuthorizationState,
) (uint64, error) {
	fi.mu.RLock()
	if state.completed {
		capability := state.capability
		fi.mu.RUnlock()
		return capability, nil
	}
	done := state.done
	fi.mu.RUnlock()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-done:
		fi.mu.RLock()
		capability := state.capability
		fi.mu.RUnlock()
		return capability, nil
	}
}

func (fi *FileInfo) ExportsOTelMetrics() bool {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	return fi.service.ExportsOTelMetrics()
}

func (fi *FileInfo) ExportsOTelTraces() bool {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	return fi.service.ExportsOTelTraces()
}

func (fi *FileInfo) ExportsOTelMetricsSpan() bool {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	return fi.service.ExportsOTelMetricsSpan()
}

func (fi *FileInfo) LogEnricherEnabled() bool {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	return fi.service.LogEnricherEnabled
}

func (fi *FileInfo) SetSDKLanguage(t svc.InstrumentableType) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.service.SDKLanguage = t
}

func (fi *FileInfo) SetHarvestedRoutes(m route.Matcher) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.service.HarvestedRouteMatcher = m
}

func (fi *FileInfo) SetMetadata(m map[attr.Name]string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	// A setter call is an ownership event even when m contains the same value:
	// callers may have intentionally adopted the provisional version.
	fi.provisionalServiceMeta = nil
	fi.service.Metadata = m
}

func (fi *FileInfo) SetHostNameInstance(hostName, instance string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.service.HostName = hostName
	fi.service.UID.Instance = instance
}

func (fi *FileInfo) SetHostName(h string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	fi.service.HostName = h
}

func (fi *FileInfo) SetAutoServiceName(name string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	// Preserve same-value setter intent by retiring any provisional receipt.
	fi.provisionalServiceName = nil
	fi.service.UID.Name = name
	fi.service.SetAutoName()
}

func (fi *FileInfo) SetUID(uid svc.UID) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	// SetUID owns the complete identity, including a same-value service name.
	fi.provisionalServiceName = nil
	fi.service.UID = uid
}

func (fi *FileInfo) AutoName() bool {
	fi.mu.RLock()
	defer fi.mu.RUnlock()
	return fi.service.AutoName()
}

// ApplyServiceDefaults sets an auto-derived service name (when none is set)
// and the SDK language. Intended for use during discovery, before *FileInfo
// is shared downstream.
func (fi *FileInfo) ApplyServiceDefaults(t svc.InstrumentableType) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if fi.service.UID.Name == "" {
		fi.provisionalServiceName = nil
		fi.service.UID.Name = fi.ExecutableName()
		fi.service.SetAutoName()
	}
	fi.service.SDKLanguage = t
}

// ApplyEnvVariables parses the process environment and updates the service
// attributes (EnvVars, Metadata, UID name/namespace) from OTEL_SERVICE_NAME
// and OTEL_RESOURCE_ATTRIBUTES. Intended for use during discovery.
func (fi *FileInfo) ApplyEnvVariables(envVars map[string]string) {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	// Environment application is a whole identity/metadata publication. Clear
	// both receipts even when the parsed values equal their provisional values.
	fi.provisionalServiceName = nil
	fi.provisionalServiceMeta = nil

	fi.service.EnvVars = envVars
	m := maps.Clone(fi.service.Metadata)
	if m == nil {
		m = map[attr.Name]string{}
	}
	allVars := map[string]string{}

	if resourceAttrs, ok := fi.service.EnvVars[envResourceAttrs]; ok {
		attributes.ParseOTELResourceVariable(resourceAttrs, func(k, v string) { allVars[k] = v })
		for k, v := range allVars {
			if v != "" && !strings.HasPrefix(v, "$") {
				key := attr.Name(k)
				if _, exists := m[key]; !exists {
					m[key] = v
				}
			}
		}
	}
	fi.service.Metadata = m

	if svcName := fi.service.EnvVars[envServiceName]; svcName != "" && !strings.HasPrefix(svcName, "$") {
		fi.service.UID.Name = svcName
	} else if svcName := allVars[serviceNameKey]; svcName != "" && !strings.HasPrefix(svcName, "$") {
		fi.service.UID.Name = svcName
	}

	if svcNamespace := allVars[serviceNamespaceKey]; svcNamespace != "" && !strings.HasPrefix(svcNamespace, "$") {
		fi.service.UID.Namespace = svcNamespace
	}
}

// EnsureExportsOTelMetrics returns true if this call flipped the flag.
func (fi *FileInfo) EnsureExportsOTelMetrics() bool {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if fi.service.ExportsOTelMetrics() {
		return false
	}
	fi.service.SetExportsOTelMetrics()
	return true
}

func (fi *FileInfo) EnsureExportsOTelTraces() bool {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if fi.service.ExportsOTelTraces() {
		return false
	}
	fi.service.SetExportsOTelTraces()
	return true
}

func (fi *FileInfo) EnsureExportsOTelMetricsSpan() bool {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if fi.service.ExportsOTelMetricsSpan() {
		return false
	}
	fi.service.SetExportsOTelMetricsSpan()
	return true
}
