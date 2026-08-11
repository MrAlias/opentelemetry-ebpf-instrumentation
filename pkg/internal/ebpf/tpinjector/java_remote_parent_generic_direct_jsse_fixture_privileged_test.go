// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector

import (
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"
)

var javaRemoteParentGenericDirectJSSEProgramNames = map[string]struct{}{
	"obi_continue2_protocol_http":             {},
	"obi_continue_protocol_http":              {},
	"obi_continue_protocol_http_tp":           {},
	"obi_continue_protocol_http_tp_validate":  {},
	"obi_handle_buf_with_args":                {},
	"obi_kprobe_java_remote_parent_tcp_close": {},
	"obi_kprobe_security_file_ioctl":          {},
	"obi_kprobe_sys_ioctl":                    {},
	"obi_large_buf_emit_continue":             {},
	"obi_protocol_http":                       {},
}

type javaRemoteParentGenericDirectJSSEFixture struct {
	JumpTable *ebpf.Map `ebpf:"jump_table"`

	ObiContinue2ProtocolHTTP           *ebpf.Program `ebpf:"obi_continue2_protocol_http"`
	ObiContinueProtocolHTTP            *ebpf.Program `ebpf:"obi_continue_protocol_http"`
	ObiContinueProtocolHTTPTraceparent *ebpf.Program `ebpf:"obi_continue_protocol_http_tp"`
	ObiContinueProtocolHTTPValidate    *ebpf.Program `ebpf:"obi_continue_protocol_http_tp_validate"`
	ObiHandleBufWithArgs               *ebpf.Program `ebpf:"obi_handle_buf_with_args"`
	ObiJavaRemoteParentTCPClose        *ebpf.Program `ebpf:"obi_kprobe_java_remote_parent_tcp_close"`
	ObiSecurityFileIoctl               *ebpf.Program `ebpf:"obi_kprobe_security_file_ioctl"`
	ObiSysIoctl                        *ebpf.Program `ebpf:"obi_kprobe_sys_ioctl"`
	ObiLargeBufEmitContinue            *ebpf.Program `ebpf:"obi_large_buf_emit_continue"`
	ObiProtocolHTTP                    *ebpf.Program `ebpf:"obi_protocol_http"`

	links []link.Link
}

func loadJavaRemoteParentGenericDirectJSSEFixture(
	t *testing.T,
	primary *BpfJavaRemoteParentMaps,
) *javaRemoteParentGenericDirectJSSEFixture {
	t.Helper()

	spec, err := generictracer.LoadBpf()
	require.NoError(t, err)
	ebpfcommon.FixupSpec(spec, false)
	for name := range spec.Programs {
		if _, keep := javaRemoteParentGenericDirectJSSEProgramNames[name]; !keep {
			delete(spec.Programs, name)
		}
	}
	for _, mapSpec := range spec.Maps {
		mapSpec.Pinning = ebpf.PinNone
	}
	require.NoError(t, ebpfconvenience.RewriteConstants(spec, map[string]any{
		"wakeup_data_bytes":           uint32(232_000),
		"filter_pids":                 int32(0),
		"capture_header_buffer":       int32(1),
		"high_request_volume":         uint32(0),
		"disable_black_box_cp":        uint32(0),
		"http_max_captured_bytes":     uint32(8_192),
		"tcp_max_captured_bytes":      uint32(0),
		"mysql_max_captured_bytes":    uint32(0),
		"kafka_max_captured_bytes":    uint32(0),
		"postgres_max_captured_bytes": uint32(0),
		"mssql_max_captured_bytes":    uint32(0),
		"max_transaction_time":        uint64((5 * time.Minute).Nanoseconds()),
		"g_bpf_debug":                 false,
		"g_bpf_traceparent_enabled":   true,
		"java_remote_parent_enabled":  true,
		"ssl_prewrite_max_age_ns":     uint64((30 * time.Second).Nanoseconds()),
		"jvm_sampling_interval_ns":    uint64(0),
	}))

	replacements := javaRemoteParentGenericDirectJSSEMapReplacements(primary)
	exactOwnerReplacements := map[string]*ebpf.Map{
		"java_remote_parent_handoff_mutations": primary.JavaRemoteParentHandoffMutations,
		"java_remote_parent_task_claims":       primary.JavaRemoteParentTaskClaims,
		"java_thread_mapping_claims":           primary.JavaThreadMappingClaims,
	}
	for name, expected := range exactOwnerReplacements {
		require.Samef(t, expected, replacements[name], "replacement %q", name)
	}
	require.Len(t, replacements, 47+len(exactOwnerReplacements))
	fixture := &javaRemoteParentGenericDirectJSSEFixture{}
	err = spec.LoadAndAssign(fixture, &ebpf.CollectionOptions{
		Programs:        ebpf.ProgramOptions{LogSizeStart: 640 * 1024},
		MapReplacements: replacements,
	})
	if err != nil {
		_ = fixture.closeObjects()
		var verifierErr *ebpf.VerifierError
		if errors.Is(err, unix.EPERM) && !errors.As(err, &verifierErr) {
			t.Skipf("insufficient capability to load generic Java parser programs: %v", err)
		}
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		require.NoError(t, fixture.close(primary.JavaRemoteParentDataHookReadiness))
	})

	fixture.populateTailCalls(t)
	return fixture
}

func (f *javaRemoteParentGenericDirectJSSEFixture) populateTailCalls(t *testing.T) {
	t.Helper()

	for _, entry := range []struct {
		slot    uint32
		program *ebpf.Program
	}{
		{slot: 0, program: f.ObiProtocolHTTP},
		{slot: 1, program: f.ObiContinueProtocolHTTP},
		{slot: 2, program: f.ObiContinue2ProtocolHTTP},
		{slot: 3, program: f.ObiContinueProtocolHTTPTraceparent},
		{slot: 5, program: f.ObiHandleBufWithArgs},
		{slot: 13, program: f.ObiLargeBufEmitContinue},
		{slot: 14, program: f.ObiContinueProtocolHTTPValidate},
	} {
		require.NotNil(t, entry.program)
		require.NoError(t, f.JumpTable.Update(
			entry.slot,
			uint32(entry.program.FD()),
			ebpf.UpdateAny,
		))
	}
}

func (f *javaRemoteParentGenericDirectJSSEFixture) attach(
	t *testing.T,
	readiness *ebpf.Map,
) {
	t.Helper()

	setJavaRemoteParentDataHookReadiness(t, readiness, false)
	for _, probe := range []struct {
		symbol  string
		program *ebpf.Program
	}{
		{symbol: "sys_ioctl", program: f.ObiSysIoctl},
		{symbol: "security_file_ioctl", program: f.ObiSecurityFileIoctl},
		{symbol: "tcp_close", program: f.ObiJavaRemoteParentTCPClose},
	} {
		attached, err := link.Kprobe(probe.symbol, probe.program, nil)
		require.NoErrorf(t, err, "attach %s", probe.symbol)
		f.links = append(f.links, attached)
	}
	setJavaRemoteParentDataHookReadiness(t, readiness, true)
	assertJavaRemoteParentGenericDirectJSSEReadiness(t, readiness, 1)
}

func (f *javaRemoteParentGenericDirectJSSEFixture) close(readiness *ebpf.Map) error {
	var closeErrors []error
	key := uint32(0)
	state := uint32(0)
	if err := readiness.Update(&key, &state, ebpf.UpdateAny); err != nil {
		closeErrors = append(closeErrors, fmt.Errorf("disable Java data-hook readiness: %w", err))
	} else {
		var observed uint32
		if err := readiness.Lookup(&key, &observed); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("read disabled Java data-hook readiness: %w", err))
		} else if observed != 0 {
			closeErrors = append(closeErrors, fmt.Errorf("disabled Java data-hook readiness is %d", observed))
		}
	}

	for index := len(f.links) - 1; index >= 0; index-- {
		if err := f.links[index].Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close generic Java hook %d: %w", index, err))
		}
	}
	f.links = nil
	if err := f.closeObjects(); err != nil {
		closeErrors = append(closeErrors, err)
	}
	return errors.Join(closeErrors...)
}

func (f *javaRemoteParentGenericDirectJSSEFixture) closeObjects() error {
	var closeErrors []error
	for _, object := range []struct {
		name   string
		closer io.Closer
	}{
		{name: "jump_table", closer: f.JumpTable},
		{name: "obi_continue2_protocol_http", closer: f.ObiContinue2ProtocolHTTP},
		{name: "obi_continue_protocol_http", closer: f.ObiContinueProtocolHTTP},
		{name: "obi_continue_protocol_http_tp", closer: f.ObiContinueProtocolHTTPTraceparent},
		{name: "obi_continue_protocol_http_tp_validate", closer: f.ObiContinueProtocolHTTPValidate},
		{name: "obi_handle_buf_with_args", closer: f.ObiHandleBufWithArgs},
		{name: "obi_kprobe_java_remote_parent_tcp_close", closer: f.ObiJavaRemoteParentTCPClose},
		{name: "obi_kprobe_security_file_ioctl", closer: f.ObiSecurityFileIoctl},
		{name: "obi_kprobe_sys_ioctl", closer: f.ObiSysIoctl},
		{name: "obi_large_buf_emit_continue", closer: f.ObiLargeBufEmitContinue},
		{name: "obi_protocol_http", closer: f.ObiProtocolHTTP},
	} {
		if object.closer == nil {
			continue
		}
		if err := object.closer.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close %s: %w", object.name, err))
		}
	}
	return errors.Join(closeErrors...)
}

func javaRemoteParentGenericDirectJSSEMapReplacements(
	primary *BpfJavaRemoteParentMaps,
) map[string]*ebpf.Map {
	return map[string]*ebpf.Map{
		"debug_events":                                             primary.DebugEvents,
		"incoming_trace_ambiguity":                                 primary.IncomingTraceAmbiguity,
		"incoming_trace_candidate_value_storage":                   primary.IncomingTraceCandidateValueStorage,
		"incoming_trace_candidates":                                primary.IncomingTraceCandidates,
		"incoming_trace_claims":                                    primary.IncomingTraceClaims,
		"incoming_trace_connection_key_storage":                    primary.IncomingTraceConnectionKeyStorage,
		"incoming_trace_generation":                                primary.IncomingTraceGeneration,
		"incoming_trace_heads":                                     primary.IncomingTraceHeads,
		"incoming_trace_map":                                       primary.IncomingTraceMap,
		"incoming_trace_snapshot_storage":                          primary.IncomingTraceSnapshotStorage,
		"java_authorized_processes":                                primary.JavaAuthorizedProcesses,
		"java_process_incarnations":                                primary.JavaProcessIncarnations,
		"java_remote_parent_alias_replay_retain_workspace_storage": primary.JavaRemoteParentAliasReplayRetainWorkspaceStorage,
		"java_remote_parent_alias_replays":                         primary.JavaRemoteParentAliasReplays,
		"java_remote_parent_ambiguity":                             primary.JavaRemoteParentAmbiguity,
		"java_remote_parent_claims":                                primary.JavaRemoteParentClaims,
		"java_remote_parent_cleanup_workspace_storage":             primary.JavaRemoteParentCleanupWorkspaceStorage,
		"java_remote_parent_connection_snapshot_storage":           primary.JavaRemoteParentConnectionSnapshotStorage,
		"java_remote_parent_connections":                           primary.JavaRemoteParentConnections,
		"java_remote_parent_cookie_connections":                    primary.JavaRemoteParentCookieConnections,
		"java_remote_parent_data_acks":                             primary.JavaRemoteParentDataAcks,
		"java_remote_parent_data_hook_readiness":                   primary.JavaRemoteParentDataHookReadiness,
		"java_remote_parent_data_signals":                          primary.JavaRemoteParentDataSignals,
		"java_remote_parent_fallback":                              primary.JavaRemoteParentFallback,
		"java_remote_parent_generation":                            primary.JavaRemoteParentGeneration,
		"java_remote_parent_generation_index":                      primary.JavaRemoteParentGenerationIndex,
		"java_remote_parent_handoff_capture_workspace_storage":     primary.JavaRemoteParentHandoffCaptureWorkspaceStorage,
		"java_remote_parent_handoff_claims":                        primary.JavaRemoteParentHandoffClaims,
		"java_remote_parent_handoff_mutations":                     primary.JavaRemoteParentHandoffMutations,
		"java_remote_parent_handoffs":                              primary.JavaRemoteParentHandoffs,
		"java_remote_parent_incoming_snapshot_storage":             primary.JavaRemoteParentIncomingSnapshotStorage,
		"java_remote_parent_janitor_workspace_storage":             primary.JavaRemoteParentJanitorWorkspaceStorage,
		"java_remote_parent_owner_guards":                          primary.JavaRemoteParentOwnerGuards,
		"java_remote_parent_owners":                                primary.JavaRemoteParentOwners,
		"java_remote_parent_stage_state_storage":                   primary.JavaRemoteParentStageStateStorage,
		"java_remote_parent_state":                                 primary.JavaRemoteParentState,
		"java_remote_parent_stats":                                 primary.JavaRemoteParentStats,
		"java_remote_parent_task_claims":                           primary.JavaRemoteParentTaskClaims,
		"java_remote_parent_tasks":                                 primary.JavaRemoteParentTasks,
		"java_remote_parent_terminal":                              primary.JavaRemoteParentTerminal,
		"java_retired_processes":                                   primary.JavaRetiredProcesses,
		"java_thread_mapping_claims":                               primary.JavaThreadMappingClaims,
		"java_tasks":                                               primary.JavaTasks,
		"java_vt_identities":                                       primary.JavaVtIdentities,
		"java_vt_threads":                                          primary.JavaVtThreads,
		"jrp_recv_cur":                                             primary.JrpRecvCur,
		"jrp_recv_guard":                                           primary.JrpRecvGuard,
		"pid_cache":                                                primary.PidCache,
		"trace_map":                                                primary.TraceMap,
		"valid_pids":                                               primary.ValidPids,
	}
}

func assertJavaRemoteParentGenericDirectJSSEReadiness(
	t *testing.T,
	readiness *ebpf.Map,
	want uint32,
) {
	t.Helper()

	key := uint32(0)
	var state uint32
	require.NoError(t, readiness.Lookup(&key, &state))
	require.Equal(t, want, state)
}
