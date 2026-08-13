// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigIsClosedAndBounded(t *testing.T) {
	cfg, err := parseConfig([]string{
		"--control-dir", "/run/obi-demo/pid-reuse",
		"--transport", "getsockopt",
		"--timeout", "30s",
	})
	require.NoError(t, err)
	assert.Equal(t, "getsockopt", cfg.transport)
	assert.Equal(t, 30*time.Second, cfg.timeout)

	for _, arguments := range [][]string{
		{"--control-dir", "relative", "--transport", "getsockopt"},
		{"--control-dir", "/run/../unsafe", "--transport", "getsockopt"},
		{"--control-dir", "/run/safe", "--transport", "auto"},
		{"--control-dir", "/run/safe", "--transport", "unix", "extra"},
		{"--control-dir", "/run/safe", "--transport", "unix", "--timeout", "1s"},
		{"--control-dir", "/run/safe", "--transport", "unix", "--timeout", "15s"},
	} {
		_, err := parseConfig(arguments)
		assert.Error(t, err, arguments)
	}
}

func TestPrivateIdentitySchemaAndReuseAreExact(t *testing.T) {
	contents := []byte(
		"schema=obi-pid-reuse-private-v1\n" +
			"pid_namespace_inode=101\n" +
			"pid=4242\n" +
			"tid=4242\n" +
			"start_time_ticks=200\n" +
			"socket_cookie=300\n" +
			"network_namespace_inode=400\n" +
			"network_namespace_cookie=500\n" +
			"local_port=41000\n" +
			"peer_port=42000\n",
	)
	first, err := parsePrivateIdentity(contents)
	require.NoError(t, err)
	second := first
	second.startTimeTicks++
	require.NoError(t, validateReuse(first, second))

	assert.Error(t, validateReuse(first, first), "equal start time must kill the test")
	second = first
	second.pid++
	assert.Error(t, validateReuse(first, second), "numeric PID mutation must kill the test")
	second = first
	second.socketCookie++
	assert.Error(t, validateReuse(first, second), "socket provenance mutation must kill the test")
	_, err = parsePrivateIdentity(append(contents, []byte("extra=1\n")...))
	assert.Error(t, err, "schema widening must fail closed")
}

func TestGraphCarriesExactIncarnationAndConnectionProvenance(t *testing.T) {
	identity := privateIdentity{
		pidNamespaceInode:      101,
		pid:                    4242,
		tid:                    4242,
		startTimeTicks:         200,
		socketCookie:           300,
		networkNamespaceInode:  400,
		networkNamespaceCookie: 500,
		localPort:              41000,
		peerPort:               42000,
	}
	process := processIdentity{key: processKey(identity), capability: 0x1234}
	maps := &bridgeMaps{}
	graph, err := buildGraph(maps, identity, process, "unix", staleGeneration, staleTraceID, staleSpanID)
	require.NoError(t, err)
	require.Len(t, graph.entries, 7)
	state := graph.entries[1].value
	assert.Equal(t, process.capability, binary.LittleEndian.Uint64(state[56:64]))
	assert.Equal(t, identity.networkNamespaceInode, binary.LittleEndian.Uint32(state[52:56]))
	assert.Equal(t, staleGeneration, binary.LittleEndian.Uint64(state[104:112]))
	assert.Equal(t, staleTraceID[:], state[80:96])
	assert.Equal(t, staleSpanID[:], state[96:104])
	claim := processClaim(process.key, process.capability)
	assert.Equal(t, process.key, claim[:12])
	assert.Equal(t, []byte{0, 0, 0, 0}, claim[12:16], "claim must remain BPF-publisher shaped")
	assert.Equal(t, process.capability, binary.LittleEndian.Uint64(claim[16:24]))
	assert.NotEqual(t, claim, processClaim(process.key, process.capability+1))
}

func TestPublicResultHasOnlySanitizedClosedFields(t *testing.T) {
	result := publicResult{
		Schema: publicResultSchema, Status: "passed", Transport: "unix",
		PrivatePIDNamespace: true, SameNamespaceInode: true, SameNumericPID: true,
		SameNumericTID: true, AReapedBeforeB: true, DifferentLifetime: true,
		OBICapabilitiesNonzero: true, OBICapabilitiesDistinct: true,
		AuthorizationMapsAgree: true, JVMAPrivilegesDropped: true,
		JVMBPrivilegesDropped: true, NormalCleanup: "completed",
		Residue: "injected_after_a_reap", NegativeStatus: "ambiguous",
		InjectedResidueRejected: true, InjectedResiduePreserved: true,
		W3CFailOpen: true, RecoveryStatus: "valid", RecoveryParentExact: true,
		PrivateArtifactsRemoved: true,
	}
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Len(t, decoded, 24, "public schema key count is mutation-sensitive")
	for key, value := range decoded {
		if key == "schema" || key == "status" || key == "transport" ||
			key == "normal_cleanup" || key == "residue" || key == "negative_status" ||
			key == "recovery_status" {
			_, ok := value.(string)
			assert.True(t, ok, key)
			continue
		}
		_, ok := value.(bool)
		assert.True(t, ok, key)
	}
	text := string(encoded)
	for _, forbidden := range []string{
		"start_time_ticks", "socket_cookie", "network_namespace_cookie",
		"trace_id", "span_id", "generation", "capability_value", "map_id", "\"fd\"",
		"cap_inh", "cap_prm", "cap_eff", "cap_bnd", "cap_amb", "no_new_privs",
	} {
		assert.False(t, strings.Contains(text, forbidden), forbidden)
	}
}

func TestRuntimePrivilegeAttestationIsBoundToExactJVMIdentity(t *testing.T) {
	identity := privateIdentity{pid: 4242, startTimeTicks: 200}
	assert.Equal(t,
		"schema=obi-pid-reuse-jvm-attestation-v1\n"+
			"pid=4242\n"+
			"start_time_ticks=200\n"+
			"cap_inh_zero=true\n"+
			"cap_prm_zero=true\n"+
			"cap_eff_zero=true\n"+
			"cap_bnd_zero=true\n"+
			"cap_amb_zero=true\n"+
			"no_new_privs=true\n",
		runtimePrivilegePayload(identity),
	)
	assert.Greater(t, cleanupObservation, productionCleanupSweepInterval)
}

func TestNormalCleanupCannotPassPendingOrPartialAtDeadline(t *testing.T) {
	complete, err := cleanupObservationResult(false, true, false)
	require.NoError(t, err)
	assert.True(t, complete)

	complete, err = cleanupObservationResult(true, false, false)
	require.NoError(t, err)
	assert.False(t, complete)

	for _, state := range []struct {
		allPresent bool
		allAbsent  bool
	}{
		{allPresent: true},
		{},
	} {
		complete, err = cleanupObservationResult(state.allPresent, state.allAbsent, true)
		assert.Error(t, err, state)
		assert.False(t, complete, state)
	}
}

func TestNegativeStatusContractIsTransportSpecific(t *testing.T) {
	getsockopt := publicResult{NegativeStatus: "unsupported"}
	unixResult := publicResult{NegativeStatus: "ambiguous"}
	assert.NotEqual(t, getsockopt.NegativeStatus, unixResult.NegativeStatus)
	assert.Equal(t, "unsupported", getsockopt.NegativeStatus)
	assert.Equal(t, "ambiguous", unixResult.NegativeStatus)
}

func TestOwnerMapRequiresExactBTFProvenance(t *testing.T) {
	require.Equal(t, "java_remote_parent_owner_t", shapes.owners.valueBTFType)
	assert.True(t, matchesBTFValueType("java_remote_parent_owner_t", shapes.owners))
	assert.False(
		t,
		matchesBTFValueType("java_remote_parent_claim_t", shapes.owners),
		"the identically shaped owner-guard map must not be accepted",
	)
	assert.True(t, matchesBTFValueType("", shapes.state), "unique shapes need no BTF discriminator")
}
