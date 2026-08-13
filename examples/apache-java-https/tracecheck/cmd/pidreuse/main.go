// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

const (
	privateIdentitySchema = "obi-pid-reuse-private-v1"
	publicResultSchema    = "obi-pid-reuse-public-v1"
	controlDirectoryMode  = 0o700
	controlFileMode       = 0o600
	maximumControlBytes   = 4096
	maximumMapEntries     = 50_000
	pollInterval          = 10 * time.Millisecond
	// runJavaRemoteParentCleanup caps the production sweep ticker at 10s in
	// pkg/internal/ebpf/tpinjector/java_remote_parent.go. Allow a full cadence
	// plus scheduling margin after phase A is reaped.
	productionCleanupSweepInterval = 10 * time.Second
	cleanupObservation             = productionCleanupSweepInterval + 5*time.Second
	activeLifecycle                = byte(1)
	probeNonce                     = uint64(1)
	staleGeneration                = uint64(0x3601)
	recoveryGeneration             = uint64(0x3602)
)

var (
	staleTraceID    = [16]byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	staleSpanID     = [8]byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	recoveryTraceID = [16]byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}
	recoverySpanID  = [8]byte{0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb}
)

type config struct {
	controlDir string
	transport  string
	timeout    time.Duration
}

type privateIdentity struct {
	pidNamespaceInode      uint32
	pid                    uint32
	tid                    uint32
	startTimeTicks         uint64
	socketCookie           uint64
	networkNamespaceInode  uint32
	networkNamespaceCookie uint64
	localPort              uint16
	peerPort               uint16
}

type processIdentity struct {
	key        []byte
	capability uint64
}

type publicResult struct {
	Schema                   string `json:"schema"`
	Status                   string `json:"status"`
	Transport                string `json:"transport"`
	PrivatePIDNamespace      bool   `json:"private_pid_namespace"`
	SameNamespaceInode       bool   `json:"same_namespace_inode"`
	SameNumericPID           bool   `json:"same_numeric_pid"`
	SameNumericTID           bool   `json:"same_numeric_tid"`
	AReapedBeforeB           bool   `json:"a_reaped_before_b"`
	DifferentLifetime        bool   `json:"different_lifetime"`
	OBICapabilitiesNonzero   bool   `json:"obi_capabilities_nonzero"`
	OBICapabilitiesDistinct  bool   `json:"obi_capabilities_distinct"`
	AuthorizationMapsAgree   bool   `json:"authorization_maps_agree"`
	JVMAPrivilegesDropped    bool   `json:"jvm_a_privileges_dropped"`
	JVMBPrivilegesDropped    bool   `json:"jvm_b_privileges_dropped"`
	NormalCleanup            string `json:"normal_cleanup"`
	Residue                  string `json:"residue"`
	SamePrimarySocket        bool   `json:"same_primary_socket"`
	NegativeStatus           string `json:"negative_status"`
	InjectedResidueRejected  bool   `json:"injected_residue_rejected"`
	InjectedResiduePreserved bool   `json:"injected_residue_preserved"`
	W3CFailOpen              bool   `json:"w3c_fail_open"`
	RecoveryStatus           string `json:"recovery_status"`
	RecoveryParentExact      bool   `json:"recovery_parent_exact"`
	PrivateArtifactsRemoved  bool   `json:"private_artifacts_removed"`
}

type mapShape struct {
	label     string
	name      string
	typeID    ebpf.MapType
	keySize   uint32
	valueSize uint32
	// valueBTFType disambiguates maps whose 15-byte kernel names and wire
	// layouts collide. It is intentionally required for the owner index:
	// java_remote_parent_owners and java_remote_parent_owner_guards are both
	// HASH<12,24> maps named "java_remote_par" by the kernel.
	valueBTFType string
}

var shapes = struct {
	process, authorized, retired, processClaims mapShape
	fallback, state, generations, connections   mapShape
	cookieConnections, owners, ambiguity        mapShape
	dataSignals, dataAcks                       mapShape
}{
	process:           mapShape{"process incarnations", "java_process_in", ebpf.Hash, 12, 8, ""},
	authorized:        mapShape{"process authorization", "java_authorized", ebpf.Hash, 12, 8, ""},
	retired:           mapShape{"retired processes", "java_retired_pr", ebpf.Hash, 24, 8, ""},
	processClaims:     mapShape{"process claims", "java_thread_map", ebpf.Hash, 12, 24, ""},
	fallback:          mapShape{"fallback", "java_remote_par", ebpf.Hash, 12, 64, ""},
	state:             mapShape{"state", "java_remote_par", ebpf.Hash, 24, 128, ""},
	generations:       mapShape{"generation index", "java_remote_par", ebpf.Hash, 24, 32, ""},
	connections:       mapShape{"connection index", "java_remote_par", ebpf.Hash, 40, 56, ""},
	cookieConnections: mapShape{"cookie connection index", "java_remote_par", ebpf.Hash, 48, 56, ""},
	owners: mapShape{
		"owner index", "java_remote_par", ebpf.Hash, 12, 24, "java_remote_parent_owner_t",
	},
	ambiguity:   mapShape{"ambiguity reservation", "java_remote_par", ebpf.Hash, 24, 8, ""},
	dataSignals: mapShape{"data signals", "java_remote_par", ebpf.LRUHash, 12, 8, ""},
	dataAcks:    mapShape{"data acknowledgements", "java_remote_par", ebpf.LRUHash, 24, 72, ""},
}

type bridgeMaps struct {
	process, authorized, retired, processClaims *ebpf.Map
	fallback, state, generations, connections   *ebpf.Map
	cookieConnections, owners, ambiguity        *ebpf.Map
	dataSignals, dataAcks                       *ebpf.Map
}

func (maps *bridgeMaps) close() {
	for _, candidate := range []*ebpf.Map{
		maps.process, maps.authorized, maps.retired, maps.processClaims,
		maps.fallback, maps.state, maps.generations, maps.connections,
		maps.cookieConnections, maps.owners, maps.ambiguity,
		maps.dataSignals, maps.dataAcks,
	} {
		if candidate != nil {
			candidate.Close()
		}
	}
}

type rawEntry struct {
	label string
	m     *ebpf.Map
	key   []byte
	value []byte
}

type generationGraph struct {
	entries []rawEntry
}

func main() {
	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()
	result, err := run(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "encode sanitized PID reuse result")
		os.Exit(1)
	}
}

func parseConfig(arguments []string) (config, error) {
	var cfg config
	flags := flag.NewFlagSet("pidreuse", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&cfg.controlDir, "control-dir", "", "private fixture control directory")
	flags.StringVar(&cfg.transport, "transport", "", "forced bridge transport")
	flags.DurationVar(&cfg.timeout, "timeout", 120*time.Second, "total bounded fixture timeout")
	if err := flags.Parse(arguments); err != nil {
		return config{}, errors.New("invalid PID reuse controller arguments")
	}
	if flags.NArg() != 0 {
		return config{}, errors.New("unexpected positional arguments")
	}
	if !filepath.IsAbs(cfg.controlDir) || filepath.Clean(cfg.controlDir) != cfg.controlDir || cfg.controlDir == "/" {
		return config{}, errors.New("control-dir must be a non-root absolute clean path")
	}
	if cfg.transport != "getsockopt" && cfg.transport != "unix" {
		return config{}, errors.New("transport must be getsockopt or unix")
	}
	if cfg.timeout < 30*time.Second || cfg.timeout > 3*time.Minute {
		return config{}, errors.New("timeout must be between 30s and 3m")
	}
	return cfg, nil
}

func run(ctx context.Context, cfg config) (_ publicResult, returnedErr error) {
	if err := validateControlDirectory(cfg.controlDir); err != nil {
		return publicResult{}, err
	}

	first, err := waitIdentity(ctx, cfg.controlDir, "identity-a")
	if err != nil {
		return publicResult{}, err
	}
	if err := waitExactFile(ctx, cfg.controlDir, "java-a-ready", "java-a-ready-v1\n"); err != nil {
		return publicResult{}, err
	}
	if err := waitExactFile(ctx, cfg.controlDir, "jvm-a-attestation", runtimePrivilegePayload(first)); err != nil {
		return publicResult{}, fmt.Errorf("phase A JVM runtime privilege attestation: %w", err)
	}

	maps, aProcess, err := discoverBridgeMaps(first)
	if err != nil {
		return publicResult{}, err
	}
	defer maps.close()
	if err := requireAuthorizationAgreement(maps, aProcess); err != nil {
		return publicResult{}, err
	}

	aGraph, err := buildGraph(maps, first, aProcess, cfg.transport, staleGeneration, staleTraceID, staleSpanID)
	if err != nil {
		return publicResult{}, err
	}
	if err := insertGraph(aGraph); err != nil {
		return publicResult{}, fmt.Errorf("stage phase A bridge graph: %w", err)
	}
	aGraphOwned := true
	defer func() {
		if returnedErr != nil && aGraphOwned {
			_ = deleteGraphExact(aGraph, true)
		}
	}()
	if err := publishControlFile(cfg.controlDir, "a-stage", "a-stage-v1\n"); err != nil {
		return publicResult{}, err
	}
	if err := waitExactFile(ctx, cfg.controlDir, "a-armed", "a-armed-v1\n"); err != nil {
		return publicResult{}, err
	}
	aPersistent, aEphemeral := splitGraph(aGraph)
	if err := verifyGraphExact(aPersistent); err != nil {
		return publicResult{}, fmt.Errorf("phase A graph changed before process exit: %w", err)
	}
	if cfg.transport == "getsockopt" {
		if err := requireGraphAbsent(aEphemeral); err != nil {
			return publicResult{}, fmt.Errorf("phase A acknowledgement was not consumed: %w", err)
		}
	}
	if err := publishControlFile(cfg.controlDir, "a-exit", "a-exit-v1\n"); err != nil {
		return publicResult{}, err
	}
	if err := waitExactFile(ctx, cfg.controlDir, "a-reaped", "a-reaped-v1\n"); err != nil {
		return publicResult{}, err
	}

	if err := observeNormalCleanup(ctx, aGraph); err != nil {
		return publicResult{}, err
	}
	aGraphOwned = false

	claim := processClaim(aProcess.key, aProcess.capability)
	if err := acquireProcessClaim(ctx, maps.processClaims, aProcess.key, claim); err != nil {
		return publicResult{}, err
	}
	claimHeld := true
	defer func() {
		if claimHeld {
			_ = deleteExact(maps.processClaims, aProcess.key, claim, true)
		}
	}()

	retirementKey := retiredKey(aProcess.key, aProcess.capability)
	retirementValue, retirementPresent, err := lookupOptional(maps.retired, retirementKey)
	if err != nil {
		return publicResult{}, errors.New("inspect exact phase A retirement marker")
	}
	if retirementPresent && binary.LittleEndian.Uint64(retirementValue) == 0 {
		return publicResult{}, errors.New("phase A retirement marker is malformed")
	}
	retirementQuarantined := false
	defer func() {
		if returnedErr != nil && retirementQuarantined {
			_ = restoreExact(maps.retired, retirementKey, retirementValue)
		}
	}()
	if retirementPresent {
		if err := deleteExact(maps.retired, retirementKey, retirementValue, false); err != nil {
			return publicResult{}, errors.New("quarantine exact phase A retirement marker")
		}
		retirementQuarantined = true
	}
	incarnationValue, incarnationPresent, err := lookupOptional(maps.process, aProcess.key)
	if err != nil {
		return publicResult{}, errors.New("inspect exact phase A incarnation after normal cleanup")
	}
	if incarnationPresent && binary.LittleEndian.Uint64(incarnationValue) != aProcess.capability {
		return publicResult{}, errors.New("phase A incarnation changed before stale-residue injection")
	}
	if incarnationPresent {
		if err := deleteExact(maps.process, aProcess.key, incarnationValue, false); err != nil {
			return publicResult{}, errors.New("quarantine exact phase A incarnation")
		}
	}
	incarnationQuarantined := incarnationPresent
	defer func() {
		if returnedErr != nil && incarnationQuarantined {
			_ = restoreExact(maps.process, aProcess.key, u64Bytes(aProcess.capability))
		}
	}()
	if err := insertGraph(aGraph); err != nil {
		return publicResult{}, fmt.Errorf("inject labeled phase A stale residue: %w", err)
	}
	aGraphOwned = true
	if err := verifyGraphExact(aGraph); err != nil {
		return publicResult{}, fmt.Errorf("verify injected phase A stale residue: %w", err)
	}
	if err := deleteExact(maps.processClaims, aProcess.key, claim, false); err != nil {
		return publicResult{}, errors.New("release phase A injection fence")
	}
	claimHeld = false
	if err := publishControlFile(cfg.controlDir, "start-b", "start-b-v1\n"); err != nil {
		return publicResult{}, err
	}

	second, err := waitIdentity(ctx, cfg.controlDir, "identity-b")
	if err != nil {
		return publicResult{}, err
	}
	if err := waitExactFile(ctx, cfg.controlDir, "reuse-proved", "reuse-proved-v1\n"); err != nil {
		return publicResult{}, err
	}
	if err := validateReuse(first, second); err != nil {
		return publicResult{}, err
	}
	if err := waitExactFile(ctx, cfg.controlDir, "java-b-ready", "java-b-ready-v1\n"); err != nil {
		return publicResult{}, err
	}
	if err := waitExactFile(ctx, cfg.controlDir, "jvm-b-attestation", runtimePrivilegePayload(second)); err != nil {
		return publicResult{}, fmt.Errorf("phase B JVM runtime privilege attestation: %w", err)
	}
	bProcess, err := waitProcessCapability(ctx, maps, second, aProcess.capability)
	if err != nil {
		return publicResult{}, err
	}
	incarnationQuarantined = false
	if err := verifyGraphExact(aGraph); err != nil {
		return publicResult{}, fmt.Errorf("injected residue did not survive until phase B: %w", err)
	}
	if err := publishControlFile(cfg.controlDir, "b-negative", "b-negative-v1\n"); err != nil {
		return publicResult{}, err
	}
	expectedNegative := "ambiguous"
	if cfg.transport == "getsockopt" {
		expectedNegative = "unsupported"
	}
	negativeContents := "schema=obi-pid-reuse-java-result-v1\nstatus=" + expectedNegative + "\nw3c_fail_open=true\n"
	if err := waitExactFile(ctx, cfg.controlDir, "b-negative-result", negativeContents); err != nil {
		return publicResult{}, err
	}
	if err := verifyGraphExact(aGraph); err != nil {
		return publicResult{}, fmt.Errorf("phase B consumed or mutated injected phase A residue: %w", err)
	}

	if err := deleteGraphExact(aGraph, false); err != nil {
		return publicResult{}, fmt.Errorf("remove injected phase A residue: %w", err)
	}
	aGraphOwned = false
	if retirementQuarantined {
		if err := restoreExact(maps.retired, retirementKey, retirementValue); err != nil {
			return publicResult{}, errors.New("restore exact phase A retirement marker")
		}
		retirementQuarantined = false
	}

	bGraph, err := buildGraph(maps, second, bProcess, cfg.transport, recoveryGeneration, recoveryTraceID, recoverySpanID)
	if err != nil {
		return publicResult{}, err
	}
	if err := insertGraph(bGraph); err != nil {
		return publicResult{}, fmt.Errorf("stage phase B recovery graph: %w", err)
	}
	bGraphOwned := true
	defer func() {
		if returnedErr != nil && bGraphOwned {
			_ = deleteGraphExact(bGraph, true)
		}
	}()
	if err := publishControlFile(cfg.controlDir, "b-recovery", "b-recovery-v1\n"); err != nil {
		return publicResult{}, err
	}
	if err := waitExactFile(
		ctx,
		cfg.controlDir,
		"b-recovery-result",
		"schema=obi-pid-reuse-java-result-v1\nstatus=valid\nparent_exact=true\n",
	); err != nil {
		return publicResult{}, err
	}
	if err := waitGraphAbsent(ctx, bGraph); err != nil {
		return publicResult{}, fmt.Errorf("phase B recovery graph was not consumed: %w", err)
	}
	bGraphOwned = false

	for _, name := range []string{"identity-a", "identity-b", "jvm-a-attestation", "jvm-b-attestation"} {
		if err := removePrivateFile(cfg.controlDir, name); err != nil {
			return publicResult{}, err
		}
	}

	return publicResult{
		Schema:                   publicResultSchema,
		Status:                   "passed",
		Transport:                cfg.transport,
		PrivatePIDNamespace:      true,
		SameNamespaceInode:       true,
		SameNumericPID:           true,
		SameNumericTID:           true,
		AReapedBeforeB:           true,
		DifferentLifetime:        true,
		OBICapabilitiesNonzero:   true,
		OBICapabilitiesDistinct:  true,
		AuthorizationMapsAgree:   true,
		JVMAPrivilegesDropped:    true,
		JVMBPrivilegesDropped:    true,
		NormalCleanup:            "completed",
		Residue:                  "injected_after_a_reap",
		SamePrimarySocket:        true,
		NegativeStatus:           expectedNegative,
		InjectedResidueRejected:  true,
		InjectedResiduePreserved: true,
		W3CFailOpen:              true,
		RecoveryStatus:           "valid",
		RecoveryParentExact:      true,
		PrivateArtifactsRemoved:  true,
	}, nil
}

func validateControlDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("inspect PID reuse control directory")
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != controlDirectoryMode || metadata.Uid != 0 {
		return errors.New("PID reuse control directory is not a root-owned private real directory")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("PID reuse control directory is not canonical")
	}
	return nil
}

func waitIdentity(ctx context.Context, directory, name string) (privateIdentity, error) {
	for {
		contents, present, err := readPrivateFile(filepath.Join(directory, name), 1, maximumControlBytes)
		if err != nil {
			return privateIdentity{}, err
		}
		if present {
			return parsePrivateIdentity(contents)
		}
		if err := waitPoll(ctx); err != nil {
			return privateIdentity{}, errors.New("timed out waiting for private process identity")
		}
	}
}

func parsePrivateIdentity(contents []byte) (privateIdentity, error) {
	if len(contents) == 0 || contents[len(contents)-1] != '\n' {
		return privateIdentity{}, errors.New("private process identity is not newline terminated")
	}
	values := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || value == "" {
			return privateIdentity{}, errors.New("private process identity has malformed fields")
		}
		if _, duplicate := values[key]; duplicate {
			return privateIdentity{}, errors.New("private process identity has duplicate fields")
		}
		values[key] = value
	}
	expected := []string{
		"schema", "pid_namespace_inode", "pid", "tid", "start_time_ticks",
		"socket_cookie", "network_namespace_inode", "network_namespace_cookie",
		"local_port", "peer_port",
	}
	if len(values) != len(expected) || values["schema"] != privateIdentitySchema {
		return privateIdentity{}, errors.New("private process identity schema is not exact")
	}
	for _, key := range expected {
		if _, exists := values[key]; !exists {
			return privateIdentity{}, errors.New("private process identity is missing a required field")
		}
	}
	parse := func(key string, maximum uint64) (uint64, error) {
		value, err := strconv.ParseUint(values[key], 10, 64)
		if err != nil || value == 0 || value > maximum {
			return 0, errors.New("private process identity has an invalid numeric field")
		}
		return value, nil
	}
	pidNamespace, err := parse("pid_namespace_inode", uint64(^uint32(0)))
	if err != nil {
		return privateIdentity{}, err
	}
	pid, err := parse("pid", uint64(^uint32(0)))
	if err != nil {
		return privateIdentity{}, err
	}
	tid, err := parse("tid", uint64(^uint32(0)))
	if err != nil || tid != pid {
		return privateIdentity{}, errors.New("private process identity PID/TID is invalid")
	}
	startTime, err := parse("start_time_ticks", ^uint64(0))
	if err != nil {
		return privateIdentity{}, err
	}
	socketCookie, err := parse("socket_cookie", ^uint64(0))
	if err != nil {
		return privateIdentity{}, err
	}
	networkNamespace, err := parse("network_namespace_inode", uint64(^uint32(0)))
	if err != nil {
		return privateIdentity{}, err
	}
	networkCookie, err := parse("network_namespace_cookie", ^uint64(0))
	if err != nil {
		return privateIdentity{}, err
	}
	localPort, err := parse("local_port", uint64(^uint16(0)))
	if err != nil {
		return privateIdentity{}, err
	}
	peerPort, err := parse("peer_port", uint64(^uint16(0)))
	if err != nil {
		return privateIdentity{}, err
	}
	return privateIdentity{
		pidNamespaceInode:      uint32(pidNamespace),
		pid:                    uint32(pid),
		tid:                    uint32(tid),
		startTimeTicks:         startTime,
		socketCookie:           socketCookie,
		networkNamespaceInode:  uint32(networkNamespace),
		networkNamespaceCookie: networkCookie,
		localPort:              uint16(localPort),
		peerPort:               uint16(peerPort),
	}, nil
}

func validateReuse(first, second privateIdentity) error {
	if first.pidNamespaceInode != second.pidNamespaceInode ||
		first.pid != second.pid || first.tid != second.tid {
		return errors.New("controlled JVMs do not share the exact namespace PID/TID identity")
	}
	if first.startTimeTicks == second.startTimeTicks {
		return errors.New("controlled JVMs do not have distinct process lifetimes")
	}
	if first.socketCookie != second.socketCookie ||
		first.networkNamespaceInode != second.networkNamespaceInode ||
		first.networkNamespaceCookie != second.networkNamespaceCookie ||
		first.localPort != second.localPort || first.peerPort != second.peerPort {
		return errors.New("controlled JVMs do not share the exact inherited socket identity")
	}
	return nil
}

func runtimePrivilegePayload(identity privateIdentity) string {
	return fmt.Sprintf(
		"schema=obi-pid-reuse-jvm-attestation-v1\n"+
			"pid=%d\n"+
			"start_time_ticks=%d\n"+
			"cap_inh_zero=true\n"+
			"cap_prm_zero=true\n"+
			"cap_eff_zero=true\n"+
			"cap_bnd_zero=true\n"+
			"cap_amb_zero=true\n"+
			"no_new_privs=true\n",
		identity.pid,
		identity.startTimeTicks,
	)
}

func discoverBridgeMaps(identity privateIdentity) (*bridgeMaps, processIdentity, error) {
	key := processKey(identity)
	processMap, processMapID, capability, err := findProcessMap(key)
	if err != nil {
		return nil, processIdentity{}, err
	}
	related, err := mapsRelatedToTarget(processMapID)
	if err != nil {
		processMap.Close()
		return nil, processIdentity{}, err
	}
	maps := &bridgeMaps{process: processMap}
	open := func(shape mapShape) (*ebpf.Map, error) { return openRelatedMap(related, shape) }
	for _, target := range []struct {
		shape mapShape
		set   func(*ebpf.Map)
	}{
		{shapes.authorized, func(m *ebpf.Map) { maps.authorized = m }},
		{shapes.retired, func(m *ebpf.Map) { maps.retired = m }},
		{shapes.processClaims, func(m *ebpf.Map) { maps.processClaims = m }},
		{shapes.fallback, func(m *ebpf.Map) { maps.fallback = m }},
		{shapes.state, func(m *ebpf.Map) { maps.state = m }},
		{shapes.generations, func(m *ebpf.Map) { maps.generations = m }},
		{shapes.connections, func(m *ebpf.Map) { maps.connections = m }},
		{shapes.cookieConnections, func(m *ebpf.Map) { maps.cookieConnections = m }},
		{shapes.owners, func(m *ebpf.Map) { maps.owners = m }},
		{shapes.ambiguity, func(m *ebpf.Map) { maps.ambiguity = m }},
		{shapes.dataSignals, func(m *ebpf.Map) { maps.dataSignals = m }},
		{shapes.dataAcks, func(m *ebpf.Map) { maps.dataAcks = m }},
	} {
		candidate, openErr := open(target.shape)
		if openErr != nil {
			maps.close()
			return nil, processIdentity{}, openErr
		}
		target.set(candidate)
	}
	return maps, processIdentity{key: key, capability: capability}, nil
}

func findProcessMap(key []byte) (*ebpf.Map, ebpf.MapID, uint64, error) {
	var found *ebpf.Map
	var foundID ebpf.MapID
	var capability uint64
	for id := ebpf.MapID(0); ; {
		next, err := ebpf.MapGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			closeMap(found)
			return nil, 0, 0, errors.New("enumerate live BPF maps")
		}
		id = next
		candidate, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := candidate.Info()
		if err != nil || !matchesShape(info, shapes.process) {
			candidate.Close()
			continue
		}
		value, present, err := lookupOptional(candidate, key)
		if err != nil {
			candidate.Close()
			closeMap(found)
			return nil, 0, 0, errors.New("read process incarnation map")
		}
		if !present {
			candidate.Close()
			continue
		}
		current := binary.LittleEndian.Uint64(value)
		if current == 0 {
			candidate.Close()
			closeMap(found)
			return nil, 0, 0, errors.New("controlled JVM has a zero process incarnation")
		}
		if found != nil {
			candidate.Close()
			found.Close()
			return nil, 0, 0, errors.New("multiple live process maps contain the controlled JVM")
		}
		found, foundID, capability = candidate, id, current
	}
	if found == nil {
		return nil, 0, 0, errors.New("controlled JVM process incarnation was not found")
	}
	return found, foundID, capability, nil
}

func mapsRelatedToTarget(target ebpf.MapID) (map[ebpf.MapID]struct{}, error) {
	related := make(map[ebpf.MapID]struct{})
	referenced := false
	for id := ebpf.ProgramID(0); ; {
		next, err := ebpf.ProgramGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return nil, errors.New("enumerate live BPF programs")
		}
		id = next
		program, err := ebpf.NewProgramFromID(id)
		if err != nil {
			continue
		}
		info, infoErr := program.Info()
		program.Close()
		if infoErr != nil {
			continue
		}
		ids, ok := info.MapIDs()
		if !ok || !containsMapID(ids, target) {
			continue
		}
		referenced = true
		for _, candidate := range ids {
			related[candidate] = struct{}{}
		}
	}
	if !referenced {
		return nil, errors.New("controlled JVM process map has no inspectable program relationships")
	}
	return related, nil
}

func openRelatedMap(related map[ebpf.MapID]struct{}, shape mapShape) (*ebpf.Map, error) {
	var found *ebpf.Map
	for id := range related {
		candidate, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := candidate.Info()
		if err != nil || !matchesShape(info, shape) {
			candidate.Close()
			continue
		}
		if shape.valueBTFType != "" {
			name, typeErr := mapBTFValueTypeName(candidate)
			if typeErr != nil {
				candidate.Close()
				if found != nil {
					found.Close()
				}
				return nil, fmt.Errorf("inspect BTF provenance for %s: %w", shape.label, typeErr)
			}
			if !matchesBTFValueType(name, shape) {
				candidate.Close()
				continue
			}
		}
		if found != nil {
			candidate.Close()
			found.Close()
			return nil, fmt.Errorf("multiple related maps match %s", shape.label)
		}
		found = candidate
	}
	if found == nil {
		return nil, fmt.Errorf("related map was not found for %s", shape.label)
	}
	return found, nil
}

func matchesShape(info *ebpf.MapInfo, shape mapShape) bool {
	return info.Type == shape.typeID && info.Name == shape.name &&
		info.KeySize == shape.keySize && info.ValueSize == shape.valueSize &&
		info.MaxEntries > 0 && info.MaxEntries <= maximumMapEntries
}

func matchesBTFValueType(name string, shape mapShape) bool {
	return shape.valueBTFType == "" || name == shape.valueBTFType
}

// bpfMapInfo is the stable prefix of Linux's struct bpf_map_info through
// btf_value_type_id. Keeping the kernel ABI local avoids guessing between the
// identically truncated owner and owner-guard map names.
type bpfMapInfo struct {
	typeID                uint32
	id                    uint32
	keySize               uint32
	valueSize             uint32
	maxEntries            uint32
	flags                 uint32
	name                  [16]byte
	interfaceIndex        uint32
	btfVmlinuxValueTypeID uint32
	networkNamespaceDev   uint64
	networkNamespaceInode uint64
	btfID                 uint32
	btfKeyTypeID          uint32
	btfValueTypeID        uint32
}

type bpfObjectInfoAttribute struct {
	descriptor uint32
	length     uint32
	info       uint64
}

func mapBTFValueTypeName(candidate *ebpf.Map) (string, error) {
	var info bpfMapInfo
	attribute := bpfObjectInfoAttribute{
		descriptor: uint32(candidate.FD()),
		length:     uint32(unsafe.Sizeof(info)),
		info:       uint64(uintptr(unsafe.Pointer(&info))),
	}
	_, _, errno := unix.Syscall(
		unix.SYS_BPF,
		uintptr(unix.BPF_OBJ_GET_INFO_BY_FD),
		uintptr(unsafe.Pointer(&attribute)),
		unsafe.Sizeof(attribute),
	)
	runtime.KeepAlive(candidate)
	runtime.KeepAlive(&info)
	if errno != 0 {
		return "", errno
	}
	if info.btfID == 0 || info.btfValueTypeID == 0 {
		return "", errors.New("map does not expose a BTF value type")
	}
	handle, err := btf.NewHandleFromID(btf.ID(info.btfID))
	if err != nil {
		return "", err
	}
	defer handle.Close()
	specification, err := handle.Spec(nil)
	if err != nil {
		return "", err
	}
	valueType, err := specification.TypeByID(btf.TypeID(info.btfValueTypeID))
	if err != nil {
		return "", err
	}
	if valueType.TypeName() == "" {
		return "", errors.New("map BTF value type is unnamed")
	}
	return valueType.TypeName(), nil
}

func containsMapID(values []ebpf.MapID, target ebpf.MapID) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func requireAuthorizationAgreement(maps *bridgeMaps, process processIdentity) error {
	value, present, err := lookupOptional(maps.authorized, process.key)
	if err != nil || !present || binary.LittleEndian.Uint64(value) != process.capability || process.capability == 0 {
		return errors.New("OBI authorization and incarnation maps do not agree")
	}
	return nil
}

func waitProcessCapability(
	ctx context.Context,
	maps *bridgeMaps,
	identity privateIdentity,
	previous uint64,
) (processIdentity, error) {
	key := processKey(identity)
	for {
		incarnation, iPresent, iErr := lookupOptional(maps.process, key)
		authorized, qPresent, qErr := lookupOptional(maps.authorized, key)
		if iErr != nil || qErr != nil {
			return processIdentity{}, errors.New("read phase B OBI process capabilities")
		}
		if iPresent && qPresent {
			i := binary.LittleEndian.Uint64(incarnation)
			q := binary.LittleEndian.Uint64(authorized)
			if i != 0 && i == q && i != previous {
				return processIdentity{key: key, capability: i}, nil
			}
			// Q and I are distinct maps. Process discovery and in-JVM
			// registration rotate them in separate operations, so intermediate A/B
			// combinations are observable but never accepted as evidence.
		}
		if err := waitPoll(ctx); err != nil {
			return processIdentity{}, errors.New("timed out waiting for distinct phase B OBI capability")
		}
	}
}

func buildGraph(
	maps *bridgeMaps,
	identity privateIdentity,
	process processIdentity,
	transport string,
	generation uint64,
	traceID [16]byte,
	spanID [8]byte,
) (generationGraph, error) {
	if generation == 0 || process.capability == 0 {
		return generationGraph{}, errors.New("cannot build graph with zero provenance")
	}
	observed, err := monotonicNow()
	if err != nil {
		return generationGraph{}, err
	}
	owner := append([]byte(nil), process.key...)
	connection := connectionBytes(identity)
	stateKey := make([]byte, 24)
	copy(stateKey, owner)
	binary.LittleEndian.PutUint64(stateKey[16:24], generation)
	record := recordBytes(generation, observed, traceID, spanID)

	state := make([]byte, 128)
	state[0] = activeLifecycle
	binary.LittleEndian.PutUint64(state[8:16], observed)
	copy(state[16:52], connection)
	binary.LittleEndian.PutUint32(state[52:56], identity.networkNamespaceInode)
	binary.LittleEndian.PutUint64(state[56:64], process.capability)
	copy(state[64:128], record)

	index := make([]byte, 32)
	copy(index[0:12], process.key)
	binary.LittleEndian.PutUint64(index[16:24], process.capability)
	binary.LittleEndian.PutUint64(index[24:32], observed)

	connectionKey := make([]byte, 40)
	copy(connectionKey, connection)
	binary.LittleEndian.PutUint32(connectionKey[36:40], identity.networkNamespaceInode)
	cookieKey := make([]byte, 48)
	copy(cookieKey, connection)
	binary.LittleEndian.PutUint64(cookieKey[40:48], identity.networkNamespaceCookie)
	connectionValue := make([]byte, 56)
	copy(connectionValue, owner)
	binary.LittleEndian.PutUint64(connectionValue[16:24], generation)
	binary.LittleEndian.PutUint64(connectionValue[24:32], identity.networkNamespaceCookie)
	binary.LittleEndian.PutUint64(connectionValue[32:40], generation)
	binary.LittleEndian.PutUint64(connectionValue[40:48], identity.socketCookie)
	binary.LittleEndian.PutUint32(connectionValue[48:52], identity.networkNamespaceInode)

	ownerValue := make([]byte, 24)
	binary.LittleEndian.PutUint64(ownerValue[0:8], generation)
	binary.LittleEndian.PutUint64(ownerValue[8:16], process.capability)
	ownerValue[16] = activeLifecycle

	entries := []rawEntry{
		{"ambiguity reservation", maps.ambiguity, stateKey, make([]byte, 8)},
		{"state", maps.state, stateKey, state},
		{"generation index", maps.generations, stateKey, index},
		{"connection index", maps.connections, connectionKey, connectionValue},
		{"cookie connection index", maps.cookieConnections, cookieKey, connectionValue},
		{"fallback", maps.fallback, owner, record},
		{"owner index", maps.owners, owner, ownerValue},
	}
	if transport == "getsockopt" {
		signalKey := append([]byte(nil), process.key...)
		signalValue := u64Bytes(probeNonce)
		ackKey := make([]byte, 24)
		copy(ackKey, process.key)
		binary.LittleEndian.PutUint64(ackKey[16:24], probeNonce)
		ack := make([]byte, 72)
		copy(ack[0:12], owner)
		binary.LittleEndian.PutUint64(ack[16:24], generation)
		copy(ack[24:60], connection)
		binary.LittleEndian.PutUint32(ack[60:64], identity.networkNamespaceInode)
		entries = append(entries,
			rawEntry{"data signal", maps.dataSignals, signalKey, signalValue},
			rawEntry{"data acknowledgement", maps.dataAcks, ackKey, ack},
		)
	}
	return generationGraph{entries: entries}, nil
}

func connectionBytes(identity privateIdentity) []byte {
	connection := make([]byte, 36)
	for _, offset := range []int{0, 16} {
		connection[offset+10] = 0xff
		connection[offset+11] = 0xff
		connection[offset+12] = 127
		connection[offset+15] = 1
	}
	sourcePort, destinationPort := identity.localPort, identity.peerPort
	if destinationPort > sourcePort {
		sourcePort, destinationPort = destinationPort, sourcePort
	}
	binary.LittleEndian.PutUint16(connection[32:34], sourcePort)
	binary.LittleEndian.PutUint16(connection[34:36], destinationPort)
	return connection
}

func recordBytes(
	generation, observed uint64,
	traceID [16]byte,
	spanID [8]byte,
) []byte {
	record := make([]byte, 64)
	copy(record[0:4], []byte("OBIJ"))
	binary.LittleEndian.PutUint16(record[4:6], 1)
	binary.LittleEndian.PutUint16(record[6:8], 64)
	record[8] = 1
	record[9] = 1
	copy(record[16:32], traceID[:])
	copy(record[32:40], spanID[:])
	binary.LittleEndian.PutUint64(record[40:48], generation)
	binary.LittleEndian.PutUint64(record[48:56], observed)
	return record
}

func monotonicNow() (uint64, error) {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &value); err != nil {
		return 0, errors.New("read monotonic clock")
	}
	nanoseconds := uint64(value.Sec)*uint64(time.Second) + uint64(value.Nsec)
	if nanoseconds == 0 {
		return 0, errors.New("monotonic clock returned zero")
	}
	return nanoseconds, nil
}

func insertGraph(graph generationGraph) error {
	inserted := make([]rawEntry, 0, len(graph.entries))
	for _, entry := range graph.entries {
		if err := entry.m.Update(entry.key, entry.value, ebpf.UpdateNoExist); err != nil {
			for index := len(inserted) - 1; index >= 0; index-- {
				_ = deleteExact(inserted[index].m, inserted[index].key, inserted[index].value, true)
			}
			return fmt.Errorf("insert %s", entry.label)
		}
		inserted = append(inserted, entry)
	}
	return verifyGraphExact(graph)
}

func verifyGraphExact(graph generationGraph) error {
	for _, entry := range graph.entries {
		value, present, err := lookupOptional(entry.m, entry.key)
		if err != nil || !present || !bytes.Equal(value, entry.value) {
			return fmt.Errorf("%s is absent or changed", entry.label)
		}
	}
	return nil
}

func deleteGraphExact(graph generationGraph, allowAbsent bool) error {
	for index := len(graph.entries) - 1; index >= 0; index-- {
		entry := graph.entries[index]
		if err := deleteExact(entry.m, entry.key, entry.value, allowAbsent); err != nil {
			return fmt.Errorf("delete exact %s", entry.label)
		}
	}
	return nil
}

func observeNormalCleanup(ctx context.Context, graph generationGraph) error {
	deadline := time.Now().Add(cleanupObservation)
	for {
		present, absent, err := graphPresence(graph)
		if err != nil {
			return err
		}
		complete, err := cleanupObservationResult(present, absent, time.Now().After(deadline))
		if err != nil {
			return err
		}
		if complete {
			return nil
		}
		if err := waitPoll(ctx); err != nil {
			return errors.New("timed out observing normal phase A cleanup")
		}
	}
}

func cleanupObservationResult(allPresent, allAbsent, deadlinePassed bool) (bool, error) {
	if allAbsent {
		return true, nil
	}
	if !deadlinePassed {
		return false, nil
	}
	if allPresent {
		return false, errors.New("normal phase A cleanup did not remove the graph within a production sweep cadence")
	}
	return false, errors.New("normal phase A cleanup left a partial graph")
}

func graphPresence(graph generationGraph) (allPresent, allAbsent bool, err error) {
	present := 0
	for _, entry := range graph.entries {
		value, exists, lookupErr := lookupOptional(entry.m, entry.key)
		if lookupErr != nil {
			return false, false, errors.New("inspect generation graph")
		}
		if exists {
			if !bytes.Equal(value, entry.value) {
				return false, false, fmt.Errorf("%s changed during cleanup", entry.label)
			}
			present++
		}
	}
	return present == len(graph.entries), present == 0, nil
}

func splitGraph(graph generationGraph) (generationGraph, generationGraph) {
	persistent := generationGraph{}
	ephemeral := generationGraph{}
	for _, entry := range graph.entries {
		if entry.label == "data signal" || entry.label == "data acknowledgement" {
			ephemeral.entries = append(ephemeral.entries, entry)
		} else {
			persistent.entries = append(persistent.entries, entry)
		}
	}
	return persistent, ephemeral
}

func requireGraphAbsent(graph generationGraph) error {
	for _, entry := range graph.entries {
		_, present, err := lookupOptional(entry.m, entry.key)
		if err != nil || present {
			return fmt.Errorf("%s remains present", entry.label)
		}
	}
	return nil
}

func waitGraphAbsent(ctx context.Context, graph generationGraph) error {
	for {
		_, absent, err := graphPresence(graph)
		if err != nil {
			return err
		}
		if absent {
			return nil
		}
		if err := waitPoll(ctx); err != nil {
			return errors.New("timed out waiting for graph consumption")
		}
	}
}

func processClaim(processKey []byte, capability uint64) []byte {
	claim := make([]byte, 24)
	copy(claim[0:12], processKey)
	// Match a BPF-published claim.  A tagged userspace cleanup claim would be
	// eligible for production recovery and could disappear while this fixture
	// is installing the deliberately stale generation graph.
	binary.LittleEndian.PutUint64(claim[16:24], capability)
	return claim
}

func acquireProcessClaim(ctx context.Context, claims *ebpf.Map, key, value []byte) error {
	for {
		err := claims.Update(key, value, ebpf.UpdateNoExist)
		if err == nil {
			observed, present, lookupErr := lookupOptional(claims, key)
			if lookupErr != nil || !present || !bytes.Equal(observed, value) {
				return errors.New("revalidate PID reuse process claim")
			}
			return nil
		}
		if !errors.Is(err, ebpf.ErrKeyExist) {
			return errors.New("acquire PID reuse process claim")
		}
		if err := waitPoll(ctx); err != nil {
			return errors.New("timed out acquiring PID reuse process claim")
		}
	}
}

func lookupOptional(target *ebpf.Map, key []byte) ([]byte, bool, error) {
	var value []byte
	err := target.Lookup(key, &value)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

func deleteExact(target *ebpf.Map, key, expected []byte, allowAbsent bool) error {
	current, present, err := lookupOptional(target, key)
	if err != nil {
		return err
	}
	if !present {
		if allowAbsent {
			return nil
		}
		return errors.New("exact map entry is absent")
	}
	if !bytes.Equal(current, expected) {
		return errors.New("exact map entry changed")
	}
	if err := target.Delete(key); err != nil {
		return err
	}
	_, present, err = lookupOptional(target, key)
	if err != nil || present {
		return errors.New("exact map entry deletion was not retained")
	}
	return nil
}

func restoreExact(target *ebpf.Map, key, value []byte) error {
	if err := target.Update(key, value, ebpf.UpdateNoExist); err != nil {
		current, present, lookupErr := lookupOptional(target, key)
		if lookupErr == nil && present && bytes.Equal(current, value) {
			return nil
		}
		return err
	}
	return nil
}

func processKey(identity privateIdentity) []byte {
	key := make([]byte, 12)
	binary.LittleEndian.PutUint32(key[0:4], identity.tid)
	binary.LittleEndian.PutUint32(key[4:8], identity.pid)
	binary.LittleEndian.PutUint32(key[8:12], identity.pidNamespaceInode)
	return key
}

func retiredKey(process []byte, capability uint64) []byte {
	key := make([]byte, 24)
	copy(key[0:12], process)
	binary.LittleEndian.PutUint64(key[16:24], capability)
	return key
}

func u64Bytes(value uint64) []byte {
	encoded := make([]byte, 8)
	binary.LittleEndian.PutUint64(encoded, value)
	return encoded
}

func readPrivateFile(path string, minimum, maximum int64) ([]byte, bool, error) {
	descriptor, err := syscall.Open(
		path,
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0,
	)
	if errors.Is(err, syscall.ENOENT) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, errors.New("open private PID reuse control file")
	}
	file := os.NewFile(uintptr(descriptor), path)
	defer file.Close()
	var metadata syscall.Stat_t
	if err := syscall.Fstat(descriptor, &metadata); err != nil {
		return nil, false, errors.New("inspect private PID reuse control file")
	}
	if metadata.Nlink != 1 {
		// Atomic hard-link publication briefly exposes two names. Do not accept
		// that intermediate state, but allow the bounded caller to retry it.
		return nil, false, nil
	}
	if metadata.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		metadata.Mode&0o7777 != controlFileMode || metadata.Uid != 0 ||
		metadata.Size < minimum || metadata.Size > maximum {
		return nil, false, errors.New("PID reuse control file metadata is unsafe")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) != metadata.Size || int64(len(contents)) > maximum {
		return nil, false, errors.New("read bounded PID reuse control file")
	}
	return contents, true, nil
}

func waitExactFile(ctx context.Context, directory, name, expected string) error {
	for {
		contents, present, err := readPrivateFile(filepath.Join(directory, name), int64(len(expected)), int64(len(expected)))
		if err != nil {
			return err
		}
		if present {
			if string(contents) != expected {
				return errors.New("PID reuse control file has unexpected contents")
			}
			return nil
		}
		if err := waitPoll(ctx); err != nil {
			return errors.New("timed out waiting for PID reuse control file")
		}
	}
}

func publishControlFile(directory, name, contents string) error {
	if strings.Contains(name, "/") || name == "" || len(contents) == 0 || len(contents) > maximumControlBytes {
		return errors.New("invalid PID reuse control publication")
	}
	temporary := filepath.Join(directory, ".controller-tmp-"+strconv.Itoa(os.Getpid())+"-"+name)
	destination := filepath.Join(directory, name)
	descriptor, err := syscall.Open(
		temporary,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		controlFileMode,
	)
	if err != nil {
		return errors.New("create PID reuse control temporary file")
	}
	file := os.NewFile(uintptr(descriptor), temporary)
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := io.WriteString(file, contents); err != nil {
		file.Close()
		return errors.New("write PID reuse control file")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return errors.New("sync PID reuse control file")
	}
	if err := file.Close(); err != nil {
		return errors.New("close PID reuse control file")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, temporary, unix.AT_FDCWD, destination, unix.RENAME_NOREPLACE); err != nil {
		return errors.New("publish PID reuse control file")
	}
	removeTemporary = false
	return nil
}

func removePrivateFile(directory, name string) error {
	path := filepath.Join(directory, name)
	if _, present, err := readPrivateFile(path, 1, maximumControlBytes); err != nil || !present {
		return errors.New("private PID reuse artifact is absent or unsafe")
	}
	if err := os.Remove(path); err != nil {
		return errors.New("remove private PID reuse artifact")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("private PID reuse artifact removal was not retained")
	}
	return nil
}

func waitPoll(ctx context.Context) error {
	timer := time.NewTimer(pollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func closeMap(candidate *ebpf.Map) {
	if candidate != nil {
		candidate.Close()
	}
}
