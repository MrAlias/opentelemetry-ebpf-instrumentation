// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/javabridge"
)

const (
	javaRemoteParentPackagedJVMBenchmarkEnv                     = "OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK"
	javaRemoteParentPackagedJVMBenchmarkArtifactEnv             = "OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_ARTIFACT"
	javaRemoteParentPackagedJVMBenchmarkValidateArtifactEnv     = "OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_ARTIFACT"
	javaRemoteParentPackagedJVMBenchmarkValidateCICrosslinksEnv = "OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_CI_CROSSLINKS"
	javaRemoteParentPackagedJVMBenchmarkValidateAgentEnv        = "OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_AGENT"
	javaRemoteParentPackagedJVMBenchmarkValidateTestBinaryEnv   = "OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_TEST_BINARY"
	javaRemoteParentPackagedJVMBenchmarkValidateRevisionEnv     = "OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_REVISION"
	javaRemoteParentPackagedJVMBenchmarkValidateKernelEnv       = "OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_KERNEL"
	javaRemoteParentPackagedJVMBenchmarkValidateJavaEnv         = "OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_JAVA"
	javaRemoteParentPackagedJVMBenchmarkValidateSockoptBPFEnv   = "OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_SOCKOPT_BPF"
	javaRemoteParentPackagedJVMBenchmarkValidateSockopsBPFEnv   = "OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_VALIDATE_SOCKOPS_BPF"
	javaRemoteParentPackagedJVMBenchmarkExclusiveCgroupBPFEnv   = "OBI_JAVA_REMOTE_PARENT_PACKAGED_JVM_BENCHMARK_EXCLUSIVE_CGROUP_BPF"
	packagedJVMBenchmarkArtifactSchemaVersion                   = 1
	packagedJVMBenchmarkArtifactName                            = "java_remote_parent_packaged_jvm_getsockopt"
	packagedJVMBenchmarkHarness                                 = "packaged_agent_java_jni_cgroup_getsockopt"
	packagedJVMBenchmarkWarmupIterations                        = 16
	packagedJVMBenchmarkMeasurementIterations                   = 256
	packagedJVMBenchmarkConcurrency                             = 1
	packagedJVMBenchmarkJavaID                                  = 65534
	packagedJVMBenchmarkP99LimitNS                              = int64(time.Millisecond)
	packagedJVMBenchmarkGateKind                                = "p99_lt"
	packagedJVMBenchmarkTimedCall                               = "System.nanoTime around BootstrapNative.takeRemoteParent(fd,reused_byte_array)"
	packagedJVMBenchmarkResponseStorage                         = "one reused 64-byte Java byte array"
	packagedJVMBenchmarkAgentOptions                            = "remoteParentTransport=disabled"
	packagedJVMBenchmarkProbeClass                              = "io.opentelemetry.obi.java.probe.RemoteParentGetsockoptBenchmarkProbe"
	packagedJVMBenchmarkMissControl                             = "assert exact negotiated process, incarnation, connection, namespace, and generation; delete only java_remote_parent_state; retain and exactly assert owner and generation index; preserve generation; restore state; run full cleanup"
	packagedJVMBenchmarkAgentBinding                            = "opened read-only fd 3; fstat and SHA-256 before and after execution"
	packagedJVMBenchmarkMaxArtifactBytes                        = 1 << 20
	packagedJVMBenchmarkEffectiveQueryFlag                      = "BPF_F_QUERY_EFFECTIVE"
	packagedJVMBenchmarkCgroupRoot                              = "/sys/fs/cgroup"
	packagedJVMBenchmarkRevisionAndIdentityMode                 = "revision_and_identity"
	packagedJVMBenchmarkBoundaryIdentityOnlyMode                = "boundary_identity_only"
	packagedJVMBenchmarkRevisionAndIdentityEvidence             = "exact boundary identities and supported direct revisions unchanged"
	packagedJVMBenchmarkBoundaryIdentityOnlyEvidence            = "exact boundary identities unchanged; attach-detach completed between queries cannot be excluded"
	packagedJVMBenchmarkExclusiveTopologyPremise                = "operator_controlled_no_concurrent_cgroup_bpf_mutation"
	packagedJVMBenchmarkRevisionPremiseNotRequired              = "not_required_all_direct_queries_revision_supported"
	packagedJVMBenchmarkExpectedCalls                           = 2 * (packagedJVMBenchmarkWarmupIterations + packagedJVMBenchmarkMeasurementIterations)
	packagedJVMBenchmarkArtifactV2SchemaVersion                 = 2
	packagedJVMBenchmarkArtifactV2Name                          = "java_remote_parent_packaged_jvm_transport"
	packagedJVMBenchmarkV2Harness                               = "packaged_agent_java_concurrent_transport"
	packagedJVMBenchmarkV2Concurrency                           = 8
	packagedJVMBenchmarkV2PrimaryP99LimitNS                     = int64(time.Millisecond)
	packagedJVMBenchmarkV2UnixP99LimitNS                        = int64(50 * time.Millisecond)
	packagedJVMBenchmarkV2TimeoutP50MinimumNS                   = int64(50 * time.Millisecond)
	packagedJVMBenchmarkV2TimeoutP99LimitNS                     = int64(100 * time.Millisecond)
	packagedJVMBenchmarkV2TimeoutMillis                         = 50
	packagedJVMBenchmarkV2MaxArtifactBytes                      = packagedJVMBenchmarkMaxArtifactBytes
	packagedJVMBenchmarkRetrievalTTL                            = 30 * time.Second
	packagedJVMBenchmarkStaleAge                                = 31 * time.Second
)

var packagedJVMBenchmarkV2SeriesSpecs = []packagedJVMBenchmarkV2SeriesSpec{
	{Scope: "raw_jni", Transport: "getsockopt", Outcome: "miss", ExpectedStatus: int(javabridge.StatusMissing)},
	{Scope: "raw_jni", Transport: "getsockopt", Outcome: "hit", ExpectedStatus: int(javabridge.StatusValid)},
	{Scope: "raw_jni", Transport: "getsockopt", Outcome: "stale", ExpectedStatus: int(javabridge.StatusStale)},
	{Scope: "bridge_provider_jni", Transport: "getsockopt", Outcome: "miss", ExpectedStatus: int(javabridge.StatusMissing)},
	{Scope: "bridge_provider_jni", Transport: "getsockopt", Outcome: "hit", ExpectedStatus: int(javabridge.StatusValid)},
	{Scope: "bridge_provider_jni", Transport: "getsockopt", Outcome: "stale", ExpectedStatus: int(javabridge.StatusStale)},
	{Scope: "raw_jni", Transport: "unix", Outcome: "miss", ExpectedStatus: int(javabridge.StatusMissing)},
	{Scope: "raw_jni", Transport: "unix", Outcome: "hit", ExpectedStatus: int(javabridge.StatusValid)},
	{Scope: "raw_jni", Transport: "unix", Outcome: "stale", ExpectedStatus: int(javabridge.StatusStale)},
	{Scope: "bridge_provider_jni", Transport: "unix", Outcome: "miss", ExpectedStatus: int(javabridge.StatusMissing)},
	{Scope: "bridge_provider_jni", Transport: "unix", Outcome: "hit", ExpectedStatus: int(javabridge.StatusValid)},
	{Scope: "bridge_provider_jni", Transport: "unix", Outcome: "stale", ExpectedStatus: int(javabridge.StatusStale)},
	{Scope: "raw_jni", Transport: "unix", Outcome: "timeout", ExpectedStatus: int(javabridge.StatusTimeout)},
	{Scope: "bridge_provider_jni", Transport: "unix", Outcome: "timeout", ExpectedStatus: int(javabridge.StatusTimeout)},
}

var expectedPackagedJVMBenchmarkV2Provenance = packagedJVMBenchmarkArtifactV2Provenance{
	Harness: packagedJVMBenchmarkV2Harness,
	Measures: []string{
		"packaged_agent", "java_workers", "raw_jni", "bridge_provider", "jni",
		"kernel_getsockopt", "cgroup_bpf", "unix_server", "thread_allocated_bytes",
	},
	Excludes: []string{
		"application_request", "instrumentation", "throughput", "application_throughput", "process_cpu",
		"rss_growth", "native_memory_growth", "direct_memory_growth", "fd_growth",
		"thread_growth", "map_growth", "run_to_run_variance", "native_sanitizers",
	},
}

var expectedPackagedJVMBenchmarkCgroupAttachTypes = []string{
	"CGroupGetsockopt",
	"CGroupSetsockopt",
	"CGroupSockOps",
}

var expectedPackagedJVMBenchmarkProvenance = packagedJVMBenchmarkArtifactProvenance{
	Harness: packagedJVMBenchmarkHarness,
	Measures: []string{
		"packaged_agent",
		"java_native_call",
		"jni",
		"kernel_getsockopt",
		"cgroup_bpf",
	},
	Excludes: []string{
		"application_request",
		"instrumentation",
		"provider_selection",
		"record_decode",
		"unix_transport",
		"throughput",
		"allocations",
		"resource_growth",
		"concurrency",
		"run_to_run_variance",
	},
}

var expectedPackagedJVMBenchmarkJVMArguments = []string{
	"-javaagent:<agent-artifact-fd>=remoteParentTransport=disabled",
	"-cp",
	"<agent-artifact-fd>",
	packagedJVMBenchmarkProbeClass,
}

var expectedPackagedJVMBenchmarkEnvironment = []string{
	"HOME=/nonexistent",
	"LANG=C",
	"LC_ALL=C",
	"PATH=/usr/bin:/bin",
	"TMPDIR=/tmp",
	"TZ=UTC",
}

var forbiddenPackagedJVMBenchmarkEnvironment = map[string]struct{}{
	"BASH_ENV":          {},
	"CLASSPATH":         {},
	"ENV":               {},
	"GLIBC_TUNABLES":    {},
	"JAVA_TOOL_OPTIONS": {},
	"JDK_JAVA_OPTIONS":  {},
	"LD_AUDIT":          {},
	"LD_DEBUG":          {},
	"LD_LIBRARY_PATH":   {},
	"LD_PRELOAD":        {},
	"LD_PROFILE":        {},
	"_JAVA_OPTIONS":     {},
}

type packagedJVMBenchmarkArtifact struct {
	SchemaVersion int                                    `json:"schema_version"`
	Benchmark     string                                 `json:"benchmark"`
	CreatedAt     string                                 `json:"created_at"`
	Provenance    packagedJVMBenchmarkArtifactProvenance `json:"provenance"`
	Source        packagedJVMBenchmarkArtifactSource     `json:"source"`
	Inputs        packagedJVMBenchmarkArtifactInputs     `json:"inputs"`
	Runtime       packagedJVMBenchmarkArtifactRuntime    `json:"runtime"`
	Setup         packagedJVMBenchmarkArtifactSetup      `json:"setup"`
	Series        []packagedJVMBenchmarkArtifactSeries   `json:"series"`
}

type packagedJVMBenchmarkArtifactSource struct {
	Revision     string `json:"revision"`
	Dirty        bool   `json:"dirty"`
	StatusSHA256 string `json:"status_sha256"`
	PatchSHA256  string `json:"patch_sha256"`
}

type packagedJVMBenchmarkArtifactInputs struct {
	GoToolchain   string                                   `json:"go_toolchain"`
	TestBinary    packagedJVMBenchmarkArtifactFileIdentity `json:"test_binary"`
	AgentArtifact packagedJVMBenchmarkArtifactFileIdentity `json:"agent_artifact"`
	SockoptBPF    packagedJVMBenchmarkArtifactBlobIdentity `json:"sockopt_bpf"`
	SockopsBPF    packagedJVMBenchmarkArtifactBlobIdentity `json:"sockops_bpf"`
}

type packagedJVMBenchmarkArtifactFileIdentity struct {
	SHA256 string `json:"sha256"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Size   int64  `json:"size"`
}

type packagedJVMBenchmarkArtifactBlobIdentity struct {
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

type packagedJVMBenchmarkArtifactCICrosslinks struct {
	Revision           string
	KernelRelease      string
	JavaExecutable     string
	AgentArtifact      packagedJVMBenchmarkArtifactFileIdentity
	TestBinary         packagedJVMBenchmarkArtifactFileIdentity
	SockoptBPFArtifact packagedJVMBenchmarkArtifactBlobIdentity
	SockopsBPFArtifact packagedJVMBenchmarkArtifactBlobIdentity
}

type packagedJVMBenchmarkSourceOwner struct {
	UID uint32
	GID uint32
}

type packagedJVMBenchmarkNegotiationAuthority struct {
	Process            BpfJavaRemoteParentPidKeyT
	ProcessIncarnation uint64
	Connection         BpfJavaRemoteParentConnectionInfoT
	ConnectionNetns    uint32
	Generation         uint64
}

type packagedJVMBenchmarkCgroupBPFSnapshot struct {
	TargetCgroup        string
	CgroupHierarchy     []string
	EffectiveQueryFlags uint32
	Chains              []packagedJVMBenchmarkCgroupBPFChainSnapshot
}

type packagedJVMBenchmarkCgroupBPFChainSnapshot struct {
	AttachType                 string
	EffectiveRevisionSupported bool
	EffectiveRevision          uint64
	EffectivePrograms          []packagedJVMBenchmarkArtifactBPFProgram
	Topology                   []packagedJVMBenchmarkArtifactCgroupTopology
}

type packagedJVMBenchmarkIntendedCgroupBPFProgram struct {
	AttachType string
	Program    packagedJVMBenchmarkArtifactBPFProgram
}

type packagedJVMBenchmarkArtifactProvenance struct {
	Harness   string                                `json:"harness"`
	Measures  []string                              `json:"measures"`
	Excludes  []string                              `json:"excludes"`
	CgroupBPF packagedJVMBenchmarkArtifactCgroupBPF `json:"cgroup_bpf"`
}

type packagedJVMBenchmarkArtifactCgroupBPF struct {
	TargetCgroup             string                                      `json:"target_cgroup"`
	CgroupHierarchy          []string                                    `json:"cgroup_hierarchy"`
	EffectiveQueryFlag       string                                      `json:"effective_query_flag"`
	EffectiveQueryFlags      uint32                                      `json:"effective_query_flags"`
	PreAttachChainsEmpty     bool                                        `json:"pre_attach_chains_empty"`
	StabilityMode            string                                      `json:"stability_mode"`
	StabilityEvidence        string                                      `json:"stability_evidence"`
	ExclusiveTopologyPremise string                                      `json:"exclusive_topology_premise"`
	StabilityChecks          packagedJVMBenchmarkArtifactStabilityChecks `json:"stability_checks"`
	Chains                   []packagedJVMBenchmarkArtifactCgroupChain   `json:"chains"`
}

type packagedJVMBenchmarkArtifactStabilityChecks struct {
	ExpectedCalls             int `json:"expected_calls"`
	ObservedPreCallSnapshots  int `json:"observed_pre_call_snapshots"`
	ObservedPostCallSnapshots int `json:"observed_post_call_snapshots"`
	QueryErrors               int `json:"query_errors"`
	TopologyMismatches        int `json:"topology_mismatches"`
}

type packagedJVMBenchmarkCgroupBPFStabilityTracker struct {
	checks packagedJVMBenchmarkArtifactStabilityChecks
}

type packagedJVMBenchmarkProbeResult struct {
	line string
	err  error
	eof  bool
}

type packagedJVMBenchmarkArtifactCgroupChain struct {
	AttachType                 string                                       `json:"attach_type"`
	IntendedProgram            packagedJVMBenchmarkArtifactBPFProgram       `json:"intended_program"`
	EffectiveRevisionSupported bool                                         `json:"effective_revision_supported"`
	EffectiveRevision          uint64                                       `json:"effective_revision"`
	EffectivePrograms          []packagedJVMBenchmarkArtifactBPFProgram     `json:"effective_programs"`
	Topology                   []packagedJVMBenchmarkArtifactCgroupTopology `json:"topology"`
}

type packagedJVMBenchmarkArtifactCgroupTopology struct {
	CgroupPath              string                                   `json:"cgroup_path"`
	DirectRevisionSupported bool                                     `json:"direct_revision_supported"`
	DirectRevision          uint64                                   `json:"direct_revision"`
	DirectPrograms          []packagedJVMBenchmarkArtifactBPFProgram `json:"direct_programs"`
}

type packagedJVMBenchmarkArtifactBPFProgram struct {
	ID          uint32 `json:"id"`
	Tag         string `json:"tag"`
	Name        string `json:"name"`
	ProgramType string `json:"program_type"`
}

type packagedJVMBenchmarkArtifactRuntime struct {
	JavaExecutable   string `json:"java_executable"`
	JavaVersion      string `json:"java_version"`
	KernelRelease    string `json:"kernel_release"`
	Architecture     string `json:"architecture"`
	CPUModel         string `json:"cpu_model"`
	LogicalCPUs      int    `json:"logical_cpus"`
	MemoryTotalBytes uint64 `json:"memory_total_bytes"`
	CgroupMode       string `json:"cgroup_mode"`
	CgroupPath       string `json:"cgroup_path"`
	JavaUID          int    `json:"java_uid"`
	JavaGID          int    `json:"java_gid"`
	JavaCapabilities string `json:"java_capabilities"`
	NoNewPrivileges  bool   `json:"no_new_privileges"`
	BPFDescriptors   int    `json:"bpf_descriptors"`
}

type packagedJVMBenchmarkArtifactSetup struct {
	WarmupIterations      int      `json:"warmup_iterations"`
	MeasurementIterations int      `json:"measurement_iterations"`
	Concurrency           int      `json:"concurrency"`
	TimedCall             string   `json:"timed_call"`
	ResponseStorage       string   `json:"response_storage"`
	AgentOptions          string   `json:"agent_options"`
	MissControl           string   `json:"miss_control"`
	AgentArtifactBinding  string   `json:"agent_artifact_binding"`
	JVMArguments          []string `json:"jvm_arguments"`
	Environment           []string `json:"environment"`
}

type packagedJVMBenchmarkArtifactSeries struct {
	Outcome        string                              `json:"outcome"`
	ExpectedStatus int                                 `json:"expected_status"`
	SamplesNS      []int64                             `json:"samples_ns"`
	TotalTimedNS   int64                               `json:"total_timed_ns"`
	P50NS          int64                               `json:"p50_ns"`
	P95NS          int64                               `json:"p95_ns"`
	P99NS          int64                               `json:"p99_ns"`
	Valid          int                                 `json:"valid"`
	Missing        int                                 `json:"missing"`
	Errors         int                                 `json:"errors"`
	Correct        bool                                `json:"correct"`
	LatencyGate    packagedJVMBenchmarkArtifactLatency `json:"latency_gate"`
}

type packagedJVMBenchmarkArtifactLatency struct {
	Kind     string `json:"kind"`
	P99MaxNS int64  `json:"p99_max_ns"`
	Passed   bool   `json:"passed"`
}

// Schema v2 is additive to the retained schema-v1 contract above. It gives concurrency,
// transport, provider, allocation, and exact call accounting their own identities instead of
// changing the meaning of the single-thread getsockopt fields.
type packagedJVMBenchmarkArtifactV2 struct {
	SchemaVersion int                                      `json:"schema_version"`
	Benchmark     string                                   `json:"benchmark"`
	CreatedAt     string                                   `json:"created_at"`
	Provenance    packagedJVMBenchmarkArtifactV2Provenance `json:"provenance"`
	Source        packagedJVMBenchmarkArtifactSource       `json:"source"`
	Inputs        packagedJVMBenchmarkArtifactInputs       `json:"inputs"`
	Runtime       packagedJVMBenchmarkArtifactRuntime      `json:"runtime"`
	Setup         packagedJVMBenchmarkArtifactV2Setup      `json:"setup"`
	Series        []packagedJVMBenchmarkArtifactV2Series   `json:"series"`
}

type packagedJVMBenchmarkArtifactV2Provenance struct {
	Harness   string                                       `json:"harness"`
	Measures  []string                                     `json:"measures"`
	Excludes  []string                                     `json:"excludes"`
	CgroupBPF packagedJVMBenchmarkArtifactV2CgroupBPF      `json:"cgroup_bpf"`
	Unix      packagedJVMBenchmarkArtifactV2UnixProvenance `json:"unix"`
}

type packagedJVMBenchmarkArtifactV2UnixProvenance struct {
	Server             string `json:"server"`
	Handler            string `json:"handler"`
	Observer           string `json:"observer"`
	TimeoutFixture     string `json:"timeout_fixture"`
	SocketPathRetained bool   `json:"socket_path_retained"`
}

type packagedJVMBenchmarkArtifactV2CgroupBPF struct {
	TargetCgroup             string                                    `json:"target_cgroup"`
	CgroupHierarchy          []string                                  `json:"cgroup_hierarchy"`
	EffectiveQueryFlag       string                                    `json:"effective_query_flag"`
	EffectiveQueryFlags      uint32                                    `json:"effective_query_flags"`
	PreAttachChainsEmpty     bool                                      `json:"pre_attach_chains_empty"`
	StabilityMode            string                                    `json:"stability_mode"`
	StabilityEvidence        string                                    `json:"stability_evidence"`
	ExclusiveTopologyPremise string                                    `json:"exclusive_topology_premise"`
	StabilityChecks          packagedJVMBenchmarkArtifactV2Stability   `json:"stability_checks"`
	Chains                   []packagedJVMBenchmarkArtifactCgroupChain `json:"chains"`
}

type packagedJVMBenchmarkArtifactV2Stability struct {
	ExpectedBatches            int `json:"expected_batches"`
	ExpectedPrimaryCalls       int `json:"expected_primary_calls"`
	ObservedPreBatchSnapshots  int `json:"observed_pre_batch_snapshots"`
	ObservedPostBatchSnapshots int `json:"observed_post_batch_snapshots"`
	QueryErrors                int `json:"query_errors"`
	TopologyMismatches         int `json:"topology_mismatches"`
}

type packagedJVMBenchmarkArtifactV2Setup struct {
	WarmupBatches          int      `json:"warmup_batches"`
	MeasurementBatches     int      `json:"measurement_batches"`
	Concurrency            int      `json:"concurrency"`
	RetainedCallsPerSeries int      `json:"retained_calls_per_series"`
	TotalCallsPerSeries    int      `json:"total_calls_per_series"`
	BatchSynchronization   string   `json:"batch_synchronization"`
	RawTimedCall           string   `json:"raw_timed_call"`
	ProviderTimedCall      string   `json:"provider_timed_call"`
	ResponseStorage        string   `json:"response_storage"`
	AllocationMeasurement  string   `json:"allocation_measurement"`
	AllocationControl      string   `json:"allocation_control"`
	AgentOptions           string   `json:"agent_options"`
	PrimaryMissControl     string   `json:"primary_miss_control"`
	UnixMissControl        string   `json:"unix_miss_control"`
	UnixTimeoutDeadlineNS  int64    `json:"unix_timeout_deadline_ns"`
	RetrievalTTLNS         int64    `json:"retrieval_ttl_ns"`
	StaleAgeNS             int64    `json:"stale_age_ns"`
	UnixServerUID          int      `json:"unix_server_uid"`
	UnixSocketGID          int      `json:"unix_socket_gid"`
	UnixMaxConcurrent      int      `json:"unix_max_concurrent"`
	AgentArtifactBinding   string   `json:"agent_artifact_binding"`
	JVMArguments           []string `json:"jvm_arguments"`
	Environment            []string `json:"environment"`
}

type packagedJVMBenchmarkV2SeriesSpec struct {
	Scope          string
	Transport      string
	Outcome        string
	ExpectedStatus int
}

type packagedJVMBenchmarkV2SeriesObservation struct {
	Spec                   packagedJVMBenchmarkV2SeriesSpec
	SamplesNS              []int64
	AllocatedBytes         []int64
	AllocationControlBytes []int64
	Statuses               packagedJVMBenchmarkArtifactV2Statuses
	Calls                  packagedJVMBenchmarkArtifactV2Calls
}

type packagedJVMBenchmarkArtifactV2Series struct {
	Scope          string                                   `json:"scope"`
	Transport      string                                   `json:"transport"`
	Outcome        string                                   `json:"outcome"`
	ExpectedStatus int                                      `json:"expected_status"`
	SamplesNS      []int64                                  `json:"samples_ns"`
	TotalTimedNS   int64                                    `json:"total_timed_ns"`
	P50NS          int64                                    `json:"p50_ns"`
	P95NS          int64                                    `json:"p95_ns"`
	P99NS          int64                                    `json:"p99_ns"`
	Statuses       packagedJVMBenchmarkArtifactV2Statuses   `json:"status_counts"`
	Calls          packagedJVMBenchmarkArtifactV2Calls      `json:"call_counts"`
	Allocation     packagedJVMBenchmarkArtifactV2Allocation `json:"allocation"`
	Correct        bool                                     `json:"correct"`
	LatencyGate    packagedJVMBenchmarkArtifactV2Latency    `json:"latency_gate"`
}

type packagedJVMBenchmarkArtifactV2Statuses struct {
	Unknown         int `json:"unknown"`
	Valid           int `json:"valid"`
	Missing         int `json:"missing"`
	Stale           int `json:"stale"`
	Unsupported     int `json:"unsupported"`
	Malformed       int `json:"malformed"`
	VersionMismatch int `json:"version_mismatch"`
	Ambiguous       int `json:"ambiguous"`
	Unauthorized    int `json:"unauthorized"`
	AlreadyConsumed int `json:"already_consumed"`
	Timeout         int `json:"timeout"`
	Overload        int `json:"overload"`
	TransportError  int `json:"transport_error"`
	Disabled        int `json:"disabled"`
}

type packagedJVMBenchmarkArtifactV2Calls struct {
	ExpectedJavaCalls           int    `json:"expected_java_calls"`
	ObservedJavaCalls           int    `json:"observed_java_calls"`
	ExpectedNativeCalls         int    `json:"expected_native_calls"`
	ObservedNativeCalls         int    `json:"observed_native_calls"`
	ExpectedBridgeCalls         int    `json:"expected_bridge_calls"`
	ObservedBridgeCalls         int    `json:"observed_bridge_calls"`
	ExpectedPrimaryBPFCalls     int    `json:"expected_primary_bpf_calls"`
	ObservedPrimaryBPFCalls     int    `json:"observed_primary_bpf_calls"`
	PrimaryBPFStatus            string `json:"primary_bpf_status"`
	PrimaryBPFStatusBefore      uint64 `json:"primary_bpf_status_before"`
	PrimaryBPFStatusAfter       uint64 `json:"primary_bpf_status_after"`
	ExpectedUnixServerRequests  int    `json:"expected_unix_server_requests"`
	ObservedUnixServerRequests  int    `json:"observed_unix_server_requests"`
	UnixServerStatus            string `json:"unix_server_status"`
	UnixServerStatusBefore      uint64 `json:"unix_server_status_before"`
	UnixServerStatusAfter       uint64 `json:"unix_server_status_after"`
	ExpectedTimeoutFullRequests int    `json:"expected_timeout_full_requests"`
	ObservedTimeoutFullRequests int    `json:"observed_timeout_full_requests"`
}

type packagedJVMBenchmarkArtifactV2Allocation struct {
	Method              string  `json:"method"`
	Control             string  `json:"control"`
	SamplesBytes        []int64 `json:"samples_bytes"`
	ControlSamplesBytes []int64 `json:"control_samples_bytes"`
	TotalBytes          int64   `json:"total_bytes"`
	P50Bytes            int64   `json:"p50_bytes"`
	P95Bytes            int64   `json:"p95_bytes"`
	P99Bytes            int64   `json:"p99_bytes"`
	ControlTotalBytes   int64   `json:"control_total_bytes"`
	ControlP50Bytes     int64   `json:"control_p50_bytes"`
	ControlP95Bytes     int64   `json:"control_p95_bytes"`
	ControlP99Bytes     int64   `json:"control_p99_bytes"`
}

type packagedJVMBenchmarkArtifactV2Latency struct {
	Kind     string `json:"kind"`
	P50MinNS int64  `json:"p50_min_ns"`
	P99MaxNS int64  `json:"p99_max_ns"`
	Passed   bool   `json:"passed"`
}

func newPackagedJVMBenchmarkArtifact(
	createdAt time.Time,
	source packagedJVMBenchmarkArtifactSource,
	inputs packagedJVMBenchmarkArtifactInputs,
	cgroupBPF packagedJVMBenchmarkArtifactCgroupBPF,
	runtime packagedJVMBenchmarkArtifactRuntime,
	missSamples []int64,
	hitSamples []int64,
) packagedJVMBenchmarkArtifact {
	return packagedJVMBenchmarkArtifact{
		SchemaVersion: packagedJVMBenchmarkArtifactSchemaVersion,
		Benchmark:     packagedJVMBenchmarkArtifactName,
		CreatedAt:     createdAt.UTC().Format(time.RFC3339Nano),
		Provenance: packagedJVMBenchmarkArtifactProvenance{
			Harness:   expectedPackagedJVMBenchmarkProvenance.Harness,
			Measures:  slices.Clone(expectedPackagedJVMBenchmarkProvenance.Measures),
			Excludes:  slices.Clone(expectedPackagedJVMBenchmarkProvenance.Excludes),
			CgroupBPF: cgroupBPF,
		},
		Source:  source,
		Inputs:  inputs,
		Runtime: runtime,
		Setup: packagedJVMBenchmarkArtifactSetup{
			WarmupIterations:      packagedJVMBenchmarkWarmupIterations,
			MeasurementIterations: packagedJVMBenchmarkMeasurementIterations,
			Concurrency:           packagedJVMBenchmarkConcurrency,
			TimedCall:             packagedJVMBenchmarkTimedCall,
			ResponseStorage:       packagedJVMBenchmarkResponseStorage,
			AgentOptions:          packagedJVMBenchmarkAgentOptions,
			MissControl:           packagedJVMBenchmarkMissControl,
			AgentArtifactBinding:  packagedJVMBenchmarkAgentBinding,
			JVMArguments:          slices.Clone(expectedPackagedJVMBenchmarkJVMArguments),
			Environment:           slices.Clone(expectedPackagedJVMBenchmarkEnvironment),
		},
		Series: []packagedJVMBenchmarkArtifactSeries{
			summarizePackagedJVMBenchmarkSeries("miss", int(javabridge.StatusMissing), missSamples),
			summarizePackagedJVMBenchmarkSeries("hit", int(javabridge.StatusValid), hitSamples),
		},
	}
}

func summarizePackagedJVMBenchmarkSeries(
	outcome string,
	expectedStatus int,
	samples []int64,
) packagedJVMBenchmarkArtifactSeries {
	series := packagedJVMBenchmarkArtifactSeries{
		Outcome:        outcome,
		ExpectedStatus: expectedStatus,
		SamplesNS:      slices.Clone(samples),
		Correct:        true,
		LatencyGate: packagedJVMBenchmarkArtifactLatency{
			Kind:     packagedJVMBenchmarkGateKind,
			P99MaxNS: packagedJVMBenchmarkP99LimitNS,
		},
	}
	for _, sample := range samples {
		series.TotalTimedNS += sample
	}
	if len(samples) > 0 {
		sortedSamples := slices.Clone(samples)
		sort.Slice(sortedSamples, func(i, j int) bool { return sortedSamples[i] < sortedSamples[j] })
		series.P50NS = packagedJVMBenchmarkPercentile(sortedSamples, 50)
		series.P95NS = packagedJVMBenchmarkPercentile(sortedSamples, 95)
		series.P99NS = packagedJVMBenchmarkPercentile(sortedSamples, 99)
		series.LatencyGate.Passed = series.P99NS < series.LatencyGate.P99MaxNS
	}
	if expectedStatus == int(javabridge.StatusValid) {
		series.Valid = len(samples)
	} else if expectedStatus == int(javabridge.StatusMissing) {
		series.Missing = len(samples)
	}
	return series
}

func packagedJVMBenchmarkPercentile(sortedSamples []int64, percentage int) int64 {
	rank := (len(sortedSamples)*percentage + 99) / 100
	return sortedSamples[rank-1]
}

func newPackagedJVMBenchmarkArtifactV2(
	createdAt time.Time,
	source packagedJVMBenchmarkArtifactSource,
	inputs packagedJVMBenchmarkArtifactInputs,
	cgroupBPF packagedJVMBenchmarkArtifactCgroupBPF,
	runtimeIdentity packagedJVMBenchmarkArtifactRuntime,
	observations []packagedJVMBenchmarkV2SeriesObservation,
) packagedJVMBenchmarkArtifactV2 {
	series := make([]packagedJVMBenchmarkArtifactV2Series, len(observations))
	for index := range observations {
		series[index] = summarizePackagedJVMBenchmarkSeriesV2(observations[index])
	}
	totalBatches := len(packagedJVMBenchmarkV2SeriesSpecs) *
		(packagedJVMBenchmarkWarmupIterations + packagedJVMBenchmarkMeasurementIterations)
	totalCalls := packagedJVMBenchmarkV2Concurrency *
		(packagedJVMBenchmarkWarmupIterations + packagedJVMBenchmarkMeasurementIterations)
	primarySeries := 0
	for _, spec := range packagedJVMBenchmarkV2SeriesSpecs {
		if spec.Transport == "getsockopt" {
			primarySeries++
		}
	}
	return packagedJVMBenchmarkArtifactV2{
		SchemaVersion: packagedJVMBenchmarkArtifactV2SchemaVersion,
		Benchmark:     packagedJVMBenchmarkArtifactV2Name,
		CreatedAt:     createdAt.UTC().Format(time.RFC3339Nano),
		Provenance: packagedJVMBenchmarkArtifactV2Provenance{
			Harness:  expectedPackagedJVMBenchmarkV2Provenance.Harness,
			Measures: slices.Clone(expectedPackagedJVMBenchmarkV2Provenance.Measures),
			Excludes: slices.Clone(expectedPackagedJVMBenchmarkV2Provenance.Excludes),
			CgroupBPF: packagedJVMBenchmarkArtifactV2CgroupBPF{
				TargetCgroup:             cgroupBPF.TargetCgroup,
				CgroupHierarchy:          slices.Clone(cgroupBPF.CgroupHierarchy),
				EffectiveQueryFlag:       cgroupBPF.EffectiveQueryFlag,
				EffectiveQueryFlags:      cgroupBPF.EffectiveQueryFlags,
				PreAttachChainsEmpty:     cgroupBPF.PreAttachChainsEmpty,
				StabilityMode:            cgroupBPF.StabilityMode,
				StabilityEvidence:        cgroupBPF.StabilityEvidence,
				ExclusiveTopologyPremise: cgroupBPF.ExclusiveTopologyPremise,
				StabilityChecks: packagedJVMBenchmarkArtifactV2Stability{
					ExpectedBatches:            totalBatches,
					ExpectedPrimaryCalls:       primarySeries * totalCalls,
					ObservedPreBatchSnapshots:  cgroupBPF.StabilityChecks.ObservedPreCallSnapshots,
					ObservedPostBatchSnapshots: cgroupBPF.StabilityChecks.ObservedPostCallSnapshots,
					QueryErrors:                cgroupBPF.StabilityChecks.QueryErrors,
					TopologyMismatches:         cgroupBPF.StabilityChecks.TopologyMismatches,
				},
				Chains: slices.Clone(cgroupBPF.Chains),
			},
			Unix: packagedJVMBenchmarkArtifactV2UnixProvenance{
				Server:             "javabridge.NewServer production authenticated Unix server",
				Handler:            "javabridge.NewMapHandler over the benchmark BPF maps",
				Observer:           "ServerOptions.Observe exact operation/status counter",
				TimeoutFixture:     "production Unix server handler waits for the request deadline and returns TIMEOUT after a complete authenticated request",
				SocketPathRetained: false,
			},
		},
		Source:  source,
		Inputs:  inputs,
		Runtime: runtimeIdentity,
		Setup: packagedJVMBenchmarkArtifactV2Setup{
			WarmupBatches:          packagedJVMBenchmarkWarmupIterations,
			MeasurementBatches:     packagedJVMBenchmarkMeasurementIterations,
			Concurrency:            packagedJVMBenchmarkV2Concurrency,
			RetainedCallsPerSeries: packagedJVMBenchmarkV2Concurrency * packagedJVMBenchmarkMeasurementIterations,
			TotalCallsPerSeries:    totalCalls,
			BatchSynchronization:   "eight fixed worker threads stage authority, rendezvous, then share one release latch",
			RawTimedCall:           "System.nanoTime and ThreadMXBean around BootstrapNative.takeRemoteParent(fd-or-minus-one,reused_byte_array)",
			ProviderTimedCall:      "System.nanoTime and ThreadMXBean around RemoteParentBridge.takeRemoteParent()",
			ResponseStorage:        "one reused 64-byte JNI response array per worker; provider uses its packaged pool",
			AllocationMeasurement:  "com.sun.management.ThreadMXBean.getThreadAllocatedBytes keyed by the calling worker Java Thread.getId before and after the timed call",
			AllocationControl:      "paired same-worker consecutive ThreadMXBean counter reads immediately before each call; retained separately without net-allocation claim",
			AgentOptions:           packagedJVMBenchmarkAgentOptions,
			PrimaryMissControl:     packagedJVMBenchmarkMissControl,
			UnixMissControl:        "no staged owner generation for the exact authenticated worker TID; production MapHandler returns missing",
			UnixTimeoutDeadlineNS:  int64(packagedJVMBenchmarkV2TimeoutMillis * time.Millisecond),
			RetrievalTTLNS:         packagedJVMBenchmarkRetrievalTTL.Nanoseconds(),
			StaleAgeNS:             packagedJVMBenchmarkStaleAge.Nanoseconds(),
			UnixServerUID:          0,
			UnixSocketGID:          packagedJVMBenchmarkJavaID,
			UnixMaxConcurrent:      packagedJVMBenchmarkV2Concurrency * 4,
			AgentArtifactBinding:   packagedJVMBenchmarkAgentBinding,
			JVMArguments: []string{
				"-javaagent:<agent-artifact-fd>=remoteParentTransport=disabled", "-cp",
				"<agent-artifact-fd>", packagedJVMBenchmarkProbeClass,
				"<host> <process-capability> <warmup-batches> <measurement-batches> <workers>",
			},
			Environment: slices.Clone(expectedPackagedJVMBenchmarkEnvironment),
		},
		Series: series,
	}
}

func summarizePackagedJVMBenchmarkSeriesV2(
	observation packagedJVMBenchmarkV2SeriesObservation,
) packagedJVMBenchmarkArtifactV2Series {
	samples := slices.Clone(observation.SamplesNS)
	allocated := slices.Clone(observation.AllocatedBytes)
	controls := slices.Clone(observation.AllocationControlBytes)
	series := packagedJVMBenchmarkArtifactV2Series{
		Scope:          observation.Spec.Scope,
		Transport:      observation.Spec.Transport,
		Outcome:        observation.Spec.Outcome,
		ExpectedStatus: observation.Spec.ExpectedStatus,
		SamplesNS:      samples,
		Statuses:       observation.Statuses,
		Calls:          observation.Calls,
		Correct:        true,
		Allocation: packagedJVMBenchmarkArtifactV2Allocation{
			Method:              "com.sun.management.ThreadMXBean.getThreadAllocatedBytes",
			Control:             "paired consecutive counter reads on the same worker",
			SamplesBytes:        allocated,
			ControlSamplesBytes: controls,
		},
	}
	series.TotalTimedNS, series.P50NS, series.P95NS, series.P99NS =
		packagedJVMBenchmarkV2Summary(samples)
	series.Allocation.TotalBytes, series.Allocation.P50Bytes,
		series.Allocation.P95Bytes, series.Allocation.P99Bytes =
		packagedJVMBenchmarkV2Summary(allocated)
	series.Allocation.ControlTotalBytes, series.Allocation.ControlP50Bytes,
		series.Allocation.ControlP95Bytes, series.Allocation.ControlP99Bytes =
		packagedJVMBenchmarkV2Summary(controls)
	series.LatencyGate = packagedJVMBenchmarkV2Gate(observation.Spec, series.P50NS, series.P99NS)
	return series
}

func packagedJVMBenchmarkV2Summary(samples []int64) (int64, int64, int64, int64) {
	if len(samples) == 0 {
		return 0, 0, 0, 0
	}
	sorted := slices.Clone(samples)
	var total int64
	for _, sample := range sorted {
		total += sample
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return total,
		packagedJVMBenchmarkPercentile(sorted, 50),
		packagedJVMBenchmarkPercentile(sorted, 95),
		packagedJVMBenchmarkPercentile(sorted, 99)
}

func packagedJVMBenchmarkV2Gate(
	spec packagedJVMBenchmarkV2SeriesSpec,
	p50 int64,
	p99 int64,
) packagedJVMBenchmarkArtifactV2Latency {
	gate := packagedJVMBenchmarkArtifactV2Latency{Kind: "p99_lt"}
	switch {
	case spec.Transport == "getsockopt":
		gate.P99MaxNS = packagedJVMBenchmarkV2PrimaryP99LimitNS
	case spec.Outcome == "timeout":
		gate.Kind = "p50_gte_p99_lte"
		gate.P50MinNS = packagedJVMBenchmarkV2TimeoutP50MinimumNS
		gate.P99MaxNS = packagedJVMBenchmarkV2TimeoutP99LimitNS
	default:
		gate.P99MaxNS = packagedJVMBenchmarkV2UnixP99LimitNS
	}
	gate.Passed = p99 < gate.P99MaxNS
	if gate.Kind == "p50_gte_p99_lte" {
		gate.Passed = p50 >= gate.P50MinNS && p99 <= gate.P99MaxNS
	}
	return gate
}

func (counts *packagedJVMBenchmarkArtifactV2Statuses) add(status int) error {
	switch javabridge.Status(status) {
	case javabridge.StatusUnknown:
		counts.Unknown++
	case javabridge.StatusValid:
		counts.Valid++
	case javabridge.StatusMissing:
		counts.Missing++
	case javabridge.StatusStale:
		counts.Stale++
	case javabridge.StatusUnsupported:
		counts.Unsupported++
	case javabridge.StatusMalformed:
		counts.Malformed++
	case javabridge.StatusVersionMismatch:
		counts.VersionMismatch++
	case javabridge.StatusAmbiguous:
		counts.Ambiguous++
	case javabridge.StatusUnauthorized:
		counts.Unauthorized++
	case javabridge.StatusAlreadyConsumed:
		counts.AlreadyConsumed++
	case javabridge.StatusTimeout:
		counts.Timeout++
	case javabridge.StatusOverload:
		counts.Overload++
	case javabridge.StatusTransportError:
		counts.TransportError++
	case javabridge.StatusDisabled:
		counts.Disabled++
	default:
		return fmt.Errorf("unknown packaged JVM benchmark status %d", status)
	}
	return nil
}

func (counts packagedJVMBenchmarkArtifactV2Statuses) total() int {
	return counts.Unknown + counts.Valid + counts.Missing + counts.Stale + counts.Unsupported +
		counts.Malformed + counts.VersionMismatch + counts.Ambiguous + counts.Unauthorized +
		counts.AlreadyConsumed + counts.Timeout + counts.Overload + counts.TransportError + counts.Disabled
}

func packagedJVMBenchmarkEnvironment(environment []string) ([]string, error) {
	for _, value := range environment {
		name, _, found := strings.Cut(value, "=")
		if !found || name == "" {
			return nil, fmt.Errorf("malformed host environment entry %q", value)
		}
		if _, forbidden := forbiddenPackagedJVMBenchmarkEnvironment[name]; forbidden {
			return nil, fmt.Errorf("forbidden packaged JVM benchmark environment variable %s is set", name)
		}
	}
	return slices.Clone(expectedPackagedJVMBenchmarkEnvironment), nil
}

type packagedJVMBenchmarkExecutableBinding struct {
	InvocationPath string
	ResolvedPath   string
}

type packagedJVMBenchmarkProbeLog struct {
	mu     sync.Mutex
	output bytes.Buffer
}

func (log *packagedJVMBenchmarkProbeLog) Write(value []byte) (int, error) {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.output.Write(value)
}

func (log *packagedJVMBenchmarkProbeLog) String() string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.output.String()
}

// bindPackagedJVMBenchmarkExecutable validates and binds the executable reached by path while
// preserving its invocation identity. Multicall executables such as BusyBox select an applet from
// argv[0], so the resolved file must be executed with the original sh path as argv[0].
func bindPackagedJVMBenchmarkExecutable(
	path string,
) (packagedJVMBenchmarkExecutableBinding, error) {
	invocation, err := filepath.Abs(path)
	if err != nil {
		return packagedJVMBenchmarkExecutableBinding{}, fmt.Errorf(
			"resolve executable invocation path: %w", err,
		)
	}
	invocation = filepath.Clean(invocation)
	if !filepath.IsAbs(invocation) {
		return packagedJVMBenchmarkExecutableBinding{}, errors.New(
			"executable invocation path is not absolute",
		)
	}
	resolved, err := filepath.EvalSymlinks(invocation)
	if err != nil {
		return packagedJVMBenchmarkExecutableBinding{}, fmt.Errorf(
			"resolve executable invocation symlinks: %w", err,
		)
	}
	resolved = filepath.Clean(resolved)
	if !filepath.IsAbs(resolved) {
		return packagedJVMBenchmarkExecutableBinding{}, errors.New(
			"resolved executable path is not absolute",
		)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return packagedJVMBenchmarkExecutableBinding{}, fmt.Errorf(
			"stat resolved executable: %w", err,
		)
	}
	if !info.Mode().IsRegular() {
		return packagedJVMBenchmarkExecutableBinding{}, errors.New(
			"resolved executable is not a regular file",
		)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return packagedJVMBenchmarkExecutableBinding{}, errors.New(
			"resolved executable is not executable",
		)
	}
	for component := resolved; ; component = filepath.Dir(component) {
		var stat unix.Stat_t
		if err := unix.Lstat(component, &stat); err != nil {
			return packagedJVMBenchmarkExecutableBinding{}, fmt.Errorf(
				"inspect resolved executable path component %s: %w", component, err,
			)
		}
		if stat.Uid != 0 || stat.Mode&0o022 != 0 {
			return packagedJVMBenchmarkExecutableBinding{}, fmt.Errorf(
				"resolved executable path component %s is not root-controlled", component,
			)
		}
		if component == string(filepath.Separator) {
			break
		}
	}
	return packagedJVMBenchmarkExecutableBinding{
		InvocationPath: invocation,
		ResolvedPath:   resolved,
	}, nil
}

func packagedJVMBenchmarkEarlyLaunchDiagnostic(
	command *exec.Cmd,
	stderr fmt.Stringer,
) (bool, string) {
	if command == nil || command.Process == nil {
		return false, "launcher process was not started"
	}
	pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	if err != nil {
		return false, fmt.Sprintf(
			"launcher exit state unavailable: %v; stderr=%q", err, strings.TrimSpace(stderr.String()),
		)
	}
	defer unix.Close(pidfd)

	poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	count, err := unix.Poll(poll, 100)
	if err != nil {
		return false, fmt.Sprintf(
			"launcher exit poll failed: %v; stderr=%q", err, strings.TrimSpace(stderr.String()),
		)
	}
	if count == 0 || poll[0].Revents == 0 {
		return false, fmt.Sprintf(
			"launcher was still running; stderr=%q", strings.TrimSpace(stderr.String()),
		)
	}
	waitErr := command.Wait()
	return true, fmt.Sprintf(
		"launcher exited before process identity was available: %v; stderr=%q",
		waitErr,
		strings.TrimSpace(stderr.String()),
	)
}

func parsePackagedJVMBenchmarkProbeLine(
	line string,
	expectedPrefix string,
) (map[string]string, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil, errors.New("packaged JVM benchmark emitted an empty stdout message")
	}
	if fields[0] != expectedPrefix {
		return nil, fmt.Errorf(
			"packaged JVM benchmark emitted unexpected stdout message %q while waiting for %s",
			line, expectedPrefix,
		)
	}
	values := make(map[string]string, len(fields)-1)
	for _, field := range fields[1:] {
		name, value, found := strings.Cut(field, "=")
		if !found || name == "" || value == "" {
			return nil, fmt.Errorf("packaged JVM benchmark emitted invalid probe field %q", field)
		}
		if _, duplicate := values[name]; duplicate {
			return nil, fmt.Errorf("packaged JVM benchmark emitted duplicate probe field %q", name)
		}
		values[name] = value
	}
	return values, nil
}

func packagedJVMBenchmarkProbeResults(output io.Reader) <-chan packagedJVMBenchmarkProbeResult {
	results := make(chan packagedJVMBenchmarkProbeResult, 8)
	go func() {
		defer close(results)
		scanner := bufio.NewScanner(output)
		for scanner.Scan() {
			results <- packagedJVMBenchmarkProbeResult{line: scanner.Text()}
		}
		if err := scanner.Err(); err != nil {
			results <- packagedJVMBenchmarkProbeResult{
				err: fmt.Errorf("packaged JVM benchmark stdout scan failed: %w", err),
			}
			return
		}
		results <- packagedJVMBenchmarkProbeResult{eof: true}
	}()
	return results
}

func validatePackagedJVMBenchmarkProbeEOF(
	result packagedJVMBenchmarkProbeResult,
	channelOpen bool,
) error {
	if !channelOpen {
		return errors.New("packaged JVM benchmark stdout result stream closed without clean EOF")
	}
	if result.err != nil {
		return result.err
	}
	if !result.eof {
		return fmt.Errorf("packaged JVM benchmark emitted trailing stdout message %q after DONE", result.line)
	}
	if result.line != "" {
		return errors.New("packaged JVM benchmark stdout EOF result contained a line")
	}
	return nil
}

func validatePackagedJVMBenchmarkSourceOwnership(
	harnessUID uint32,
	workingDirectoryOwner packagedJVMBenchmarkSourceOwner,
	repositoryOwner packagedJVMBenchmarkSourceOwner,
) error {
	if harnessUID != 0 {
		return errors.New("packaged JVM benchmark source identity requires a root harness")
	}
	if workingDirectoryOwner.UID == 0 || workingDirectoryOwner.GID == 0 {
		return errors.New("packaged JVM benchmark source identity requires a non-root source owner")
	}
	if workingDirectoryOwner != repositoryOwner {
		return fmt.Errorf(
			"packaged JVM benchmark source ownership mismatch: cwd=%d:%d repository=%d:%d",
			workingDirectoryOwner.UID,
			workingDirectoryOwner.GID,
			repositoryOwner.UID,
			repositoryOwner.GID,
		)
	}
	return nil
}

func packagedJVMBenchmarkGitCommandArguments(
	git string,
	safeDirectory string,
	workingDirectory string,
	owner packagedJVMBenchmarkSourceOwner,
	arguments ...string,
) ([]string, error) {
	if !filepath.IsAbs(git) || filepath.Clean(git) != git {
		return nil, errors.New("packaged JVM benchmark git executable must be an absolute clean path")
	}
	if !filepath.IsAbs(safeDirectory) || filepath.Clean(safeDirectory) != safeDirectory {
		return nil, errors.New("packaged JVM benchmark Git safe directory must be an absolute clean path")
	}
	if strings.ContainsAny(safeDirectory, "*?") {
		return nil, errors.New("packaged JVM benchmark Git safe directory must not contain wildcards")
	}
	if !filepath.IsAbs(workingDirectory) || filepath.Clean(workingDirectory) != workingDirectory {
		return nil, errors.New("packaged JVM benchmark Git working directory must be an absolute clean path")
	}
	if owner.UID == 0 || owner.GID == 0 {
		return nil, errors.New("packaged JVM benchmark git command requires a non-root source owner")
	}
	commandArguments := []string{
		"--reuid=" + strconv.FormatUint(uint64(owner.UID), 10),
		"--regid=" + strconv.FormatUint(uint64(owner.GID), 10),
		"--clear-groups",
		"--no-new-privs",
		"--inh-caps=-all",
		"--ambient-caps=-all",
		"--bounding-set=-all",
		"--",
		git,
		"-c",
		"safe.directory=" + safeDirectory,
		"-C",
		workingDirectory,
	}
	return append(commandArguments, arguments...), nil
}

func validatePackagedJVMBenchmarkNegotiationAuthority(
	negotiation packagedJVMBenchmarkNegotiationAuthority,
	expected packagedJVMBenchmarkNegotiationAuthority,
) error {
	if negotiation.Process != expected.Process {
		return errors.New("packaged JVM benchmark negotiation process does not match staged process")
	}
	if negotiation.ProcessIncarnation != expected.ProcessIncarnation {
		return errors.New("packaged JVM benchmark negotiation incarnation does not match staged incarnation")
	}
	if negotiation.Connection != expected.Connection {
		return errors.New("packaged JVM benchmark negotiation connection does not match staged connection")
	}
	if negotiation.ConnectionNetns != expected.ConnectionNetns {
		return errors.New("packaged JVM benchmark negotiation namespace does not match staged namespace")
	}
	if negotiation.Generation != expected.Generation {
		return errors.New("packaged JVM benchmark negotiation generation does not match staged generation")
	}
	return nil
}

func validatePackagedJVMBenchmarkCgroupBPFPreAttach(
	snapshot packagedJVMBenchmarkCgroupBPFSnapshot,
) error {
	if err := validatePackagedJVMBenchmarkCgroupBPFSnapshotShape(snapshot); err != nil {
		return err
	}
	for _, chain := range snapshot.Chains {
		if len(chain.EffectivePrograms) != 0 {
			return fmt.Errorf(
				"packaged JVM benchmark found foreign preexisting effective %s programs",
				chain.AttachType,
			)
		}
		for _, topology := range chain.Topology {
			if len(topology.DirectPrograms) != 0 {
				return fmt.Errorf(
					"packaged JVM benchmark found foreign preexisting %s program at %s",
					chain.AttachType, topology.CgroupPath,
				)
			}
		}
	}
	return nil
}

func bindPackagedJVMBenchmarkCgroupBPFAttribution(
	preAttach packagedJVMBenchmarkCgroupBPFSnapshot,
	snapshot packagedJVMBenchmarkCgroupBPFSnapshot,
	intended []packagedJVMBenchmarkIntendedCgroupBPFProgram,
	operatorPremise string,
) (packagedJVMBenchmarkArtifactCgroupBPF, error) {
	if err := validatePackagedJVMBenchmarkCgroupBPFPreAttach(preAttach); err != nil {
		return packagedJVMBenchmarkArtifactCgroupBPF{}, err
	}
	if err := validatePackagedJVMBenchmarkCgroupBPFSnapshotShape(snapshot); err != nil {
		return packagedJVMBenchmarkArtifactCgroupBPF{}, err
	}
	if err := validatePackagedJVMBenchmarkCgroupBPFAttachedRevisionCapabilities(snapshot); err != nil {
		return packagedJVMBenchmarkArtifactCgroupBPF{}, err
	}
	if err := validatePackagedJVMBenchmarkCgroupBPFQueryScopeUnchanged(preAttach, snapshot); err != nil {
		return packagedJVMBenchmarkArtifactCgroupBPF{}, err
	}
	if len(intended) != len(expectedPackagedJVMBenchmarkCgroupAttachTypes) {
		return packagedJVMBenchmarkArtifactCgroupBPF{}, errors.New(
			"packaged JVM benchmark intended cgroup BPF program count is invalid",
		)
	}
	if operatorPremise != "" && operatorPremise != packagedJVMBenchmarkExclusiveTopologyPremise {
		return packagedJVMBenchmarkArtifactCgroupBPF{}, fmt.Errorf(
			"packaged JVM benchmark exclusive cgroup BPF premise is invalid: %q",
			operatorPremise,
		)
	}
	stabilityMode, stabilityEvidence, exclusiveTopologyPremise :=
		packagedJVMBenchmarkCgroupBPFStabilityContract(snapshot)
	if stabilityMode == packagedJVMBenchmarkBoundaryIdentityOnlyMode &&
		operatorPremise != packagedJVMBenchmarkExclusiveTopologyPremise {
		return packagedJVMBenchmarkArtifactCgroupBPF{}, fmt.Errorf(
			"packaged JVM benchmark direct cgroup BPF revisions are unavailable; set %s=%s only on an operator-controlled topology with no concurrent cgroup BPF mutation",
			javaRemoteParentPackagedJVMBenchmarkExclusiveCgroupBPFEnv,
			packagedJVMBenchmarkExclusiveTopologyPremise,
		)
	}
	attribution := packagedJVMBenchmarkArtifactCgroupBPF{
		TargetCgroup:             snapshot.TargetCgroup,
		CgroupHierarchy:          slices.Clone(snapshot.CgroupHierarchy),
		EffectiveQueryFlag:       packagedJVMBenchmarkEffectiveQueryFlag,
		EffectiveQueryFlags:      snapshot.EffectiveQueryFlags,
		PreAttachChainsEmpty:     true,
		StabilityMode:            stabilityMode,
		StabilityEvidence:        stabilityEvidence,
		ExclusiveTopologyPremise: exclusiveTopologyPremise,
		Chains: make(
			[]packagedJVMBenchmarkArtifactCgroupChain, 0, len(snapshot.Chains),
		),
	}
	for index, chain := range snapshot.Chains {
		expected := intended[index]
		if expected.AttachType != chain.AttachType {
			return packagedJVMBenchmarkArtifactCgroupBPF{}, fmt.Errorf(
				"packaged JVM benchmark intended attach type mismatch: got %s, want %s",
				expected.AttachType, chain.AttachType,
			)
		}
		if err := validatePackagedJVMBenchmarkBPFProgram(expected.Program); err != nil {
			return packagedJVMBenchmarkArtifactCgroupBPF{}, fmt.Errorf(
				"packaged JVM benchmark intended %s program: %w", chain.AttachType, err,
			)
		}
		if len(chain.EffectivePrograms) != 1 {
			return packagedJVMBenchmarkArtifactCgroupBPF{}, fmt.Errorf(
				"packaged JVM benchmark effective %s chain has %d programs, want exactly one intended program",
				chain.AttachType, len(chain.EffectivePrograms),
			)
		}
		if chain.EffectivePrograms[0] != expected.Program {
			return packagedJVMBenchmarkArtifactCgroupBPF{}, fmt.Errorf(
				"packaged JVM benchmark effective %s program differs from intended program",
				chain.AttachType,
			)
		}
		for topologyIndex, topology := range chain.Topology {
			expectedPrograms := 0
			if topologyIndex == len(chain.Topology)-1 {
				expectedPrograms = 1
			}
			if len(topology.DirectPrograms) != expectedPrograms {
				return packagedJVMBenchmarkArtifactCgroupBPF{}, fmt.Errorf(
					"packaged JVM benchmark %s topology at %s has %d programs, want %d",
					chain.AttachType,
					topology.CgroupPath,
					len(topology.DirectPrograms),
					expectedPrograms,
				)
			}
			if expectedPrograms == 1 && topology.DirectPrograms[0] != expected.Program {
				return packagedJVMBenchmarkArtifactCgroupBPF{}, fmt.Errorf(
					"packaged JVM benchmark direct %s program differs from intended program",
					chain.AttachType,
				)
			}
		}
		attribution.Chains = append(attribution.Chains, packagedJVMBenchmarkArtifactCgroupChain{
			AttachType:                 chain.AttachType,
			IntendedProgram:            expected.Program,
			EffectiveRevisionSupported: chain.EffectiveRevisionSupported,
			EffectiveRevision:          chain.EffectiveRevision,
			EffectivePrograms:          slices.Clone(chain.EffectivePrograms),
			Topology:                   clonePackagedJVMBenchmarkCgroupBPFTopology(chain.Topology),
		})
	}
	if err := validatePackagedJVMBenchmarkCgroupBPFAttributionTopology(
		attribution, snapshot.TargetCgroup,
	); err != nil {
		return packagedJVMBenchmarkArtifactCgroupBPF{}, err
	}
	return attribution, nil
}

func validatePackagedJVMBenchmarkCgroupBPFSnapshotUnchanged(
	attached packagedJVMBenchmarkCgroupBPFSnapshot,
	current packagedJVMBenchmarkCgroupBPFSnapshot,
) error {
	if err := validatePackagedJVMBenchmarkCgroupBPFSnapshotShape(attached); err != nil {
		return err
	}
	if err := validatePackagedJVMBenchmarkCgroupBPFSnapshotShape(current); err != nil {
		return err
	}
	if err := validatePackagedJVMBenchmarkCgroupBPFAttachedRevisionCapabilities(attached); err != nil {
		return err
	}
	if err := validatePackagedJVMBenchmarkCgroupBPFAttachedRevisionCapabilities(current); err != nil {
		return err
	}
	if err := validatePackagedJVMBenchmarkCgroupBPFQueryScopeUnchanged(attached, current); err != nil {
		return err
	}
	for chainIndex, baselineChain := range attached.Chains {
		currentChain := current.Chains[chainIndex]
		if !slices.Equal(baselineChain.EffectivePrograms, currentChain.EffectivePrograms) {
			return errors.New("packaged JVM benchmark effective cgroup BPF chains changed after attribution")
		}
		for topologyIndex, baselineTopology := range baselineChain.Topology {
			currentTopology := currentChain.Topology[topologyIndex]
			if baselineTopology.DirectRevisionSupported != currentTopology.DirectRevisionSupported {
				return errors.New("packaged JVM benchmark direct cgroup BPF revision support changed after attribution")
			}
			if !slices.Equal(baselineTopology.DirectPrograms, currentTopology.DirectPrograms) {
				return errors.New("packaged JVM benchmark direct cgroup BPF chains changed after attribution")
			}
			if baselineTopology.DirectRevisionSupported &&
				baselineTopology.DirectRevision != currentTopology.DirectRevision {
				return errors.New("packaged JVM benchmark direct cgroup BPF revisions changed after attribution")
			}
		}
	}
	return nil
}

func newPackagedJVMBenchmarkCgroupBPFStabilityTracker() *packagedJVMBenchmarkCgroupBPFStabilityTracker {
	return newPackagedJVMBenchmarkCgroupBPFStabilityTrackerForCalls(packagedJVMBenchmarkExpectedCalls)
}

func newPackagedJVMBenchmarkCgroupBPFStabilityTrackerForCalls(
	expectedCalls int,
) *packagedJVMBenchmarkCgroupBPFStabilityTracker {
	return &packagedJVMBenchmarkCgroupBPFStabilityTracker{
		checks: packagedJVMBenchmarkArtifactStabilityChecks{
			ExpectedCalls: expectedCalls,
		},
	}
}

func (tracker *packagedJVMBenchmarkCgroupBPFStabilityTracker) ObservePreCall(
	attached packagedJVMBenchmarkCgroupBPFSnapshot,
	current packagedJVMBenchmarkCgroupBPFSnapshot,
	queryErr error,
) error {
	return tracker.observeCallSnapshot(true, attached, current, queryErr)
}

func (tracker *packagedJVMBenchmarkCgroupBPFStabilityTracker) ObservePostCall(
	attached packagedJVMBenchmarkCgroupBPFSnapshot,
	current packagedJVMBenchmarkCgroupBPFSnapshot,
	queryErr error,
) error {
	return tracker.observeCallSnapshot(false, attached, current, queryErr)
}

func (tracker *packagedJVMBenchmarkCgroupBPFStabilityTracker) observeCallSnapshot(
	preCall bool,
	attached packagedJVMBenchmarkCgroupBPFSnapshot,
	current packagedJVMBenchmarkCgroupBPFSnapshot,
	queryErr error,
) error {
	if queryErr != nil {
		tracker.checks.QueryErrors++
		return fmt.Errorf("query packaged JVM benchmark cgroup BPF call bracket: %w", queryErr)
	}
	if err := validatePackagedJVMBenchmarkCgroupBPFSnapshotUnchanged(attached, current); err != nil {
		tracker.checks.TopologyMismatches++
		return err
	}
	if preCall {
		tracker.checks.ObservedPreCallSnapshots++
	} else {
		tracker.checks.ObservedPostCallSnapshots++
	}
	return nil
}

func (tracker *packagedJVMBenchmarkCgroupBPFStabilityTracker) Checks() packagedJVMBenchmarkArtifactStabilityChecks {
	return tracker.checks
}

func validatePackagedJVMBenchmarkCgroupBPFStabilityChecks(
	checks packagedJVMBenchmarkArtifactStabilityChecks,
) error {
	if checks.ExpectedCalls != packagedJVMBenchmarkExpectedCalls ||
		checks.ObservedPreCallSnapshots != checks.ExpectedCalls ||
		checks.ObservedPostCallSnapshots != checks.ExpectedCalls ||
		checks.QueryErrors != 0 || checks.TopologyMismatches != 0 {
		return fmt.Errorf(
			"packaged JVM benchmark cgroup BPF stability checks are incomplete or failed: %+v",
			checks,
		)
	}
	return nil
}

func validatePackagedJVMBenchmarkCgroupBPFQueryScopeUnchanged(
	baseline packagedJVMBenchmarkCgroupBPFSnapshot,
	current packagedJVMBenchmarkCgroupBPFSnapshot,
) error {
	if baseline.TargetCgroup != current.TargetCgroup ||
		baseline.EffectiveQueryFlags != current.EffectiveQueryFlags ||
		!slices.Equal(baseline.CgroupHierarchy, current.CgroupHierarchy) ||
		len(baseline.Chains) != len(current.Chains) {
		return errors.New("packaged JVM benchmark cgroup BPF query scope changed after attribution")
	}
	for chainIndex, baselineChain := range baseline.Chains {
		currentChain := current.Chains[chainIndex]
		if baselineChain.AttachType != currentChain.AttachType ||
			len(baselineChain.Topology) != len(currentChain.Topology) {
			return errors.New("packaged JVM benchmark cgroup BPF query scope changed after attribution")
		}
		for topologyIndex, baselineTopology := range baselineChain.Topology {
			if baselineTopology.CgroupPath != currentChain.Topology[topologyIndex].CgroupPath {
				return errors.New("packaged JVM benchmark cgroup BPF query scope changed after attribution")
			}
		}
	}
	return nil
}

func validatePackagedJVMBenchmarkCgroupBPFSnapshotShape(
	snapshot packagedJVMBenchmarkCgroupBPFSnapshot,
) error {
	if snapshot.EffectiveQueryFlags != uint32(unix.BPF_F_QUERY_EFFECTIVE) {
		return errors.New("packaged JVM benchmark effective cgroup BPF query flags are invalid")
	}
	if err := validatePackagedJVMBenchmarkCgroupHierarchy(
		snapshot.TargetCgroup, snapshot.CgroupHierarchy,
	); err != nil {
		return err
	}
	if len(snapshot.Chains) != len(expectedPackagedJVMBenchmarkCgroupAttachTypes) {
		return fmt.Errorf("packaged JVM benchmark cgroup BPF chain count is invalid: %d", len(snapshot.Chains))
	}
	for index, chain := range snapshot.Chains {
		if chain.AttachType != expectedPackagedJVMBenchmarkCgroupAttachTypes[index] {
			return fmt.Errorf("packaged JVM benchmark cgroup BPF attach type is invalid: %q", chain.AttachType)
		}
		if chain.EffectiveRevisionSupported || chain.EffectiveRevision != 0 {
			return fmt.Errorf(
				"packaged JVM benchmark %s effective query incorrectly claims revision support",
				chain.AttachType,
			)
		}
		if len(chain.Topology) != len(snapshot.CgroupHierarchy) {
			return fmt.Errorf("packaged JVM benchmark %s topology length is invalid", chain.AttachType)
		}
		for topologyIndex, topology := range chain.Topology {
			if topology.CgroupPath != snapshot.CgroupHierarchy[topologyIndex] {
				return fmt.Errorf("packaged JVM benchmark %s topology path is invalid", chain.AttachType)
			}
			if topology.DirectRevisionSupported != (topology.DirectRevision != 0) {
				return fmt.Errorf(
					"packaged JVM benchmark %s direct revision support is inconsistent with revision at %s",
					chain.AttachType, topology.CgroupPath,
				)
			}
			for _, program := range topology.DirectPrograms {
				if err := validatePackagedJVMBenchmarkBPFProgram(program); err != nil {
					return fmt.Errorf("packaged JVM benchmark direct %s program: %w", chain.AttachType, err)
				}
			}
		}
		for _, program := range chain.EffectivePrograms {
			if err := validatePackagedJVMBenchmarkBPFProgram(program); err != nil {
				return fmt.Errorf("packaged JVM benchmark effective %s program: %w", chain.AttachType, err)
			}
		}
	}
	return nil
}

func validatePackagedJVMBenchmarkCgroupBPFAttachedRevisionCapabilities(
	snapshot packagedJVMBenchmarkCgroupBPFSnapshot,
) error {
	for _, chain := range snapshot.Chains {
		for _, topology := range chain.Topology {
			if topology.DirectRevisionSupported != (topology.DirectRevision != 0) {
				return fmt.Errorf(
					"packaged JVM benchmark %s direct revision capability does not match the query result at %s",
					chain.AttachType, topology.CgroupPath,
				)
			}
		}
	}
	return nil
}

func packagedJVMBenchmarkCgroupBPFStabilityContract(
	snapshot packagedJVMBenchmarkCgroupBPFSnapshot,
) (string, string, string) {
	for _, chain := range snapshot.Chains {
		for _, topology := range chain.Topology {
			if !topology.DirectRevisionSupported {
				return packagedJVMBenchmarkBoundaryIdentityOnlyMode,
					packagedJVMBenchmarkBoundaryIdentityOnlyEvidence,
					packagedJVMBenchmarkExclusiveTopologyPremise
			}
		}
	}
	return packagedJVMBenchmarkRevisionAndIdentityMode,
		packagedJVMBenchmarkRevisionAndIdentityEvidence,
		packagedJVMBenchmarkRevisionPremiseNotRequired
}

func validatePackagedJVMBenchmarkCgroupBPFAttribution(
	attribution packagedJVMBenchmarkArtifactCgroupBPF,
	expectedTarget string,
) error {
	if err := validatePackagedJVMBenchmarkCgroupBPFAttributionTopology(
		attribution, expectedTarget,
	); err != nil {
		return err
	}
	return validatePackagedJVMBenchmarkCgroupBPFStabilityChecks(attribution.StabilityChecks)
}

func validatePackagedJVMBenchmarkCgroupBPFAttributionTopology(
	attribution packagedJVMBenchmarkArtifactCgroupBPF,
	expectedTarget string,
) error {
	if attribution.TargetCgroup != expectedTarget || !attribution.PreAttachChainsEmpty ||
		attribution.EffectiveQueryFlag != packagedJVMBenchmarkEffectiveQueryFlag ||
		attribution.EffectiveQueryFlags != uint32(unix.BPF_F_QUERY_EFFECTIVE) {
		return errors.New("packaged JVM benchmark cgroup BPF attribution identity is invalid")
	}
	snapshot := packagedJVMBenchmarkCgroupBPFSnapshot{
		TargetCgroup:        attribution.TargetCgroup,
		CgroupHierarchy:     slices.Clone(attribution.CgroupHierarchy),
		EffectiveQueryFlags: attribution.EffectiveQueryFlags,
		Chains: make(
			[]packagedJVMBenchmarkCgroupBPFChainSnapshot, 0, len(attribution.Chains),
		),
	}
	intended := make([]packagedJVMBenchmarkIntendedCgroupBPFProgram, 0, len(attribution.Chains))
	programIDs := map[uint32]struct{}{}
	for _, chain := range attribution.Chains {
		snapshot.Chains = append(snapshot.Chains, packagedJVMBenchmarkCgroupBPFChainSnapshot{
			AttachType:                 chain.AttachType,
			EffectiveRevisionSupported: chain.EffectiveRevisionSupported,
			EffectiveRevision:          chain.EffectiveRevision,
			EffectivePrograms:          slices.Clone(chain.EffectivePrograms),
			Topology:                   clonePackagedJVMBenchmarkCgroupBPFTopology(chain.Topology),
		})
		intended = append(intended, packagedJVMBenchmarkIntendedCgroupBPFProgram{
			AttachType: chain.AttachType,
			Program:    chain.IntendedProgram,
		})
		if _, duplicate := programIDs[chain.IntendedProgram.ID]; duplicate {
			return errors.New("packaged JVM benchmark intended cgroup BPF program IDs are not unique")
		}
		programIDs[chain.IntendedProgram.ID] = struct{}{}
	}
	if err := validatePackagedJVMBenchmarkCgroupBPFSnapshotShape(snapshot); err != nil {
		return err
	}
	if err := validatePackagedJVMBenchmarkCgroupBPFAttachedRevisionCapabilities(snapshot); err != nil {
		return err
	}
	stabilityMode, stabilityEvidence, exclusiveTopologyPremise :=
		packagedJVMBenchmarkCgroupBPFStabilityContract(snapshot)
	if attribution.StabilityMode != stabilityMode ||
		attribution.StabilityEvidence != stabilityEvidence ||
		attribution.ExclusiveTopologyPremise != exclusiveTopologyPremise {
		return errors.New("packaged JVM benchmark cgroup BPF stability contract is invalid")
	}
	for index, chain := range snapshot.Chains {
		expected := intended[index]
		expectedProgramType := "CGroupSockopt"
		if chain.AttachType == "CGroupSockOps" {
			expectedProgramType = "SockOps"
		}
		if expected.Program.ProgramType != expectedProgramType {
			return fmt.Errorf("packaged JVM benchmark attributed %s program type is invalid", chain.AttachType)
		}
		if chain.AttachType != expected.AttachType || len(chain.EffectivePrograms) != 1 ||
			chain.EffectivePrograms[0] != expected.Program {
			return fmt.Errorf("packaged JVM benchmark attributed %s effective chain is invalid", chain.AttachType)
		}
		for topologyIndex, topology := range chain.Topology {
			if topologyIndex == len(chain.Topology)-1 {
				if len(topology.DirectPrograms) != 1 || topology.DirectPrograms[0] != expected.Program {
					return fmt.Errorf("packaged JVM benchmark attributed %s target attachment is invalid", chain.AttachType)
				}
			} else if len(topology.DirectPrograms) != 0 {
				return fmt.Errorf("packaged JVM benchmark attributed %s ancestor attachment is unexpected", chain.AttachType)
			}
		}
	}
	return nil
}

func validatePackagedJVMBenchmarkCgroupHierarchy(target string, hierarchy []string) error {
	if !filepath.IsAbs(target) || filepath.Clean(target) != target || len(hierarchy) == 0 ||
		hierarchy[0] != packagedJVMBenchmarkCgroupRoot || hierarchy[len(hierarchy)-1] != target {
		return errors.New("packaged JVM benchmark cgroup hierarchy identity is invalid")
	}
	for index, path := range hierarchy {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("packaged JVM benchmark cgroup hierarchy path is invalid")
		}
		if index > 0 && filepath.Dir(path) != hierarchy[index-1] {
			return errors.New("packaged JVM benchmark cgroup hierarchy is not contiguous")
		}
	}
	return nil
}

func validatePackagedJVMBenchmarkBPFProgram(
	program packagedJVMBenchmarkArtifactBPFProgram,
) error {
	if program.ID == 0 || len(program.Tag) != 16 || !isLowerHex(program.Tag) ||
		program.Name == "" || strings.TrimSpace(program.Name) != program.Name ||
		strings.ContainsAny(program.Name, "\x00\r\n") || program.ProgramType == "" {
		return errors.New("program ID, tag, name, or type is invalid")
	}
	return nil
}

func clonePackagedJVMBenchmarkCgroupBPFTopology(
	topology []packagedJVMBenchmarkArtifactCgroupTopology,
) []packagedJVMBenchmarkArtifactCgroupTopology {
	clone := make([]packagedJVMBenchmarkArtifactCgroupTopology, len(topology))
	for index, entry := range topology {
		clone[index] = entry
		clone[index].DirectPrograms = slices.Clone(entry.DirectPrograms)
	}
	return clone
}

func validatePackagedJVMBenchmarkArtifact(artifact packagedJVMBenchmarkArtifact) error {
	if artifact.SchemaVersion != packagedJVMBenchmarkArtifactSchemaVersion {
		return fmt.Errorf("unsupported packaged JVM benchmark schema version: %d", artifact.SchemaVersion)
	}
	if artifact.Benchmark != packagedJVMBenchmarkArtifactName {
		return fmt.Errorf("unexpected packaged JVM benchmark name: %q", artifact.Benchmark)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, artifact.CreatedAt)
	if err != nil || createdAt.Location() != time.UTC {
		return fmt.Errorf("invalid packaged JVM benchmark creation time: %q", artifact.CreatedAt)
	}
	if artifact.Provenance.Harness != expectedPackagedJVMBenchmarkProvenance.Harness ||
		!slices.Equal(artifact.Provenance.Measures, expectedPackagedJVMBenchmarkProvenance.Measures) ||
		!slices.Equal(artifact.Provenance.Excludes, expectedPackagedJVMBenchmarkProvenance.Excludes) {
		return errors.New("unexpected packaged JVM benchmark provenance")
	}
	if err := validatePackagedJVMBenchmarkSource(artifact.Source); err != nil {
		return err
	}
	if err := validatePackagedJVMBenchmarkInputs(artifact.Inputs); err != nil {
		return err
	}
	if err := validatePackagedJVMBenchmarkRuntime(artifact.Runtime); err != nil {
		return err
	}
	if err := validatePackagedJVMBenchmarkCgroupBPFAttribution(
		artifact.Provenance.CgroupBPF, artifact.Runtime.CgroupPath,
	); err != nil {
		return err
	}
	if artifact.Setup.WarmupIterations != packagedJVMBenchmarkWarmupIterations ||
		artifact.Setup.MeasurementIterations != packagedJVMBenchmarkMeasurementIterations ||
		artifact.Setup.Concurrency != packagedJVMBenchmarkConcurrency ||
		artifact.Setup.TimedCall != packagedJVMBenchmarkTimedCall ||
		artifact.Setup.ResponseStorage != packagedJVMBenchmarkResponseStorage ||
		artifact.Setup.AgentOptions != packagedJVMBenchmarkAgentOptions ||
		artifact.Setup.MissControl != packagedJVMBenchmarkMissControl ||
		artifact.Setup.AgentArtifactBinding != packagedJVMBenchmarkAgentBinding ||
		!slices.Equal(artifact.Setup.JVMArguments, expectedPackagedJVMBenchmarkJVMArguments) ||
		!slices.Equal(artifact.Setup.Environment, expectedPackagedJVMBenchmarkEnvironment) {
		return errors.New("unexpected packaged JVM benchmark setup")
	}
	if len(artifact.Series) != 2 {
		return fmt.Errorf("unexpected packaged JVM benchmark series count: %d", len(artifact.Series))
	}
	for index, expected := range []struct {
		outcome string
		status  int
	}{{"miss", int(javabridge.StatusMissing)}, {"hit", int(javabridge.StatusValid)}} {
		if err := validatePackagedJVMBenchmarkSeries(
			artifact.Series[index], expected.outcome, expected.status,
		); err != nil {
			return fmt.Errorf("packaged JVM benchmark series %d: %w", index, err)
		}
	}
	return nil
}

func validatePackagedJVMBenchmarkSource(source packagedJVMBenchmarkArtifactSource) error {
	if (len(source.Revision) != 40 && len(source.Revision) != 64) ||
		!isLowerHex(source.Revision) {
		return errors.New("packaged JVM benchmark source revision is invalid")
	}
	if !isSHA256(source.StatusSHA256) || !isSHA256(source.PatchSHA256) {
		return errors.New("packaged JVM benchmark source state digest is invalid")
	}
	emptySHA256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if source.Dirty {
		if source.StatusSHA256 == emptySHA256 || source.PatchSHA256 == emptySHA256 {
			return errors.New("packaged JVM benchmark dirty source identity is incomplete")
		}
	} else if source.StatusSHA256 != emptySHA256 || source.PatchSHA256 != emptySHA256 {
		return errors.New("packaged JVM benchmark clean source identity is inconsistent")
	}
	return nil
}

func validatePackagedJVMBenchmarkInputs(inputs packagedJVMBenchmarkArtifactInputs) error {
	if inputs.GoToolchain == "" || strings.TrimSpace(inputs.GoToolchain) != inputs.GoToolchain ||
		strings.ContainsAny(inputs.GoToolchain, "\x00\r\n") {
		return errors.New("packaged JVM benchmark Go toolchain identity is invalid")
	}
	if err := validatePackagedJVMBenchmarkFileIdentity(inputs.TestBinary); err != nil {
		return fmt.Errorf("packaged JVM benchmark test binary identity: %w", err)
	}
	if err := validatePackagedJVMBenchmarkFileIdentity(inputs.AgentArtifact); err != nil {
		return fmt.Errorf("packaged JVM benchmark agent artifact identity: %w", err)
	}
	if err := validatePackagedJVMBenchmarkBlobIdentity(inputs.SockoptBPF); err != nil {
		return fmt.Errorf("packaged JVM benchmark sockopt BPF identity: %w", err)
	}
	if err := validatePackagedJVMBenchmarkBlobIdentity(inputs.SockopsBPF); err != nil {
		return fmt.Errorf("packaged JVM benchmark sockops BPF identity: %w", err)
	}
	return nil
}

func validatePackagedJVMBenchmarkFileIdentity(identity packagedJVMBenchmarkArtifactFileIdentity) error {
	if !isSHA256(identity.SHA256) || identity.Device == 0 || identity.Inode == 0 || identity.Size <= 0 {
		return errors.New("SHA-256, device, inode, or size is invalid")
	}
	return nil
}

func packagedJVMBenchmarkFileIdentityAtPath(
	path string,
) (packagedJVMBenchmarkArtifactFileIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return packagedJVMBenchmarkArtifactFileIdentity{}, errors.New(
			"packaged JVM benchmark crosslink path must be absolute and clean",
		)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return packagedJVMBenchmarkArtifactFileIdentity{}, fmt.Errorf(
			"open packaged JVM benchmark crosslink: %w", err,
		)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return packagedJVMBenchmarkArtifactFileIdentity{}, errors.New(
			"create packaged JVM benchmark crosslink file handle",
		)
	}
	defer file.Close()

	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return packagedJVMBenchmarkArtifactFileIdentity{}, fmt.Errorf(
			"stat packaged JVM benchmark crosslink: %w", err,
		)
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size <= 0 {
		return packagedJVMBenchmarkArtifactFileIdentity{}, errors.New(
			"packaged JVM benchmark crosslink is not a nonempty regular file",
		)
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, io.NewSectionReader(file, 0, before.Size)); err != nil {
		return packagedJVMBenchmarkArtifactFileIdentity{}, fmt.Errorf(
			"hash packaged JVM benchmark crosslink: %w", err,
		)
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return packagedJVMBenchmarkArtifactFileIdentity{}, fmt.Errorf(
			"restat packaged JVM benchmark crosslink: %w", err,
		)
	}
	if before.Dev != after.Dev || before.Ino != after.Ino ||
		before.Mode != after.Mode || before.Size != after.Size ||
		before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return packagedJVMBenchmarkArtifactFileIdentity{}, errors.New(
			"packaged JVM benchmark crosslink changed while hashing",
		)
	}
	return packagedJVMBenchmarkArtifactFileIdentity{
		SHA256: hex.EncodeToString(digest.Sum(nil)),
		Device: uint64(before.Dev),
		Inode:  before.Ino,
		Size:   before.Size,
	}, nil
}

func validatePackagedJVMBenchmarkArtifactCICrosslinks(
	artifact packagedJVMBenchmarkArtifact,
	crosslinks packagedJVMBenchmarkArtifactCICrosslinks,
) error {
	if artifact.Source.Dirty || artifact.Source.Revision != crosslinks.Revision {
		return errors.New("packaged JVM benchmark CI source crosslink is invalid")
	}
	if artifact.Runtime.KernelRelease != crosslinks.KernelRelease {
		return errors.New("packaged JVM benchmark CI kernel crosslink is invalid")
	}
	if artifact.Runtime.JavaExecutable != crosslinks.JavaExecutable {
		return errors.New("packaged JVM benchmark CI Java crosslink is invalid")
	}
	if artifact.Inputs.AgentArtifact != crosslinks.AgentArtifact {
		return errors.New("packaged JVM benchmark CI agent artifact crosslink is invalid")
	}
	if artifact.Inputs.TestBinary != crosslinks.TestBinary {
		return errors.New("packaged JVM benchmark CI test binary crosslink is invalid")
	}
	if artifact.Inputs.SockoptBPF != crosslinks.SockoptBPFArtifact {
		return errors.New("packaged JVM benchmark CI sockopt BPF artifact crosslink is invalid")
	}
	if artifact.Inputs.SockopsBPF != crosslinks.SockopsBPFArtifact {
		return errors.New("packaged JVM benchmark CI sockops BPF artifact crosslink is invalid")
	}
	return nil
}

func validatePackagedJVMBenchmarkArtifactV2CICrosslinks(
	artifact packagedJVMBenchmarkArtifactV2,
	crosslinks packagedJVMBenchmarkArtifactCICrosslinks,
) error {
	legacy := packagedJVMBenchmarkArtifact{
		Source:  artifact.Source,
		Inputs:  artifact.Inputs,
		Runtime: artifact.Runtime,
	}
	return validatePackagedJVMBenchmarkArtifactCICrosslinks(legacy, crosslinks)
}

func packagedJVMBenchmarkBlobIdentityAtPath(
	path string,
) (packagedJVMBenchmarkArtifactBlobIdentity, error) {
	identity, err := packagedJVMBenchmarkFileIdentityAtPath(path)
	if err != nil {
		return packagedJVMBenchmarkArtifactBlobIdentity{}, err
	}
	if identity.Size > int64(math.MaxInt) {
		return packagedJVMBenchmarkArtifactBlobIdentity{}, errors.New(
			"packaged JVM benchmark BPF artifact is too large",
		)
	}
	return packagedJVMBenchmarkArtifactBlobIdentity{
		SHA256: identity.SHA256,
		Size:   int(identity.Size),
	}, nil
}

func validatePackagedJVMBenchmarkBlobIdentity(identity packagedJVMBenchmarkArtifactBlobIdentity) error {
	if !isSHA256(identity.SHA256) || identity.Size <= 0 {
		return errors.New("SHA-256 or size is invalid")
	}
	return nil
}

func isSHA256(value string) bool {
	return len(value) == 64 && isLowerHex(value)
}

func isLowerHex(value string) bool {
	digest, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(digest) == value
}

func validatePackagedJVMBenchmarkRuntime(runtime packagedJVMBenchmarkArtifactRuntime) error {
	if !filepath.IsAbs(runtime.JavaExecutable) || filepath.Clean(runtime.JavaExecutable) != runtime.JavaExecutable {
		return errors.New("packaged JVM benchmark Java executable must be an absolute clean path")
	}
	if runtime.JavaVersion == "" || runtime.KernelRelease == "" || runtime.Architecture == "" || runtime.CPUModel == "" {
		return errors.New("packaged JVM benchmark runtime identity is incomplete")
	}
	if runtime.LogicalCPUs <= 0 || runtime.MemoryTotalBytes == 0 {
		return errors.New("packaged JVM benchmark hardware identity is incomplete")
	}
	if runtime.CgroupMode != "v2" || !filepath.IsAbs(runtime.CgroupPath) ||
		filepath.Clean(runtime.CgroupPath) != runtime.CgroupPath {
		return errors.New("packaged JVM benchmark cgroup identity is invalid")
	}
	if runtime.JavaUID != packagedJVMBenchmarkJavaID ||
		runtime.JavaGID != packagedJVMBenchmarkJavaID ||
		runtime.JavaCapabilities != "all_zero" ||
		!runtime.NoNewPrivileges || runtime.BPFDescriptors != 0 {
		return errors.New("packaged JVM benchmark Java privilege identity is invalid")
	}
	return nil
}

func validatePackagedJVMBenchmarkSeries(
	series packagedJVMBenchmarkArtifactSeries,
	expectedOutcome string,
	expectedStatus int,
) error {
	if series.Outcome != expectedOutcome || series.ExpectedStatus != expectedStatus {
		return fmt.Errorf(
			"unexpected identity: got %s/%d, want %s/%d",
			series.Outcome, series.ExpectedStatus, expectedOutcome, expectedStatus,
		)
	}
	if len(series.SamplesNS) != packagedJVMBenchmarkMeasurementIterations {
		return fmt.Errorf("unexpected sample count: %d", len(series.SamplesNS))
	}
	sortedSamples := slices.Clone(series.SamplesNS)
	var total int64
	for _, sample := range sortedSamples {
		if sample <= 0 {
			return fmt.Errorf("non-positive latency sample: %d", sample)
		}
		if sample > math.MaxInt64-total {
			return errors.New("latency sample total overflows int64")
		}
		total += sample
	}
	sort.Slice(sortedSamples, func(i, j int) bool { return sortedSamples[i] < sortedSamples[j] })
	p50 := packagedJVMBenchmarkPercentile(sortedSamples, 50)
	p95 := packagedJVMBenchmarkPercentile(sortedSamples, 95)
	p99 := packagedJVMBenchmarkPercentile(sortedSamples, 99)
	if series.TotalTimedNS != total || series.P50NS != p50 || series.P95NS != p95 || series.P99NS != p99 {
		return errors.New("latency summary does not match retained samples")
	}
	if series.Errors != 0 || series.Valid < 0 || series.Missing < 0 ||
		series.Valid+series.Missing+series.Errors != len(series.SamplesNS) {
		return errors.New("invalid packaged JVM benchmark status counts")
	}
	if (expectedStatus == int(javabridge.StatusValid) &&
		(series.Valid != len(series.SamplesNS) || series.Missing != 0)) ||
		(expectedStatus == int(javabridge.StatusMissing) &&
			(series.Missing != len(series.SamplesNS) || series.Valid != 0)) {
		return errors.New("unexpected packaged JVM benchmark status distribution")
	}
	if !series.Correct {
		return errors.New("packaged JVM benchmark series is not correct")
	}
	if series.LatencyGate.Kind != packagedJVMBenchmarkGateKind ||
		series.LatencyGate.P99MaxNS != packagedJVMBenchmarkP99LimitNS {
		return errors.New("unexpected packaged JVM benchmark latency gate")
	}
	if series.LatencyGate.Passed != (p99 < packagedJVMBenchmarkP99LimitNS) {
		return errors.New("inconsistent packaged JVM benchmark latency gate result")
	}
	return nil
}

func validatePackagedJVMBenchmarkArtifactV2(artifact packagedJVMBenchmarkArtifactV2) error {
	if artifact.SchemaVersion != packagedJVMBenchmarkArtifactV2SchemaVersion ||
		artifact.Benchmark != packagedJVMBenchmarkArtifactV2Name {
		return fmt.Errorf("unexpected packaged JVM benchmark v2 identity: %d/%q", artifact.SchemaVersion, artifact.Benchmark)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, artifact.CreatedAt)
	if err != nil || createdAt.Location() != time.UTC {
		return fmt.Errorf("invalid packaged JVM benchmark v2 creation time: %q", artifact.CreatedAt)
	}
	if artifact.Provenance.Harness != expectedPackagedJVMBenchmarkV2Provenance.Harness ||
		!slices.Equal(artifact.Provenance.Measures, expectedPackagedJVMBenchmarkV2Provenance.Measures) ||
		!slices.Equal(artifact.Provenance.Excludes, expectedPackagedJVMBenchmarkV2Provenance.Excludes) {
		return errors.New("unexpected packaged JVM benchmark v2 provenance")
	}
	expectedUnix := packagedJVMBenchmarkArtifactV2UnixProvenance{
		Server:             "javabridge.NewServer production authenticated Unix server",
		Handler:            "javabridge.NewMapHandler over the benchmark BPF maps",
		Observer:           "ServerOptions.Observe exact operation/status counter",
		TimeoutFixture:     "production Unix server handler waits for the request deadline and returns TIMEOUT after a complete authenticated request",
		SocketPathRetained: false,
	}
	if artifact.Provenance.Unix != expectedUnix {
		return errors.New("unexpected packaged JVM benchmark v2 Unix provenance")
	}
	if err := validatePackagedJVMBenchmarkSource(artifact.Source); err != nil {
		return err
	}
	if err := validatePackagedJVMBenchmarkInputs(artifact.Inputs); err != nil {
		return err
	}
	if err := validatePackagedJVMBenchmarkRuntime(artifact.Runtime); err != nil {
		return err
	}
	if err := validatePackagedJVMBenchmarkCgroupBPFV2(
		artifact.Provenance.CgroupBPF, artifact.Runtime.CgroupPath,
	); err != nil {
		return err
	}
	totalCalls := packagedJVMBenchmarkV2Concurrency *
		(packagedJVMBenchmarkWarmupIterations + packagedJVMBenchmarkMeasurementIterations)
	expectedSetup := packagedJVMBenchmarkArtifactV2Setup{
		WarmupBatches:          packagedJVMBenchmarkWarmupIterations,
		MeasurementBatches:     packagedJVMBenchmarkMeasurementIterations,
		Concurrency:            packagedJVMBenchmarkV2Concurrency,
		RetainedCallsPerSeries: packagedJVMBenchmarkV2Concurrency * packagedJVMBenchmarkMeasurementIterations,
		TotalCallsPerSeries:    totalCalls,
		BatchSynchronization:   "eight fixed worker threads stage authority, rendezvous, then share one release latch",
		RawTimedCall:           "System.nanoTime and ThreadMXBean around BootstrapNative.takeRemoteParent(fd-or-minus-one,reused_byte_array)",
		ProviderTimedCall:      "System.nanoTime and ThreadMXBean around RemoteParentBridge.takeRemoteParent()",
		ResponseStorage:        "one reused 64-byte JNI response array per worker; provider uses its packaged pool",
		AllocationMeasurement:  "com.sun.management.ThreadMXBean.getThreadAllocatedBytes keyed by the calling worker Java Thread.getId before and after the timed call",
		AllocationControl:      "paired same-worker consecutive ThreadMXBean counter reads immediately before each call; retained separately without net-allocation claim",
		AgentOptions:           packagedJVMBenchmarkAgentOptions,
		PrimaryMissControl:     packagedJVMBenchmarkMissControl,
		UnixMissControl:        "no staged owner generation for the exact authenticated worker TID; production MapHandler returns missing",
		UnixTimeoutDeadlineNS:  int64(packagedJVMBenchmarkV2TimeoutMillis * time.Millisecond),
		RetrievalTTLNS:         packagedJVMBenchmarkRetrievalTTL.Nanoseconds(),
		StaleAgeNS:             packagedJVMBenchmarkStaleAge.Nanoseconds(),
		UnixServerUID:          0,
		UnixSocketGID:          packagedJVMBenchmarkJavaID,
		UnixMaxConcurrent:      packagedJVMBenchmarkV2Concurrency * 4,
		AgentArtifactBinding:   packagedJVMBenchmarkAgentBinding,
		JVMArguments: []string{
			"-javaagent:<agent-artifact-fd>=remoteParentTransport=disabled", "-cp",
			"<agent-artifact-fd>", packagedJVMBenchmarkProbeClass,
			"<host> <process-capability> <warmup-batches> <measurement-batches> <workers>",
		},
		Environment: slices.Clone(expectedPackagedJVMBenchmarkEnvironment),
	}
	if !packagedJVMBenchmarkV2SetupEqual(artifact.Setup, expectedSetup) {
		return errors.New("unexpected packaged JVM benchmark v2 setup")
	}
	if len(artifact.Series) != len(packagedJVMBenchmarkV2SeriesSpecs) {
		return fmt.Errorf("unexpected packaged JVM benchmark v2 series count: %d", len(artifact.Series))
	}
	for index, spec := range packagedJVMBenchmarkV2SeriesSpecs {
		if err := validatePackagedJVMBenchmarkSeriesV2(artifact.Series[index], spec); err != nil {
			return fmt.Errorf("packaged JVM benchmark v2 series %d: %w", index, err)
		}
	}
	return nil
}

func packagedJVMBenchmarkV2SetupEqual(
	actual packagedJVMBenchmarkArtifactV2Setup,
	expected packagedJVMBenchmarkArtifactV2Setup,
) bool {
	return actual.WarmupBatches == expected.WarmupBatches &&
		actual.MeasurementBatches == expected.MeasurementBatches &&
		actual.Concurrency == expected.Concurrency &&
		actual.RetainedCallsPerSeries == expected.RetainedCallsPerSeries &&
		actual.TotalCallsPerSeries == expected.TotalCallsPerSeries &&
		actual.BatchSynchronization == expected.BatchSynchronization &&
		actual.RawTimedCall == expected.RawTimedCall &&
		actual.ProviderTimedCall == expected.ProviderTimedCall &&
		actual.ResponseStorage == expected.ResponseStorage &&
		actual.AllocationMeasurement == expected.AllocationMeasurement &&
		actual.AllocationControl == expected.AllocationControl &&
		actual.AgentOptions == expected.AgentOptions &&
		actual.PrimaryMissControl == expected.PrimaryMissControl &&
		actual.UnixMissControl == expected.UnixMissControl &&
		actual.UnixTimeoutDeadlineNS == expected.UnixTimeoutDeadlineNS &&
		actual.RetrievalTTLNS == expected.RetrievalTTLNS &&
		actual.StaleAgeNS == expected.StaleAgeNS &&
		actual.UnixServerUID == expected.UnixServerUID &&
		actual.UnixSocketGID == expected.UnixSocketGID &&
		actual.UnixMaxConcurrent == expected.UnixMaxConcurrent &&
		actual.AgentArtifactBinding == expected.AgentArtifactBinding &&
		slices.Equal(actual.JVMArguments, expected.JVMArguments) &&
		slices.Equal(actual.Environment, expected.Environment)
}

func validatePackagedJVMBenchmarkCgroupBPFV2(
	cgroup packagedJVMBenchmarkArtifactV2CgroupBPF,
	target string,
) error {
	totalBatches := len(packagedJVMBenchmarkV2SeriesSpecs) *
		(packagedJVMBenchmarkWarmupIterations + packagedJVMBenchmarkMeasurementIterations)
	totalCalls := packagedJVMBenchmarkV2Concurrency *
		(packagedJVMBenchmarkWarmupIterations + packagedJVMBenchmarkMeasurementIterations)
	primarySeries := 0
	for _, spec := range packagedJVMBenchmarkV2SeriesSpecs {
		if spec.Transport == "getsockopt" {
			primarySeries++
		}
	}
	checks := cgroup.StabilityChecks
	if checks.ExpectedBatches != totalBatches ||
		checks.ExpectedPrimaryCalls != primarySeries*totalCalls ||
		checks.ObservedPreBatchSnapshots != totalBatches ||
		checks.ObservedPostBatchSnapshots != totalBatches ||
		checks.QueryErrors != 0 || checks.TopologyMismatches != 0 {
		return errors.New("packaged JVM benchmark v2 BPF stability checks are incomplete or failed")
	}
	legacy := packagedJVMBenchmarkArtifactCgroupBPF{
		TargetCgroup:             cgroup.TargetCgroup,
		CgroupHierarchy:          cgroup.CgroupHierarchy,
		EffectiveQueryFlag:       cgroup.EffectiveQueryFlag,
		EffectiveQueryFlags:      cgroup.EffectiveQueryFlags,
		PreAttachChainsEmpty:     cgroup.PreAttachChainsEmpty,
		StabilityMode:            cgroup.StabilityMode,
		StabilityEvidence:        cgroup.StabilityEvidence,
		ExclusiveTopologyPremise: cgroup.ExclusiveTopologyPremise,
		StabilityChecks: packagedJVMBenchmarkArtifactStabilityChecks{
			ExpectedCalls:             totalBatches,
			ObservedPreCallSnapshots:  checks.ObservedPreBatchSnapshots,
			ObservedPostCallSnapshots: checks.ObservedPostBatchSnapshots,
			QueryErrors:               checks.QueryErrors,
			TopologyMismatches:        checks.TopologyMismatches,
		},
		Chains: cgroup.Chains,
	}
	return validatePackagedJVMBenchmarkCgroupBPFAttributionTopology(legacy, target)
}

func validatePackagedJVMBenchmarkSeriesV2(
	series packagedJVMBenchmarkArtifactV2Series,
	spec packagedJVMBenchmarkV2SeriesSpec,
) error {
	if series.Scope != spec.Scope || series.Transport != spec.Transport ||
		series.Outcome != spec.Outcome || series.ExpectedStatus != spec.ExpectedStatus {
		return fmt.Errorf("unexpected identity: got %s/%s/%s/%d", series.Scope, series.Transport, series.Outcome, series.ExpectedStatus)
	}
	retainedCalls := packagedJVMBenchmarkV2Concurrency * packagedJVMBenchmarkMeasurementIterations
	if len(series.SamplesNS) != retainedCalls ||
		len(series.Allocation.SamplesBytes) != retainedCalls ||
		len(series.Allocation.ControlSamplesBytes) != retainedCalls {
		return errors.New("unexpected packaged JVM benchmark v2 retained sample count")
	}
	if err := validatePackagedJVMBenchmarkV2Summary(
		series.SamplesNS, true, series.TotalTimedNS, series.P50NS, series.P95NS, series.P99NS,
	); err != nil {
		return fmt.Errorf("latency: %w", err)
	}
	if series.Allocation.Method != "com.sun.management.ThreadMXBean.getThreadAllocatedBytes" ||
		series.Allocation.Control != "paired consecutive counter reads on the same worker" {
		return errors.New("unexpected packaged JVM benchmark v2 allocation method")
	}
	if err := validatePackagedJVMBenchmarkV2Summary(
		series.Allocation.SamplesBytes, false, series.Allocation.TotalBytes,
		series.Allocation.P50Bytes, series.Allocation.P95Bytes, series.Allocation.P99Bytes,
	); err != nil {
		return fmt.Errorf("allocation: %w", err)
	}
	if err := validatePackagedJVMBenchmarkV2Summary(
		series.Allocation.ControlSamplesBytes, false, series.Allocation.ControlTotalBytes,
		series.Allocation.ControlP50Bytes, series.Allocation.ControlP95Bytes,
		series.Allocation.ControlP99Bytes,
	); err != nil {
		return fmt.Errorf("allocation control: %w", err)
	}
	totalCalls := packagedJVMBenchmarkV2Concurrency *
		(packagedJVMBenchmarkWarmupIterations + packagedJVMBenchmarkMeasurementIterations)
	if series.Statuses.total() != totalCalls ||
		packagedJVMBenchmarkV2StatusCount(series.Statuses, spec.ExpectedStatus) != totalCalls {
		return errors.New("unexpected packaged JVM benchmark v2 status distribution")
	}
	expectedBridge := 0
	if spec.Scope == "bridge_provider_jni" {
		expectedBridge = totalCalls
	}
	expectedPrimary := 0
	if spec.Transport == "getsockopt" {
		expectedPrimary = totalCalls
	}
	expectedServer := 0
	if spec.Transport == "unix" && spec.Outcome != "timeout" {
		expectedServer = totalCalls
	}
	expectedTimeout := 0
	if spec.Outcome == "timeout" {
		expectedTimeout = totalCalls
	}
	expectedCalls := packagedJVMBenchmarkArtifactV2Calls{
		ExpectedJavaCalls:           totalCalls,
		ObservedJavaCalls:           totalCalls,
		ExpectedNativeCalls:         totalCalls,
		ObservedNativeCalls:         totalCalls,
		ExpectedBridgeCalls:         expectedBridge,
		ObservedBridgeCalls:         expectedBridge,
		ExpectedPrimaryBPFCalls:     expectedPrimary,
		ObservedPrimaryBPFCalls:     expectedPrimary,
		PrimaryBPFStatus:            "not_applicable",
		ExpectedUnixServerRequests:  expectedServer,
		ObservedUnixServerRequests:  expectedServer,
		UnixServerStatus:            "not_applicable",
		ExpectedTimeoutFullRequests: expectedTimeout,
		ObservedTimeoutFullRequests: expectedTimeout,
	}
	if expectedPrimary != 0 {
		expectedCalls.PrimaryBPFStatus = javabridge.Status(spec.ExpectedStatus).String()
		expectedCalls.PrimaryBPFStatusBefore = series.Calls.PrimaryBPFStatusBefore
		expectedCalls.PrimaryBPFStatusAfter = series.Calls.PrimaryBPFStatusAfter
		if series.Calls.PrimaryBPFStatusAfter < series.Calls.PrimaryBPFStatusBefore ||
			series.Calls.PrimaryBPFStatusAfter-series.Calls.PrimaryBPFStatusBefore != uint64(expectedPrimary) {
			return errors.New("packaged JVM benchmark v2 primary BPF status delta is inconsistent")
		}
	}
	if expectedServer != 0 || expectedTimeout != 0 {
		expectedCalls.UnixServerStatus = javabridge.Status(spec.ExpectedStatus).String()
		expectedCalls.UnixServerStatusBefore = series.Calls.UnixServerStatusBefore
		expectedCalls.UnixServerStatusAfter = series.Calls.UnixServerStatusAfter
		expectedDelta := expectedServer + expectedTimeout
		if series.Calls.UnixServerStatusAfter < series.Calls.UnixServerStatusBefore ||
			series.Calls.UnixServerStatusAfter-series.Calls.UnixServerStatusBefore != uint64(expectedDelta) {
			return errors.New("packaged JVM benchmark v2 Unix server status delta is inconsistent")
		}
	}
	if series.Calls != expectedCalls {
		return errors.New("packaged JVM benchmark v2 call deltas are incomplete or inconsistent")
	}
	if !series.Correct {
		return errors.New("packaged JVM benchmark v2 series is not correct")
	}
	expectedGate := packagedJVMBenchmarkV2Gate(spec, series.P50NS, series.P99NS)
	if series.LatencyGate != expectedGate {
		return errors.New("inconsistent packaged JVM benchmark v2 latency gate")
	}
	return nil
}

func validatePackagedJVMBenchmarkV2Summary(
	samples []int64,
	positive bool,
	total int64,
	p50 int64,
	p95 int64,
	p99 int64,
) error {
	var recomputed int64
	for _, sample := range samples {
		if sample < 0 || (positive && sample == 0) {
			return fmt.Errorf("invalid retained sample: %d", sample)
		}
		if sample > math.MaxInt64-recomputed {
			return errors.New("retained sample total overflows int64")
		}
		recomputed += sample
	}
	sorted := slices.Clone(samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	if total != recomputed || p50 != packagedJVMBenchmarkPercentile(sorted, 50) ||
		p95 != packagedJVMBenchmarkPercentile(sorted, 95) ||
		p99 != packagedJVMBenchmarkPercentile(sorted, 99) {
		return errors.New("summary does not match retained samples")
	}
	return nil
}

func packagedJVMBenchmarkV2StatusCount(
	counts packagedJVMBenchmarkArtifactV2Statuses,
	status int,
) int {
	switch javabridge.Status(status) {
	case javabridge.StatusUnknown:
		return counts.Unknown
	case javabridge.StatusValid:
		return counts.Valid
	case javabridge.StatusMissing:
		return counts.Missing
	case javabridge.StatusStale:
		return counts.Stale
	case javabridge.StatusUnsupported:
		return counts.Unsupported
	case javabridge.StatusMalformed:
		return counts.Malformed
	case javabridge.StatusVersionMismatch:
		return counts.VersionMismatch
	case javabridge.StatusAmbiguous:
		return counts.Ambiguous
	case javabridge.StatusUnauthorized:
		return counts.Unauthorized
	case javabridge.StatusAlreadyConsumed:
		return counts.AlreadyConsumed
	case javabridge.StatusTimeout:
		return counts.Timeout
	case javabridge.StatusOverload:
		return counts.Overload
	case javabridge.StatusTransportError:
		return counts.TransportError
	case javabridge.StatusDisabled:
		return counts.Disabled
	default:
		return -1
	}
}

func writePackagedJVMBenchmarkArtifactV2(
	artifactPath string,
	artifact packagedJVMBenchmarkArtifactV2,
) error {
	if err := validatePackagedJVMBenchmarkArtifactV2(artifact); err != nil {
		return err
	}
	payload, err := json.Marshal(artifact)
	if err != nil {
		return fmt.Errorf("marshal packaged JVM benchmark v2 artifact: %w", err)
	}
	payload = append(payload, '\n')
	if len(payload) > packagedJVMBenchmarkV2MaxArtifactBytes {
		return errors.New("packaged JVM benchmark v2 artifact is too large")
	}

	directoryFD, artifactName, err := openBenchmarkArtifactDirectory(artifactPath)
	if err != nil {
		return err
	}
	defer unix.Close(directoryFD)
	temporary, temporaryName, err := createBenchmarkArtifactTemporary(directoryFD)
	if err != nil {
		return err
	}
	temporaryClosed := false
	published := false
	defer func() {
		if !temporaryClosed {
			_ = temporary.Close()
		}
		if !published {
			_ = unix.Unlinkat(directoryFD, temporaryName, 0)
		}
	}()
	if _, err := temporary.Write(payload); err != nil {
		return fmt.Errorf("write packaged JVM benchmark v2 artifact: %w", err)
	}
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set packaged JVM benchmark v2 artifact permissions: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync packaged JVM benchmark v2 artifact: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close packaged JVM benchmark v2 artifact: %w", err)
	}
	temporaryClosed = true
	if err := unix.Linkat(directoryFD, temporaryName, directoryFD, artifactName, 0); err != nil {
		return fmt.Errorf("publish packaged JVM benchmark v2 artifact: %w", err)
	}
	published = true
	_ = unix.Unlinkat(directoryFD, temporaryName, 0)
	return unix.Fsync(directoryFD)
}

func writePackagedJVMBenchmarkArtifact(
	artifactPath string,
	artifact packagedJVMBenchmarkArtifact,
) error {
	if err := validatePackagedJVMBenchmarkArtifact(artifact); err != nil {
		return err
	}
	payload, err := json.Marshal(artifact)
	if err != nil {
		return fmt.Errorf("marshal packaged JVM benchmark artifact: %w", err)
	}
	payload = append(payload, '\n')
	if len(payload) > packagedJVMBenchmarkMaxArtifactBytes {
		return errors.New("packaged JVM benchmark artifact is too large")
	}

	directoryFD, artifactName, err := openBenchmarkArtifactDirectory(artifactPath)
	if err != nil {
		return err
	}
	defer unix.Close(directoryFD)

	temporary, temporaryName, err := createBenchmarkArtifactTemporary(directoryFD)
	if err != nil {
		return err
	}
	temporaryClosed := false
	published := false
	defer func() {
		if !temporaryClosed {
			_ = temporary.Close()
		}
		if !published {
			_ = unix.Unlinkat(directoryFD, temporaryName, 0)
		}
	}()

	if _, err := temporary.Write(payload); err != nil {
		return fmt.Errorf("write packaged JVM benchmark artifact: %w", err)
	}
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set packaged JVM benchmark artifact permissions: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync packaged JVM benchmark artifact: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close packaged JVM benchmark artifact: %w", err)
	}
	temporaryClosed = true
	if err := unix.Linkat(directoryFD, temporaryName, directoryFD, artifactName, 0); err != nil {
		return fmt.Errorf("publish packaged JVM benchmark artifact: %w", err)
	}
	published = true
	_ = unix.Unlinkat(directoryFD, temporaryName, 0)
	if err := unix.Fsync(directoryFD); err != nil {
		return fmt.Errorf("sync packaged JVM benchmark artifact directory: %w", err)
	}
	return nil
}

func decodePackagedJVMBenchmarkArtifact(input io.Reader) (packagedJVMBenchmarkArtifact, error) {
	payload, err := io.ReadAll(io.LimitReader(input, packagedJVMBenchmarkMaxArtifactBytes+1))
	if err != nil {
		return packagedJVMBenchmarkArtifact{}, fmt.Errorf("read packaged JVM benchmark artifact: %w", err)
	}
	if len(payload) > packagedJVMBenchmarkMaxArtifactBytes {
		return packagedJVMBenchmarkArtifact{}, errors.New("packaged JVM benchmark artifact is too large")
	}
	if err := validatePackagedJVMBenchmarkJSONSchema(payload); err != nil {
		return packagedJVMBenchmarkArtifact{}, err
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var artifact packagedJVMBenchmarkArtifact
	if err := decoder.Decode(&artifact); err != nil {
		return artifact, fmt.Errorf("decode packaged JVM benchmark artifact: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return artifact, errors.New("packaged JVM benchmark artifact has trailing JSON")
	}
	if err := validatePackagedJVMBenchmarkArtifact(artifact); err != nil {
		return artifact, err
	}
	return artifact, nil
}

func decodePackagedJVMBenchmarkArtifactV2(
	input io.Reader,
) (packagedJVMBenchmarkArtifactV2, error) {
	payload, err := io.ReadAll(io.LimitReader(input, packagedJVMBenchmarkV2MaxArtifactBytes+1))
	if err != nil {
		return packagedJVMBenchmarkArtifactV2{}, fmt.Errorf("read packaged JVM benchmark v2 artifact: %w", err)
	}
	if len(payload) > packagedJVMBenchmarkV2MaxArtifactBytes {
		return packagedJVMBenchmarkArtifactV2{}, errors.New("packaged JVM benchmark v2 artifact is too large")
	}
	if err := validatePackagedJVMBenchmarkV2UniqueJSON(payload); err != nil {
		return packagedJVMBenchmarkArtifactV2{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var artifact packagedJVMBenchmarkArtifactV2
	if err := decoder.Decode(&artifact); err != nil {
		return artifact, fmt.Errorf("decode packaged JVM benchmark v2 artifact: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return artifact, errors.New("packaged JVM benchmark v2 artifact has trailing JSON")
	}
	if err := validatePackagedJVMBenchmarkArtifactV2(artifact); err != nil {
		return artifact, err
	}
	return artifact, nil
}

func validatePackagedJVMBenchmarkV2UniqueJSON(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := consumePackagedJVMBenchmarkJSONValue(
		decoder, packagedJVMBenchmarkV2JSONSchema(), "$",
	); err != nil {
		return fmt.Errorf("validate packaged JVM benchmark v2 JSON: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("packaged JVM benchmark v2 artifact has trailing JSON")
		}
		return fmt.Errorf("inspect packaged JVM benchmark v2 trailing JSON: %w", err)
	}
	return nil
}

func packagedJVMBenchmarkV2JSONSchema() *packagedJVMBenchmarkJSONSchema {
	return packagedJVMBenchmarkV2JSONSchemaForType(
		reflect.TypeOf(packagedJVMBenchmarkArtifactV2{}),
	)
}

func packagedJVMBenchmarkV2JSONSchemaForType(
	typeOf reflect.Type,
) *packagedJVMBenchmarkJSONSchema {
	switch typeOf.Kind() {
	case reflect.String:
		return &packagedJVMBenchmarkJSONSchema{kind: packagedJVMBenchmarkJSONString}
	case reflect.Bool:
		return &packagedJVMBenchmarkJSONSchema{kind: packagedJVMBenchmarkJSONBoolean}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return &packagedJVMBenchmarkJSONSchema{kind: packagedJVMBenchmarkJSONNumber}
	case reflect.Slice, reflect.Array:
		return &packagedJVMBenchmarkJSONSchema{
			kind:    packagedJVMBenchmarkJSONKindArray,
			element: packagedJVMBenchmarkV2JSONSchemaForType(typeOf.Elem()),
		}
	case reflect.Struct:
		fields := make(map[string]*packagedJVMBenchmarkJSONSchema, typeOf.NumField())
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
			if name == "" {
				name = field.Name
			}
			if name == "-" {
				continue
			}
			fields[name] = packagedJVMBenchmarkV2JSONSchemaForType(field.Type)
		}
		return &packagedJVMBenchmarkJSONSchema{
			kind:   packagedJVMBenchmarkJSONKindObject,
			fields: fields,
		}
	default:
		panic(fmt.Sprintf("unsupported packaged JVM benchmark v2 JSON type %s", typeOf))
	}
}

type packagedJVMBenchmarkJSONKind uint8

const (
	packagedJVMBenchmarkJSONString packagedJVMBenchmarkJSONKind = iota + 1
	packagedJVMBenchmarkJSONNumber
	packagedJVMBenchmarkJSONBoolean
	packagedJVMBenchmarkJSONKindObject
	packagedJVMBenchmarkJSONKindArray
)

type packagedJVMBenchmarkJSONSchema struct {
	kind    packagedJVMBenchmarkJSONKind
	fields  map[string]*packagedJVMBenchmarkJSONSchema
	element *packagedJVMBenchmarkJSONSchema
}

func validatePackagedJVMBenchmarkJSONSchema(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := consumePackagedJVMBenchmarkJSONValue(
		decoder, packagedJVMBenchmarkArtifactJSONSchema(), "$",
	); err != nil {
		return fmt.Errorf("validate packaged JVM benchmark JSON schema: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("packaged JVM benchmark artifact has trailing JSON")
		}
		return fmt.Errorf("inspect packaged JVM benchmark trailing JSON: %w", err)
	}
	return nil
}

func consumePackagedJVMBenchmarkJSONValue(
	decoder *json.Decoder,
	schema *packagedJVMBenchmarkJSONSchema,
	path string,
) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("%s must not be null", path)
	}
	switch schema.kind {
	case packagedJVMBenchmarkJSONString:
		if _, ok := token.(string); !ok {
			return fmt.Errorf("%s must be a JSON string", path)
		}
		return nil
	case packagedJVMBenchmarkJSONNumber:
		if _, ok := token.(json.Number); !ok {
			return fmt.Errorf("%s must be a JSON number", path)
		}
		return nil
	case packagedJVMBenchmarkJSONBoolean:
		if _, ok := token.(bool); !ok {
			return fmt.Errorf("%s must be a JSON boolean", path)
		}
		return nil
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return fmt.Errorf("%s must be a JSON container", path)
	}
	switch schema.kind {
	case packagedJVMBenchmarkJSONKindObject:
		if delimiter != json.Delim('{') {
			return fmt.Errorf("%s must be a JSON object", path)
		}
		names := map[string]struct{}{}
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return errors.New("JSON object name is not a string")
			}
			fieldSchema, expected := schema.fields[name]
			if !expected {
				for canonicalName := range schema.fields {
					if strings.EqualFold(name, canonicalName) {
						return fmt.Errorf(
							"%s has noncanonical JSON name %q; expected %q",
							path, name, canonicalName,
						)
					}
				}
				return fmt.Errorf("%s has unknown field %q", path, name)
			}
			if _, exists := names[name]; exists {
				return fmt.Errorf("%s has duplicate JSON name %q", path, name)
			}
			names[name] = struct{}{}
			if err := consumePackagedJVMBenchmarkJSONValue(
				decoder, fieldSchema, path+"."+name,
			); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("JSON object has an invalid closing delimiter")
		}
		for name := range schema.fields {
			if _, present := names[name]; !present {
				return fmt.Errorf("%s is missing required field %q", path, name)
			}
		}
	case packagedJVMBenchmarkJSONKindArray:
		if delimiter != json.Delim('[') {
			return fmt.Errorf("%s must be a JSON array", path)
		}
		index := 0
		for decoder.More() {
			if err := consumePackagedJVMBenchmarkJSONValue(
				decoder, schema.element, fmt.Sprintf("%s[%d]", path, index),
			); err != nil {
				return err
			}
			index++
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("JSON array has an invalid closing delimiter")
		}
	default:
		return fmt.Errorf("%s has unsupported JSON schema kind %d", path, schema.kind)
	}
	return nil
}

func packagedJVMBenchmarkArtifactJSONSchema() *packagedJVMBenchmarkJSONSchema {
	stringValue := &packagedJVMBenchmarkJSONSchema{kind: packagedJVMBenchmarkJSONString}
	numberValue := &packagedJVMBenchmarkJSONSchema{kind: packagedJVMBenchmarkJSONNumber}
	booleanValue := &packagedJVMBenchmarkJSONSchema{kind: packagedJVMBenchmarkJSONBoolean}
	stringArray := &packagedJVMBenchmarkJSONSchema{
		kind:    packagedJVMBenchmarkJSONKindArray,
		element: stringValue,
	}
	fileIdentity := jsonObjectSchema(map[string]*packagedJVMBenchmarkJSONSchema{
		"sha256": stringValue,
		"device": numberValue,
		"inode":  numberValue,
		"size":   numberValue,
	})
	blobIdentity := jsonObjectSchema(map[string]*packagedJVMBenchmarkJSONSchema{
		"sha256": stringValue,
		"size":   numberValue,
	})
	latencyGate := jsonObjectSchema(map[string]*packagedJVMBenchmarkJSONSchema{
		"kind":       stringValue,
		"p99_max_ns": numberValue,
		"passed":     booleanValue,
	})
	series := jsonObjectSchema(map[string]*packagedJVMBenchmarkJSONSchema{
		"outcome":         stringValue,
		"expected_status": numberValue,
		"samples_ns": {
			kind:    packagedJVMBenchmarkJSONKindArray,
			element: numberValue,
		},
	})
	for _, field := range []string{
		"total_timed_ns", "p50_ns", "p95_ns", "p99_ns", "valid", "missing", "errors",
	} {
		series.fields[field] = numberValue
	}
	series.fields["correct"] = booleanValue
	series.fields["latency_gate"] = latencyGate
	bpfProgram := jsonObjectSchema(map[string]*packagedJVMBenchmarkJSONSchema{
		"id":           numberValue,
		"tag":          stringValue,
		"name":         stringValue,
		"program_type": stringValue,
	})
	bpfProgramArray := &packagedJVMBenchmarkJSONSchema{
		kind:    packagedJVMBenchmarkJSONKindArray,
		element: bpfProgram,
	}
	cgroupTopology := jsonObjectSchema(map[string]*packagedJVMBenchmarkJSONSchema{
		"cgroup_path":               stringValue,
		"direct_revision_supported": booleanValue,
		"direct_revision":           numberValue,
		"direct_programs":           bpfProgramArray,
	})
	cgroupChain := jsonObjectSchema(map[string]*packagedJVMBenchmarkJSONSchema{
		"attach_type":                  stringValue,
		"intended_program":             bpfProgram,
		"effective_revision_supported": booleanValue,
		"effective_revision":           numberValue,
		"effective_programs":           bpfProgramArray,
		"topology": {
			kind:    packagedJVMBenchmarkJSONKindArray,
			element: cgroupTopology,
		},
	})
	stabilityChecks := jsonObjectSchema(map[string]*packagedJVMBenchmarkJSONSchema{
		"expected_calls":               numberValue,
		"observed_pre_call_snapshots":  numberValue,
		"observed_post_call_snapshots": numberValue,
		"query_errors":                 numberValue,
		"topology_mismatches":          numberValue,
	})
	cgroupBPF := jsonObjectSchema(map[string]*packagedJVMBenchmarkJSONSchema{
		"target_cgroup":              stringValue,
		"cgroup_hierarchy":           stringArray,
		"effective_query_flag":       stringValue,
		"effective_query_flags":      numberValue,
		"pre_attach_chains_empty":    booleanValue,
		"stability_mode":             stringValue,
		"stability_evidence":         stringValue,
		"exclusive_topology_premise": stringValue,
		"stability_checks":           stabilityChecks,
		"chains": {
			kind:    packagedJVMBenchmarkJSONKindArray,
			element: cgroupChain,
		},
	})

	return jsonObjectSchema(map[string]*packagedJVMBenchmarkJSONSchema{
		"schema_version": numberValue,
		"benchmark":      stringValue,
		"created_at":     stringValue,
		"provenance": jsonObjectSchema(map[string]*packagedJVMBenchmarkJSONSchema{
			"harness":    stringValue,
			"measures":   stringArray,
			"excludes":   stringArray,
			"cgroup_bpf": cgroupBPF,
		}),
		"source": jsonObjectSchema(map[string]*packagedJVMBenchmarkJSONSchema{
			"revision":      stringValue,
			"dirty":         booleanValue,
			"status_sha256": stringValue,
			"patch_sha256":  stringValue,
		}),
		"inputs": jsonObjectSchema(map[string]*packagedJVMBenchmarkJSONSchema{
			"go_toolchain":   stringValue,
			"test_binary":    fileIdentity,
			"agent_artifact": fileIdentity,
			"sockopt_bpf":    blobIdentity,
			"sockops_bpf":    blobIdentity,
		}),
		"runtime": jsonObjectSchema(map[string]*packagedJVMBenchmarkJSONSchema{
			"java_executable":    stringValue,
			"java_version":       stringValue,
			"kernel_release":     stringValue,
			"architecture":       stringValue,
			"cpu_model":          stringValue,
			"logical_cpus":       numberValue,
			"memory_total_bytes": numberValue,
			"cgroup_mode":        stringValue,
			"cgroup_path":        stringValue,
			"java_uid":           numberValue,
			"java_gid":           numberValue,
			"java_capabilities":  stringValue,
			"no_new_privileges":  booleanValue,
			"bpf_descriptors":    numberValue,
		}),
		"setup": jsonObjectSchema(map[string]*packagedJVMBenchmarkJSONSchema{
			"warmup_iterations":      numberValue,
			"measurement_iterations": numberValue,
			"concurrency":            numberValue,
			"timed_call":             stringValue,
			"response_storage":       stringValue,
			"agent_options":          stringValue,
			"miss_control":           stringValue,
			"agent_artifact_binding": stringValue,
			"jvm_arguments":          stringArray,
			"environment":            stringArray,
		}),
		"series": &packagedJVMBenchmarkJSONSchema{
			kind:    packagedJVMBenchmarkJSONKindArray,
			element: series,
		},
	})
}

func jsonObjectSchema(
	fields map[string]*packagedJVMBenchmarkJSONSchema,
) *packagedJVMBenchmarkJSONSchema {
	return &packagedJVMBenchmarkJSONSchema{
		kind:   packagedJVMBenchmarkJSONKindObject,
		fields: fields,
	}
}

func TestPackagedJVMBenchmarkArtifactRoundTrip(t *testing.T) {
	artifact := validPackagedJVMBenchmarkArtifact()
	artifactPath := filepath.Join(t.TempDir(), "packaged-jvm-benchmark.json")
	require.NoError(t, writePackagedJVMBenchmarkArtifact(artifactPath, artifact))

	contents, err := os.ReadFile(artifactPath)
	require.NoError(t, err)
	require.True(t, bytes.HasSuffix(contents, []byte{'\n'}))
	decoded, err := decodePackagedJVMBenchmarkArtifact(bytes.NewReader(contents))
	require.NoError(t, err)
	require.Equal(t, artifact, decoded)
	info, err := os.Stat(artifactPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestPackagedJVMBenchmarkArtifactRetainsFailedGate(t *testing.T) {
	artifact := validPackagedJVMBenchmarkArtifact()
	slow := make([]int64, packagedJVMBenchmarkMeasurementIterations)
	for index := range slow {
		slow[index] = packagedJVMBenchmarkP99LimitNS + int64(index+1)
	}
	artifact.Series[0] = summarizePackagedJVMBenchmarkSeries(
		"miss", int(javabridge.StatusMissing), slow,
	)
	require.False(t, artifact.Series[0].LatencyGate.Passed)
	require.NoError(t, validatePackagedJVMBenchmarkArtifact(artifact))

	artifactPath := filepath.Join(t.TempDir(), "failed-packaged-jvm-benchmark.json")
	require.NoError(t, writePackagedJVMBenchmarkArtifact(artifactPath, artifact))
	contents, err := os.ReadFile(artifactPath)
	require.NoError(t, err)
	decoded, err := decodePackagedJVMBenchmarkArtifact(bytes.NewReader(contents))
	require.NoError(t, err)
	require.False(t, decoded.Series[0].LatencyGate.Passed)
}

func TestPackagedJVMBenchmarkArtifactWriterRejectsOversizedPayloadBeforePublication(
	t *testing.T,
) {
	artifact := validPackagedJVMBenchmarkArtifact()
	artifact.Runtime.JavaVersion = strings.Repeat("x", packagedJVMBenchmarkMaxArtifactBytes)
	directory := t.TempDir()
	artifactPath := filepath.Join(directory, "oversized-packaged-jvm-benchmark.json")

	err := writePackagedJVMBenchmarkArtifact(artifactPath, artifact)
	require.ErrorContains(t, err, "artifact is too large")
	_, statErr := os.Stat(artifactPath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
	entries, readErr := os.ReadDir(directory)
	require.NoError(t, readErr)
	require.Empty(t, entries)
}

func TestPackagedJVMBenchmarkEnvironmentIsMinimal(t *testing.T) {
	environment, err := packagedJVMBenchmarkEnvironment([]string{
		"PATH=/attacker-controlled",
		"UNRELATED=value=with=equals",
		javaRemoteParentPackagedJVMBenchmarkExclusiveCgroupBPFEnv + "=" + packagedJVMBenchmarkExclusiveTopologyPremise,
	})
	require.NoError(t, err)
	require.Equal(t, expectedPackagedJVMBenchmarkEnvironment, environment)

	for _, value := range environment {
		name, _, found := strings.Cut(value, "=")
		require.True(t, found)
		_, forbidden := forbiddenPackagedJVMBenchmarkEnvironment[name]
		require.Falsef(t, forbidden, "minimal environment contains forbidden variable %s", name)
	}
}

func TestPackagedJVMBenchmarkShellInvocationPreservesMulticallApplet(t *testing.T) {
	directory := t.TempDir()
	shellPath, err := exec.LookPath("sh")
	require.NoError(t, err)
	shell, err := bindPackagedJVMBenchmarkExecutable(shellPath)
	require.NoError(t, err)
	invocationLink := filepath.Join(directory, "sh")
	require.NoError(t, os.Symlink(shell.ResolvedPath, invocationLink))

	binding, err := bindPackagedJVMBenchmarkExecutable(invocationLink)
	require.NoError(t, err)
	require.Equal(t, invocationLink, binding.InvocationPath)
	require.Equal(t, shell.ResolvedPath, binding.ResolvedPath)

	retarget := filepath.Join(directory, "retarget")
	require.NoError(t, os.WriteFile(retarget, []byte("#!/bin/sh\nexit 99\n"), 0o700))
	require.NoError(t, os.Remove(invocationLink))
	require.NoError(t, os.Symlink(retarget, invocationLink))
	mutatedTarget, err := filepath.EvalSymlinks(invocationLink)
	require.NoError(t, err)
	require.NotEqual(t, binding.ResolvedPath, mutatedTarget)

	command := exec.Command(
		binding.ResolvedPath,
		"-c",
		`IFS= read -r _ || exit 1; exec "$@"`,
		"sh",
		"/bin/true",
	)
	command.Args[0] = binding.InvocationPath
	require.Equal(t, binding.ResolvedPath, command.Path)
	require.Equal(t, binding.InvocationPath, command.Args[0])
	stdin, err := command.StdinPipe()
	require.NoError(t, err)
	var stderr packagedJVMBenchmarkProbeLog
	command.Stderr = &stderr
	require.NoError(t, command.Start())
	waited := false
	defer func() {
		_ = stdin.Close()
		if waited {
			return
		}
		_ = command.Process.Kill()
		_ = command.Wait()
	}()

	var namespace unix.Stat_t
	require.NoError(t, unix.Stat(
		fmt.Sprintf("/proc/%d/ns/pid_for_children", command.Process.Pid),
		&namespace,
	))
	exited, diagnostic := packagedJVMBenchmarkEarlyLaunchDiagnostic(command, &stderr)
	require.False(t, exited)
	require.Contains(t, diagnostic, "launcher was still running")
	_, err = io.WriteString(stdin, "\n")
	require.NoError(t, err)
	require.NoError(t, stdin.Close())
	require.NoErrorf(t, command.Wait(), "multicall shell gate stderr: %s", stderr.String())
	waited = true

	broken := exec.Command(
		binding.ResolvedPath,
		"-c",
		`printf '%s\n' 'synthetic early launch failure' >&2; exit 127`,
	)
	broken.Args[0] = binding.InvocationPath
	var brokenStderr packagedJVMBenchmarkProbeLog
	broken.Stderr = &brokenStderr
	require.NoError(t, broken.Start())
	exited, diagnostic = packagedJVMBenchmarkEarlyLaunchDiagnostic(broken, &brokenStderr)
	require.True(t, exited)
	require.Contains(t, diagnostic, "exit status 127")
	require.Contains(t, diagnostic, "synthetic early launch failure")
}

func TestPackagedJVMBenchmarkExecutableInvocationPathRejectsInvalidTargets(t *testing.T) {
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing")
	_, err := bindPackagedJVMBenchmarkExecutable(missing)
	require.ErrorContains(t, err, "resolve executable invocation symlinks")

	brokenLink := filepath.Join(directory, "broken-link")
	require.NoError(t, os.Symlink(missing, brokenLink))
	_, err = bindPackagedJVMBenchmarkExecutable(brokenLink)
	require.ErrorContains(t, err, "resolve executable invocation symlinks")

	notExecutable := filepath.Join(directory, "not-executable")
	require.NoError(t, os.WriteFile(notExecutable, []byte("not executable\n"), 0o600))
	_, err = bindPackagedJVMBenchmarkExecutable(notExecutable)
	require.ErrorContains(t, err, "resolved executable is not executable")

	_, err = bindPackagedJVMBenchmarkExecutable(directory)
	require.ErrorContains(t, err, "resolved executable is not a regular file")

	untrusted := filepath.Join(directory, "untrusted-executable")
	require.NoError(t, os.WriteFile(untrusted, []byte("#!/bin/sh\nexit 0\n"), 0o777))
	_, err = bindPackagedJVMBenchmarkExecutable(untrusted)
	require.ErrorContains(t, err, "is not root-controlled")
}

func TestPackagedJVMBenchmarkEnvironmentRejectsLoaderAndJVMControls(t *testing.T) {
	for name := range forbiddenPackagedJVMBenchmarkEnvironment {
		t.Run(name, func(t *testing.T) {
			environment, err := packagedJVMBenchmarkEnvironment([]string{name + "=attacker-controlled"})
			require.Nil(t, environment)
			require.ErrorContains(t, err, name)
		})
	}

	environment, err := packagedJVMBenchmarkEnvironment([]string{"MALFORMED"})
	require.Nil(t, environment)
	require.ErrorContains(t, err, "malformed host environment entry")
}

func TestParsePackagedJVMBenchmarkProbeLineFailsClosed(t *testing.T) {
	fields, err := parsePackagedJVMBenchmarkProbeLine("READY tid=12 fd=34", "READY")
	require.NoError(t, err)
	require.Equal(t, map[string]string{"tid": "12", "fd": "34"}, fields)

	tests := []struct {
		name      string
		line      string
		wantError string
	}{
		{"empty", "   ", "empty stdout message"},
		{"unexpected prefix", "NOISE key=value", "unexpected stdout message"},
		{"unexpected message", "agent initialized", "unexpected stdout message"},
		{"missing separator", "READY invalid", "invalid probe field"},
		{"empty key", "READY =value", "invalid probe field"},
		{"empty value", "READY key=", "invalid probe field"},
		{"duplicate field", "READY key=one key=two", "duplicate probe field"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fields, err := parsePackagedJVMBenchmarkProbeLine(test.line, "READY")
			require.Nil(t, fields)
			require.ErrorContains(t, err, test.wantError)
		})
	}
}

func TestPackagedJVMBenchmarkProbeResultsRequireCleanEOFAfterDone(t *testing.T) {
	tests := []struct {
		name      string
		output    io.Reader
		wantError string
	}{
		{
			name:   "clean EOF",
			output: strings.NewReader("DONE samples=512\n"),
		},
		{
			name:      "ordinary trailing line",
			output:    strings.NewReader("DONE samples=512\nNOISE after=done\n"),
			wantError: "trailing stdout message",
		},
		{
			name: "overlong trailing line",
			output: strings.NewReader(
				"DONE samples=512\n" + strings.Repeat("x", bufio.MaxScanTokenSize+1),
			),
			wantError: "stdout scan failed",
		},
		{
			name: "read error after DONE",
			output: io.MultiReader(
				strings.NewReader("DONE samples=512\n"),
				iotest.ErrReader(errors.New("injected stdout read failure")),
			),
			wantError: "injected stdout read failure",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := packagedJVMBenchmarkProbeResults(test.output)
			done, channelOpen := <-results
			require.True(t, channelOpen)
			require.NoError(t, done.err)
			require.False(t, done.eof)
			fields, err := parsePackagedJVMBenchmarkProbeLine(done.line, "DONE")
			require.NoError(t, err)
			require.Equal(t, map[string]string{"samples": "512"}, fields)

			terminal, channelOpen := <-results
			err = validatePackagedJVMBenchmarkProbeEOF(terminal, channelOpen)
			if test.wantError == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, test.wantError)
		})
	}
}

func TestValidatePackagedJVMBenchmarkProbeEOFFailsClosed(t *testing.T) {
	require.ErrorContains(
		t,
		validatePackagedJVMBenchmarkProbeEOF(packagedJVMBenchmarkProbeResult{}, false),
		"closed without clean EOF",
	)
	require.ErrorContains(
		t,
		validatePackagedJVMBenchmarkProbeEOF(
			packagedJVMBenchmarkProbeResult{eof: true, line: "impossible"},
			true,
		),
		"EOF result contained a line",
	)
}

func TestPackagedJVMBenchmarkGitCommandScopesTrustAndDropsToExactSourceOwner(t *testing.T) {
	owner := packagedJVMBenchmarkSourceOwner{UID: 1002, GID: 1005}
	require.NoError(t, validatePackagedJVMBenchmarkSourceOwnership(0, owner, owner))

	arguments, err := packagedJVMBenchmarkGitCommandArguments(
		"/usr/bin/git",
		"/workspace/repository",
		"/workspace/repository/pkg",
		owner,
		"rev-parse",
		"--show-toplevel",
	)
	require.NoError(t, err)
	require.Equal(t, []string{
		"--reuid=1002",
		"--regid=1005",
		"--clear-groups",
		"--no-new-privs",
		"--inh-caps=-all",
		"--ambient-caps=-all",
		"--bounding-set=-all",
		"--",
		"/usr/bin/git",
		"-c",
		"safe.directory=/workspace/repository",
		"-C",
		"/workspace/repository/pkg",
		"rev-parse",
		"--show-toplevel",
	}, arguments)
}

func TestPackagedJVMBenchmarkGitCommandScopesDubiousOwnershipTrust(t *testing.T) {
	git, err := exec.LookPath("git")
	require.NoError(t, err)
	git, err = filepath.EvalSymlinks(git)
	require.NoError(t, err)
	repository := t.TempDir()
	command := exec.Command(git, "init", "--quiet", repository)
	command.Env = expectedPackagedJVMBenchmarkEnvironment
	require.NoError(t, command.Run())
	workingDirectory := filepath.Join(repository, "pkg")
	require.NoError(t, os.Mkdir(workingDirectory, 0o755))

	owner := packagedJVMBenchmarkSourceOwner{UID: 1002, GID: 1005}
	arguments, err := packagedJVMBenchmarkGitCommandArguments(
		git,
		repository,
		workingDirectory,
		owner,
		"rev-parse",
		"--show-toplevel",
	)
	require.NoError(t, err)
	gitArgumentsIndex := slices.Index(arguments, git)
	require.NotEqual(t, -1, gitArgumentsIndex)

	dubiousEnvironment := append(
		slices.Clone(expectedPackagedJVMBenchmarkEnvironment),
		"GIT_TEST_ASSUME_DIFFERENT_OWNER=1",
	)
	withoutScopedTrust := exec.Command(git, arguments[gitArgumentsIndex+3:]...)
	withoutScopedTrust.Env = dubiousEnvironment
	output, err := withoutScopedTrust.CombinedOutput()
	require.Error(t, err)
	require.Contains(t, string(output), "dubious ownership")

	withScopedTrust := exec.Command(git, arguments[gitArgumentsIndex+1:]...)
	withScopedTrust.Env = dubiousEnvironment
	output, err = withScopedTrust.Output()
	require.NoError(t, err)
	require.Equal(t, repository, strings.TrimSpace(string(output)))
}

func TestPackagedJVMBenchmarkSourceOwnershipAndGitCommandRejectMutations(t *testing.T) {
	owner := packagedJVMBenchmarkSourceOwner{UID: 1002, GID: 1005}
	tests := []struct {
		name      string
		validate  func() error
		wantError string
	}{
		{
			name: "non-root harness",
			validate: func() error {
				return validatePackagedJVMBenchmarkSourceOwnership(owner.UID, owner, owner)
			},
			wantError: "requires a root harness",
		},
		{
			name: "root source owner",
			validate: func() error {
				return validatePackagedJVMBenchmarkSourceOwnership(
					0, packagedJVMBenchmarkSourceOwner{UID: 0, GID: 0}, packagedJVMBenchmarkSourceOwner{UID: 0, GID: 0},
				)
			},
			wantError: "requires a non-root source owner",
		},
		{
			name: "repository uid mismatch",
			validate: func() error {
				return validatePackagedJVMBenchmarkSourceOwnership(
					0, owner, packagedJVMBenchmarkSourceOwner{UID: owner.UID + 1, GID: owner.GID},
				)
			},
			wantError: "source ownership mismatch",
		},
		{
			name: "repository gid mismatch",
			validate: func() error {
				return validatePackagedJVMBenchmarkSourceOwnership(
					0, owner, packagedJVMBenchmarkSourceOwner{UID: owner.UID, GID: owner.GID + 1},
				)
			},
			wantError: "source ownership mismatch",
		},
		{
			name: "relative git",
			validate: func() error {
				_, err := packagedJVMBenchmarkGitCommandArguments(
					"git", "/workspace/repository", "/workspace/repository/pkg", owner,
				)
				return err
			},
			wantError: "git executable must be an absolute clean path",
		},
		{
			name: "relative safe directory",
			validate: func() error {
				_, err := packagedJVMBenchmarkGitCommandArguments(
					"/usr/bin/git", "workspace/repository", "/workspace/repository/pkg", owner,
				)
				return err
			},
			wantError: "safe directory must be an absolute clean path",
		},
		{
			name: "unclean safe directory",
			validate: func() error {
				_, err := packagedJVMBenchmarkGitCommandArguments(
					"/usr/bin/git", "/workspace/../workspace/repository", "/workspace/repository/pkg", owner,
				)
				return err
			},
			wantError: "safe directory must be an absolute clean path",
		},
		{
			name: "wildcard safe directory",
			validate: func() error {
				_, err := packagedJVMBenchmarkGitCommandArguments(
					"/usr/bin/git", "/workspace/*", "/workspace/repository/pkg", owner,
				)
				return err
			},
			wantError: "safe directory must not contain wildcards",
		},
		{
			name: "relative working directory",
			validate: func() error {
				_, err := packagedJVMBenchmarkGitCommandArguments(
					"/usr/bin/git", "/workspace/repository", "workspace/repository/pkg", owner,
				)
				return err
			},
			wantError: "working directory must be an absolute clean path",
		},
		{
			name: "unclean working directory",
			validate: func() error {
				_, err := packagedJVMBenchmarkGitCommandArguments(
					"/usr/bin/git", "/workspace/repository", "/workspace/repository/../repository/pkg", owner,
				)
				return err
			},
			wantError: "working directory must be an absolute clean path",
		},
		{
			name: "root command owner",
			validate: func() error {
				_, err := packagedJVMBenchmarkGitCommandArguments(
					"/usr/bin/git", "/workspace/repository", "/workspace/repository/pkg",
					packagedJVMBenchmarkSourceOwner{},
				)
				return err
			},
			wantError: "git command requires a non-root source owner",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.ErrorContains(t, test.validate(), test.wantError)
		})
	}
}

func TestPackagedJVMBenchmarkNegotiationAuthorityRejectsEveryMutation(t *testing.T) {
	expected := packagedJVMBenchmarkNegotiationAuthority{
		Process: BpfJavaRemoteParentPidKeyT{
			Pid: 101,
			Tid: 202,
			Ns:  303,
		},
		ProcessIncarnation: 404,
		Connection: BpfJavaRemoteParentConnectionInfoT{
			S_addr: [16]uint8{1, 2, 3},
			D_addr: [16]uint8{4, 5, 6},
			S_port: 707,
			D_port: 808,
		},
		ConnectionNetns: 909,
		Generation:      1_010,
	}
	require.NoError(t, validatePackagedJVMBenchmarkNegotiationAuthority(expected, expected))

	tests := []struct {
		name      string
		mutate    func(*packagedJVMBenchmarkNegotiationAuthority)
		wantError string
	}{
		{"process", func(a *packagedJVMBenchmarkNegotiationAuthority) { a.Process.Pid++ }, "negotiation process"},
		{"incarnation", func(a *packagedJVMBenchmarkNegotiationAuthority) { a.ProcessIncarnation++ }, "negotiation incarnation"},
		{"connection", func(a *packagedJVMBenchmarkNegotiationAuthority) { a.Connection.D_port++ }, "negotiation connection"},
		{"namespace", func(a *packagedJVMBenchmarkNegotiationAuthority) { a.ConnectionNetns++ }, "negotiation namespace"},
		{"generation", func(a *packagedJVMBenchmarkNegotiationAuthority) { a.Generation++ }, "negotiation generation"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := expected
			test.mutate(&mutated)
			require.ErrorContains(
				t,
				validatePackagedJVMBenchmarkNegotiationAuthority(mutated, expected),
				test.wantError,
			)
		})
	}
}

func TestPackagedJVMBenchmarkCgroupBPFAttributionRejectsForeignAndChangedChains(t *testing.T) {
	attribution := validPackagedJVMBenchmarkCgroupBPFAttribution()
	attached, intended := packagedJVMBenchmarkCgroupBPFTestInputs(attribution)
	preAttach := emptyPackagedJVMBenchmarkCgroupBPFPreAttach(attached)
	require.NoError(t, validatePackagedJVMBenchmarkCgroupBPFPreAttach(preAttach))
	bound, err := bindPackagedJVMBenchmarkCgroupBPFAttribution(
		preAttach, attached, intended, "",
	)
	require.NoError(t, err)
	expectedBound := attribution
	expectedBound.StabilityChecks = packagedJVMBenchmarkArtifactStabilityChecks{}
	require.Equal(t, expectedBound, bound)

	foreign := packagedJVMBenchmarkArtifactBPFProgram{
		ID: 999, Tag: "f123456789abcdef", Name: "foreign", ProgramType: "CGroupSockopt",
	}
	tests := []struct {
		name      string
		mutate    func(*packagedJVMBenchmarkCgroupBPFSnapshot, []packagedJVMBenchmarkIntendedCgroupBPFProgram)
		preAttach bool
		wantError string
	}{
		{
			name: "foreign preexisting effective program",
			mutate: func(snapshot *packagedJVMBenchmarkCgroupBPFSnapshot, _ []packagedJVMBenchmarkIntendedCgroupBPFProgram) {
				snapshot.Chains[0].EffectivePrograms = []packagedJVMBenchmarkArtifactBPFProgram{foreign}
			},
			preAttach: true,
			wantError: "foreign preexisting effective",
		},
		{
			name: "foreign preexisting ancestor program",
			mutate: func(snapshot *packagedJVMBenchmarkCgroupBPFSnapshot, _ []packagedJVMBenchmarkIntendedCgroupBPFProgram) {
				snapshot.Chains[0].Topology[0].DirectPrograms = []packagedJVMBenchmarkArtifactBPFProgram{foreign}
			},
			preAttach: true,
			wantError: "foreign preexisting",
		},
		{
			name: "foreign injected effective program",
			mutate: func(snapshot *packagedJVMBenchmarkCgroupBPFSnapshot, _ []packagedJVMBenchmarkIntendedCgroupBPFProgram) {
				snapshot.Chains[0].EffectivePrograms = append(snapshot.Chains[0].EffectivePrograms, foreign)
			},
			wantError: "want exactly one intended program",
		},
		{
			name: "foreign injected ancestor program",
			mutate: func(snapshot *packagedJVMBenchmarkCgroupBPFSnapshot, _ []packagedJVMBenchmarkIntendedCgroupBPFProgram) {
				snapshot.Chains[0].Topology[0].DirectPrograms = []packagedJVMBenchmarkArtifactBPFProgram{foreign}
			},
			wantError: "topology at",
		},
		{
			name: "missing intended program",
			mutate: func(snapshot *packagedJVMBenchmarkCgroupBPFSnapshot, _ []packagedJVMBenchmarkIntendedCgroupBPFProgram) {
				snapshot.Chains[0].EffectivePrograms = nil
			},
			wantError: "want exactly one intended program",
		},
		{
			name: "missing intended target attachment",
			mutate: func(snapshot *packagedJVMBenchmarkCgroupBPFSnapshot, _ []packagedJVMBenchmarkIntendedCgroupBPFProgram) {
				snapshot.Chains[0].Topology[len(snapshot.Chains[0].Topology)-1].DirectPrograms = nil
			},
			wantError: "topology at",
		},
		{
			name: "wrong queried program id",
			mutate: func(snapshot *packagedJVMBenchmarkCgroupBPFSnapshot, _ []packagedJVMBenchmarkIntendedCgroupBPFProgram) {
				snapshot.Chains[0].EffectivePrograms[0].ID++
			},
			wantError: "differs from intended",
		},
		{
			name: "wrong queried program tag",
			mutate: func(snapshot *packagedJVMBenchmarkCgroupBPFSnapshot, _ []packagedJVMBenchmarkIntendedCgroupBPFProgram) {
				snapshot.Chains[0].EffectivePrograms[0].Tag = "aaaaaaaaaaaaaaaa"
			},
			wantError: "differs from intended",
		},
		{
			name: "wrong attach type",
			mutate: func(snapshot *packagedJVMBenchmarkCgroupBPFSnapshot, _ []packagedJVMBenchmarkIntendedCgroupBPFProgram) {
				snapshot.Chains[0].AttachType = "CGroupSetsockopt"
			},
			wantError: "attach type is invalid",
		},
		{
			name: "wrong intended id",
			mutate: func(_ *packagedJVMBenchmarkCgroupBPFSnapshot, intended []packagedJVMBenchmarkIntendedCgroupBPFProgram) {
				intended[0].Program.ID++
			},
			wantError: "differs from intended",
		},
		{
			name: "wrong intended attach type",
			mutate: func(_ *packagedJVMBenchmarkCgroupBPFSnapshot, intended []packagedJVMBenchmarkIntendedCgroupBPFProgram) {
				intended[0].AttachType = "CGroupSetsockopt"
			},
			wantError: "intended attach type mismatch",
		},
		{
			name: "wrong intended tag",
			mutate: func(_ *packagedJVMBenchmarkCgroupBPFSnapshot, intended []packagedJVMBenchmarkIntendedCgroupBPFProgram) {
				intended[0].Program.Tag = "bbbbbbbbbbbbbbbb"
			},
			wantError: "differs from intended",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var snapshot packagedJVMBenchmarkCgroupBPFSnapshot
			if test.preAttach {
				snapshot = preAttach
			} else {
				snapshot = attached
			}
			snapshot.Chains = clonePackagedJVMBenchmarkCgroupBPFChains(snapshot.Chains)
			mutatedIntended := slices.Clone(intended)
			test.mutate(&snapshot, mutatedIntended)
			if test.preAttach {
				require.ErrorContains(t, validatePackagedJVMBenchmarkCgroupBPFPreAttach(snapshot), test.wantError)
				return
			}
			_, err := bindPackagedJVMBenchmarkCgroupBPFAttribution(
				preAttach, snapshot, mutatedIntended, "",
			)
			require.ErrorContains(t, err, test.wantError)
		})
	}
}

func TestPackagedJVMBenchmarkCgroupBPFRevisionCompatibilityAndStability(t *testing.T) {
	attached, _ := packagedJVMBenchmarkCgroupBPFTestInputs(validPackagedJVMBenchmarkCgroupBPFAttribution())
	require.False(t, attached.Chains[0].EffectiveRevisionSupported)
	require.Zero(t, attached.Chains[0].EffectiveRevision,
		"effective cgroup queries have no revision even when direct revisions are supported")
	restoredIDs := attached
	restoredIDs.Chains = clonePackagedJVMBenchmarkCgroupBPFChains(attached.Chains)
	restoredIDs.Chains[1].Topology[0].DirectRevision++
	require.Equal(t, attached.Chains[1].EffectivePrograms, restoredIDs.Chains[1].EffectivePrograms)
	require.Equal(t, attached.Chains[1].Topology[0].DirectPrograms, restoredIDs.Chains[1].Topology[0].DirectPrograms)
	require.ErrorContains(
		t,
		validatePackagedJVMBenchmarkCgroupBPFSnapshotUnchanged(attached, restoredIDs),
		"direct cgroup BPF revisions changed after attribution",
	)

	effectiveRevision := attached
	effectiveRevision.Chains = clonePackagedJVMBenchmarkCgroupBPFChains(attached.Chains)
	effectiveRevision.Chains[0].EffectiveRevisionSupported = true
	effectiveRevision.Chains[0].EffectiveRevision = 1
	require.ErrorContains(t,
		validatePackagedJVMBenchmarkCgroupBPFSnapshotShape(effectiveRevision),
		"effective query incorrectly claims revision support",
	)

	zeroDirectRevision := attached
	zeroDirectRevision.Chains = clonePackagedJVMBenchmarkCgroupBPFChains(attached.Chains)
	zeroDirectRevision.Chains[0].Topology[0].DirectRevisionSupported = false
	zeroDirectRevision.Chains[0].Topology[0].DirectRevision = 0
	require.NoError(t, validatePackagedJVMBenchmarkCgroupBPFAttachedRevisionCapabilities(zeroDirectRevision))
	mode, _, premise := packagedJVMBenchmarkCgroupBPFStabilityContract(zeroDirectRevision)
	require.Equal(t, packagedJVMBenchmarkBoundaryIdentityOnlyMode, mode)
	require.Equal(t, packagedJVMBenchmarkExclusiveTopologyPremise, premise)

	revisionless := attached
	revisionless.Chains = clonePackagedJVMBenchmarkCgroupBPFChains(attached.Chains)
	for chainIndex := range revisionless.Chains {
		for topologyIndex := range revisionless.Chains[chainIndex].Topology {
			revisionless.Chains[chainIndex].Topology[topologyIndex].DirectRevisionSupported = false
			revisionless.Chains[chainIndex].Topology[topologyIndex].DirectRevision = 0
		}
	}
	preAttach := emptyPackagedJVMBenchmarkCgroupBPFPreAttach(revisionless)
	intended := packagedJVMBenchmarkCgroupBPFIntendedPrograms(
		validPackagedJVMBenchmarkCgroupBPFAttribution(),
	)
	_, err := bindPackagedJVMBenchmarkCgroupBPFAttribution(
		preAttach, revisionless, intended, "",
	)
	require.ErrorContains(t, err, javaRemoteParentPackagedJVMBenchmarkExclusiveCgroupBPFEnv)
	_, err = bindPackagedJVMBenchmarkCgroupBPFAttribution(
		preAttach, revisionless, intended, "operator_controlled",
	)
	require.ErrorContains(t, err, "exclusive cgroup BPF premise is invalid")
	bound, err := bindPackagedJVMBenchmarkCgroupBPFAttribution(
		preAttach, revisionless, intended, packagedJVMBenchmarkExclusiveTopologyPremise,
	)
	require.NoError(t, err)
	require.Equal(t, packagedJVMBenchmarkBoundaryIdentityOnlyMode, bound.StabilityMode)
	require.Equal(t, packagedJVMBenchmarkBoundaryIdentityOnlyEvidence, bound.StabilityEvidence)
	require.Equal(t, packagedJVMBenchmarkExclusiveTopologyPremise, bound.ExclusiveTopologyPremise)

	mixedSupport := attached
	mixedSupport.Chains = clonePackagedJVMBenchmarkCgroupBPFChains(attached.Chains)
	for topologyIndex := range mixedSupport.Chains[2].Topology {
		mixedSupport.Chains[2].Topology[topologyIndex].DirectRevisionSupported = false
		mixedSupport.Chains[2].Topology[topologyIndex].DirectRevision = 0
	}
	mode, _, _ = packagedJVMBenchmarkCgroupBPFStabilityContract(mixedSupport)
	require.Equal(t, packagedJVMBenchmarkBoundaryIdentityOnlyMode, mode,
		"one unsupported attach type requires the honest boundary-only contract")

	revisionlessCurrent := revisionless
	revisionlessCurrent.Chains = clonePackagedJVMBenchmarkCgroupBPFChains(revisionless.Chains)
	require.NoError(t, validatePackagedJVMBenchmarkCgroupBPFSnapshotUnchanged(
		revisionless, revisionlessCurrent,
	))
	revisionlessCurrent.Chains[0].EffectivePrograms = nil
	require.ErrorContains(t,
		validatePackagedJVMBenchmarkCgroupBPFSnapshotUnchanged(revisionless, revisionlessCurrent),
		"effective cgroup BPF chains changed",
	)

	supportToggle := revisionless
	supportToggle.Chains = clonePackagedJVMBenchmarkCgroupBPFChains(revisionless.Chains)
	for index := range supportToggle.Chains[0].Topology {
		supportToggle.Chains[0].Topology[index].DirectRevisionSupported = true
		supportToggle.Chains[0].Topology[index].DirectRevision = uint64(index + 1)
	}
	require.ErrorContains(t,
		validatePackagedJVMBenchmarkCgroupBPFSnapshotUnchanged(revisionless, supportToggle),
		"revision support changed",
	)
}

func TestPackagedJVMBenchmarkCgroupBPFStabilityTrackerCountsActualCallBrackets(t *testing.T) {
	attached, _ := packagedJVMBenchmarkCgroupBPFTestInputs(
		validPackagedJVMBenchmarkCgroupBPFAttribution(),
	)
	tracker := newPackagedJVMBenchmarkCgroupBPFStabilityTracker()
	for range packagedJVMBenchmarkExpectedCalls {
		require.NoError(t, tracker.ObservePreCall(attached, attached, nil))
		require.NoError(t, tracker.ObservePostCall(attached, attached, nil))
	}
	require.NoError(t, validatePackagedJVMBenchmarkCgroupBPFStabilityChecks(tracker.Checks()))

	missingPost := newPackagedJVMBenchmarkCgroupBPFStabilityTracker()
	for range packagedJVMBenchmarkExpectedCalls {
		require.NoError(t, missingPost.ObservePreCall(attached, attached, nil))
	}
	require.ErrorContains(t,
		validatePackagedJVMBenchmarkCgroupBPFStabilityChecks(missingPost.Checks()),
		"incomplete or failed",
	)

	queryFailure := newPackagedJVMBenchmarkCgroupBPFStabilityTracker()
	require.ErrorContains(t,
		queryFailure.ObservePreCall(attached, packagedJVMBenchmarkCgroupBPFSnapshot{}, errors.New("query failed")),
		"query failed",
	)
	require.Equal(t, 1, queryFailure.Checks().QueryErrors)

	topologyFailure := newPackagedJVMBenchmarkCgroupBPFStabilityTracker()
	changed := attached
	changed.Chains = clonePackagedJVMBenchmarkCgroupBPFChains(attached.Chains)
	changed.Chains[0].EffectivePrograms = nil
	require.ErrorContains(t,
		topologyFailure.ObservePostCall(attached, changed, nil),
		"effective cgroup BPF chains changed",
	)
	require.Equal(t, 1, topologyFailure.Checks().TopologyMismatches)
}

func emptyPackagedJVMBenchmarkCgroupBPFPreAttach(
	attached packagedJVMBenchmarkCgroupBPFSnapshot,
) packagedJVMBenchmarkCgroupBPFSnapshot {
	preAttach := attached
	preAttach.Chains = clonePackagedJVMBenchmarkCgroupBPFChains(attached.Chains)
	for chainIndex := range preAttach.Chains {
		preAttach.Chains[chainIndex].EffectivePrograms = []packagedJVMBenchmarkArtifactBPFProgram{}
		for topologyIndex := range preAttach.Chains[chainIndex].Topology {
			preAttach.Chains[chainIndex].Topology[topologyIndex].DirectPrograms =
				[]packagedJVMBenchmarkArtifactBPFProgram{}
		}
	}
	return preAttach
}

func packagedJVMBenchmarkCgroupBPFTestInputs(
	attribution packagedJVMBenchmarkArtifactCgroupBPF,
) (packagedJVMBenchmarkCgroupBPFSnapshot, []packagedJVMBenchmarkIntendedCgroupBPFProgram) {
	snapshot := packagedJVMBenchmarkCgroupBPFSnapshot{
		TargetCgroup:        attribution.TargetCgroup,
		CgroupHierarchy:     slices.Clone(attribution.CgroupHierarchy),
		EffectiveQueryFlags: attribution.EffectiveQueryFlags,
		Chains:              make([]packagedJVMBenchmarkCgroupBPFChainSnapshot, 0, len(attribution.Chains)),
	}
	for _, chain := range attribution.Chains {
		snapshot.Chains = append(snapshot.Chains, packagedJVMBenchmarkCgroupBPFChainSnapshot{
			AttachType:                 chain.AttachType,
			EffectiveRevisionSupported: chain.EffectiveRevisionSupported,
			EffectiveRevision:          chain.EffectiveRevision,
			EffectivePrograms:          slices.Clone(chain.EffectivePrograms),
			Topology:                   clonePackagedJVMBenchmarkCgroupBPFTopology(chain.Topology),
		})
	}
	return snapshot, packagedJVMBenchmarkCgroupBPFIntendedPrograms(attribution)
}

func packagedJVMBenchmarkCgroupBPFIntendedPrograms(
	attribution packagedJVMBenchmarkArtifactCgroupBPF,
) []packagedJVMBenchmarkIntendedCgroupBPFProgram {
	intended := make([]packagedJVMBenchmarkIntendedCgroupBPFProgram, len(attribution.Chains))
	for index, chain := range attribution.Chains {
		intended[index] = packagedJVMBenchmarkIntendedCgroupBPFProgram{
			AttachType: chain.AttachType,
			Program:    chain.IntendedProgram,
		}
	}
	return intended
}

func clonePackagedJVMBenchmarkCgroupBPFChains(
	chains []packagedJVMBenchmarkCgroupBPFChainSnapshot,
) []packagedJVMBenchmarkCgroupBPFChainSnapshot {
	clone := make([]packagedJVMBenchmarkCgroupBPFChainSnapshot, len(chains))
	for index, chain := range chains {
		clone[index] = chain
		clone[index].EffectivePrograms = slices.Clone(chain.EffectivePrograms)
		clone[index].Topology = clonePackagedJVMBenchmarkCgroupBPFTopology(chain.Topology)
	}
	return clone
}

func TestValidatePackagedJVMBenchmarkArtifact(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*packagedJVMBenchmarkArtifact)
		wantError string
	}{
		{"schema", func(a *packagedJVMBenchmarkArtifact) { a.SchemaVersion++ }, "unsupported packaged JVM benchmark schema"},
		{"name", func(a *packagedJVMBenchmarkArtifact) { a.Benchmark += "-mutated" }, "unexpected packaged JVM benchmark name"},
		{"creation time", func(a *packagedJVMBenchmarkArtifact) { a.CreatedAt = "yesterday" }, "invalid packaged JVM benchmark creation time"},
		{"harness", func(a *packagedJVMBenchmarkArtifact) { a.Provenance.Harness += "-mutated" }, "unexpected packaged JVM benchmark provenance"},
		{"measures", func(a *packagedJVMBenchmarkArtifact) { a.Provenance.Measures[0] = "native_fixture" }, "unexpected packaged JVM benchmark provenance"},
		{"excludes", func(a *packagedJVMBenchmarkArtifact) { a.Provenance.Excludes = a.Provenance.Excludes[1:] }, "unexpected packaged JVM benchmark provenance"},
		{"BPF query flag name", func(a *packagedJVMBenchmarkArtifact) { a.Provenance.CgroupBPF.EffectiveQueryFlag = "none" }, "attribution identity is invalid"},
		{"BPF query flag value", func(a *packagedJVMBenchmarkArtifact) { a.Provenance.CgroupBPF.EffectiveQueryFlags = 0 }, "attribution identity is invalid"},
		{"BPF preattach evidence", func(a *packagedJVMBenchmarkArtifact) { a.Provenance.CgroupBPF.PreAttachChainsEmpty = false }, "attribution identity is invalid"},
		{"BPF stability mode", func(a *packagedJVMBenchmarkArtifact) {
			a.Provenance.CgroupBPF.StabilityMode = packagedJVMBenchmarkBoundaryIdentityOnlyMode
		}, "stability contract is invalid"},
		{"BPF stability evidence", func(a *packagedJVMBenchmarkArtifact) {
			a.Provenance.CgroupBPF.StabilityEvidence = packagedJVMBenchmarkBoundaryIdentityOnlyEvidence
		}, "stability contract is invalid"},
		{"BPF topology premise", func(a *packagedJVMBenchmarkArtifact) {
			a.Provenance.CgroupBPF.ExclusiveTopologyPremise = packagedJVMBenchmarkExclusiveTopologyPremise
		}, "stability contract is invalid"},
		{"BPF expected stability checks", func(a *packagedJVMBenchmarkArtifact) { a.Provenance.CgroupBPF.StabilityChecks.ExpectedCalls-- }, "stability checks are incomplete or failed"},
		{"BPF missing pre-call observation", func(a *packagedJVMBenchmarkArtifact) {
			a.Provenance.CgroupBPF.StabilityChecks.ObservedPreCallSnapshots--
		}, "stability checks are incomplete or failed"},
		{"BPF missing post-call observation", func(a *packagedJVMBenchmarkArtifact) {
			a.Provenance.CgroupBPF.StabilityChecks.ObservedPostCallSnapshots--
		}, "stability checks are incomplete or failed"},
		{"BPF query error", func(a *packagedJVMBenchmarkArtifact) { a.Provenance.CgroupBPF.StabilityChecks.QueryErrors++ }, "stability checks are incomplete or failed"},
		{"BPF topology mismatch", func(a *packagedJVMBenchmarkArtifact) { a.Provenance.CgroupBPF.StabilityChecks.TopologyMismatches++ }, "stability checks are incomplete or failed"},
		{"BPF target", func(a *packagedJVMBenchmarkArtifact) { a.Provenance.CgroupBPF.TargetCgroup += "-other" }, "attribution identity is invalid"},
		{"BPF hierarchy", func(a *packagedJVMBenchmarkArtifact) {
			a.Provenance.CgroupBPF.CgroupHierarchy = a.Provenance.CgroupBPF.CgroupHierarchy[1:]
		}, "hierarchy identity is invalid"},
		{"BPF attach type", func(a *packagedJVMBenchmarkArtifact) {
			a.Provenance.CgroupBPF.Chains[0].AttachType = "CGroupSetsockopt"
		}, "attach type is invalid"},
		{"BPF intended id", func(a *packagedJVMBenchmarkArtifact) { a.Provenance.CgroupBPF.Chains[0].IntendedProgram.ID += 1_000 }, "effective chain is invalid"},
		{"BPF intended tag", func(a *packagedJVMBenchmarkArtifact) {
			a.Provenance.CgroupBPF.Chains[0].IntendedProgram.Tag = "aaaaaaaaaaaaaaaa"
		}, "effective chain is invalid"},
		{"BPF intended type", func(a *packagedJVMBenchmarkArtifact) {
			a.Provenance.CgroupBPF.Chains[0].IntendedProgram.ProgramType = "SockOps"
		}, "program type is invalid"},
		{"BPF effective revision support", func(a *packagedJVMBenchmarkArtifact) {
			a.Provenance.CgroupBPF.Chains[0].EffectiveRevisionSupported = true
		}, "effective query incorrectly claims revision support"},
		{"BPF effective revision", func(a *packagedJVMBenchmarkArtifact) { a.Provenance.CgroupBPF.Chains[0].EffectiveRevision = 1 }, "effective query incorrectly claims revision support"},
		{"BPF missing effective program", func(a *packagedJVMBenchmarkArtifact) { a.Provenance.CgroupBPF.Chains[0].EffectivePrograms = nil }, "effective chain is invalid"},
		{"BPF foreign effective program", func(a *packagedJVMBenchmarkArtifact) {
			a.Provenance.CgroupBPF.Chains[0].EffectivePrograms = append(a.Provenance.CgroupBPF.Chains[0].EffectivePrograms, a.Provenance.CgroupBPF.Chains[1].IntendedProgram)
		}, "effective chain is invalid"},
		{"BPF topology revision support", func(a *packagedJVMBenchmarkArtifact) {
			a.Provenance.CgroupBPF.Chains[0].Topology[0].DirectRevisionSupported = false
		}, "direct revision support is inconsistent"},
		{"BPF topology revision value", func(a *packagedJVMBenchmarkArtifact) {
			a.Provenance.CgroupBPF.Chains[0].Topology[0].DirectRevision = 0
		}, "direct revision support is inconsistent"},
		{"BPF foreign ancestor", func(a *packagedJVMBenchmarkArtifact) {
			a.Provenance.CgroupBPF.Chains[0].Topology[0].DirectPrograms = []packagedJVMBenchmarkArtifactBPFProgram{a.Provenance.CgroupBPF.Chains[1].IntendedProgram}
		}, "ancestor attachment is unexpected"},
		{"source revision", func(a *packagedJVMBenchmarkArtifact) { a.Source.Revision = "00" }, "source revision is invalid"},
		{"source status digest", func(a *packagedJVMBenchmarkArtifact) { a.Source.StatusSHA256 = "00" }, "source state digest is invalid"},
		{"source patch digest", func(a *packagedJVMBenchmarkArtifact) { a.Source.PatchSHA256 = "00" }, "source state digest is invalid"},
		{"source dirty mismatch", func(a *packagedJVMBenchmarkArtifact) { a.Source.Dirty = false }, "clean source identity is inconsistent"},
		{"Go toolchain", func(a *packagedJVMBenchmarkArtifact) { a.Inputs.GoToolchain = "" }, "Go toolchain identity is invalid"},
		{"test binary digest", func(a *packagedJVMBenchmarkArtifact) { a.Inputs.TestBinary.SHA256 = "00" }, "test binary identity"},
		{"test binary device", func(a *packagedJVMBenchmarkArtifact) { a.Inputs.TestBinary.Device = 0 }, "test binary identity"},
		{"test binary inode", func(a *packagedJVMBenchmarkArtifact) { a.Inputs.TestBinary.Inode = 0 }, "test binary identity"},
		{"agent digest", func(a *packagedJVMBenchmarkArtifact) { a.Inputs.AgentArtifact.SHA256 = "00" }, "agent artifact identity"},
		{"agent size", func(a *packagedJVMBenchmarkArtifact) { a.Inputs.AgentArtifact.Size = 0 }, "agent artifact identity"},
		{"sockopt BPF digest", func(a *packagedJVMBenchmarkArtifact) { a.Inputs.SockoptBPF.SHA256 = "00" }, "sockopt BPF identity"},
		{"sockops BPF size", func(a *packagedJVMBenchmarkArtifact) { a.Inputs.SockopsBPF.Size = 0 }, "sockops BPF identity"},
		{"hardware", func(a *packagedJVMBenchmarkArtifact) { a.Runtime.LogicalCPUs = 0 }, "hardware identity is incomplete"},
		{"cgroup", func(a *packagedJVMBenchmarkArtifact) { a.Runtime.CgroupMode = "v1" }, "cgroup identity is invalid"},
		{"Java privileges", func(a *packagedJVMBenchmarkArtifact) { a.Runtime.BPFDescriptors = 1 }, "Java privilege identity is invalid"},
		{"timed call", func(a *packagedJVMBenchmarkArtifact) { a.Setup.TimedCall = "getsockopt only" }, "unexpected packaged JVM benchmark setup"},
		{"response storage", func(a *packagedJVMBenchmarkArtifact) { a.Setup.ResponseStorage = "allocated per call" }, "unexpected packaged JVM benchmark setup"},
		{"miss control", func(a *packagedJVMBenchmarkArtifact) { a.Setup.MissControl = "full cleanup before lookup" }, "unexpected packaged JVM benchmark setup"},
		{"agent binding", func(a *packagedJVMBenchmarkArtifact) { a.Setup.AgentArtifactBinding = "path hash" }, "unexpected packaged JVM benchmark setup"},
		{"jvm arguments", func(a *packagedJVMBenchmarkArtifact) { a.Setup.JVMArguments = nil }, "unexpected packaged JVM benchmark setup"},
		{"environment", func(a *packagedJVMBenchmarkArtifact) {
			a.Setup.Environment = append(a.Setup.Environment, "LD_PRELOAD=/tmp/x.so")
		}, "unexpected packaged JVM benchmark setup"},
		{"series count", func(a *packagedJVMBenchmarkArtifact) { a.Series = a.Series[:1] }, "unexpected packaged JVM benchmark series count"},
		{"series order", func(a *packagedJVMBenchmarkArtifact) { a.Series[0], a.Series[1] = a.Series[1], a.Series[0] }, "unexpected identity"},
		{"sample count", func(a *packagedJVMBenchmarkArtifact) {
			a.Series[0].SamplesNS = a.Series[0].SamplesNS[:len(a.Series[0].SamplesNS)-1]
		}, "unexpected sample count"},
		{"sample value", func(a *packagedJVMBenchmarkArtifact) { a.Series[0].SamplesNS[0] = 0 }, "non-positive latency sample"},
		{"sample total", func(a *packagedJVMBenchmarkArtifact) { a.Series[0].TotalTimedNS++ }, "latency summary does not match retained samples"},
		{"percentile", func(a *packagedJVMBenchmarkArtifact) { a.Series[0].P99NS++ }, "latency summary does not match retained samples"},
		{"status counts", func(a *packagedJVMBenchmarkArtifact) { a.Series[0].Errors++ }, "invalid packaged JVM benchmark status counts"},
		{"status distribution", func(a *packagedJVMBenchmarkArtifact) { a.Series[0].Missing--; a.Series[0].Valid++ }, "unexpected packaged JVM benchmark status distribution"},
		{"correctness", func(a *packagedJVMBenchmarkArtifact) { a.Series[0].Correct = false }, "series is not correct"},
		{"gate definition", func(a *packagedJVMBenchmarkArtifact) { a.Series[0].LatencyGate.P99MaxNS++ }, "unexpected packaged JVM benchmark latency gate"},
		{"gate result", func(a *packagedJVMBenchmarkArtifact) {
			a.Series[0].LatencyGate.Passed = !a.Series[0].LatencyGate.Passed
		}, "inconsistent packaged JVM benchmark latency gate result"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifact := validPackagedJVMBenchmarkArtifact()
			test.mutate(&artifact)
			require.ErrorContains(t, validatePackagedJVMBenchmarkArtifact(artifact), test.wantError)
		})
	}
}

func TestValidatePackagedJVMBenchmarkArtifactRevisionlessBoundaryMode(t *testing.T) {
	mixed := validPackagedJVMBenchmarkArtifact()
	mixedCgroupBPF := &mixed.Provenance.CgroupBPF
	mixedCgroupBPF.Chains[0].Topology[0].DirectRevisionSupported = false
	mixedCgroupBPF.Chains[0].Topology[0].DirectRevision = 0
	mixedCgroupBPF.StabilityMode = packagedJVMBenchmarkBoundaryIdentityOnlyMode
	mixedCgroupBPF.StabilityEvidence = packagedJVMBenchmarkBoundaryIdentityOnlyEvidence
	mixedCgroupBPF.ExclusiveTopologyPremise = packagedJVMBenchmarkExclusiveTopologyPremise
	require.NoError(t, validatePackagedJVMBenchmarkArtifact(mixed),
		"one unsupported direct hierarchy query requires and permits boundary-only evidence")

	artifact := validPackagedJVMBenchmarkArtifact()
	cgroupBPF := &artifact.Provenance.CgroupBPF
	cgroupBPF.StabilityMode = packagedJVMBenchmarkBoundaryIdentityOnlyMode
	cgroupBPF.StabilityEvidence = packagedJVMBenchmarkBoundaryIdentityOnlyEvidence
	cgroupBPF.ExclusiveTopologyPremise = packagedJVMBenchmarkExclusiveTopologyPremise
	for chainIndex := range cgroupBPF.Chains {
		for topologyIndex := range cgroupBPF.Chains[chainIndex].Topology {
			cgroupBPF.Chains[chainIndex].Topology[topologyIndex].DirectRevisionSupported = false
			cgroupBPF.Chains[chainIndex].Topology[topologyIndex].DirectRevision = 0
		}
	}
	require.NoError(t, validatePackagedJVMBenchmarkArtifact(artifact))

	contents, err := json.Marshal(artifact)
	require.NoError(t, err)
	decoded, err := decodePackagedJVMBenchmarkArtifact(bytes.NewReader(contents))
	require.NoError(t, err)
	require.Equal(t, artifact, decoded)

	artifact.Provenance.CgroupBPF.ExclusiveTopologyPremise = ""
	require.ErrorContains(
		t, validatePackagedJVMBenchmarkArtifact(artifact), "stability contract is invalid",
	)
}

func TestDecodePackagedJVMBenchmarkArtifactRejectsUnknownTrailingAndDuplicateJSON(t *testing.T) {
	contents, err := json.Marshal(validPackagedJVMBenchmarkArtifact())
	require.NoError(t, err)
	unknown := append([]byte(`{"unknown":true,`), contents[1:]...)
	_, err = decodePackagedJVMBenchmarkArtifact(bytes.NewReader(unknown))
	require.ErrorContains(t, err, "unknown field")

	_, err = decodePackagedJVMBenchmarkArtifact(bytes.NewReader(append(contents, []byte(` {}`)...)))
	require.ErrorContains(t, err, "trailing JSON")

	tests := []struct {
		name    string
		payload []byte
		field   string
	}{
		{
			name:    "top level",
			payload: append([]byte(`{"schema_version":1,`), contents[1:]...),
			field:   "schema_version",
		},
		{
			name: "nested object",
			payload: bytes.Replace(
				contents,
				[]byte(`"source":{"revision":`),
				[]byte(`"source":{"dirty":true,"revision":`),
				1,
			),
			field: "dirty",
		},
		{
			name: "object in array",
			payload: bytes.Replace(
				contents,
				[]byte(`"series":[{"outcome":`),
				[]byte(`"series":[{"outcome":"miss","outcome":`),
				1,
			),
			field: "outcome",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodePackagedJVMBenchmarkArtifact(bytes.NewReader(test.payload))
			require.ErrorContains(t, err, `duplicate JSON name "`+test.field+`"`)
		})
	}
}

func TestDecodePackagedJVMBenchmarkArtifactRejectsCaseAliases(t *testing.T) {
	contents, err := json.Marshal(validPackagedJVMBenchmarkArtifact())
	require.NoError(t, err)
	tests := []struct {
		name      string
		payload   []byte
		alias     string
		canonical string
	}{
		{
			name:      "single top-level alias",
			payload:   replacePackagedJVMBenchmarkJSONBytes(t, contents, `"schema_version"`, `"SCHEMA_VERSION"`),
			alias:     "SCHEMA_VERSION",
			canonical: "schema_version",
		},
		{
			name:      "single nested alias",
			payload:   replacePackagedJVMBenchmarkJSONBytes(t, contents, `"bpf_descriptors"`, `"BPF_DESCRIPTORS"`),
			alias:     "BPF_DESCRIPTORS",
			canonical: "bpf_descriptors",
		},
		{
			name:      "top-level alias plus canonical",
			payload:   append([]byte(`{"SCHEMA_VERSION":999,`), contents[1:]...),
			alias:     "SCHEMA_VERSION",
			canonical: "schema_version",
		},
		{
			name: "nested alias plus canonical",
			payload: replacePackagedJVMBenchmarkJSONBytes(
				t, contents, `"dirty":true`, `"DIRTY":false,"dirty":true`,
			),
			alias:     "DIRTY",
			canonical: "dirty",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodePackagedJVMBenchmarkArtifact(bytes.NewReader(test.payload))
			require.ErrorContains(t, err, `noncanonical JSON name "`+test.alias+`"`)
			require.ErrorContains(t, err, `expected "`+test.canonical+`"`)
		})
	}
}

func TestDecodePackagedJVMBenchmarkArtifactRequiresNonNullTypedSchema(t *testing.T) {
	valid := validPackagedJVMBenchmarkArtifact()
	failedGate := validPackagedJVMBenchmarkArtifact()
	slow := make([]int64, packagedJVMBenchmarkMeasurementIterations)
	for index := range slow {
		slow[index] = packagedJVMBenchmarkP99LimitNS + int64(index+1)
	}
	failedGate.Series[0] = summarizePackagedJVMBenchmarkSeries(
		"miss", int(javabridge.StatusMissing), slow,
	)
	require.False(t, failedGate.Series[0].LatencyGate.Passed)

	tests := []struct {
		name      string
		artifact  packagedJVMBenchmarkArtifact
		mutate    func(map[string]any)
		wantError string
	}{
		{
			name:     "omitted source dirty",
			artifact: valid,
			mutate: func(root map[string]any) {
				delete(packagedJVMBenchmarkJSONObject(t, root, "source"), "dirty")
			},
			wantError: `$.source is missing required field "dirty"`,
		},
		{
			name:     "null source dirty",
			artifact: valid,
			mutate: func(root map[string]any) {
				packagedJVMBenchmarkJSONObject(t, root, "source")["dirty"] = nil
			},
			wantError: "$.source.dirty must not be null",
		},
		{
			name:     "wrong source dirty type",
			artifact: valid,
			mutate: func(root map[string]any) {
				packagedJVMBenchmarkJSONObject(t, root, "source")["dirty"] = "false"
			},
			wantError: "$.source.dirty must be a JSON boolean",
		},
		{
			name:     "omitted cgroup BPF provenance",
			artifact: valid,
			mutate: func(root map[string]any) {
				delete(packagedJVMBenchmarkJSONObject(t, root, "provenance"), "cgroup_bpf")
			},
			wantError: `$.provenance is missing required field "cgroup_bpf"`,
		},
		{
			name:     "null cgroup BPF intended program",
			artifact: valid,
			mutate: func(root map[string]any) {
				cgroup := packagedJVMBenchmarkJSONObject(
					t, packagedJVMBenchmarkJSONObject(t, root, "provenance"), "cgroup_bpf",
				)
				chains, ok := cgroup["chains"].([]any)
				require.True(t, ok)
				chain, ok := chains[0].(map[string]any)
				require.True(t, ok)
				chain["intended_program"] = nil
			},
			wantError: "$.provenance.cgroup_bpf.chains[0].intended_program must not be null",
		},
		{
			name:     "omitted cgroup BPF stability mode",
			artifact: valid,
			mutate: func(root map[string]any) {
				cgroup := packagedJVMBenchmarkJSONObject(
					t, packagedJVMBenchmarkJSONObject(t, root, "provenance"), "cgroup_bpf",
				)
				delete(cgroup, "stability_mode")
			},
			wantError: `$.provenance.cgroup_bpf is missing required field "stability_mode"`,
		},
		{
			name:     "omitted cgroup BPF stability checks",
			artifact: valid,
			mutate: func(root map[string]any) {
				cgroup := packagedJVMBenchmarkJSONObject(
					t, packagedJVMBenchmarkJSONObject(t, root, "provenance"), "cgroup_bpf",
				)
				delete(cgroup, "stability_checks")
			},
			wantError: `$.provenance.cgroup_bpf is missing required field "stability_checks"`,
		},
		{
			name:     "null cgroup BPF query errors",
			artifact: valid,
			mutate: func(root map[string]any) {
				cgroup := packagedJVMBenchmarkJSONObject(
					t, packagedJVMBenchmarkJSONObject(t, root, "provenance"), "cgroup_bpf",
				)
				checks := packagedJVMBenchmarkJSONObject(t, cgroup, "stability_checks")
				checks["query_errors"] = nil
			},
			wantError: "$.provenance.cgroup_bpf.stability_checks.query_errors must not be null",
		},
		{
			name:     "null effective revision support",
			artifact: valid,
			mutate: func(root map[string]any) {
				cgroup := packagedJVMBenchmarkJSONObject(
					t, packagedJVMBenchmarkJSONObject(t, root, "provenance"), "cgroup_bpf",
				)
				chains, ok := cgroup["chains"].([]any)
				require.True(t, ok)
				chain, ok := chains[0].(map[string]any)
				require.True(t, ok)
				chain["effective_revision_supported"] = nil
			},
			wantError: "$.provenance.cgroup_bpf.chains[0].effective_revision_supported must not be null",
		},
		{
			name:     "wrong direct revision support type",
			artifact: valid,
			mutate: func(root map[string]any) {
				cgroup := packagedJVMBenchmarkJSONObject(
					t, packagedJVMBenchmarkJSONObject(t, root, "provenance"), "cgroup_bpf",
				)
				chains, ok := cgroup["chains"].([]any)
				require.True(t, ok)
				chain, ok := chains[0].(map[string]any)
				require.True(t, ok)
				topology, ok := chain["topology"].([]any)
				require.True(t, ok)
				entry, ok := topology[0].(map[string]any)
				require.True(t, ok)
				entry["direct_revision_supported"] = "true"
			},
			wantError: "$.provenance.cgroup_bpf.chains[0].topology[0].direct_revision_supported must be a JSON boolean",
		},
		{
			name:     "wrong cgroup BPF topology type",
			artifact: valid,
			mutate: func(root map[string]any) {
				cgroup := packagedJVMBenchmarkJSONObject(
					t, packagedJVMBenchmarkJSONObject(t, root, "provenance"), "cgroup_bpf",
				)
				chains, ok := cgroup["chains"].([]any)
				require.True(t, ok)
				chain, ok := chains[0].(map[string]any)
				require.True(t, ok)
				chain["topology"] = map[string]any{}
			},
			wantError: "$.provenance.cgroup_bpf.chains[0].topology must be a JSON array",
		},
		{
			name:     "omitted runtime BPF descriptors",
			artifact: valid,
			mutate: func(root map[string]any) {
				delete(packagedJVMBenchmarkJSONObject(t, root, "runtime"), "bpf_descriptors")
			},
			wantError: `$.runtime is missing required field "bpf_descriptors"`,
		},
		{
			name:     "null runtime BPF descriptors",
			artifact: valid,
			mutate: func(root map[string]any) {
				packagedJVMBenchmarkJSONObject(t, root, "runtime")["bpf_descriptors"] = nil
			},
			wantError: "$.runtime.bpf_descriptors must not be null",
		},
		{
			name:     "wrong runtime BPF descriptors type",
			artifact: valid,
			mutate: func(root map[string]any) {
				packagedJVMBenchmarkJSONObject(t, root, "runtime")["bpf_descriptors"] = "0"
			},
			wantError: "$.runtime.bpf_descriptors must be a JSON number",
		},
		{
			name:     "omitted miss valid count",
			artifact: valid,
			mutate: func(root map[string]any) {
				delete(packagedJVMBenchmarkJSONSeries(t, root, 0), "valid")
			},
			wantError: `$.series[0] is missing required field "valid"`,
		},
		{
			name:     "null miss valid count",
			artifact: valid,
			mutate: func(root map[string]any) {
				packagedJVMBenchmarkJSONSeries(t, root, 0)["valid"] = nil
			},
			wantError: "$.series[0].valid must not be null",
		},
		{
			name:     "omitted hit missing count",
			artifact: valid,
			mutate: func(root map[string]any) {
				delete(packagedJVMBenchmarkJSONSeries(t, root, 1), "missing")
			},
			wantError: `$.series[1] is missing required field "missing"`,
		},
		{
			name:     "null hit missing count",
			artifact: valid,
			mutate: func(root map[string]any) {
				packagedJVMBenchmarkJSONSeries(t, root, 1)["missing"] = nil
			},
			wantError: "$.series[1].missing must not be null",
		},
		{
			name:     "omitted series errors",
			artifact: valid,
			mutate: func(root map[string]any) {
				delete(packagedJVMBenchmarkJSONSeries(t, root, 0), "errors")
			},
			wantError: `$.series[0] is missing required field "errors"`,
		},
		{
			name:     "null series errors",
			artifact: valid,
			mutate: func(root map[string]any) {
				packagedJVMBenchmarkJSONSeries(t, root, 0)["errors"] = nil
			},
			wantError: "$.series[0].errors must not be null",
		},
		{
			name:     "omitted false latency gate result",
			artifact: failedGate,
			mutate: func(root map[string]any) {
				delete(packagedJVMBenchmarkJSONObject(
					t, packagedJVMBenchmarkJSONSeries(t, root, 0), "latency_gate",
				), "passed")
			},
			wantError: `$.series[0].latency_gate is missing required field "passed"`,
		},
		{
			name:     "null false latency gate result",
			artifact: failedGate,
			mutate: func(root map[string]any) {
				packagedJVMBenchmarkJSONObject(
					t, packagedJVMBenchmarkJSONSeries(t, root, 0), "latency_gate",
				)["passed"] = nil
			},
			wantError: "$.series[0].latency_gate.passed must not be null",
		},
		{
			name:     "wrong nested object type",
			artifact: valid,
			mutate: func(root map[string]any) {
				packagedJVMBenchmarkJSONObject(t, root, "inputs")["test_binary"] = []any{}
			},
			wantError: "$.inputs.test_binary must be a JSON object",
		},
		{
			name:     "wrong nested array element type",
			artifact: valid,
			mutate: func(root map[string]any) {
				packagedJVMBenchmarkJSONObject(t, root, "setup")["environment"] = []any{true}
			},
			wantError: "$.setup.environment[0] must be a JSON string",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := mutatePackagedJVMBenchmarkJSON(t, test.artifact, test.mutate)
			_, err := decodePackagedJVMBenchmarkArtifact(bytes.NewReader(payload))
			require.ErrorContains(t, err, test.wantError)
		})
	}
}

func replacePackagedJVMBenchmarkJSONBytes(
	t *testing.T,
	payload []byte,
	oldValue string,
	newValue string,
) []byte {
	t.Helper()
	mutated := bytes.Replace(payload, []byte(oldValue), []byte(newValue), 1)
	require.False(t, bytes.Equal(payload, mutated), "JSON mutation did not match %q", oldValue)
	return mutated
}

func mutatePackagedJVMBenchmarkJSON(
	t *testing.T,
	artifact packagedJVMBenchmarkArtifact,
	mutate func(map[string]any),
) []byte {
	t.Helper()
	payload, err := json.Marshal(artifact)
	require.NoError(t, err)
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var root map[string]any
	require.NoError(t, decoder.Decode(&root))
	mutate(root)
	mutated, err := json.Marshal(root)
	require.NoError(t, err)
	return mutated
}

func packagedJVMBenchmarkJSONObject(
	t *testing.T,
	parent map[string]any,
	name string,
) map[string]any {
	t.Helper()
	object, ok := parent[name].(map[string]any)
	require.Truef(t, ok, "%s is not a test JSON object", name)
	return object
}

func packagedJVMBenchmarkJSONSeries(
	t *testing.T,
	root map[string]any,
	index int,
) map[string]any {
	t.Helper()
	series, ok := root["series"].([]any)
	require.True(t, ok, "series is not a test JSON array")
	require.Greater(t, len(series), index)
	object, ok := series[index].(map[string]any)
	require.Truef(t, ok, "series %d is not a test JSON object", index)
	return object
}

func TestValidatePackagedJVMBenchmarkArtifactFile(t *testing.T) {
	artifactPath := os.Getenv(javaRemoteParentPackagedJVMBenchmarkValidateArtifactEnv)
	if artifactPath == "" {
		t.Skipf("set %s to validate a retained packaged JVM benchmark artifact", javaRemoteParentPackagedJVMBenchmarkValidateArtifactEnv)
	}
	file, err := os.Open(artifactPath)
	require.NoError(t, err)
	defer file.Close()
	_, err = decodePackagedJVMBenchmarkArtifactV2(file)
	require.NoError(t, err)
}

func TestValidatePackagedJVMBenchmarkArtifactCICrosslinks(t *testing.T) {
	artifactPath := os.Getenv(javaRemoteParentPackagedJVMBenchmarkValidateArtifactEnv)
	if artifactPath == "" ||
		os.Getenv(javaRemoteParentPackagedJVMBenchmarkValidateCICrosslinksEnv) != "1" {
		t.Skipf(
			"set %s and %s=1 to validate packaged JVM benchmark CI crosslinks",
			javaRemoteParentPackagedJVMBenchmarkValidateArtifactEnv,
			javaRemoteParentPackagedJVMBenchmarkValidateCICrosslinksEnv,
		)
	}
	revision := os.Getenv(javaRemoteParentPackagedJVMBenchmarkValidateRevisionEnv)
	kernelRelease := os.Getenv(javaRemoteParentPackagedJVMBenchmarkValidateKernelEnv)
	javaExecutable := os.Getenv(javaRemoteParentPackagedJVMBenchmarkValidateJavaEnv)
	agentPath := os.Getenv(javaRemoteParentPackagedJVMBenchmarkValidateAgentEnv)
	testBinaryPath := os.Getenv(javaRemoteParentPackagedJVMBenchmarkValidateTestBinaryEnv)
	sockoptBPFPath := os.Getenv(javaRemoteParentPackagedJVMBenchmarkValidateSockoptBPFEnv)
	sockopsBPFPath := os.Getenv(javaRemoteParentPackagedJVMBenchmarkValidateSockopsBPFEnv)
	require.NotEmpty(t, revision)
	require.NotEmpty(t, kernelRelease)
	require.NotEmpty(t, javaExecutable)
	require.NotEmpty(t, agentPath)
	require.NotEmpty(t, testBinaryPath)
	require.NotEmpty(t, sockoptBPFPath)
	require.NotEmpty(t, sockopsBPFPath)

	file, err := os.Open(artifactPath)
	require.NoError(t, err)
	defer file.Close()
	artifact, err := decodePackagedJVMBenchmarkArtifactV2(file)
	require.NoError(t, err)
	agentIdentity, err := packagedJVMBenchmarkFileIdentityAtPath(agentPath)
	require.NoError(t, err)
	testBinaryIdentity, err := packagedJVMBenchmarkFileIdentityAtPath(testBinaryPath)
	require.NoError(t, err)
	sockoptBPFIdentity, err := packagedJVMBenchmarkBlobIdentityAtPath(sockoptBPFPath)
	require.NoError(t, err)
	sockopsBPFIdentity, err := packagedJVMBenchmarkBlobIdentityAtPath(sockopsBPFPath)
	require.NoError(t, err)
	require.NoError(t, validatePackagedJVMBenchmarkArtifactV2CICrosslinks(
		artifact,
		packagedJVMBenchmarkArtifactCICrosslinks{
			Revision:           revision,
			KernelRelease:      kernelRelease,
			JavaExecutable:     javaExecutable,
			AgentArtifact:      agentIdentity,
			TestBinary:         testBinaryIdentity,
			SockoptBPFArtifact: sockoptBPFIdentity,
			SockopsBPFArtifact: sockopsBPFIdentity,
		},
	))
}

func TestValidatePackagedJVMBenchmarkArtifactCICrosslinksRejectsMutations(t *testing.T) {
	artifact := validPackagedJVMBenchmarkArtifact()
	artifact.Source = packagedJVMBenchmarkArtifactSource{
		Revision:     "0123456789abcdef0123456789abcdef01234567",
		Dirty:        false,
		StatusSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		PatchSHA256:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}
	crosslinks := packagedJVMBenchmarkArtifactCICrosslinks{
		Revision:           artifact.Source.Revision,
		KernelRelease:      artifact.Runtime.KernelRelease,
		JavaExecutable:     artifact.Runtime.JavaExecutable,
		AgentArtifact:      artifact.Inputs.AgentArtifact,
		TestBinary:         artifact.Inputs.TestBinary,
		SockoptBPFArtifact: artifact.Inputs.SockoptBPF,
		SockopsBPFArtifact: artifact.Inputs.SockopsBPF,
	}
	require.NoError(t, validatePackagedJVMBenchmarkArtifactCICrosslinks(
		artifact, crosslinks,
	))

	tests := []struct {
		name   string
		mutate func(*packagedJVMBenchmarkArtifact, *packagedJVMBenchmarkArtifactCICrosslinks)
	}{
		{"dirty source", func(a *packagedJVMBenchmarkArtifact, _ *packagedJVMBenchmarkArtifactCICrosslinks) {
			a.Source.Dirty = true
		}},
		{"revision", func(_ *packagedJVMBenchmarkArtifact, value *packagedJVMBenchmarkArtifactCICrosslinks) {
			value.Revision = "1123456789abcdef0123456789abcdef01234567"
		}},
		{"kernel", func(_ *packagedJVMBenchmarkArtifact, value *packagedJVMBenchmarkArtifactCICrosslinks) {
			value.KernelRelease += ".changed"
		}},
		{"Java", func(_ *packagedJVMBenchmarkArtifact, value *packagedJVMBenchmarkArtifactCICrosslinks) {
			value.JavaExecutable = "/different/java"
		}},
		{"agent", func(_ *packagedJVMBenchmarkArtifact, value *packagedJVMBenchmarkArtifactCICrosslinks) {
			value.AgentArtifact.SHA256 = strings.Repeat("a", 64)
		}},
		{"test binary", func(_ *packagedJVMBenchmarkArtifact, value *packagedJVMBenchmarkArtifactCICrosslinks) {
			value.TestBinary.Inode++
		}},
		{"sockopt BPF", func(_ *packagedJVMBenchmarkArtifact, value *packagedJVMBenchmarkArtifactCICrosslinks) {
			value.SockoptBPFArtifact.Size++
		}},
		{"sockops BPF", func(_ *packagedJVMBenchmarkArtifact, value *packagedJVMBenchmarkArtifactCICrosslinks) {
			value.SockopsBPFArtifact.SHA256 = strings.Repeat("b", 64)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutatedArtifact := artifact
			mutatedCrosslinks := crosslinks
			test.mutate(&mutatedArtifact, &mutatedCrosslinks)
			require.Error(t, validatePackagedJVMBenchmarkArtifactCICrosslinks(
				mutatedArtifact,
				mutatedCrosslinks,
			))
		})
	}
}

func TestPackagedJVMBenchmarkArtifactV2StrictContract(t *testing.T) {
	artifact := validPackagedJVMBenchmarkArtifactV2()
	require.NoError(t, validatePackagedJVMBenchmarkArtifactV2(artifact))
	require.Len(t, artifact.Series, 14)
	for index, spec := range packagedJVMBenchmarkV2SeriesSpecs {
		require.Equal(t, spec.Scope, artifact.Series[index].Scope)
		require.Equal(t, spec.Transport, artifact.Series[index].Transport)
		require.Equal(t, spec.Outcome, artifact.Series[index].Outcome)
		require.Equal(t, spec.ExpectedStatus, artifact.Series[index].ExpectedStatus)
	}
	payload, err := json.Marshal(artifact)
	require.NoError(t, err)
	require.Less(t, len(payload), packagedJVMBenchmarkV2MaxArtifactBytes)
	decoded, err := decodePackagedJVMBenchmarkArtifactV2(bytes.NewReader(payload))
	require.NoError(t, err)
	require.Equal(t, artifact, decoded)
}

func TestPackagedJVMBenchmarkArtifactV2RejectsSemanticMutations(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*packagedJVMBenchmarkArtifactV2)
		wantError string
	}{
		{"schema", func(a *packagedJVMBenchmarkArtifactV2) { a.SchemaVersion = 1 }, "v2 identity"},
		{"series order", func(a *packagedJVMBenchmarkArtifactV2) { a.Series[0], a.Series[1] = a.Series[1], a.Series[0] }, "unexpected identity"},
		{"latency sample", func(a *packagedJVMBenchmarkArtifactV2) { a.Series[0].SamplesNS[0]++ }, "summary does not match"},
		{"allocation sample", func(a *packagedJVMBenchmarkArtifactV2) { a.Series[0].Allocation.SamplesBytes[0]++ }, "summary does not match"},
		{"allocation control", func(a *packagedJVMBenchmarkArtifactV2) { a.Series[0].Allocation.ControlSamplesBytes[0]++ }, "summary does not match"},
		{"status", func(a *packagedJVMBenchmarkArtifactV2) { a.Series[0].Statuses.Missing-- }, "status distribution"},
		{"native calls", func(a *packagedJVMBenchmarkArtifactV2) { a.Series[0].Calls.ObservedNativeCalls-- }, "call deltas"},
		{"BPF delta", func(a *packagedJVMBenchmarkArtifactV2) { a.Series[0].Calls.PrimaryBPFStatusAfter-- }, "BPF status delta"},
		{"server delta", func(a *packagedJVMBenchmarkArtifactV2) { a.Series[6].Calls.UnixServerStatusAfter-- }, "Unix server status delta"},
		{"gate", func(a *packagedJVMBenchmarkArtifactV2) { a.Series[0].LatencyGate.Passed = false }, "latency gate"},
		{"batch snapshots", func(a *packagedJVMBenchmarkArtifactV2) {
			a.Provenance.CgroupBPF.StabilityChecks.ObservedPostBatchSnapshots--
		}, "stability checks"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifact := validPackagedJVMBenchmarkArtifactV2()
			test.mutate(&artifact)
			require.ErrorContains(t, validatePackagedJVMBenchmarkArtifactV2(artifact), test.wantError)
		})
	}
}

func TestDecodePackagedJVMBenchmarkArtifactV2RejectsStructuralMutations(t *testing.T) {
	payload, err := json.Marshal(validPackagedJVMBenchmarkArtifactV2())
	require.NoError(t, err)
	tests := []struct {
		name      string
		payload   []byte
		wantError string
	}{
		{
			name: "unknown",
			payload: bytes.Replace(payload, []byte(`{"schema_version":2,`),
				[]byte(`{"unknown_root":0,"schema_version":2,`), 1),
			wantError: "unknown field",
		},
		{
			name: "duplicate",
			payload: bytes.Replace(payload, []byte(`{"schema_version":2,`),
				[]byte(`{"schema_version":2,"schema_version":2,`), 1),
			wantError: "duplicate JSON name",
		},
		{
			name:      "null",
			payload:   bytes.Replace(payload, []byte(`"correct":true`), []byte(`"correct":null`), 1),
			wantError: "must not be null",
		},
		{
			name:      "omitted zero",
			payload:   bytes.Replace(payload, []byte(`"unknown":0,`), nil, 1),
			wantError: `missing required field "unknown"`,
		},
		{
			name:      "trailing",
			payload:   append(slices.Clone(payload), []byte(` {}`)...),
			wantError: "trailing JSON",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodePackagedJVMBenchmarkArtifactV2(bytes.NewReader(test.payload))
			require.ErrorContains(t, err, test.wantError)
		})
	}
}

func validPackagedJVMBenchmarkArtifactV2() packagedJVMBenchmarkArtifactV2 {
	legacy := validPackagedJVMBenchmarkArtifact()
	totalBatches := len(packagedJVMBenchmarkV2SeriesSpecs) *
		(packagedJVMBenchmarkWarmupIterations + packagedJVMBenchmarkMeasurementIterations)
	legacy.Provenance.CgroupBPF.StabilityChecks = packagedJVMBenchmarkArtifactStabilityChecks{
		ExpectedCalls:             totalBatches,
		ObservedPreCallSnapshots:  totalBatches,
		ObservedPostCallSnapshots: totalBatches,
	}
	retained := packagedJVMBenchmarkV2Concurrency * packagedJVMBenchmarkMeasurementIterations
	total := packagedJVMBenchmarkV2Concurrency *
		(packagedJVMBenchmarkWarmupIterations + packagedJVMBenchmarkMeasurementIterations)
	observations := make([]packagedJVMBenchmarkV2SeriesObservation, len(packagedJVMBenchmarkV2SeriesSpecs))
	for index, spec := range packagedJVMBenchmarkV2SeriesSpecs {
		latency := int64(100_000)
		if spec.Transport == "unix" {
			latency = int64(time.Millisecond)
		}
		if spec.Outcome == "timeout" {
			latency = packagedJVMBenchmarkV2TimeoutP50MinimumNS
		}
		statuses := packagedJVMBenchmarkArtifactV2Statuses{}
		for range total {
			if err := statuses.add(spec.ExpectedStatus); err != nil {
				panic(err)
			}
		}
		calls := packagedJVMBenchmarkArtifactV2Calls{
			ExpectedJavaCalls: total, ObservedJavaCalls: total,
			ExpectedNativeCalls: total, ObservedNativeCalls: total,
			PrimaryBPFStatus: "not_applicable", UnixServerStatus: "not_applicable",
		}
		if spec.Scope == "bridge_provider_jni" {
			calls.ExpectedBridgeCalls, calls.ObservedBridgeCalls = total, total
		}
		if spec.Transport == "getsockopt" {
			calls.ExpectedPrimaryBPFCalls, calls.ObservedPrimaryBPFCalls = total, total
			calls.PrimaryBPFStatus = javabridge.Status(spec.ExpectedStatus).String()
			calls.PrimaryBPFStatusBefore = uint64(100 + index*total)
			calls.PrimaryBPFStatusAfter = calls.PrimaryBPFStatusBefore + uint64(total)
		} else {
			calls.UnixServerStatus = javabridge.Status(spec.ExpectedStatus).String()
			calls.UnixServerStatusAfter = uint64(total)
			if spec.Outcome == "timeout" {
				calls.ExpectedTimeoutFullRequests, calls.ObservedTimeoutFullRequests = total, total
			} else {
				calls.ExpectedUnixServerRequests, calls.ObservedUnixServerRequests = total, total
			}
		}
		observations[index] = packagedJVMBenchmarkV2SeriesObservation{
			Spec:                   spec,
			SamplesNS:              slices.Repeat([]int64{latency}, retained),
			AllocatedBytes:         slices.Repeat([]int64{64}, retained),
			AllocationControlBytes: slices.Repeat([]int64{0}, retained),
			Statuses:               statuses,
			Calls:                  calls,
		}
	}
	return newPackagedJVMBenchmarkArtifactV2(
		time.Date(2026, time.August, 13, 0, 0, 0, 0, time.UTC),
		legacy.Source, legacy.Inputs, legacy.Provenance.CgroupBPF, legacy.Runtime, observations,
	)
}

func validPackagedJVMBenchmarkArtifact() packagedJVMBenchmarkArtifact {
	miss := make([]int64, packagedJVMBenchmarkMeasurementIterations)
	hit := make([]int64, packagedJVMBenchmarkMeasurementIterations)
	for index := range packagedJVMBenchmarkMeasurementIterations {
		miss[index] = int64(10_000 + index)
		hit[index] = int64(20_000 + index)
	}
	return newPackagedJVMBenchmarkArtifact(
		time.Date(2026, time.August, 13, 12, 0, 0, 0, time.UTC),
		packagedJVMBenchmarkArtifactSource{
			Revision:     "0123456789abcdef0123456789abcdef01234567",
			Dirty:        true,
			StatusSHA256: "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			PatchSHA256:  "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		packagedJVMBenchmarkArtifactInputs{
			GoToolchain: "go1.25.0",
			TestBinary: packagedJVMBenchmarkArtifactFileIdentity{
				SHA256: "3123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				Device: 1,
				Inode:  2,
				Size:   3,
			},
			AgentArtifact: packagedJVMBenchmarkArtifactFileIdentity{
				SHA256: "4123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				Device: 4,
				Inode:  5,
				Size:   6,
			},
			SockoptBPF: packagedJVMBenchmarkArtifactBlobIdentity{
				SHA256: "5123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				Size:   7,
			},
			SockopsBPF: packagedJVMBenchmarkArtifactBlobIdentity{
				SHA256: "6123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				Size:   8,
			},
		},
		validPackagedJVMBenchmarkCgroupBPFAttribution(),
		packagedJVMBenchmarkArtifactRuntime{
			JavaExecutable:   "/usr/bin/java",
			JavaVersion:      "openjdk version 21",
			KernelRelease:    "6.12.0-test",
			Architecture:     "amd64",
			CPUModel:         "fixture CPU",
			LogicalCPUs:      8,
			MemoryTotalBytes: 8 * 1024 * 1024 * 1024,
			CgroupMode:       "v2",
			CgroupPath:       "/sys/fs/cgroup/fixture",
			JavaUID:          packagedJVMBenchmarkJavaID,
			JavaGID:          packagedJVMBenchmarkJavaID,
			JavaCapabilities: "all_zero",
			NoNewPrivileges:  true,
			BPFDescriptors:   0,
		},
		miss,
		hit,
	)
}

func validPackagedJVMBenchmarkCgroupBPFAttribution() packagedJVMBenchmarkArtifactCgroupBPF {
	hierarchy := []string{packagedJVMBenchmarkCgroupRoot, "/sys/fs/cgroup/fixture"}
	programs := []packagedJVMBenchmarkArtifactBPFProgram{
		{ID: 101, Tag: "0123456789abcdef", Name: "obi_getsockopt", ProgramType: "CGroupSockopt"},
		{ID: 102, Tag: "1123456789abcdef", Name: "obi_setsockopt", ProgramType: "CGroupSockopt"},
		{ID: 103, Tag: "2123456789abcdef", Name: "obi_sockops", ProgramType: "SockOps"},
	}
	chains := make([]packagedJVMBenchmarkArtifactCgroupChain, len(programs))
	for index, program := range programs {
		chains[index] = packagedJVMBenchmarkArtifactCgroupChain{
			AttachType:                 expectedPackagedJVMBenchmarkCgroupAttachTypes[index],
			IntendedProgram:            program,
			EffectiveRevisionSupported: false,
			EffectiveRevision:          0,
			EffectivePrograms:          []packagedJVMBenchmarkArtifactBPFProgram{program},
			Topology: []packagedJVMBenchmarkArtifactCgroupTopology{
				{
					CgroupPath:              hierarchy[0],
					DirectRevisionSupported: true,
					DirectRevision:          uint64(30 + index),
					DirectPrograms:          []packagedJVMBenchmarkArtifactBPFProgram{},
				},
				{
					CgroupPath:              hierarchy[1],
					DirectRevisionSupported: true,
					DirectRevision:          uint64(40 + index),
					DirectPrograms:          []packagedJVMBenchmarkArtifactBPFProgram{program},
				},
			},
		}
	}
	return packagedJVMBenchmarkArtifactCgroupBPF{
		TargetCgroup:             hierarchy[len(hierarchy)-1],
		CgroupHierarchy:          hierarchy,
		EffectiveQueryFlag:       packagedJVMBenchmarkEffectiveQueryFlag,
		EffectiveQueryFlags:      uint32(unix.BPF_F_QUERY_EFFECTIVE),
		PreAttachChainsEmpty:     true,
		StabilityMode:            packagedJVMBenchmarkRevisionAndIdentityMode,
		StabilityEvidence:        packagedJVMBenchmarkRevisionAndIdentityEvidence,
		ExclusiveTopologyPremise: packagedJVMBenchmarkRevisionPremiseNotRequired,
		StabilityChecks: packagedJVMBenchmarkArtifactStabilityChecks{
			ExpectedCalls:             packagedJVMBenchmarkExpectedCalls,
			ObservedPreCallSnapshots:  packagedJVMBenchmarkExpectedCalls,
			ObservedPostCallSnapshots: packagedJVMBenchmarkExpectedCalls,
			QueryErrors:               0,
			TopologyMismatches:        0,
		},
		Chains: chains,
	}
}
