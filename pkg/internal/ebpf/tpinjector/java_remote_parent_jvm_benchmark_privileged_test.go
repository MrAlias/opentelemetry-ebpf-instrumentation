// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/javabridge"
)

const (
	packagedJVMBenchmarkTimeout         = 3 * time.Minute
	packagedJVMBenchmarkFirstGeneration = uint64(2_000_000)
	packagedJVMBenchmarkCapability      = uint64(0x6e5d4c3b2a190817)
)

// TestJavaRemoteParentPackagedJVMGetsockoptBenchmark records single-thread hit and true state-map
// miss latency through the packaged agent, a direct Java native call, JNI, the kernel syscall, and
// the attached cgroup BPF program. It is intentionally opt-in and does not claim concurrency,
// allocation, resource-growth, or application throughput evidence.
func TestJavaRemoteParentPackagedJVMGetsockoptBenchmark(t *testing.T) {
	if os.Getenv(javaRemoteParentPackagedJVMBenchmarkEnv) != "1" {
		t.Skipf("set %s=1 to run the packaged JVM getsockopt benchmark", javaRemoteParentPackagedJVMBenchmarkEnv)
	}
	artifactPath := os.Getenv(javaRemoteParentPackagedJVMBenchmarkArtifactEnv)
	require.NotEmptyf(t, artifactPath, "set %s to a fresh artifact path", javaRemoteParentPackagedJVMBenchmarkArtifactEnv)
	require.Zero(t, os.Geteuid(), "packaged JVM benchmark must start as root so the Java child can drop privileges")
	agentPath, java := javaRemoteParentJVMProbeRuntime(t)
	agentPath = canonicalPackagedJVMBenchmarkPath(t, agentPath, "agent artifact")
	java = canonicalPackagedJVMBenchmarkPath(t, java, "Java executable")
	setpriv, err := exec.LookPath("setpriv")
	require.NoError(t, err)
	setpriv = canonicalPackagedJVMBenchmarkPath(t, setpriv, "setpriv executable")
	shell, err := exec.LookPath("sh")
	require.NoError(t, err)
	shell = canonicalPackagedJVMBenchmarkPath(t, shell, "shell executable")
	javaEnvironment, err := packagedJVMBenchmarkEnvironment(os.Environ())
	require.NoError(t, err)
	sourceIdentity := packagedJVMBenchmarkSourceIdentity(t, setpriv, javaEnvironment)

	agentArtifact := openPackagedJVMBenchmarkRegularFile(t, agentPath, "agent artifact")
	agentArtifactClosed := false
	defer func() {
		if !agentArtifactClosed {
			_ = agentArtifact.Close()
		}
	}()
	agentIdentity := packagedJVMBenchmarkOpenFileIdentity(t, agentArtifact, "agent artifact")
	testBinary, err := os.Open("/proc/self/exe")
	require.NoError(t, err)
	testBinaryClosed := false
	defer func() {
		if !testBinaryClosed {
			_ = testBinary.Close()
		}
	}()
	testBinaryIdentity := packagedJVMBenchmarkOpenFileIdentity(t, testBinary, "test binary")
	sockoptBPFIdentity := packagedJVMBenchmarkBlobIdentity(_BpfJavaRemoteParentBytes)
	sockopsBPFIdentity := packagedJVMBenchmarkBlobIdentity(_BpfBytes)
	require.NoError(t, validatePackagedJVMBenchmarkBlobIdentity(sockoptBPFIdentity))
	require.NoError(t, validatePackagedJVMBenchmarkBlobIdentity(sockopsBPFIdentity))
	requireJavaRemoteParentPrimarySockoptSupport(t)
	cgroupPath := currentCgroupV2Path(t)
	startedAt := time.Now()

	objects := loadJavaRemoteParentFixture(t)
	setJavaRemoteParentDataHookReadiness(t, objects.JavaRemoteParentDataHookReadiness, true)
	bpfResources := preparePackagedJVMBenchmarkBPF(t, &objects)
	preAttachCgroupBPF := queryPackagedJVMBenchmarkCgroupBPF(t, cgroupPath)
	require.NoError(t, validatePackagedJVMBenchmarkCgroupBPFPreAttach(preAttachCgroupBPF))
	bpfResources.Attach(t, cgroupPath)
	attachedCgroupBPF := queryPackagedJVMBenchmarkCgroupBPF(t, cgroupPath)
	cgroupBPFAttribution, err := bindPackagedJVMBenchmarkCgroupBPFAttribution(
		preAttachCgroupBPF,
		attachedCgroupBPF,
		bpfResources.IntendedPrograms(t),
		os.Getenv(javaRemoteParentPackagedJVMBenchmarkExclusiveCgroupBPFEnv),
	)
	require.NoError(t, err)
	cgroupBPFStabilityTracker := newPackagedJVMBenchmarkCgroupBPFStabilityTracker()

	ctx, cancel := context.WithTimeout(context.Background(), packagedJVMBenchmarkTimeout)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		shell,
		"-c",
		`IFS= read -r _; exec "$@"`,
		"sh",
		setpriv,
		"--reuid="+strconv.Itoa(packagedJVMBenchmarkJavaID),
		"--regid="+strconv.Itoa(packagedJVMBenchmarkJavaID),
		"--clear-groups",
		"--no-new-privs",
		"--inh-caps=-all",
		"--ambient-caps=-all",
		"--bounding-set=-all",
		"--",
		java,
		"-javaagent:/proc/self/fd/3="+packagedJVMBenchmarkAgentOptions,
		"-cp",
		"/proc/self/fd/3",
		packagedJVMBenchmarkProbeClass,
		"127.0.0.1",
		strconv.FormatUint(packagedJVMBenchmarkCapability, 10),
		strconv.Itoa(packagedJVMBenchmarkWarmupIterations),
		strconv.Itoa(packagedJVMBenchmarkMeasurementIterations),
	)
	command.Dir = "/"
	command.Env = javaEnvironment
	command.ExtraFiles = []*os.File{agentArtifact}
	stdin, err := command.StdinPipe()
	require.NoError(t, err)
	stdout, err := command.StdoutPipe()
	require.NoError(t, err)
	var stderr javaRemoteParentJVMProbeLog
	command.Stderr = &stderr
	require.NoError(t, command.Start())
	waited := false
	defer func() {
		if waited {
			return
		}
		_ = stdin.Close()
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
	}()

	process := javaRemoteParentProcessKey(t, command.Process.Pid)
	require.NoError(t, objects.JavaAuthorizedProcesses.Update(
		process, packagedJVMBenchmarkCapability, ebpf.UpdateAny,
	))
	require.NoError(t, objects.JavaProcessIncarnations.Update(
		process, packagedJVMBenchmarkCapability, ebpf.UpdateAny,
	))
	_, err = io.WriteString(stdin, "\n")
	require.NoError(t, err)

	lines := packagedJVMBenchmarkProbeResults(stdout)
	listen := waitForPackagedJVMBenchmarkProbe(t, ctx, lines, "LISTEN", &stderr)
	requirePackagedJVMBenchmarkFields(t, listen, map[string]string{
		"port": listen["port"],
	})
	port := parsePackagedJVMBenchmarkInt(t, listen, "port")
	require.Greater(t, port, 0)
	require.LessOrEqual(t, port, 65535)
	connection, err := net.DialTCP(
		"tcp4",
		nil,
		&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port},
	)
	require.NoError(t, err)
	connectionClosed := false
	defer func() {
		if !connectionClosed {
			_ = connection.Close()
		}
	}()

	ready := waitForPackagedJVMBenchmarkProbe(t, ctx, lines, "READY", &stderr)
	requirePackagedJVMBenchmarkFields(t, ready, map[string]string{
		"tid":                    ready["tid"],
		"fd":                     ready["fd"],
		"warmup_iterations":      strconv.Itoa(packagedJVMBenchmarkWarmupIterations),
		"measurement_iterations": strconv.Itoa(packagedJVMBenchmarkMeasurementIterations),
	})
	tid := javaRemoteParentJVMProbeUint32(t, ready, "tid")
	requirePackagedJVMBenchmarkUnprivilegedProcess(t, command.Process.Pid)
	descriptors, err := packagedJVMBenchmarkBPFDescriptors(command.Process.Pid)
	require.NoError(t, err)
	require.Empty(t, descriptors, "Java child received BPF descriptors: %v", descriptors)
	javaSocketFD := javaRemoteParentJVMProbeInt(t, ready, "fd")
	require.GreaterOrEqual(t, javaSocketFD, 0)
	pidfd, err := unix.PidfdOpen(command.Process.Pid, 0)
	require.NoError(t, err)
	pidfdClosed := false
	defer func() {
		if !pidfdClosed {
			_ = unix.Close(pidfd)
		}
	}()
	javaSocketDuplicate, err := unix.PidfdGetfd(pidfd, javaSocketFD, 0)
	require.NoError(t, err)
	javaSocketDuplicateClosed := false
	defer func() {
		if !javaSocketDuplicateClosed {
			_ = unix.Close(javaSocketDuplicate)
		}
	}()
	javaSocketCookie := socketCookie(t, javaSocketDuplicate)
	var seededSocketCookie uint64
	require.NoError(t, objects.JavaRemoteParentSocketCookies.Lookup(
		uint32(javaSocketDuplicate), &seededSocketCookie,
	))
	require.Equal(t, javaSocketCookie, seededSocketCookie)

	owner := process
	owner.Tid = tid
	connectionInfo := javaRemoteParentJVMConnectionInfo(t, connection)
	netns := currentNamespaceID(t, fmt.Sprintf("/proc/%d/ns/net", command.Process.Pid))
	nextGeneration := packagedJVMBenchmarkFirstGeneration
	nextNonce := uint64(1)
	samples := map[string][]int64{
		"miss": make([]int64, 0, packagedJVMBenchmarkMeasurementIterations),
		"hit":  make([]int64, 0, packagedJVMBenchmarkMeasurementIterations),
	}
	for _, outcome := range []string{"miss", "hit"} {
		for _, phase := range []struct {
			name       string
			iterations int
			retain     bool
		}{
			{name: "warmup", iterations: packagedJVMBenchmarkWarmupIterations},
			{name: "measurement", iterations: packagedJVMBenchmarkMeasurementIterations, retain: true},
		} {
			for iteration := range phase.iterations {
				generation := nextGeneration
				nextGeneration++
				stageRemoteParent(
					t,
					&objects.BpfJavaRemoteParentMaps,
					process,
					owner,
					packagedJVMBenchmarkCapability,
					connectionInfo,
					netns,
					javaSocketCookie,
					generation,
					nextNonce,
				)
				_, err = fmt.Fprintf(
					stdin, "ARM %s %s %d %d\n", phase.name, outcome, iteration, generation,
				)
				require.NoError(t, err)
				armed := waitForPackagedJVMBenchmarkProbe(t, ctx, lines, "ARMED", &stderr)
				requirePackagedJVMBenchmarkFields(t, armed, map[string]string{
					"phase":     phase.name,
					"outcome":   outcome,
					"iteration": strconv.Itoa(iteration),
					"emit":      "1",
					"nonce":     strconv.FormatUint(nextNonce, 10),
				})

				negotiation := socketNegotiation(
					t, objects.JavaRemoteParentNegotiations, javaSocketDuplicate,
				)
				require.NoError(t, validatePackagedJVMBenchmarkNegotiationAuthority(
					packagedJVMBenchmarkNegotiationAuthority{
						Process:            negotiation.Process,
						ProcessIncarnation: negotiation.ProcessIncarnation,
						Connection:         negotiation.Connection,
						ConnectionNetns:    negotiation.ConnectionNetns,
						Generation:         negotiation.Generation,
					},
					packagedJVMBenchmarkNegotiationAuthority{
						Process:            process,
						ProcessIncarnation: packagedJVMBenchmarkCapability,
						Connection:         connectionInfo,
						ConnectionNetns:    netns,
						Generation:         generation,
					},
				))
				var missAuthority *packagedJVMBenchmarkMissAuthority
				if outcome == "miss" {
					// Delete only the acknowledged state. The owner and generation index remain
					// authoritative and are asserted byte-for-byte around the timed lookup.
					authority := removePackagedJVMBenchmarkStateOnly(
						t,
						&objects.BpfJavaRemoteParentMaps,
						owner,
						generation,
					)
					missAuthority = &authority
				}
				preCallCgroupBPF, preCallQueryErr := tryQueryPackagedJVMBenchmarkCgroupBPF(cgroupPath)
				require.NoError(t, cgroupBPFStabilityTracker.ObservePreCall(
					attachedCgroupBPF, preCallCgroupBPF, preCallQueryErr,
				))
				_, err = fmt.Fprintf(stdin, "TAKE %s %s %d\n", phase.name, outcome, iteration)
				require.NoError(t, err)
				sample := waitForPackagedJVMBenchmarkProbe(t, ctx, lines, "SAMPLE", &stderr)
				postCallCgroupBPF, postCallQueryErr := tryQueryPackagedJVMBenchmarkCgroupBPF(cgroupPath)
				require.NoError(t, cgroupBPFStabilityTracker.ObservePostCall(
					attachedCgroupBPF, postCallCgroupBPF, postCallQueryErr,
				))
				expectedStatus := javabridge.StatusMissing
				if outcome == "hit" {
					expectedStatus = javabridge.StatusValid
				}
				requirePackagedJVMBenchmarkFields(t, sample, map[string]string{
					"phase":       phase.name,
					"outcome":     outcome,
					"iteration":   strconv.Itoa(iteration),
					"status":      strconv.Itoa(int(expectedStatus)),
					"generation":  strconv.FormatUint(generation, 10),
					"duration_ns": sample["duration_ns"],
				})
				duration := parsePackagedJVMBenchmarkInt64(t, sample, "duration_ns")
				require.Positive(t, duration)
				if outcome == "miss" {
					requirePackagedJVMBenchmarkMissAuthority(t, &objects.BpfJavaRemoteParentMaps, *missAuthority)
					restorePackagedJVMBenchmarkMissState(t, objects.JavaRemoteParentState, *missAuthority)
					// Existing full cleanup runs only after the timed miss and exact restoration.
					removeBenchmarkGeneration(
						t,
						&objects.BpfJavaRemoteParentMaps,
						owner,
						negotiation,
						generation,
					)
					requirePackagedJVMBenchmarkGenerationCleaned(
						t, &objects.BpfJavaRemoteParentMaps, owner, generation,
					)
				} else {
					requirePackagedJVMBenchmarkGenerationCleaned(
						t, &objects.BpfJavaRemoteParentMaps, owner, generation,
					)
				}
				requirePackagedJVMBenchmarkDataAckMissing(
					t, objects.JavaRemoteParentDataAcks, process, nextNonce,
				)
				if phase.retain {
					samples[outcome] = append(samples[outcome], duration)
				}
				nextNonce++
			}
		}
	}

	done := waitForPackagedJVMBenchmarkProbe(t, ctx, lines, "DONE", &stderr)
	requirePackagedJVMBenchmarkFields(t, done, map[string]string{
		"samples": strconv.Itoa(2 * packagedJVMBenchmarkMeasurementIterations),
	})
	require.NoError(t, stdin.Close())
	waitForPackagedJVMBenchmarkProbeEOF(t, ctx, lines, &stderr)
	err = command.Wait()
	waited = true
	if ctx.Err() != nil {
		t.Fatalf("packaged JVM getsockopt benchmark timed out: %s", stderr.String())
	}
	require.NoErrorf(t, err, "packaged JVM getsockopt benchmark failed:\n%s", stderr.String())
	require.NoError(t, validatePackagedJVMBenchmarkCgroupBPFSnapshotUnchanged(
		attachedCgroupBPF,
		queryPackagedJVMBenchmarkCgroupBPF(t, cgroupPath),
	))
	cgroupBPFAttribution.StabilityChecks = cgroupBPFStabilityTracker.Checks()
	require.NoError(t, validatePackagedJVMBenchmarkCgroupBPFAttribution(
		cgroupBPFAttribution, cgroupPath,
	))

	// Cleanup is part of the evidence gate: any failure is fatal and happens before publication.
	require.NoError(t, connection.Close())
	connectionClosed = true
	require.NoError(t, unix.Close(javaSocketDuplicate))
	javaSocketDuplicateClosed = true
	require.NoError(t, unix.Close(pidfd))
	pidfdClosed = true
	deleteBenchmarkMapKey(t, objects.JavaProcessIncarnations, process)
	deleteBenchmarkMapKey(t, objects.JavaAuthorizedProcesses, process)
	requireBenchmarkMapKeyAbsent(t, objects.JavaProcessIncarnations, process)
	requireBenchmarkMapKeyAbsent(t, objects.JavaAuthorizedProcesses, process)
	require.NoError(t, bpfResources.Close(), "close all benchmark BPF links, programs, and maps before publication")
	require.NoError(t, validatePackagedJVMBenchmarkCgroupBPFPreAttach(
		queryPackagedJVMBenchmarkCgroupBPF(t, cgroupPath),
	), "benchmark cgroup BPF topology after cleanup is not empty")

	require.Equal(
		t,
		agentIdentity,
		packagedJVMBenchmarkOpenFileIdentity(t, agentArtifact, "agent artifact after execution"),
		"opened agent artifact changed while the benchmark was running",
	)
	require.Equal(
		t,
		testBinaryIdentity,
		packagedJVMBenchmarkOpenFileIdentity(t, testBinary, "test binary after execution"),
		"opened Go test binary changed while the benchmark was running",
	)
	require.Equal(t, sockoptBPFIdentity, packagedJVMBenchmarkBlobIdentity(_BpfJavaRemoteParentBytes),
		"embedded sockopt BPF bytes changed while the benchmark was running")
	require.Equal(t, sockopsBPFIdentity, packagedJVMBenchmarkBlobIdentity(_BpfBytes),
		"embedded sockops BPF bytes changed while the benchmark was running")
	require.Equal(t, sourceIdentity, packagedJVMBenchmarkSourceIdentity(t, setpriv, javaEnvironment),
		"source revision or dirty patch changed while the benchmark was running")
	require.NoError(t, agentArtifact.Close())
	agentArtifactClosed = true
	require.NoError(t, testBinary.Close())
	testBinaryClosed = true

	runtimeIdentity := packagedJVMBenchmarkRuntimeIdentity(
		t, java, javaEnvironment, cgroupPath,
	)
	artifact := newPackagedJVMBenchmarkArtifact(
		startedAt,
		sourceIdentity,
		packagedJVMBenchmarkArtifactInputs{
			GoToolchain:   runtime.Version(),
			TestBinary:    testBinaryIdentity,
			AgentArtifact: agentIdentity,
			SockoptBPF:    sockoptBPFIdentity,
			SockopsBPF:    sockopsBPFIdentity,
		},
		cgroupBPFAttribution,
		runtimeIdentity,
		samples["miss"],
		samples["hit"],
	)
	// Publish structurally valid failed measurements before enforcing the predeclared gate.
	require.NoError(t, writePackagedJVMBenchmarkArtifact(artifactPath, artifact))
	for _, series := range artifact.Series {
		require.Truef(
			t,
			series.LatencyGate.Passed,
			"packaged JVM benchmark %s failed p99 < %s: p99=%s",
			series.Outcome,
			time.Duration(series.LatencyGate.P99MaxNS),
			time.Duration(series.P99NS),
		)
	}
}

type packagedJVMBenchmarkBPFResources struct {
	objects        *BpfJavaRemoteParentObjects
	setsockoptLink link.Link
	getsockoptLink link.Link
	sockopsLink    link.Link
	sockopsProgram *ebpf.Program
	closed         bool
}

func preparePackagedJVMBenchmarkBPF(
	t *testing.T,
	objects *BpfJavaRemoteParentObjects,
) *packagedJVMBenchmarkBPFResources {
	t.Helper()
	resources := &packagedJVMBenchmarkBPFResources{objects: objects}
	t.Cleanup(func() {
		require.NoError(t, resources.Close(), "clean up packaged JVM benchmark BPF resources")
	})

	spec, err := LoadBpf()
	require.NoError(t, err)
	for _, mapSpec := range spec.Maps {
		mapSpec.Pinning = ebpf.PinNone
	}
	require.NoError(t, ebpfconvenience.RewriteConstants(spec, map[string]any{
		"filter_pids":                int32(0),
		"g_bpf_debug":                false,
		"inject_flags":               uint32(0),
		"java_remote_parent_enabled": true,
	}))
	programs := struct {
		ObiSockmapTracker *ebpf.Program `ebpf:"obi_sockmap_tracker"`
	}{}
	require.NoError(t, spec.LoadAndAssign(&programs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"java_remote_parent_socket_cookies": objects.JavaRemoteParentSocketCookies,
		},
	}))
	resources.sockopsProgram = programs.ObiSockmapTracker
	return resources
}

func (resources *packagedJVMBenchmarkBPFResources) Attach(t *testing.T, cgroupPath string) {
	t.Helper()
	var err error
	resources.setsockoptLink, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSetsockopt,
		Program: resources.objects.ObiJavaRemoteParentSetsockopt,
	})
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("insufficient capability to attach cgroup setsockopt BPF program: %v", err)
	}
	require.NoError(t, err)
	resources.getsockoptLink, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupGetsockopt,
		Program: resources.objects.ObiJavaRemoteParentGetsockopt,
	})
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("insufficient capability to attach cgroup getsockopt BPF program: %v", err)
	}
	require.NoError(t, err)
	resources.sockopsLink, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: resources.sockopsProgram,
	})
	require.NoError(t, err)
}

func (resources *packagedJVMBenchmarkBPFResources) IntendedPrograms(
	t *testing.T,
) []packagedJVMBenchmarkIntendedCgroupBPFProgram {
	t.Helper()
	return []packagedJVMBenchmarkIntendedCgroupBPFProgram{
		{
			AttachType: ebpf.AttachCGroupGetsockopt.String(),
			Program: packagedJVMBenchmarkProgramIdentity(
				t, resources.objects.ObiJavaRemoteParentGetsockopt,
			),
		},
		{
			AttachType: ebpf.AttachCGroupSetsockopt.String(),
			Program: packagedJVMBenchmarkProgramIdentity(
				t, resources.objects.ObiJavaRemoteParentSetsockopt,
			),
		},
		{
			AttachType: ebpf.AttachCGroupSockOps.String(),
			Program:    packagedJVMBenchmarkProgramIdentity(t, resources.sockopsProgram),
		},
	}
}

func queryPackagedJVMBenchmarkCgroupBPF(
	t *testing.T,
	targetCgroup string,
) packagedJVMBenchmarkCgroupBPFSnapshot {
	t.Helper()
	snapshot, err := tryQueryPackagedJVMBenchmarkCgroupBPF(targetCgroup)
	require.NoError(t, err)
	return snapshot
}

func tryQueryPackagedJVMBenchmarkCgroupBPF(
	targetCgroup string,
) (packagedJVMBenchmarkCgroupBPFSnapshot, error) {
	hierarchy, err := packagedJVMBenchmarkCgroupHierarchy(targetCgroup)
	if err != nil {
		return packagedJVMBenchmarkCgroupBPFSnapshot{}, err
	}
	snapshot := packagedJVMBenchmarkCgroupBPFSnapshot{
		TargetCgroup:        targetCgroup,
		CgroupHierarchy:     hierarchy,
		EffectiveQueryFlags: uint32(unix.BPF_F_QUERY_EFFECTIVE),
		Chains: make(
			[]packagedJVMBenchmarkCgroupBPFChainSnapshot,
			0,
			len(expectedPackagedJVMBenchmarkCgroupAttachTypes),
		),
	}
	for _, attach := range []ebpf.AttachType{
		ebpf.AttachCGroupGetsockopt,
		ebpf.AttachCGroupSetsockopt,
		ebpf.AttachCGroupSockOps,
	} {
		effectiveRevision, effectivePrograms, err := queryPackagedJVMBenchmarkCgroupPrograms(
			targetCgroup, attach, uint32(unix.BPF_F_QUERY_EFFECTIVE),
		)
		if err != nil {
			return packagedJVMBenchmarkCgroupBPFSnapshot{}, err
		}
		chain := packagedJVMBenchmarkCgroupBPFChainSnapshot{
			AttachType:        attach.String(),
			EffectiveRevision: effectiveRevision,
			EffectivePrograms: effectivePrograms,
			Topology: make(
				[]packagedJVMBenchmarkArtifactCgroupTopology, 0, len(hierarchy),
			),
		}
		for _, cgroupPath := range hierarchy {
			directRevision, directPrograms, err := queryPackagedJVMBenchmarkCgroupPrograms(
				cgroupPath, attach, 0,
			)
			if err != nil {
				return packagedJVMBenchmarkCgroupBPFSnapshot{}, err
			}
			chain.Topology = append(chain.Topology, packagedJVMBenchmarkArtifactCgroupTopology{
				CgroupPath:              cgroupPath,
				DirectRevisionSupported: directRevision != 0,
				DirectRevision:          directRevision,
				DirectPrograms:          directPrograms,
			})
		}
		snapshot.Chains = append(snapshot.Chains, chain)
	}
	if err := validatePackagedJVMBenchmarkCgroupBPFSnapshotShape(snapshot); err != nil {
		return packagedJVMBenchmarkCgroupBPFSnapshot{}, err
	}
	return snapshot, nil
}

func queryPackagedJVMBenchmarkCgroupPrograms(
	cgroupPath string,
	attach ebpf.AttachType,
	queryFlags uint32,
) (uint64, []packagedJVMBenchmarkArtifactBPFProgram, error) {
	cgroup, err := os.Open(cgroupPath)
	if err != nil {
		return 0, nil, fmt.Errorf(
			"open cgroup %s for %s query: %w", cgroupPath, attach, err,
		)
	}
	defer cgroup.Close()
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(int(cgroup.Fd()), &filesystem); err != nil {
		return 0, nil, fmt.Errorf(
			"inspect cgroup filesystem %s: %w", cgroupPath, err,
		)
	}
	if filesystem.Type != int64(cgroup2FilesystemMagic) {
		return 0, nil, fmt.Errorf(
			"%s is not a cgroup-v2 filesystem", cgroupPath,
		)
	}
	result, err := link.QueryPrograms(link.QueryOptions{
		Target:     int(cgroup.Fd()),
		Attach:     attach,
		QueryFlags: queryFlags,
	})
	if err != nil {
		return 0, nil, fmt.Errorf(
			"query %s programs at %s with flags %#x: %w",
			attach, cgroupPath, queryFlags, err,
		)
	}
	programs := make([]packagedJVMBenchmarkArtifactBPFProgram, 0, len(result.Programs))
	for _, attached := range result.Programs {
		program, err := ebpf.NewProgramFromID(attached.ID)
		if err != nil {
			return 0, nil, fmt.Errorf(
				"open queried %s program ID %d: %w", attach, attached.ID, err,
			)
		}
		identity, identityErr := packagedJVMBenchmarkProgramIdentityValue(program)
		closeErr := program.Close()
		if identityErr != nil || closeErr != nil {
			return 0, nil, errors.Join(identityErr, closeErr)
		}
		if uint32(attached.ID) != identity.ID {
			return 0, nil, fmt.Errorf(
				"queried %s program identity changed: queried ID %d, opened ID %d",
				attach, attached.ID, identity.ID,
			)
		}
		programs = append(programs, identity)
	}
	return result.Revision, programs, nil
}

func packagedJVMBenchmarkProgramIdentity(
	t *testing.T,
	program *ebpf.Program,
) packagedJVMBenchmarkArtifactBPFProgram {
	t.Helper()
	identity, err := packagedJVMBenchmarkProgramIdentityValue(program)
	require.NoError(t, err)
	return identity
}

func packagedJVMBenchmarkProgramIdentityValue(
	program *ebpf.Program,
) (packagedJVMBenchmarkArtifactBPFProgram, error) {
	info, err := program.Info()
	if err != nil {
		return packagedJVMBenchmarkArtifactBPFProgram{}, err
	}
	id, ok := info.ID()
	if !ok {
		return packagedJVMBenchmarkArtifactBPFProgram{}, errors.New("kernel did not provide BPF program ID")
	}
	identity := packagedJVMBenchmarkArtifactBPFProgram{
		ID:          uint32(id),
		Tag:         info.Tag,
		Name:        info.Name,
		ProgramType: info.Type.String(),
	}
	if err := validatePackagedJVMBenchmarkBPFProgram(identity); err != nil {
		return packagedJVMBenchmarkArtifactBPFProgram{}, err
	}
	return identity, nil
}

func packagedJVMBenchmarkCgroupHierarchy(target string) ([]string, error) {
	target = filepath.Clean(target)
	relative, err := filepath.Rel(packagedJVMBenchmarkCgroupRoot, target)
	if err != nil {
		return nil, err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf(
			"benchmark cgroup %s is outside %s", target, packagedJVMBenchmarkCgroupRoot,
		)
	}
	reversed := []string{target}
	for path := target; path != packagedJVMBenchmarkCgroupRoot; {
		parent := filepath.Dir(path)
		if path == parent {
			return nil, errors.New("cgroup hierarchy did not reach root")
		}
		reversed = append(reversed, parent)
		path = parent
	}
	hierarchy := make([]string, len(reversed))
	for index := range reversed {
		hierarchy[index] = reversed[len(reversed)-1-index]
	}
	if err := validatePackagedJVMBenchmarkCgroupHierarchy(target, hierarchy); err != nil {
		return nil, err
	}
	return hierarchy, nil
}

func (resources *packagedJVMBenchmarkBPFResources) Close() error {
	if resources.closed {
		return nil
	}
	resources.closed = true
	var cleanupErrors []error
	if resources.sockopsLink != nil {
		cleanupErrors = append(cleanupErrors, resources.sockopsLink.Close())
	}
	if resources.getsockoptLink != nil {
		cleanupErrors = append(cleanupErrors, resources.getsockoptLink.Close())
	}
	if resources.setsockoptLink != nil {
		cleanupErrors = append(cleanupErrors, resources.setsockoptLink.Close())
	}
	if resources.sockopsProgram != nil {
		cleanupErrors = append(cleanupErrors, resources.sockopsProgram.Close())
	}
	if resources.objects != nil {
		cleanupErrors = append(cleanupErrors, resources.objects.Close())
	}
	return errors.Join(cleanupErrors...)
}

func waitForPackagedJVMBenchmarkProbe(
	t *testing.T,
	ctx context.Context,
	lines <-chan packagedJVMBenchmarkProbeResult,
	expectedPrefix string,
	stderr *javaRemoteParentJVMProbeLog,
) map[string]string {
	t.Helper()
	select {
	case result, ok := <-lines:
		if !ok {
			t.Fatalf(
				"packaged JVM benchmark stdout result stream closed before %s: %s",
				expectedPrefix,
				stderr.String(),
			)
		}
		if result.err != nil {
			t.Fatalf(
				"packaged JVM benchmark stdout failed before %s: %v: %s",
				expectedPrefix,
				result.err,
				stderr.String(),
			)
		}
		if result.eof {
			t.Fatalf("packaged JVM benchmark reached stdout EOF before %s: %s", expectedPrefix, stderr.String())
		}
		fields, err := parsePackagedJVMBenchmarkProbeLine(result.line, expectedPrefix)
		require.NoErrorf(t, err, "unexpected packaged JVM benchmark stdout before %s: %s", expectedPrefix, stderr.String())
		return fields
	case <-ctx.Done():
		t.Fatalf("timed out waiting for packaged JVM benchmark %s: %s", expectedPrefix, stderr.String())
	}
	return nil
}

func waitForPackagedJVMBenchmarkProbeEOF(
	t *testing.T,
	ctx context.Context,
	lines <-chan packagedJVMBenchmarkProbeResult,
	stderr *javaRemoteParentJVMProbeLog,
) {
	t.Helper()
	select {
	case result, channelOpen := <-lines:
		require.NoErrorf(
			t,
			validatePackagedJVMBenchmarkProbeEOF(result, channelOpen),
			"unexpected packaged JVM benchmark stdout after DONE: %s",
			stderr.String(),
		)
	case <-ctx.Done():
		t.Fatalf("timed out waiting for packaged JVM benchmark stdout EOF after DONE: %s", stderr.String())
	}
}

func requirePackagedJVMBenchmarkFields(
	t *testing.T,
	actual map[string]string,
	expected map[string]string,
) {
	t.Helper()
	require.Equal(t, expected, actual)
	for name, value := range actual {
		require.NotEmptyf(t, name, "empty packaged JVM probe field name")
		require.NotEmptyf(t, value, "empty packaged JVM probe field %q", name)
	}
}

func parsePackagedJVMBenchmarkInt(t *testing.T, fields map[string]string, name string) int {
	t.Helper()
	value, ok := fields[name]
	require.Truef(t, ok, "missing packaged JVM probe field %q", name)
	parsed, err := strconv.Atoi(value)
	require.NoErrorf(t, err, "invalid packaged JVM probe field %q", name)
	return parsed
}

func parsePackagedJVMBenchmarkInt64(t *testing.T, fields map[string]string, name string) int64 {
	t.Helper()
	value, ok := fields[name]
	require.Truef(t, ok, "missing packaged JVM probe field %q", name)
	parsed, err := strconv.ParseInt(value, 10, 64)
	require.NoErrorf(t, err, "invalid packaged JVM probe field %q", name)
	return parsed
}

func requirePackagedJVMBenchmarkDataAckMissing(
	t *testing.T,
	dataAcks *ebpf.Map,
	process BpfJavaRemoteParentPidKeyT,
	nonce uint64,
) {
	t.Helper()
	key := BpfJavaRemoteParentJavaRemoteParentDataSignalKeyT{
		Process: process,
		Nonce:   nonce,
	}
	var acknowledgement BpfJavaRemoteParentJavaRemoteParentDataAckT
	require.ErrorIs(t, dataAcks.Lookup(key, &acknowledgement), ebpf.ErrKeyNotExist)
}

type packagedJVMBenchmarkMissAuthority struct {
	Key             BpfJavaRemoteParentJavaRemoteParentKeyT
	State           BpfJavaRemoteParentJavaRemoteParentStateT
	Owner           BpfJavaRemoteParentJavaRemoteParentOwnerT
	GenerationIndex BpfJavaRemoteParentJavaRemoteParentGenerationIndexT
}

func removePackagedJVMBenchmarkStateOnly(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	owner BpfJavaRemoteParentPidKeyT,
	generation uint64,
) packagedJVMBenchmarkMissAuthority {
	t.Helper()
	authority := packagedJVMBenchmarkMissAuthority{
		Key: BpfJavaRemoteParentJavaRemoteParentKeyT{
			Owner:      owner,
			Generation: generation,
		},
	}
	require.NoError(t, maps.JavaRemoteParentState.Lookup(authority.Key, &authority.State))
	require.NoError(t, maps.JavaRemoteParentOwners.Lookup(owner, &authority.Owner))
	require.NoError(t, maps.JavaRemoteParentGenerationIndex.Lookup(
		authority.Key, &authority.GenerationIndex,
	))
	require.Equal(t, generation, authority.Owner.Generation)

	require.NoError(t, maps.JavaRemoteParentState.Delete(authority.Key))
	requirePackagedJVMBenchmarkMissAuthority(t, maps, authority)
	return authority
}

func requirePackagedJVMBenchmarkMissAuthority(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	authority packagedJVMBenchmarkMissAuthority,
) {
	t.Helper()
	var state BpfJavaRemoteParentJavaRemoteParentStateT
	require.ErrorIs(t, maps.JavaRemoteParentState.Lookup(authority.Key, &state), ebpf.ErrKeyNotExist)

	var owner BpfJavaRemoteParentJavaRemoteParentOwnerT
	require.NoError(t, maps.JavaRemoteParentOwners.Lookup(authority.Key.Owner, &owner))
	require.Equal(t, authority.Owner, owner, "state-map miss changed the retained owner authority")

	var generationIndex BpfJavaRemoteParentJavaRemoteParentGenerationIndexT
	require.NoError(t, maps.JavaRemoteParentGenerationIndex.Lookup(authority.Key, &generationIndex))
	require.Equal(
		t,
		authority.GenerationIndex,
		generationIndex,
		"state-map miss changed the retained generation index",
	)
}

func restorePackagedJVMBenchmarkMissState(
	t *testing.T,
	states *ebpf.Map,
	authority packagedJVMBenchmarkMissAuthority,
) {
	t.Helper()
	require.NoError(t, states.Update(authority.Key, authority.State, ebpf.UpdateNoExist))
	var restored BpfJavaRemoteParentJavaRemoteParentStateT
	require.NoError(t, states.Lookup(authority.Key, &restored))
	require.Equal(t, authority.State, restored, "restored miss state differs from captured state")
}

func requirePackagedJVMBenchmarkGenerationCleaned(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	owner BpfJavaRemoteParentPidKeyT,
	generation uint64,
) {
	t.Helper()
	key := BpfJavaRemoteParentJavaRemoteParentKeyT{Owner: owner, Generation: generation}
	requireBenchmarkMapKeyAbsent(t, maps.JavaRemoteParentState, key)
	requireBenchmarkMapKeyAbsent(t, maps.JavaRemoteParentGenerationIndex, key)
	requireBenchmarkMapKeyAbsent(t, maps.JavaRemoteParentOwners, owner)
}

func packagedJVMBenchmarkRuntimeIdentity(
	t *testing.T,
	java string,
	javaEnvironment []string,
	cgroupPath string,
) packagedJVMBenchmarkArtifactRuntime {
	t.Helper()
	javaVersionCommand := exec.Command(java, "-version")
	javaVersionCommand.Env = javaEnvironment
	javaVersion, err := javaVersionCommand.CombinedOutput()
	require.NoErrorf(t, err, "read Java version: %s", javaVersion)
	require.NotEmpty(t, strings.TrimSpace(string(javaVersion)))

	var uname unix.Utsname
	require.NoError(t, unix.Uname(&uname))
	kernelRelease := unix.ByteSliceToString(uname.Release[:])
	require.NotEmpty(t, kernelRelease)
	cpuModel := packagedJVMBenchmarkCPUModel(t)
	memoryTotal := packagedJVMBenchmarkMemoryTotal(t)

	return packagedJVMBenchmarkArtifactRuntime{
		JavaExecutable:   filepath.Clean(java),
		JavaVersion:      strings.TrimSpace(string(javaVersion)),
		KernelRelease:    kernelRelease,
		Architecture:     runtime.GOARCH,
		CPUModel:         cpuModel,
		LogicalCPUs:      runtime.NumCPU(),
		MemoryTotalBytes: memoryTotal,
		CgroupMode:       "v2",
		CgroupPath:       filepath.Clean(cgroupPath),
		JavaUID:          packagedJVMBenchmarkJavaID,
		JavaGID:          packagedJVMBenchmarkJavaID,
		JavaCapabilities: "all_zero",
		NoNewPrivileges:  true,
		BPFDescriptors:   0,
	}
}

func requirePackagedJVMBenchmarkUnprivilegedProcess(t *testing.T, pid int) {
	t.Helper()
	path := fmt.Sprintf("/proc/%d/status", pid)
	requirePackagedJVMBenchmarkUnprivilegedStatus(t, path)
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	require.NoError(t, err)
	checked := 0
	for _, task := range tasks {
		if !task.IsDir() {
			continue
		}
		path := fmt.Sprintf("/proc/%d/task/%s/status", pid, task.Name())
		if err := checkPackagedJVMBenchmarkUnprivilegedStatus(t, path); errors.Is(err, os.ErrNotExist) {
			continue
		} else {
			require.NoError(t, err)
		}
		checked++
	}
	require.Positive(t, checked, "no stable Java thread status was checked")
}

func requirePackagedJVMBenchmarkUnprivilegedStatus(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, checkPackagedJVMBenchmarkUnprivilegedStatus(t, path))
}

func checkPackagedJVMBenchmarkUnprivilegedStatus(t *testing.T, path string) error {
	t.Helper()
	status, err := readJavaRemoteParentLinuxStatus(path)
	if err != nil {
		return err
	}
	requireJavaRemoteParentUnprivilegedStatus(t, path, status)
	values, ok := status["CapBnd"]
	require.Truef(t, ok, "%s has no CapBnd field", path)
	require.Len(t, values, 1, path)
	value, err := strconv.ParseUint(values[0], 16, 64)
	require.NoErrorf(t, err, "parse CapBnd from %s", path)
	require.Zero(t, value, "CapBnd in %s", path)
	return nil
}

func packagedJVMBenchmarkBPFDescriptors(pid int) ([]string, error) {
	fdDirectory := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDirectory)
	if err != nil {
		return nil, err
	}
	var descriptors []string
	for _, entry := range entries {
		fdPath := filepath.Join(fdDirectory, entry.Name())
		target, err := os.Readlink(fdPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		lowerTarget := strings.ToLower(target)
		isBPF := strings.Contains(lowerTarget, "anon_inode") && strings.Contains(lowerTarget, "bpf")
		if !isBPF {
			contents, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%s", pid, entry.Name()))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			for line := range strings.SplitSeq(string(contents), "\n") {
				name, _, found := strings.Cut(line, ":")
				if !found {
					continue
				}
				switch name {
				case "btf_id", "link_id", "map_id", "prog_id", "token_id":
					isBPF = true
				}
			}
		}
		if isBPF {
			descriptors = append(descriptors, fmt.Sprintf("%s -> %s", entry.Name(), target))
		}
	}
	return descriptors, nil
}

func canonicalPackagedJVMBenchmarkPath(t *testing.T, path string, name string) string {
	t.Helper()
	absolute, err := filepath.Abs(path)
	require.NoErrorf(t, err, "resolve %s", name)
	canonical, err := filepath.EvalSymlinks(absolute)
	require.NoErrorf(t, err, "resolve %s symlinks", name)
	canonical = filepath.Clean(canonical)
	require.Truef(t, filepath.IsAbs(canonical), "%s path is not absolute", name)
	info, err := os.Stat(canonical)
	require.NoErrorf(t, err, "stat %s", name)
	require.Truef(t, info.Mode().IsRegular(), "%s is not a regular file", name)
	return canonical
}

func openPackagedJVMBenchmarkRegularFile(t *testing.T, path string, name string) *os.File {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	require.NoErrorf(t, err, "open %s without following symlinks", name)
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		t.Fatalf("create file handle for %s", name)
	}
	return file
}

func packagedJVMBenchmarkOpenFileIdentity(
	t *testing.T,
	file *os.File,
	name string,
) packagedJVMBenchmarkArtifactFileIdentity {
	t.Helper()
	var before unix.Stat_t
	require.NoErrorf(t, unix.Fstat(int(file.Fd()), &before), "fstat %s before hashing", name)
	require.Equalf(t, uint32(unix.S_IFREG), before.Mode&unix.S_IFMT, "%s is not a regular file", name)
	require.Positivef(t, before.Size, "%s is empty", name)

	digest := sha256.New()
	_, err := io.Copy(digest, io.NewSectionReader(file, 0, before.Size))
	require.NoErrorf(t, err, "hash opened %s", name)

	var after unix.Stat_t
	require.NoErrorf(t, unix.Fstat(int(file.Fd()), &after), "fstat %s after hashing", name)
	require.Equalf(t, before.Dev, after.Dev, "%s device changed while hashing", name)
	require.Equalf(t, before.Ino, after.Ino, "%s inode changed while hashing", name)
	require.Equalf(t, before.Mode, after.Mode, "%s mode changed while hashing", name)
	require.Equalf(t, before.Size, after.Size, "%s size changed while hashing", name)
	require.Equalf(t, before.Mtim, after.Mtim, "%s mtime changed while hashing", name)
	require.Equalf(t, before.Ctim, after.Ctim, "%s ctime changed while hashing", name)

	return packagedJVMBenchmarkArtifactFileIdentity{
		SHA256: hex.EncodeToString(digest.Sum(nil)),
		Device: uint64(before.Dev),
		Inode:  before.Ino,
		Size:   before.Size,
	}
}

func packagedJVMBenchmarkBlobIdentity(blob []byte) packagedJVMBenchmarkArtifactBlobIdentity {
	digest := sha256.Sum256(blob)
	return packagedJVMBenchmarkArtifactBlobIdentity{
		SHA256: hex.EncodeToString(digest[:]),
		Size:   len(blob),
	}
}

func packagedJVMBenchmarkSourceIdentity(
	t *testing.T,
	setpriv string,
	environment []string,
) packagedJVMBenchmarkArtifactSource {
	t.Helper()
	require.Zero(t, os.Geteuid(), "source identity must start from the root benchmark harness")
	setpriv = canonicalPackagedJVMBenchmarkPath(t, setpriv, "setpriv executable for source identity")
	git, err := exec.LookPath("git")
	require.NoError(t, err, "source identity requires git")
	git = canonicalPackagedJVMBenchmarkPath(t, git, "git executable")
	workingDirectory, err := os.Getwd()
	require.NoError(t, err)
	workingDirectory, err = filepath.EvalSymlinks(workingDirectory)
	require.NoError(t, err, "canonicalize source working directory")
	workingDirectory = filepath.Clean(workingDirectory)
	require.True(t, filepath.IsAbs(workingDirectory), "source working directory is not absolute")
	workingDirectoryOwner := packagedJVMBenchmarkSourcePathOwner(t, workingDirectory, "source working directory")
	require.NoError(t, validatePackagedJVMBenchmarkSourceOwnership(
		uint32(os.Geteuid()), workingDirectoryOwner, workingDirectoryOwner,
	))

	repositoryOutput := packagedJVMBenchmarkGitOutput(
		t, setpriv, git, workingDirectory, workingDirectoryOwner, environment,
		"rev-parse", "--show-toplevel",
	)
	repository := strings.TrimSpace(string(repositoryOutput))
	require.NotEmpty(t, repository, "git did not report a source root")
	repository, err = filepath.EvalSymlinks(repository)
	require.NoError(t, err, "canonicalize source root")
	repository = filepath.Clean(repository)
	require.True(t, filepath.IsAbs(repository), "source root is not absolute")
	relativeWorkingDirectory, err := filepath.Rel(repository, workingDirectory)
	require.NoError(t, err, "relate source working directory to repository")
	require.False(t,
		relativeWorkingDirectory == ".." || strings.HasPrefix(relativeWorkingDirectory, ".."+string(filepath.Separator)),
		"source working directory is outside the discovered repository",
	)
	repositoryOwner := packagedJVMBenchmarkSourcePathOwner(t, repository, "source repository")
	require.NoError(t, validatePackagedJVMBenchmarkSourceOwnership(
		uint32(os.Geteuid()), workingDirectoryOwner, repositoryOwner,
	))
	require.Equal(t, "true", strings.TrimSpace(string(packagedJVMBenchmarkGitOutput(
		t, setpriv, git, repository, repositoryOwner, environment,
		"rev-parse", "--is-inside-work-tree",
	))))

	revision := strings.TrimSpace(string(packagedJVMBenchmarkGitOutput(
		t, setpriv, git, repository, repositoryOwner, environment,
		"rev-parse", "--verify", "HEAD^{commit}",
	)))
	status := packagedJVMBenchmarkGitOutput(
		t, setpriv, git, repository, repositoryOwner, environment,
		"status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none",
	)
	staged := packagedJVMBenchmarkGitOutput(
		t, setpriv, git, repository, repositoryOwner, environment,
		"diff", "--cached", "--binary", "--no-ext-diff", "--submodule=diff", "HEAD", "--",
	)
	unstaged := packagedJVMBenchmarkGitOutput(
		t, setpriv, git, repository, repositoryOwner, environment,
		"diff", "--binary", "--no-ext-diff", "--submodule=diff", "--",
	)
	untracked := packagedJVMBenchmarkGitOutput(
		t, setpriv, git, repository, repositoryOwner, environment,
		"ls-files", "--others", "--exclude-standard", "-z",
	)

	patch := sha256.New()
	if len(status) > 0 {
		writePackagedJVMBenchmarkHashFrame(t, patch, "status", status)
	}
	if len(staged) > 0 {
		writePackagedJVMBenchmarkHashFrame(t, patch, "staged", staged)
	}
	if len(unstaged) > 0 {
		writePackagedJVMBenchmarkHashFrame(t, patch, "unstaged", unstaged)
	}
	for _, encodedPath := range bytes.Split(untracked, []byte{0}) {
		if len(encodedPath) == 0 {
			continue
		}
		writePackagedJVMBenchmarkUntrackedIdentity(t, patch, repository, encodedPath)
	}
	statusDigest := sha256.Sum256(status)
	identity := packagedJVMBenchmarkArtifactSource{
		Revision:     revision,
		Dirty:        len(status) > 0,
		StatusSHA256: hex.EncodeToString(statusDigest[:]),
		PatchSHA256:  hex.EncodeToString(patch.Sum(nil)),
	}
	require.NoError(t, validatePackagedJVMBenchmarkSource(identity),
		"source revision and dirty patch identity must be established")
	return identity
}

func packagedJVMBenchmarkGitOutput(
	t *testing.T,
	setpriv string,
	git string,
	repository string,
	owner packagedJVMBenchmarkSourceOwner,
	environment []string,
	arguments ...string,
) []byte {
	t.Helper()
	commandArguments, err := packagedJVMBenchmarkGitCommandArguments(
		git, repository, owner, arguments...,
	)
	require.NoError(t, err)
	command := exec.Command(setpriv, commandArguments...)
	command.Dir = "/"
	command.Env = environment
	output, err := command.Output()
	if exitError := (*exec.ExitError)(nil); errors.As(err, &exitError) {
		t.Fatalf("establish source identity with git %q: %v: %s", arguments, err, exitError.Stderr)
	}
	require.NoErrorf(t, err, "establish source identity with git %q", arguments)
	return output
}

func packagedJVMBenchmarkSourcePathOwner(
	t *testing.T,
	path string,
	name string,
) packagedJVMBenchmarkSourceOwner {
	t.Helper()
	var status unix.Stat_t
	require.NoErrorf(t, unix.Stat(path, &status), "stat %s", name)
	require.Equalf(t, uint32(unix.S_IFDIR), status.Mode&unix.S_IFMT, "%s is not a directory", name)
	return packagedJVMBenchmarkSourceOwner{UID: status.Uid, GID: status.Gid}
}

func writePackagedJVMBenchmarkHashFrame(
	t *testing.T,
	destination hash.Hash,
	label string,
	value []byte,
) {
	t.Helper()
	require.NoError(t, binary.Write(destination, binary.LittleEndian, uint64(len(label))))
	_, err := destination.Write([]byte(label))
	require.NoError(t, err)
	require.NoError(t, binary.Write(destination, binary.LittleEndian, uint64(len(value))))
	_, err = destination.Write(value)
	require.NoError(t, err)
}

func writePackagedJVMBenchmarkUntrackedIdentity(
	t *testing.T,
	destination hash.Hash,
	repository string,
	encodedPath []byte,
) {
	t.Helper()
	path := string(encodedPath)
	require.False(t, filepath.IsAbs(path), "git reported an absolute untracked path")
	require.NotEqual(t, ".", path, "git reported the source root as untracked")
	require.Equal(t, path, filepath.Clean(path), "git reported an unclean untracked path")
	fullPath := filepath.Join(repository, path)
	infoBefore, err := os.Lstat(fullPath)
	require.NoErrorf(t, err, "lstat untracked source %q", path)
	writePackagedJVMBenchmarkHashFrame(t, destination, "untracked-path", encodedPath)

	if infoBefore.Mode().IsRegular() {
		file, err := os.Open(fullPath)
		require.NoErrorf(t, err, "open untracked source %q", path)
		openedInfo, err := file.Stat()
		require.NoError(t, err)
		require.True(t, os.SameFile(infoBefore, openedInfo), "untracked source changed while opening")
		contentDigest := sha256.New()
		_, copyErr := io.Copy(contentDigest, file)
		infoAfter, statErr := file.Stat()
		closeErr := file.Close()
		require.NoError(t, copyErr)
		require.NoError(t, statErr)
		require.NoError(t, closeErr)
		require.True(t, os.SameFile(infoBefore, infoAfter), "untracked source changed while hashing")
		require.Equal(t, infoBefore.Size(), infoAfter.Size(), "untracked source size changed while hashing")
		require.Equal(t, infoBefore.ModTime(), infoAfter.ModTime(), "untracked source mtime changed while hashing")
		writePackagedJVMBenchmarkHashFrame(t, destination, "untracked-regular-sha256", contentDigest.Sum(nil))
		return
	}
	if infoBefore.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(fullPath)
		require.NoErrorf(t, err, "read untracked source symlink %q", path)
		infoAfter, err := os.Lstat(fullPath)
		require.NoError(t, err)
		require.True(t, os.SameFile(infoBefore, infoAfter), "untracked source symlink changed while reading")
		writePackagedJVMBenchmarkHashFrame(t, destination, "untracked-symlink-target", []byte(target))
		return
	}
	t.Fatalf("untracked source %q is neither a regular file nor a symlink", path)
}

func packagedJVMBenchmarkCPUModel(t *testing.T) string {
	t.Helper()
	contents, err := os.ReadFile("/proc/cpuinfo")
	require.NoError(t, err)
	for _, line := range strings.Split(string(contents), "\n") {
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "model name" || name == "Hardware" {
			model := strings.TrimSpace(value)
			if model != "" {
				return model
			}
		}
	}
	t.Fatal("CPU model is unavailable in /proc/cpuinfo")
	return ""
}

func packagedJVMBenchmarkMemoryTotal(t *testing.T) uint64 {
	t.Helper()
	contents, err := os.ReadFile("/proc/meminfo")
	require.NoError(t, err)
	for _, line := range strings.Split(string(contents), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "MemTotal:"))
		require.Len(t, fields, 2)
		require.Equal(t, "kB", fields[1])
		kilobytes, err := strconv.ParseUint(fields[0], 10, 64)
		require.NoError(t, err)
		require.LessOrEqual(t, kilobytes, ^uint64(0)/1024)
		return kilobytes * 1024
	}
	t.Fatal("MemTotal is unavailable in /proc/meminfo")
	return 0
}
