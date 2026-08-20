// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	javaRemoteParentBenchmarkArtifactEnv = "OBI_JAVA_REMOTE_PARENT_BENCHMARK_ARTIFACT"
	bridgeBenchmarkArtifactSchemaVersion = 2
	bridgeBenchmarkArtifactName          = "java_remote_parent_transport"
	benchmarkArtifactTemporaryAttempts   = 16
	bridgeBenchmarkConcurrency           = 8
	bridgeBenchmarkUnixDeadline          = 50 * time.Millisecond
	bridgeBenchmarkGetsockoptP99Limit    = time.Millisecond
	bridgeBenchmarkUnixP99Limit          = bridgeBenchmarkUnixDeadline
	bridgeBenchmarkUnixTimeoutP99Limit   = 100 * time.Millisecond
	bridgeBenchmarkHarness               = "go_privileged_transport_provider"
	bridgeBenchmarkGateP99LT             = "p99_lt"
	bridgeBenchmarkGateCorrectnessOnly   = "correctness_only"
	bridgeBenchmarkGateP50GTEP99LTE      = "p50_gte_p99_lte"
)

type bridgeBenchmarkArtifact struct {
	SchemaVersion         int                               `json:"schema_version"`
	Benchmark             string                            `json:"benchmark"`
	Provenance            bridgeBenchmarkArtifactProvenance `json:"provenance"`
	UnixTimeoutDeadlineNS int64                             `json:"unix_timeout_deadline_ns"`
	Series                []bridgeBenchmarkArtifactSeries   `json:"series"`
}

type bridgeBenchmarkArtifactProvenance struct {
	Harness  string   `json:"harness"`
	Measures []string `json:"measures"`
	Excludes []string `json:"excludes"`
}

type bridgeBenchmarkArtifactSeries struct {
	Transport           string                             `json:"transport"`
	Outcome             string                             `json:"outcome"`
	WarmupRounds        int                                `json:"warmup_rounds"`
	MeasurementRounds   int                                `json:"measurement_rounds"`
	Samples             int                                `json:"samples"`
	Concurrency         int                                `json:"concurrency"`
	BatchElapsedNS      int64                              `json:"batch_elapsed_ns"`
	P50NS               int64                              `json:"p50_ns"`
	P95NS               int64                              `json:"p95_ns"`
	P99NS               int64                              `json:"p99_ns"`
	OperationsPerSecond float64                            `json:"operations_per_second"`
	Valid               int                                `json:"valid"`
	Missing             int                                `json:"missing"`
	AlreadyConsumed     int                                `json:"already_consumed"`
	Timeout             int                                `json:"timeout"`
	Errors              int                                `json:"errors"`
	Correct             bool                               `json:"correct"`
	LatencyGate         bridgeBenchmarkArtifactLatencyGate `json:"latency_gate"`
}

type bridgeBenchmarkArtifactLatencyGate struct {
	Kind     string `json:"kind"`
	P50MinNS int64  `json:"p50_min_ns"`
	P99MaxNS int64  `json:"p99_max_ns"`
	Passed   bool   `json:"passed"`
}

type expectedBridgeBenchmarkArtifactSeries struct {
	transport         string
	outcome           string
	warmupRounds      int
	measurementRounds int
	latencyGate       bridgeBenchmarkArtifactLatencyGate
}

var expectedBridgeBenchmarkArtifactProvenance = bridgeBenchmarkArtifactProvenance{
	Harness:  bridgeBenchmarkHarness,
	Measures: []string{"transport", "provider"},
	Excludes: []string{"java", "jni"},
}

var expectedBridgeBenchmarkSeries = []expectedBridgeBenchmarkArtifactSeries{
	{
		transport: "getsockopt", outcome: "miss",
		warmupRounds: 16, measurementRounds: 512,
		latencyGate: bridgeBenchmarkArtifactLatencyGate{
			Kind: bridgeBenchmarkGateP99LT, P99MaxNS: bridgeBenchmarkGetsockoptP99Limit.Nanoseconds(),
		},
	},
	{
		transport: "getsockopt", outcome: "hit",
		warmupRounds: 16, measurementRounds: 512,
		latencyGate: bridgeBenchmarkArtifactLatencyGate{
			Kind: bridgeBenchmarkGateP99LT, P99MaxNS: bridgeBenchmarkGetsockoptP99Limit.Nanoseconds(),
		},
	},
	{
		transport: "getsockopt", outcome: "one_shot",
		warmupRounds: 16, measurementRounds: 512,
		latencyGate: bridgeBenchmarkArtifactLatencyGate{Kind: bridgeBenchmarkGateCorrectnessOnly},
	},
	{
		transport: "unix", outcome: "miss",
		warmupRounds: 8, measurementRounds: 128,
		latencyGate: bridgeBenchmarkArtifactLatencyGate{
			Kind: bridgeBenchmarkGateP99LT, P99MaxNS: bridgeBenchmarkUnixP99Limit.Nanoseconds(),
		},
	},
	{
		transport: "unix", outcome: "hit",
		warmupRounds: 8, measurementRounds: 128,
		latencyGate: bridgeBenchmarkArtifactLatencyGate{
			Kind: bridgeBenchmarkGateP99LT, P99MaxNS: bridgeBenchmarkUnixP99Limit.Nanoseconds(),
		},
	},
	{
		transport: "unix", outcome: "timeout",
		warmupRounds: 8, measurementRounds: 128,
		latencyGate: bridgeBenchmarkArtifactLatencyGate{
			Kind:     bridgeBenchmarkGateP50GTEP99LTE,
			P50MinNS: bridgeBenchmarkUnixDeadline.Nanoseconds(),
			P99MaxNS: bridgeBenchmarkUnixTimeoutP99Limit.Nanoseconds(),
		},
	},
}

func writeBridgeBenchmarkArtifact(
	artifactPath string,
	series []bridgeBenchmarkArtifactSeries,
) error {
	if artifactPath == "" {
		return nil
	}

	artifact := bridgeBenchmarkArtifact{
		SchemaVersion:         bridgeBenchmarkArtifactSchemaVersion,
		Benchmark:             bridgeBenchmarkArtifactName,
		Provenance:            expectedBridgeBenchmarkArtifactProvenance,
		UnixTimeoutDeadlineNS: bridgeBenchmarkUnixDeadline.Nanoseconds(),
		Series:                series,
	}
	if err := validateBridgeBenchmarkArtifact(artifact); err != nil {
		return err
	}

	directoryFD, artifactName, err := openBenchmarkArtifactDirectory(artifactPath)
	if err != nil {
		return err
	}
	defer unix.Close(directoryFD)

	payload, err := json.Marshal(artifact)
	if err != nil {
		return fmt.Errorf("marshal benchmark artifact: %w", err)
	}
	payload = append(payload, '\n')

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
		return fmt.Errorf("write benchmark artifact: %w", err)
	}
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set benchmark artifact permissions: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync benchmark artifact: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close benchmark artifact: %w", err)
	}
	temporaryClosed = true
	if err := unix.Linkat(directoryFD, temporaryName, directoryFD, artifactName, 0); err != nil {
		return fmt.Errorf("publish benchmark artifact: %w", err)
	}
	published = true
	_ = unix.Unlinkat(directoryFD, temporaryName, 0)
	if err := unix.Fsync(directoryFD); err != nil {
		return fmt.Errorf("sync benchmark artifact directory: %w", err)
	}

	return nil
}

func openBenchmarkArtifactDirectory(artifactPath string) (int, string, error) {
	cleanedPath := filepath.Clean(artifactPath)
	if artifactPath != cleanedPath || strings.HasSuffix(artifactPath, string(os.PathSeparator)) {
		return -1, "", fmt.Errorf("benchmark artifact path must be clean: %q", artifactPath)
	}

	artifactName := filepath.Base(cleanedPath)
	if artifactName == "." || artifactName == ".." || artifactName == string(os.PathSeparator) {
		return -1, "", fmt.Errorf("benchmark artifact path has no file name: %q", artifactPath)
	}

	directoryFD, err := openNoFollowDirectory(filepath.Dir(cleanedPath))
	if err != nil {
		return -1, "", err
	}

	var directoryStat unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryStat); err != nil {
		unix.Close(directoryFD)
		return -1, "", fmt.Errorf("stat benchmark artifact directory: %w", err)
	}
	if directoryStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(directoryFD)
		return -1, "", fmt.Errorf("benchmark artifact directory is not a directory: %s", filepath.Dir(cleanedPath))
	}
	if directoryStat.Uid != uint32(os.Geteuid()) || directoryStat.Mode&0o022 != 0 {
		unix.Close(directoryFD)
		return -1, "", fmt.Errorf("benchmark artifact directory is not private: %s", filepath.Dir(cleanedPath))
	}

	return directoryFD, artifactName, nil
}

func openNoFollowDirectory(directory string) (int, error) {
	cleanedDirectory := filepath.Clean(directory)
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_DIRECTORY | unix.O_NOFOLLOW
	start := "."
	components := strings.Split(cleanedDirectory, string(os.PathSeparator))
	if filepath.IsAbs(cleanedDirectory) {
		start = string(os.PathSeparator)
		components = strings.Split(strings.TrimPrefix(cleanedDirectory, string(os.PathSeparator)), string(os.PathSeparator))
	}

	directoryFD, err := unix.Open(start, flags, 0)
	if err != nil {
		return -1, fmt.Errorf("open benchmark artifact directory: %w", err)
	}
	for _, component := range components {
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			unix.Close(directoryFD)
			return -1, fmt.Errorf("benchmark artifact directory contains parent traversal: %q", directory)
		}

		nextDirectoryFD, err := unix.Openat(directoryFD, component, flags, 0)
		unix.Close(directoryFD)
		if err != nil {
			return -1, fmt.Errorf("open benchmark artifact directory: %w", err)
		}
		directoryFD = nextDirectoryFD
	}

	return directoryFD, nil
}

func createBenchmarkArtifactTemporary(directoryFD int) (*os.File, string, error) {
	for range benchmarkArtifactTemporaryAttempts {
		var randomBytes [16]byte
		if _, err := rand.Read(randomBytes[:]); err != nil {
			return nil, "", fmt.Errorf("create benchmark artifact temporary name: %w", err)
		}
		temporaryName := fmt.Sprintf(".benchmark-artifact-%x.tmp", randomBytes)
		temporaryFD, err := unix.Openat(
			directoryFD,
			temporaryName,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0o600,
		)
		if err == nil {
			return os.NewFile(uintptr(temporaryFD), temporaryName), temporaryName, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return nil, "", fmt.Errorf("create benchmark artifact temporary file: %w", err)
		}
	}

	return nil, "", errors.New("create benchmark artifact temporary file: exhausted name attempts")
}

func validateBridgeBenchmarkArtifact(artifact bridgeBenchmarkArtifact) error {
	if artifact.SchemaVersion != bridgeBenchmarkArtifactSchemaVersion {
		return fmt.Errorf("unsupported benchmark artifact schema version: %d", artifact.SchemaVersion)
	}
	if artifact.Benchmark != bridgeBenchmarkArtifactName {
		return fmt.Errorf("unexpected benchmark artifact name: %q", artifact.Benchmark)
	}
	if artifact.Provenance.Harness != expectedBridgeBenchmarkArtifactProvenance.Harness ||
		!slices.Equal(artifact.Provenance.Measures, expectedBridgeBenchmarkArtifactProvenance.Measures) ||
		!slices.Equal(artifact.Provenance.Excludes, expectedBridgeBenchmarkArtifactProvenance.Excludes) {
		return errors.New("unexpected benchmark artifact provenance")
	}
	if artifact.UnixTimeoutDeadlineNS != bridgeBenchmarkUnixDeadline.Nanoseconds() {
		return fmt.Errorf(
			"unexpected Unix timeout deadline: got %d, want %d",
			artifact.UnixTimeoutDeadlineNS,
			bridgeBenchmarkUnixDeadline.Nanoseconds(),
		)
	}
	if len(artifact.Series) != len(expectedBridgeBenchmarkSeries) {
		return fmt.Errorf(
			"unexpected benchmark series count: got %d, want %d",
			len(artifact.Series), len(expectedBridgeBenchmarkSeries),
		)
	}

	for index, expected := range expectedBridgeBenchmarkSeries {
		series := artifact.Series[index]
		if series.Transport != expected.transport || series.Outcome != expected.outcome {
			return fmt.Errorf(
				"unexpected benchmark series %d: got %s/%s, want %s/%s",
				index,
				series.Transport,
				series.Outcome,
				expected.transport,
				expected.outcome,
			)
		}
		if series.WarmupRounds != expected.warmupRounds ||
			series.MeasurementRounds != expected.measurementRounds ||
			series.Concurrency != bridgeBenchmarkConcurrency {
			return fmt.Errorf(
				"benchmark series %s/%s has unexpected run parameters",
				series.Transport,
				series.Outcome,
			)
		}
		if series.Samples <= 0 ||
			int64(series.Samples) != int64(series.Concurrency)*int64(series.MeasurementRounds) {
			return fmt.Errorf("benchmark series %s/%s has inconsistent sample count", series.Transport, series.Outcome)
		}
		if series.BatchElapsedNS <= 0 || series.P50NS <= 0 || series.P95NS <= 0 || series.P99NS <= 0 {
			return fmt.Errorf("benchmark series %s/%s has non-positive timing", series.Transport, series.Outcome)
		}
		if series.P50NS > series.P95NS || series.P95NS > series.P99NS {
			return fmt.Errorf("benchmark series %s/%s has non-monotonic percentiles", series.Transport, series.Outcome)
		}
		if series.BatchElapsedNS < series.P99NS {
			return fmt.Errorf("benchmark series %s/%s has impossible batch elapsed time", series.Transport, series.Outcome)
		}
		if series.OperationsPerSecond <= 0 || math.IsInf(series.OperationsPerSecond, 0) || math.IsNaN(series.OperationsPerSecond) {
			return fmt.Errorf("benchmark series %s/%s has invalid throughput", series.Transport, series.Outcome)
		}
		expectedThroughput := float64(series.Samples) * float64(time.Second) /
			float64(series.BatchElapsedNS)
		if relativeDifference(series.OperationsPerSecond, expectedThroughput) > 1e-12 {
			return fmt.Errorf("benchmark series %s/%s has inconsistent throughput", series.Transport, series.Outcome)
		}
		if series.Valid < 0 || series.Missing < 0 || series.AlreadyConsumed < 0 ||
			series.Timeout < 0 || series.Errors != 0 {
			return fmt.Errorf("benchmark series %s/%s has invalid status counts", series.Transport, series.Outcome)
		}
		if series.Valid+series.Missing+series.AlreadyConsumed+series.Timeout+series.Errors != series.Samples {
			return fmt.Errorf("benchmark series %s/%s has inconsistent status counts", series.Transport, series.Outcome)
		}
		if err := validateBridgeBenchmarkStatusDistribution(series); err != nil {
			return err
		}
		if !series.Correct {
			return fmt.Errorf("benchmark series %s/%s is not correct", series.Transport, series.Outcome)
		}
		if series.LatencyGate.Kind != expected.latencyGate.Kind ||
			series.LatencyGate.P50MinNS != expected.latencyGate.P50MinNS ||
			series.LatencyGate.P99MaxNS != expected.latencyGate.P99MaxNS {
			return fmt.Errorf("benchmark series %s/%s has an unexpected latency gate", series.Transport, series.Outcome)
		}
		gatePassed := bridgeBenchmarkLatencyGatePassed(
			expected.latencyGate,
			series.P50NS,
			series.P99NS,
		)
		if series.LatencyGate.Passed != gatePassed {
			return fmt.Errorf("benchmark series %s/%s has an inconsistent latency gate result", series.Transport, series.Outcome)
		}
	}

	return nil
}

func relativeDifference(observed, expected float64) float64 {
	return math.Abs(observed-expected) / expected
}

func validateBridgeBenchmarkStatusDistribution(series bridgeBenchmarkArtifactSeries) error {
	valid := false
	switch {
	case series.Transport == "getsockopt" && series.Outcome == "miss",
		series.Transport == "unix" && series.Outcome == "miss":
		valid = series.Valid == 0 && series.Missing == series.Samples &&
			series.AlreadyConsumed == 0 && series.Timeout == 0
	case series.Outcome == "hit":
		valid = series.Valid == series.Samples && series.Missing == 0 &&
			series.AlreadyConsumed == 0 && series.Timeout == 0
	case series.Transport == "getsockopt" && series.Outcome == "one_shot":
		valid = series.Valid == series.MeasurementRounds &&
			series.Missing+series.AlreadyConsumed == series.Samples-series.Valid &&
			series.Timeout == 0
	case series.Transport == "unix" && series.Outcome == "timeout":
		valid = series.Valid == 0 && series.Missing == 0 &&
			series.AlreadyConsumed == 0 && series.Timeout == series.Samples
	}
	if !valid {
		return fmt.Errorf(
			"benchmark series %s/%s has an unexpected status distribution",
			series.Transport,
			series.Outcome,
		)
	}
	return nil
}

func bridgeBenchmarkLatencyGatePassed(
	gate bridgeBenchmarkArtifactLatencyGate,
	p50NS int64,
	p99NS int64,
) bool {
	switch gate.Kind {
	case bridgeBenchmarkGateCorrectnessOnly:
		return true
	case bridgeBenchmarkGateP99LT:
		return p99NS < gate.P99MaxNS
	case bridgeBenchmarkGateP50GTEP99LTE:
		return p50NS >= gate.P50MinNS && p99NS <= gate.P99MaxNS
	default:
		return false
	}
}

func isBridgeBenchmarkNetTimeout(err error) bool {
	if err == nil {
		return false
	}
	var netError net.Error
	return errors.As(err, &netError) && netError.Timeout()
}

func unixBridgeRoundTrip(
	socket string,
	request []byte,
	response []byte,
	timeout time.Duration,
) (bool, error) {
	if timeout <= 0 {
		return false, errors.New("Unix benchmark deadline is required")
	}
	deadline := time.Now().Add(timeout)
	dialer := net.Dialer{Deadline: deadline}
	connection, err := dialer.Dial("unix", socket)
	if err != nil {
		return false, err
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return false, errors.Join(err, connection.Close())
	}
	if err := writeBridgeBenchmarkRequest(connection, request); err != nil {
		return false, errors.Join(err, connection.Close())
	}

	_, readErr := io.ReadFull(connection, response)
	return classifyBridgeBenchmarkRead(readErr, connection.Close())
}

func writeBridgeBenchmarkRequest(writer io.Writer, request []byte) error {
	remaining := request
	for len(remaining) > 0 {
		written, err := writer.Write(remaining)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
		remaining = remaining[written:]
	}
	return nil
}

func classifyBridgeBenchmarkRead(readErr, closeErr error) (bool, error) {
	if isBridgeBenchmarkNetTimeout(readErr) && closeErr == nil {
		return true, nil
	}
	return false, errors.Join(readErr, closeErr)
}

func TestBridgeBenchmarkArtifact(t *testing.T) {
	t.Run("writes a validated artifact", func(t *testing.T) {
		series := validBridgeBenchmarkArtifactSeries()
		artifactPath := filepath.Join(t.TempDir(), "nested", "benchmark.json")
		require.NoError(t, os.Mkdir(filepath.Dir(artifactPath), 0o700))

		require.NoError(t, writeBridgeBenchmarkArtifact(artifactPath, series))

		contents, err := os.ReadFile(artifactPath)
		require.NoError(t, err)
		require.True(t, bytes.HasSuffix(contents, []byte("\n")))
		info, err := os.Lstat(artifactPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

		var artifact bridgeBenchmarkArtifact
		require.NoError(t, json.Unmarshal(contents, &artifact))
		require.Equal(t, bridgeBenchmarkArtifact{
			SchemaVersion:         bridgeBenchmarkArtifactSchemaVersion,
			Benchmark:             bridgeBenchmarkArtifactName,
			Provenance:            expectedBridgeBenchmarkArtifactProvenance,
			UnixTimeoutDeadlineNS: bridgeBenchmarkUnixDeadline.Nanoseconds(),
			Series:                series,
		}, artifact)
	})

	t.Run("does not overwrite an artifact", func(t *testing.T) {
		directory := t.TempDir()
		require.NoError(t, os.Chmod(directory, 0o700))
		artifactPath := filepath.Join(directory, "benchmark.json")
		series := validBridgeBenchmarkArtifactSeries()
		require.NoError(t, writeBridgeBenchmarkArtifact(artifactPath, series))
		before, err := os.ReadFile(artifactPath)
		require.NoError(t, err)

		require.Error(t, writeBridgeBenchmarkArtifact(artifactPath, series))

		after, err := os.ReadFile(artifactPath)
		require.NoError(t, err)
		require.Equal(t, before, after)
	})

	t.Run("does not write invalid artifacts", func(t *testing.T) {
		artifactPath := filepath.Join(t.TempDir(), "benchmark.json")
		series := validBridgeBenchmarkArtifactSeries()
		series[0].Correct = false

		require.Error(t, writeBridgeBenchmarkArtifact(artifactPath, series))
		_, err := os.Lstat(artifactPath)
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("writes an accurately reported gate failure", func(t *testing.T) {
		directory := t.TempDir()
		require.NoError(t, os.Chmod(directory, 0o700))
		artifactPath := filepath.Join(directory, "benchmark.json")
		series := validBridgeBenchmarkArtifactSeries()
		series[0].P99NS = bridgeBenchmarkGetsockoptP99Limit.Nanoseconds()
		series[0].LatencyGate.Passed = false

		require.NoError(t, writeBridgeBenchmarkArtifact(artifactPath, series))
		contents, err := os.ReadFile(artifactPath)
		require.NoError(t, err)
		var artifact bridgeBenchmarkArtifact
		require.NoError(t, json.Unmarshal(contents, &artifact))
		require.False(t, artifact.Series[0].LatencyGate.Passed)
	})

	t.Run("accepts an empty artifact path", func(t *testing.T) {
		require.NoError(t, writeBridgeBenchmarkArtifact("", validBridgeBenchmarkArtifactSeries()))
	})

	t.Run("reports an invalid artifact parent", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "not-a-directory")
		require.NoError(t, os.WriteFile(parent, []byte("not a directory"), 0o600))

		require.Error(t, writeBridgeBenchmarkArtifact(
			filepath.Join(parent, "benchmark.json"),
			validBridgeBenchmarkArtifactSeries(),
		))
	})

	t.Run("rejects a symlinked artifact directory", func(t *testing.T) {
		targetDirectory := t.TempDir()
		linkPath := filepath.Join(t.TempDir(), "artifact-directory")
		require.NoError(t, os.Symlink(targetDirectory, linkPath))

		artifactPath := filepath.Join(linkPath, "benchmark.json")
		require.Error(t, writeBridgeBenchmarkArtifact(artifactPath, validBridgeBenchmarkArtifactSeries()))
		_, err := os.Lstat(filepath.Join(targetDirectory, "benchmark.json"))
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("rejects an intermediate symlink", func(t *testing.T) {
		targetRoot := t.TempDir()
		targetDirectory := filepath.Join(targetRoot, "artifact-directory")
		require.NoError(t, os.Mkdir(targetDirectory, 0o700))
		linkPath := filepath.Join(t.TempDir(), "intermediate")
		require.NoError(t, os.Symlink(targetRoot, linkPath))

		artifactPath := filepath.Join(linkPath, "artifact-directory", "benchmark.json")
		require.Error(t, writeBridgeBenchmarkArtifact(artifactPath, validBridgeBenchmarkArtifactSeries()))
		_, err := os.Lstat(filepath.Join(targetDirectory, "benchmark.json"))
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("rejects a group-writable artifact directory", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "artifact-directory")
		require.NoError(t, os.Mkdir(directory, 0o700))
		require.NoError(t, os.Chmod(directory, 0o770))

		require.Error(t, writeBridgeBenchmarkArtifact(
			filepath.Join(directory, "benchmark.json"),
			validBridgeBenchmarkArtifactSeries(),
		))
	})
}

func TestValidateBridgeBenchmarkArtifact(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*bridgeBenchmarkArtifact)
		wantError string
	}{
		{
			name: "schema version",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.SchemaVersion--
			},
			wantError: "unsupported benchmark artifact schema version",
		},
		{
			name: "benchmark name",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Benchmark = "other"
			},
			wantError: "unexpected benchmark artifact name",
		},
		{
			name: "provenance harness",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Provenance.Harness = "java_jni"
			},
			wantError: "unexpected benchmark artifact provenance",
		},
		{
			name: "provenance measurement scope",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Provenance.Measures[1] = "java"
			},
			wantError: "unexpected benchmark artifact provenance",
		},
		{
			name: "provenance exclusions",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Provenance.Excludes = []string{"java"}
			},
			wantError: "unexpected benchmark artifact provenance",
		},
		{
			name: "Unix deadline",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.UnixTimeoutDeadlineNS++
			},
			wantError: "unexpected Unix timeout deadline",
		},
		{
			name: "series count",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Series = artifact.Series[:len(artifact.Series)-1]
			},
			wantError: "unexpected benchmark series count",
		},
		{
			name: "series order",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Series[0], artifact.Series[1] = artifact.Series[1], artifact.Series[0]
			},
			wantError: "unexpected benchmark series 0",
		},
		{
			name: "run parameters",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Series[0].WarmupRounds++
			},
			wantError: "unexpected run parameters",
		},
		{
			name: "sample count",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Series[0].Samples--
			},
			wantError: "inconsistent sample count",
		},
		{
			name: "percentile order",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Series[0].P50NS = artifact.Series[0].P95NS + 1
			},
			wantError: "non-monotonic percentiles",
		},
		{
			name: "batch elapsed",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Series[0].BatchElapsedNS = artifact.Series[0].P99NS - 1
			},
			wantError: "impossible batch elapsed time",
		},
		{
			name: "throughput",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Series[0].OperationsPerSecond++
			},
			wantError: "inconsistent throughput",
		},
		{
			name: "negative status count",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Series[0].Timeout = -1
			},
			wantError: "invalid status counts",
		},
		{
			name: "status distribution",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Series[0].Valid++
				artifact.Series[0].Missing--
			},
			wantError: "unexpected status distribution",
		},
		{
			name: "correctness claim",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Series[0].Correct = false
			},
			wantError: "is not correct",
		},
		{
			name: "gate definition",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Series[0].LatencyGate.P99MaxNS++
			},
			wantError: "unexpected latency gate",
		},
		{
			name: "gate result claim",
			mutate: func(artifact *bridgeBenchmarkArtifact) {
				artifact.Series[0].LatencyGate.Passed = false
			},
			wantError: "inconsistent latency gate result",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			artifact := validBridgeBenchmarkArtifact()
			test.mutate(&artifact)
			require.ErrorContains(t, validateBridgeBenchmarkArtifact(artifact), test.wantError)
		})
	}
}

func TestIsBridgeBenchmarkNetTimeout(t *testing.T) {
	timeoutError := &net.DNSError{Err: "deadline", IsTimeout: true}
	require.True(t, isBridgeBenchmarkNetTimeout(timeoutError))
	require.True(t, isBridgeBenchmarkNetTimeout(errors.Join(io.EOF, timeoutError)))
	require.False(t, isBridgeBenchmarkNetTimeout(nil))
	require.False(t, isBridgeBenchmarkNetTimeout(io.EOF))
	require.False(t, isBridgeBenchmarkNetTimeout(&net.DNSError{Err: "other"}))
}

func TestClassifyBridgeBenchmarkRead(t *testing.T) {
	timeoutError := &net.DNSError{Err: "deadline", IsTimeout: true}
	timedOut, err := classifyBridgeBenchmarkRead(timeoutError, nil)
	require.True(t, timedOut)
	require.NoError(t, err)

	closeError := errors.New("close failed")
	timedOut, err = classifyBridgeBenchmarkRead(timeoutError, closeError)
	require.False(t, timedOut)
	require.ErrorIs(t, err, timeoutError)
	require.ErrorIs(t, err, closeError)

	timedOut, err = classifyBridgeBenchmarkRead(io.EOF, nil)
	require.False(t, timedOut)
	require.ErrorIs(t, err, io.EOF)

	timedOut, err = classifyBridgeBenchmarkRead(nil, nil)
	require.False(t, timedOut)
	require.NoError(t, err)
}

func TestWriteBridgeBenchmarkRequestRejectsNoProgress(t *testing.T) {
	require.ErrorIs(
		t,
		writeBridgeBenchmarkRequest(bridgeBenchmarkNoProgressWriter{}, []byte("request")),
		io.ErrNoProgress,
	)
}

func TestUnixBridgeRoundTrip(t *testing.T) {
	t.Run("complete response", func(t *testing.T) {
		request := []byte("benchmark request")
		expectedResponse := bytes.Repeat([]byte{0x5a}, 32)
		socket, listener, serverDone := startBridgeBenchmarkTestServer(
			t,
			func(connection *net.UnixConn) error {
				observedRequest := make([]byte, len(request))
				if _, err := io.ReadFull(connection, observedRequest); err != nil {
					return err
				}
				if !bytes.Equal(observedRequest, request) {
					return errors.New("server observed an unexpected request")
				}
				return writeBridgeBenchmarkRequest(connection, expectedResponse)
			},
		)
		defer listener.Close()

		response := make([]byte, len(expectedResponse))
		timedOut, err := unixBridgeRoundTrip(socket, request, response, time.Second)
		require.NoError(t, err)
		require.False(t, timedOut)
		require.Equal(t, expectedResponse, response)
		require.NoError(t, <-serverDone)
	})

	t.Run("read deadline", func(t *testing.T) {
		request := []byte("benchmark request")
		fullRequest := make(chan struct{})
		socket, listener, serverDone := startBridgeBenchmarkTestServer(
			t,
			func(connection *net.UnixConn) error {
				observedRequest := make([]byte, len(request))
				if _, err := io.ReadFull(connection, observedRequest); err != nil {
					return err
				}
				close(fullRequest)
				var untilClientClose [1]byte
				_, _ = connection.Read(untilClientClose[:])
				return nil
			},
		)
		defer listener.Close()

		response := make([]byte, 32)
		timedOut, err := unixBridgeRoundTrip(
			socket,
			request,
			response,
			bridgeBenchmarkUnixDeadline,
		)
		require.NoError(t, err)
		require.True(t, timedOut)
		requireNoWait(t, fullRequest, "server did not fully read the timeout request")
		require.NoError(t, <-serverDone)
	})

	t.Run("early EOF", func(t *testing.T) {
		request := []byte("benchmark request")
		socket, listener, serverDone := startBridgeBenchmarkTestServer(
			t,
			func(connection *net.UnixConn) error {
				observedRequest := make([]byte, len(request))
				_, err := io.ReadFull(connection, observedRequest)
				return err
			},
		)
		defer listener.Close()

		timedOut, err := unixBridgeRoundTrip(
			socket,
			request,
			make([]byte, 32),
			bridgeBenchmarkUnixDeadline,
		)
		require.Error(t, err)
		require.False(t, timedOut)
		require.NoError(t, <-serverDone)
	})

	t.Run("dial failure", func(t *testing.T) {
		socket := filepath.Join(t.TempDir(), "missing.sock")
		timedOut, err := unixBridgeRoundTrip(
			socket,
			[]byte("request"),
			make([]byte, 32),
			bridgeBenchmarkUnixDeadline,
		)
		require.Error(t, err)
		require.False(t, timedOut)
	})
}

type bridgeBenchmarkNoProgressWriter struct{}

func (bridgeBenchmarkNoProgressWriter) Write([]byte) (int, error) {
	return 0, nil
}

func startBridgeBenchmarkTestServer(
	t *testing.T,
	handle func(*net.UnixConn) error,
) (string, *net.UnixListener, <-chan error) {
	t.Helper()

	var socketID [8]byte
	_, err := rand.Read(socketID[:])
	require.NoError(t, err)
	socket := fmt.Sprintf("@obi-benchmark-%x", socketID)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	require.NoError(t, err)
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		serverDone <- handle(connection)
	}()
	return socket, listener, serverDone
}

func requireNoWait(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-signal:
	default:
		require.Fail(t, message)
	}
}

func validBridgeBenchmarkArtifact() bridgeBenchmarkArtifact {
	return bridgeBenchmarkArtifact{
		SchemaVersion: bridgeBenchmarkArtifactSchemaVersion,
		Benchmark:     bridgeBenchmarkArtifactName,
		Provenance: bridgeBenchmarkArtifactProvenance{
			Harness:  expectedBridgeBenchmarkArtifactProvenance.Harness,
			Measures: slices.Clone(expectedBridgeBenchmarkArtifactProvenance.Measures),
			Excludes: slices.Clone(expectedBridgeBenchmarkArtifactProvenance.Excludes),
		},
		UnixTimeoutDeadlineNS: bridgeBenchmarkUnixDeadline.Nanoseconds(),
		Series:                validBridgeBenchmarkArtifactSeries(),
	}
}

func validBridgeBenchmarkArtifactSeries() []bridgeBenchmarkArtifactSeries {
	return []bridgeBenchmarkArtifactSeries{
		validBridgeBenchmarkSeries("getsockopt", "miss", 16, 512, 0, 4096, 0, 0),
		validBridgeBenchmarkSeries("getsockopt", "hit", 16, 512, 4096, 0, 0, 0),
		validBridgeBenchmarkSeries("getsockopt", "one_shot", 16, 512, 512, 1792, 1792, 0),
		validBridgeBenchmarkSeries("unix", "miss", 8, 128, 0, 1024, 0, 0),
		validBridgeBenchmarkSeries("unix", "hit", 8, 128, 1024, 0, 0, 0),
		validBridgeBenchmarkSeries("unix", "timeout", 8, 128, 0, 0, 0, 1024),
	}
}

func validBridgeBenchmarkSeries(
	transport string,
	outcome string,
	warmupRounds int,
	measurementRounds int,
	valid int,
	missing int,
	alreadyConsumed int,
	timeouts int,
) bridgeBenchmarkArtifactSeries {
	samples := measurementRounds * bridgeBenchmarkConcurrency
	p50 := 10 * time.Microsecond
	p95 := 20 * time.Microsecond
	p99 := 30 * time.Microsecond
	batchElapsed := time.Duration(measurementRounds) * 100 * time.Microsecond
	if outcome == "timeout" {
		p50 = bridgeBenchmarkUnixDeadline
		p95 = 75 * time.Millisecond
		p99 = 90 * time.Millisecond
		batchElapsed = time.Duration(measurementRounds) * 60 * time.Millisecond
	}
	latencyGate := expectedBridgeBenchmarkLatencyGate(transport, outcome)
	latencyGate.Passed = bridgeBenchmarkLatencyGatePassed(
		latencyGate,
		p50.Nanoseconds(),
		p99.Nanoseconds(),
	)
	return bridgeBenchmarkArtifactSeries{
		Transport:           transport,
		Outcome:             outcome,
		WarmupRounds:        warmupRounds,
		MeasurementRounds:   measurementRounds,
		Samples:             samples,
		Concurrency:         bridgeBenchmarkConcurrency,
		BatchElapsedNS:      batchElapsed.Nanoseconds(),
		P50NS:               p50.Nanoseconds(),
		P95NS:               p95.Nanoseconds(),
		P99NS:               p99.Nanoseconds(),
		OperationsPerSecond: float64(samples) / batchElapsed.Seconds(),
		Valid:               valid,
		Missing:             missing,
		AlreadyConsumed:     alreadyConsumed,
		Timeout:             timeouts,
		Errors:              0,
		Correct:             true,
		LatencyGate:         latencyGate,
	}
}

func expectedBridgeBenchmarkLatencyGate(
	transport string,
	outcome string,
) bridgeBenchmarkArtifactLatencyGate {
	for _, expected := range expectedBridgeBenchmarkSeries {
		if expected.transport == transport && expected.outcome == outcome {
			return expected.latencyGate
		}
	}
	panic(fmt.Sprintf("unexpected benchmark series: %s/%s", transport, outcome))
}
