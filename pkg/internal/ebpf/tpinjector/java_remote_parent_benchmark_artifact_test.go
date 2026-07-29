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
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	javaRemoteParentBenchmarkArtifactEnv = "OBI_JAVA_REMOTE_PARENT_BENCHMARK_ARTIFACT"
	bridgeBenchmarkArtifactSchemaVersion = 1
	bridgeBenchmarkArtifactName          = "java_remote_parent_transport"
	benchmarkArtifactTemporaryAttempts   = 16
)

type bridgeBenchmarkArtifact struct {
	SchemaVersion int                             `json:"schema_version"`
	Benchmark     string                          `json:"benchmark"`
	Series        []bridgeBenchmarkArtifactSeries `json:"series"`
}

type bridgeBenchmarkArtifactSeries struct {
	Transport           string  `json:"transport"`
	Outcome             string  `json:"outcome"`
	WarmupRounds        int     `json:"warmup_rounds"`
	MeasurementRounds   int     `json:"measurement_rounds"`
	Samples             int     `json:"samples"`
	Concurrency         int     `json:"concurrency"`
	BatchElapsedNS      int64   `json:"batch_elapsed_ns"`
	P50NS               int64   `json:"p50_ns"`
	P95NS               int64   `json:"p95_ns"`
	P99NS               int64   `json:"p99_ns"`
	OperationsPerSecond float64 `json:"operations_per_second"`
	Valid               int     `json:"valid"`
	Missing             int     `json:"missing"`
	AlreadyConsumed     int     `json:"already_consumed"`
	Errors              int     `json:"errors"`
	Correct             bool    `json:"correct"`
}

var expectedBridgeBenchmarkSeries = []struct {
	transport string
	outcome   string
}{
	{transport: "getsockopt", outcome: "miss"},
	{transport: "getsockopt", outcome: "hit"},
	{transport: "getsockopt", outcome: "one_shot"},
	{transport: "unix", outcome: "miss"},
	{transport: "unix", outcome: "hit"},
}

func writeBridgeBenchmarkArtifact(
	artifactPath string,
	series []bridgeBenchmarkArtifactSeries,
) error {
	if artifactPath == "" {
		return nil
	}

	artifact := bridgeBenchmarkArtifact{
		SchemaVersion: bridgeBenchmarkArtifactSchemaVersion,
		Benchmark:     bridgeBenchmarkArtifactName,
		Series:        series,
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
		if series.WarmupRounds <= 0 || series.MeasurementRounds <= 0 || series.Concurrency <= 0 {
			return fmt.Errorf("benchmark series %s/%s has non-positive run parameters", series.Transport, series.Outcome)
		}
		if series.Samples <= 0 || int64(series.Samples) != int64(series.Concurrency)*int64(series.MeasurementRounds) {
			return fmt.Errorf("benchmark series %s/%s has inconsistent sample count", series.Transport, series.Outcome)
		}
		if series.BatchElapsedNS <= 0 || series.P50NS <= 0 || series.P95NS <= 0 || series.P99NS <= 0 {
			return fmt.Errorf("benchmark series %s/%s has non-positive timing", series.Transport, series.Outcome)
		}
		if series.P50NS > series.P95NS || series.P95NS > series.P99NS {
			return fmt.Errorf("benchmark series %s/%s has non-monotonic percentiles", series.Transport, series.Outcome)
		}
		if series.OperationsPerSecond <= 0 || math.IsInf(series.OperationsPerSecond, 0) || math.IsNaN(series.OperationsPerSecond) {
			return fmt.Errorf("benchmark series %s/%s has invalid throughput", series.Transport, series.Outcome)
		}
		if series.Valid < 0 || series.Missing < 0 || series.AlreadyConsumed < 0 || series.Errors != 0 {
			return fmt.Errorf("benchmark series %s/%s has invalid status counts", series.Transport, series.Outcome)
		}
		if series.Valid+series.Missing+series.AlreadyConsumed+series.Errors != series.Samples {
			return fmt.Errorf("benchmark series %s/%s has inconsistent status counts", series.Transport, series.Outcome)
		}
		if !series.Correct {
			return fmt.Errorf("benchmark series %s/%s is not correct", series.Transport, series.Outcome)
		}
	}

	return nil
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
			SchemaVersion: bridgeBenchmarkArtifactSchemaVersion,
			Benchmark:     bridgeBenchmarkArtifactName,
			Series:        series,
		}, artifact)
	})

	t.Run("does not overwrite an artifact", func(t *testing.T) {
		artifactPath := filepath.Join(t.TempDir(), "benchmark.json")
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

func validBridgeBenchmarkArtifactSeries() []bridgeBenchmarkArtifactSeries {
	return []bridgeBenchmarkArtifactSeries{
		validBridgeBenchmarkSeries("getsockopt", "miss", 16, 512, 0, 4096, 0),
		validBridgeBenchmarkSeries("getsockopt", "hit", 16, 512, 4096, 0, 0),
		validBridgeBenchmarkSeries("getsockopt", "one_shot", 16, 512, 512, 1792, 1792),
		validBridgeBenchmarkSeries("unix", "miss", 8, 128, 0, 1024, 0),
		validBridgeBenchmarkSeries("unix", "hit", 8, 128, 1024, 0, 0),
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
) bridgeBenchmarkArtifactSeries {
	samples := measurementRounds * 8
	return bridgeBenchmarkArtifactSeries{
		Transport:           transport,
		Outcome:             outcome,
		WarmupRounds:        warmupRounds,
		MeasurementRounds:   measurementRounds,
		Samples:             samples,
		Concurrency:         8,
		BatchElapsedNS:      int64(samples * 100),
		P50NS:               10,
		P95NS:               20,
		P99NS:               30,
		OperationsPerSecond: 1_000,
		Valid:               valid,
		Missing:             missing,
		AlreadyConsumed:     alreadyConsumed,
		Errors:              0,
		Correct:             true,
	}
}
