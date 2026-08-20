// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"bytes"
	"embed"
	"io/fs"
	"sort"
	"testing"

	ciliumbpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/javabridge"
)

// Keep this manifest explicit: every generated program family that shares the
// Java remote-parent stats map must carry the same ABI on both architectures.
//
//go:embed generictracer/bpf_x86_bpfel.o generictracer/bpf_arm64_bpfel.o
//go:embed gotracer/bpf_x86_bpfel.o gotracer/bpf_arm64_bpfel.o
//go:embed tpinjector/bpf_x86_bpfel.o tpinjector/bpf_arm64_bpfel.o
//go:embed tpinjector/bpfjavaremoteparent_x86_bpfel.o tpinjector/bpfjavaremoteparent_arm64_bpfel.o
//go:embed tpinjector/bpfjavaremoteparentmaps_x86_bpfel.o tpinjector/bpfjavaremoteparentmaps_arm64_bpfel.o
var javaRemoteParentGeneratedObjects embed.FS

var javaRemoteParentGeneratedObjectPaths = [...]string{
	"generictracer/bpf_x86_bpfel.o",
	"generictracer/bpf_arm64_bpfel.o",
	"gotracer/bpf_x86_bpfel.o",
	"gotracer/bpf_arm64_bpfel.o",
	"tpinjector/bpf_x86_bpfel.o",
	"tpinjector/bpf_arm64_bpfel.o",
	"tpinjector/bpfjavaremoteparent_x86_bpfel.o",
	"tpinjector/bpfjavaremoteparent_arm64_bpfel.o",
	"tpinjector/bpfjavaremoteparentmaps_x86_bpfel.o",
	"tpinjector/bpfjavaremoteparentmaps_arm64_bpfel.o",
}

func TestJavaRemoteParentGeneratedStatsMapABI(t *testing.T) {
	const expectedObjectCount = 10

	require.Len(t, javaRemoteParentGeneratedObjectPaths, expectedObjectCount)
	wantPaths := append([]string(nil), javaRemoteParentGeneratedObjectPaths[:]...)
	sort.Strings(wantPaths)
	var embeddedPaths []string
	require.NoError(t, fs.WalkDir(javaRemoteParentGeneratedObjects, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			embeddedPaths = append(embeddedPaths, path)
		}
		return nil
	}))
	sort.Strings(embeddedPaths)
	require.Equal(t, wantPaths, embeddedPaths)

	seen := make(map[string]struct{}, expectedObjectCount)
	for _, objectPath := range javaRemoteParentGeneratedObjectPaths {
		require.NotContains(t, seen, objectPath)
		seen[objectPath] = struct{}{}

		objectBytes, err := javaRemoteParentGeneratedObjects.ReadFile(objectPath)
		require.NoError(t, err, objectPath)
		require.NotEmpty(t, objectBytes, objectPath)
		spec, err := ciliumbpf.LoadCollectionSpecFromReader(bytes.NewReader(objectBytes))
		require.NoError(t, err, objectPath)

		for _, disabled := range []bool{false, true} {
			mode := "enabled"
			candidate := spec.Copy()
			if disabled {
				mode = "disabled"
				javabridge.MinimizeDisabledMaps(candidate)
			}
			stats := candidate.Maps["java_remote_parent_stats"]
			require.NotNil(t, stats, objectPath+" "+mode)
			require.Equal(t, ciliumbpf.PerCPUArray, stats.Type, objectPath+" "+mode)
			require.Equal(t, uint32(4), stats.KeySize, objectPath+" "+mode)
			require.Equal(t, uint32(8), stats.ValueSize, objectPath+" "+mode)
			require.Equal(t, uint32(37), stats.MaxEntries, objectPath+" "+mode)
			require.Zero(t, stats.Flags, objectPath+" "+mode)
			require.Equal(t, ebpfconvenience.PinInternal, stats.Pinning, objectPath+" "+mode)
		}
	}
	require.Len(t, seen, expectedObjectCount)
}
