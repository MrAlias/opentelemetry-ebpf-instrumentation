// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracecheck

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

func TestDemoMetricsMatchPrometheusReporter(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := imetrics.NewPrometheusReporter(
		&imetrics.InternalMetricsConfig{},
		nil,
		registry,
	)
	reporter.JavaRemoteParent("getsockopt", "take", "valid", 13)
	reporter.BpfMapEntries("41", "java_remote_par", "hash", 17)
	reporter.BpfMapMaxEntries("41", "java_remote_par", "hash", 19)
	reporter.AvoidInstrumentationTraces("java-backend", "apache-java-https", "instance")

	families, err := registry.Gather()
	require.NoError(t, err)
	names := demoMetricNames(t, families)

	var exposition bytes.Buffer
	for _, family := range families {
		_, err := expfmt.MetricFamilyToText(&exposition, family)
		require.NoError(t, err)
	}
	metrics := filepath.Join(t.TempDir(), "metrics.prom")
	require.NoError(t, os.WriteFile(metrics, exposition.Bytes(), 0o600))

	packageDir, err := os.Getwd()
	require.NoError(t, err)
	demoDir := filepath.Dir(packageDir)
	runner := filepath.Join(demoDir, "run.sh")
	runnerTests := filepath.Join(demoDir, "scripts", "run_test.sh")

	command := exec.Command(
		"bash",
		"-c",
		`set -Eeuo pipefail
source "$1"
metrics="$2"
java_duplicate_suppression_present "$metrics" || {
  printf 'duplicate suppression metric not found\n' >&2
  exit 1
}
bridge_total="$(bridge_success_total "$metrics")"
[[ "$bridge_total" == "13" ]] || {
  printf 'bridge total: %s\n' "$bridge_total" >&2
  exit 1
}
map_entries="$(pressure_map_metric "$metrics" "$3" 41)"
[[ "$map_entries" == "41 17" ]] || {
  printf 'map entries: %s\n' "$map_entries" >&2
  exit 1
}
map_max_entries="$(pressure_map_metric "$metrics" "$4" 41)"
[[ "$map_max_entries" == "41 19" ]] || {
  printf 'map max entries: %s\n' "$map_max_entries" >&2
  exit 1
}`,
		"metric-contract",
		runner,
		metrics,
		names["map_entries"],
		names["map_max_entries"],
	)
	output, err := command.CombinedOutput()
	require.NoErrorf(t, err, "demo rejected reporter metrics:\n%s", output)

	testSource, err := os.ReadFile(runnerTests)
	require.NoError(t, err)
	for _, name := range names {
		assert.Contains(t, string(testSource), name)
	}
}

func demoMetricNames(t *testing.T, families []*dto.MetricFamily) map[string]string {
	t.Helper()

	names := map[string]string{}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			labels := demoMetricLabels(metric)
			switch {
			case labels["transport"] == "getsockopt" &&
				labels["operation"] == "take" &&
				labels["status"] == "valid":
				names["bridge"] = family.GetName()
			case labels["map_id"] == "41" && metric.GetGauge().GetValue() == 17:
				names["map_entries"] = family.GetName()
			case labels["map_id"] == "41" && metric.GetGauge().GetValue() == 19:
				names["map_max_entries"] = family.GetName()
			case labels["service_name"] == "java-backend" &&
				labels["service_namespace"] == "apache-java-https" &&
				labels["telemetry_type"] == "traces":
				names["avoided_services"] = family.GetName()
			}
		}
	}

	for _, kind := range []string{"bridge", "map_entries", "map_max_entries", "avoided_services"} {
		assert.NotEmpty(t, names[kind], "missing %s metric family", kind)
	}
	return names
}

func demoMetricLabels(metric *dto.Metric) map[string]string {
	labels := make(map[string]string, len(metric.GetLabel()))
	for _, label := range metric.GetLabel() {
		labels[label.GetName()] = label.GetValue()
	}
	return labels
}
