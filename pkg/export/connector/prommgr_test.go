// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrometheusManagerRegistersAddressSpecificEndpoint(t *testing.T) {
	manager := &PrometheusManager{}
	collector := prometheus.NewGauge(prometheus.GaugeOpts{Name: "address_test"})

	manager.RegisterAddress("127.0.0.1", 18990, "/internal/metrics", collector)

	_, ok := manager.registries.Get(
		prometheusEndpoint{address: "127.0.0.1", port: 18990},
		"/internal/metrics",
	)
	require.True(t, ok)
	_, ok = manager.registries.Get(prometheusEndpoint{port: 18990}, "/internal/metrics")
	assert.False(t, ok)
}

func TestPrometheusListenAddress(t *testing.T) {
	assert.Equal(t, ":18990", prometheusListenAddress(prometheusEndpoint{port: 18990}))
	assert.Equal(
		t,
		"127.0.0.1:18990",
		prometheusListenAddress(prometheusEndpoint{address: "127.0.0.1", port: 18990}),
	)
	assert.Equal(
		t,
		"[::1]:18990",
		prometheusListenAddress(prometheusEndpoint{address: "::1", port: 18990}),
	)
}
