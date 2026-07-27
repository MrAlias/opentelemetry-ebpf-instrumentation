// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package tracesgen

import (
	"testing"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestWindowsResourceIdentityMatchesNormalOBI(t *testing.T) {
	service := svc.Attrs{
		UID: svc.UID{
			Name:      "obi-windows-target.exe",
			Namespace: "acceptance",
			Instance:  "4242",
		},
		SDKLanguage: svc.InstrumentableGeneric,
		HostName:    "windows-vm",
		Metadata: map[attr.Name]string{
			attr.K8sPodName: "target-pod",
		},
	}
	eventTime := time.Unix(1_750_000_000, 123_456_700)
	span := request.Span{
		Type:         request.EventTypeManualSpan,
		Method:       "process.start obi-windows-target.exe",
		RequestStart: eventTime.UnixNano(),
		Start:        eventTime.UnixNano(),
		End:          eventTime.UnixNano(),
		Service:      service,
	}
	group := []TraceSpanAndAttributes{{
		Span:       &span,
		Attributes: []attribute.KeyValue{attribute.Int64("process.pid", 4242)},
	}}

	cache := expirable2.NewLRU[svc.UID, []attribute.KeyValue](1, nil, time.Minute)
	normal := GenerateTracesWithAttributes(
		cache,
		&span.Service,
		nil,
		&meta.NodeMeta{HostID: "normal-linux-host-id"},
		group,
		ReporterName,
	)
	windows := GenerateWindowsProcessTraces(&span.Service, group)

	normalResource := traceResourceAttributes(t, normal)
	windowsResource := traceResourceAttributes(t, windows)

	assert.Equal(t, "linux", normalResource["os.type"])
	assert.Equal(t, "normal-linux-host-id", normalResource["host.id"])
	assert.Equal(t, "windows", windowsResource["os.type"])
	assert.NotContains(t, windowsResource, "host.id")

	delete(normalResource, "host.id")
	delete(normalResource, "os.type")
	delete(windowsResource, "os.type")
	assert.Equal(t, normalResource, windowsResource)

	assert.Equal(t, "opentelemetry", windowsResource["telemetry.sdk.name"])
	assert.Equal(t, attr.VendorSDKVersion, windowsResource["telemetry.sdk.version"])
	assert.Equal(t, "opentelemetry-ebpf-instrumentation", windowsResource["telemetry.distro.name"])
	assert.Equal(t, attr.TelemetryDistroVersion, windowsResource["telemetry.distro.version"])
	assert.Equal(t, ReporterName, windowsResource["otel.scope.name"])

	assertCanonicalScope(t, normal)
	assertCanonicalScope(t, windows)
}

func TestExtraResourceAttributesPreserveNormalPrecedence(t *testing.T) {
	eventTime := time.Unix(1_750_000_000, 0)
	span := request.Span{
		Type:         request.EventTypeManualSpan,
		Method:       "test",
		RequestStart: eventTime.UnixNano(),
		Start:        eventTime.UnixNano(),
		End:          eventTime.UnixNano(),
	}

	traces := generateTracesFromResourceAttributes(
		nil,
		[]attribute.KeyValue{
			semconv.OTelScopeName("user-override"),
		},
		[]TraceSpanAndAttributes{{Span: &span}},
		ReporterName,
	)

	resource := traceResourceAttributes(t, traces)
	assert.Equal(t, "user-override", resource["otel.scope.name"])
	assertCanonicalScope(t, traces)
}

func traceResourceAttributes(t *testing.T, traces ptrace.Traces) map[string]any {
	t.Helper()
	require.Equal(t, 1, traces.ResourceSpans().Len())
	return traces.ResourceSpans().At(0).Resource().Attributes().AsRaw()
}

func assertCanonicalScope(t *testing.T, traces ptrace.Traces) {
	t.Helper()
	scopeSpans := traces.ResourceSpans().At(0).ScopeSpans()
	require.Equal(t, 1, scopeSpans.Len())
	assert.Empty(t, scopeSpans.At(0).Scope().Name())
	assert.Empty(t, scopeSpans.At(0).Scope().Version())
}
