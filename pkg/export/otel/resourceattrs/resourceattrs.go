// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package resourceattrs builds the resource attributes shared by OBI
// exporters and platform-specific frontends.
package resourceattrs // import "go.opentelemetry.io/obi/pkg/export/otel/resourceattrs"

import (
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// ForService returns OBI's standard service resource attributes. A nil hostID
// omits host.id; a non-nil hostID preserves the value supplied by the platform.
func ForService(service *svc.Attrs, osType attribute.KeyValue, hostID *string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(service.UID.Name),
		// SpanMetrics requires an extra attribute besides service name
		// to generate the traces.target.info / traces_target_info metric,
		// so the service is visible in the ServicesList. It also lets the
		// App O11y plugin identify the instrumented language.
		semconv.TelemetrySDKLanguageKey.String(service.SDKLanguage.String()),
		semconv.TelemetrySDKNameKey.String(attr.VendorSDKName),
		semconv.TelemetrySDKVersion(attr.VendorSDKVersion),
		semconv.TelemetryDistroName(attr.TelemetryDistroName),
		semconv.TelemetryDistroVersion(attr.TelemetryDistroVersion),
		semconv.HostName(service.HostName),
	}

	if hostID != nil {
		attrs = append(attrs, semconv.HostID(*hostID))
	}
	attrs = append(attrs, osType)

	if service.UID.Namespace != "" {
		attrs = append(attrs, semconv.ServiceNamespace(service.UID.Namespace))
	}

	for key, value := range service.Metadata {
		attrs = append(attrs, key.OTEL().String(value))
	}

	return attrs
}

// ForApp adds OBI's application instance identity to the service resource.
func ForApp(service *svc.Attrs, osType attribute.KeyValue, hostID *string) []attribute.KeyValue {
	return append(ForService(service, osType, hostID), semconv.ServiceInstanceID(service.UID.Instance))
}
