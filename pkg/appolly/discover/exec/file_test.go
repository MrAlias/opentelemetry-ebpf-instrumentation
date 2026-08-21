// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/transform/route"
)

func TestFileInfoIDIncludesDeviceAndInode(t *testing.T) {
	fi := New(Init{Dev: 7, Ino: 42})

	if got, want := fi.ID(), (FileID{Dev: 7, Ino: 42}); got != want {
		t.Fatalf("ID() = %+v, want %+v", got, want)
	}
}

func TestServiceMetadataAdmissionRollbackIsFieldScoped(t *testing.T) {
	fi := New(Init{Service: svc.Attrs{
		UID:      svc.UID{Namespace: "production", Instance: "stable"},
		Metadata: map[attr.Name]string{"existing": "preserved"},
	}})
	receipt := fi.BeginServiceMetadataAdmission(
		"orders", attr.Name("service.version"), "1.2.3",
	)
	if receipt == nil {
		t.Fatal("missing provisional service metadata receipt")
	}
	matcher := route.NewMatcher([]string{"/orders/:id"})

	fi.SetSDKLanguage(svc.InstrumentableJava)
	fi.SetHarvestedRoutes(matcher)
	fi.SetHostNameInstance("host-a", "updated-instance")
	receipt.Rollback()

	got := fi.ServiceAttrs()
	if got.UID.Name != "" || got.UID.Namespace != "production" ||
		got.UID.Instance != "updated-instance" {
		t.Fatalf("rollback service UID = %#v", got.UID)
	}
	if got.Metadata["existing"] != "preserved" ||
		got.Metadata["service.version"] != "" {
		t.Fatalf("rollback metadata = %#v", got.Metadata)
	}
	if got.SDKLanguage != svc.InstrumentableJava || got.HostName != "host-a" ||
		got.HarvestedRouteMatcher != matcher {
		t.Fatalf("rollback erased unrelated service updates: %#v", got)
	}
	if fi.AutoName() {
		t.Fatal("rollback marked provisional service name as automatic")
	}
}

func TestServiceMetadataAdmissionSameValueSettersSupersedeReceipt(t *testing.T) {
	versionKey := attr.Name("service.version")
	fi := New(Init{})
	receipt := fi.BeginServiceMetadataAdmission("orders", versionKey, "1.2.3")
	if receipt == nil {
		t.Fatal("missing provisional service metadata receipt")
	}
	provisional := fi.ServiceAttrs()

	// These are intentional publications even though their values are
	// byte-for-byte equal to the provisional fields.
	fi.SetUID(provisional.UID)
	fi.SetMetadata(provisional.Metadata)
	receipt.Commit()
	receipt.Rollback()

	got := fi.ServiceAttrs()
	if got.UID.Name != "orders" || got.Metadata[versionKey] != "1.2.3" {
		t.Fatalf("same-value setters lost their adopted fields: %#v", got)
	}
	if fi.AutoName() {
		t.Fatal("stale commit marked a same-value externally owned name as automatic")
	}
}

func TestServiceMetadataAdmissionSameValueAutoAndEnvironmentSettersSupersedeReceipt(t *testing.T) {
	versionKey := attr.Name("service.version")

	t.Run("auto service name", func(t *testing.T) {
		fi := New(Init{})
		receipt := fi.BeginServiceMetadataAdmission("orders", versionKey, "")
		fi.SetAutoServiceName("orders")
		receipt.Rollback()

		if fi.ServiceAttrs().UID.Name != "orders" || !fi.AutoName() {
			t.Fatal("same-value automatic-name setter did not supersede receipt")
		}
	})

	t.Run("environment", func(t *testing.T) {
		fi := New(Init{})
		receipt := fi.BeginServiceMetadataAdmission("orders", versionKey, "1.2.3")
		fi.ApplyEnvVariables(map[string]string{
			envServiceName:   "orders",
			envResourceAttrs: "service.version=1.2.3",
		})
		receipt.Rollback()

		got := fi.ServiceAttrs()
		if got.UID.Name != "orders" || got.Metadata[versionKey] != "1.2.3" {
			t.Fatalf("same-value environment publication was rolled back: %#v", got)
		}
	})
}

func TestServiceMetadataAdmissionOwnershipIsPerField(t *testing.T) {
	versionKey := attr.Name("service.version")

	t.Run("identity setter supersedes only name", func(t *testing.T) {
		fi := New(Init{})
		receipt := fi.BeginServiceMetadataAdmission("derived", versionKey, "1.2.3")
		uid := fi.ServiceAttrs().UID
		uid.Name = "runtime"
		uid.Namespace = "runtime-ns"
		fi.SetUID(uid)
		receipt.Rollback()

		got := fi.ServiceAttrs()
		if got.UID.Name != "runtime" || got.UID.Namespace != "runtime-ns" || got.Metadata != nil {
			t.Fatalf("field-scoped identity rollback = %#v", got)
		}
	})

	t.Run("metadata setter supersedes only version", func(t *testing.T) {
		fi := New(Init{})
		receipt := fi.BeginServiceMetadataAdmission("derived", versionKey, "1.2.3")
		metadata := fi.ServiceAttrs().Metadata
		metadata["runtime"] = "published"
		fi.SetMetadata(metadata)
		receipt.Rollback()

		got := fi.ServiceAttrs()
		if got.UID.Name != "" || got.Metadata[versionKey] != "1.2.3" ||
			got.Metadata["runtime"] != "published" {
			t.Fatalf("field-scoped metadata rollback = %#v", got)
		}
	})
}

func TestServiceMetadataAdmissionNewReceiptSupersedesOld(t *testing.T) {
	versionKey := attr.Name("service.version")
	fi := New(Init{})
	first := fi.BeginServiceMetadataAdmission("orders", versionKey, "1.0")
	second := fi.BeginServiceMetadataAdmission("checkout", versionKey, "2.0")
	if first == nil || second == nil {
		t.Fatal("missing service metadata receipt")
	}
	first.Commit()
	first.Rollback()

	provisional := fi.ServiceAttrs()
	if provisional.UID.Name != "checkout" || provisional.Metadata[versionKey] != "2.0" {
		t.Fatalf("old receipt changed replacement provisional fields: %#v", provisional)
	}
	second.Rollback()
	got := fi.ServiceAttrs()
	if got.UID.Name != "" || got.Metadata != nil {
		t.Fatalf("replacement rollback did not restore logical baseline: %#v", got)
	}
}

func TestServiceMetadataAdmissionRollbackPreservesMetadataMapShape(t *testing.T) {
	versionKey := attr.Name("service.version")
	tests := []struct {
		name     string
		metadata map[attr.Name]string
		wantNil  bool
		wantKey  bool
	}{
		{name: "nil", metadata: nil, wantNil: true},
		{name: "empty", metadata: map[attr.Name]string{}},
		{name: "present empty version", metadata: map[attr.Name]string{versionKey: ""}, wantKey: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := New(Init{Service: svc.Attrs{Metadata: tt.metadata}})
			receipt := fi.BeginServiceMetadataAdmission("", versionKey, "1.2.3")
			if receipt == nil {
				t.Fatal("missing provisional version receipt")
			}
			receipt.Rollback()

			got := fi.ServiceAttrs().Metadata
			_, hasKey := got[versionKey]
			if (got == nil) != tt.wantNil || hasKey != tt.wantKey {
				t.Fatalf("rollback map = %#v, want nil=%v key=%v", got, tt.wantNil, tt.wantKey)
			}
		})
	}
}

func TestUpdateServiceAttrsReconcilesAdmissionByChangedField(t *testing.T) {
	versionKey := attr.Name("service.version")

	t.Run("unrelated decoration preserves receipt", func(t *testing.T) {
		fi := New(Init{})
		receipt := fi.BeginServiceMetadataAdmission("derived", versionKey, "1.2.3")
		if receipt == nil {
			t.Fatal("missing provisional service metadata receipt")
		}

		if !fi.UpdateServiceAttrs(func(service *svc.Attrs, _ bool) ServiceAttrsUpdate {
			service.UID.Namespace = "runtime-ns"
			service.UID.Instance = "runtime-instance"
			service.Metadata["deployment.environment"] = "production"
			service.HostName = "host-a"
			service.SDKLanguage = svc.InstrumentableJava
			return ServiceAttrsUpdate{
				Publish:      true,
				MetadataKeys: []attr.Name{"deployment.environment"},
			}
		}) {
			t.Fatal("service decoration was not published")
		}
		receipt.Rollback()

		got := fi.ServiceAttrs()
		if got.UID.Name != "" || got.Metadata[versionKey] != "" {
			t.Fatalf("unrelated decoration adopted provisional fields: %#v", got)
		}
		if got.UID.Namespace != "runtime-ns" || got.UID.Instance != "runtime-instance" ||
			got.Metadata["deployment.environment"] != "production" ||
			got.HostName != "host-a" || got.SDKLanguage != svc.InstrumentableJava {
			t.Fatalf("rollback erased decorator fields: %#v", got)
		}
	})

	t.Run("changed owned fields supersede receipt", func(t *testing.T) {
		fi := New(Init{})
		receipt := fi.BeginServiceMetadataAdmission("derived", versionKey, "1.2.3")
		if receipt == nil {
			t.Fatal("missing provisional service metadata receipt")
		}

		fi.UpdateServiceAttrs(func(service *svc.Attrs, _ bool) ServiceAttrsUpdate {
			service.UID.Name = "decorated"
			service.Metadata[versionKey] = "9.9.9"
			return ServiceAttrsUpdate{
				Publish:      true,
				ServiceName:  true,
				MetadataKeys: []attr.Name{versionKey},
			}
		})
		receipt.Rollback()

		got := fi.ServiceAttrs()
		if got.UID.Name != "decorated" || got.Metadata[versionKey] != "9.9.9" {
			t.Fatalf("rollback erased changed decorator fields: %#v", got)
		}
	})

	t.Run("unchanged owned fields remain provisional", func(t *testing.T) {
		fi := New(Init{})
		receipt := fi.BeginServiceMetadataAdmission("derived", versionKey, "1.2.3")
		if receipt == nil {
			t.Fatal("missing provisional service metadata receipt")
		}

		fi.UpdateServiceAttrs(func(service *svc.Attrs, _ bool) ServiceAttrsUpdate {
			service.UID.Name = "derived"
			service.Metadata[versionKey] = "1.2.3"
			return ServiceAttrsUpdate{Publish: true}
		})
		receipt.Rollback()

		got := fi.ServiceAttrs()
		if got.UID.Name != "" || got.Metadata != nil {
			t.Fatalf("unchanged decorator fields superseded receipt: %#v", got)
		}
	})
}

func TestEnsureServiceMetadataMapPreservesVersionReceipt(t *testing.T) {
	versionKey := attr.Name("service.version")
	fi := New(Init{})
	receipt := fi.BeginServiceMetadataAdmission("", versionKey, "1.2.3")
	if receipt == nil {
		t.Fatal("missing provisional version receipt")
	}

	fi.EnsureServiceMetadataMap()
	receipt.Rollback()

	got := fi.ServiceAttrs().Metadata
	if got == nil || len(got) != 0 {
		t.Fatalf("metadata map after rollback = %#v, want non-nil empty map", got)
	}
}

func TestJavaAuthorizationReadinessIsGenerationExact(t *testing.T) {
	fi := New(Init{})
	firstSequence := fi.PrepareJavaAgentCapability(11)
	firstCapability, begunFirstSequence := fi.BeginJavaAgentAuthorization()
	if firstCapability != 11 || begunFirstSequence != firstSequence {
		t.Fatalf("first authorization = (%d, %d), want (11, %d)",
			firstCapability, begunFirstSequence, firstSequence)
	}
	firstState := fi.javaAuth

	secondSequence := fi.PrepareJavaAgentCapability(22)
	if !firstState.completed || firstState.capability != 0 {
		t.Fatal("superseded readiness generation did not fail closed")
	}
	select {
	case <-firstState.done:
	default:
		t.Fatal("superseded readiness generation did not release its waiter")
	}
	secondCapability, begunSecondSequence := fi.BeginJavaAgentAuthorization()
	if secondCapability != 22 || begunSecondSequence != secondSequence {
		t.Fatalf("second authorization = (%d, %d), want (22, %d)",
			secondCapability, begunSecondSequence, secondSequence)
	}

	result := make(chan uint64, 1)
	errResult := make(chan error, 1)
	go func() {
		capability, err := fi.WaitJavaAgentAuthorization(t.Context())
		result <- capability
		errResult <- err
	}()
	fi.CompleteJavaAgentAuthorization(firstSequence, 11)
	select {
	case capability := <-result:
		t.Fatalf("stale completion released current generation with capability %d", capability)
	default:
	}
	fi.CompleteJavaAgentAuthorization(secondSequence, 22)
	if capability := <-result; capability != 22 {
		t.Fatalf("completed capability = %d, want 22", capability)
	}
	if err := <-errResult; err != nil {
		t.Fatalf("waiting for completed authorization: %v", err)
	}
}

func TestJavaAuthorizationReadinessHonorsCancellation(t *testing.T) {
	fi := New(Init{})
	fi.PrepareJavaAgentCapability(11)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	capability, err := fi.WaitJavaAgentAuthorization(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error = %v, want context.Canceled", err)
	}
	if capability != 0 {
		t.Fatalf("canceled wait capability = %d, want 0", capability)
	}
}

func TestJavaAuthorizationGenerationRejectsStalePreparation(t *testing.T) {
	fi := New(Init{})
	firstSequence := fi.PrepareJavaAgentCapability(0)
	secondSequence := fi.PrepareJavaAgentCapability(0)

	if fi.SetJavaAgentCapabilityForGeneration(firstSequence, 11) {
		t.Fatal("stale preparation overwrote the current capability")
	}
	if !fi.SetJavaAgentCapabilityForGeneration(secondSequence, 22) {
		t.Fatal("current preparation could not publish its capability")
	}
	if capability := fi.JavaAgentCapability(); capability != 22 {
		t.Fatalf("published capability = %d, want 22", capability)
	}

	capability, err := fi.WaitJavaAgentAuthorizationGeneration(
		t.Context(), firstSequence,
	)
	if err == nil {
		t.Fatal("stale exact-generation wait unexpectedly succeeded")
	}
	if capability != 0 {
		t.Fatalf("stale exact-generation capability = %d, want 0", capability)
	}
}

func TestApplyEnvVariables(t *testing.T) {
	tests := []struct {
		name       string
		envVars    map[string]string
		expectName string
		expectNS   string
		expectMeta map[attr.Name]string
	}{
		{
			name:       "OTEL_SERVICE_NAME present, but also name is in the OTEL_RESOURCE_ATTRIBUTES",
			envVars:    map[string]string{"OTEL_SERVICE_NAME": "my-service", "OTEL_RESOURCE_ATTRIBUTES": "service.name=otel-svc,label1=1,label2=2"},
			expectName: "my-service",
			expectMeta: map[attr.Name]string{"label1": "1", "label2": "2", "service.name": "otel-svc"},
		},
		{
			name:       "OTEL_SERVICE_NAME present",
			envVars:    map[string]string{"OTEL_SERVICE_NAME": "my-service"},
			expectName: "my-service",
			expectNS:   "",
			expectMeta: map[attr.Name]string{},
		},
		{
			name:       "OTEL_RESOURCE_ATTRIBUTES with service.name",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.name=otel-svc"},
			expectName: "otel-svc",
			expectMeta: map[attr.Name]string{"service.name": "otel-svc"},
		},
		{
			name:       "OTEL_RESOURCE_ATTRIBUTES with service.name and service.namespace",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.name=otel-svc,service.namespace=ns1"},
			expectName: "otel-svc",
			expectNS:   "ns1",
			expectMeta: map[attr.Name]string{"service.name": "otel-svc", "service.namespace": "ns1"},
		},
		{
			name:       "OTEL_RESOURCE_ATTRIBUTES with service.namespace",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=otel-ns"},
			expectNS:   "otel-ns",
			expectMeta: map[attr.Name]string{"service.namespace": "otel-ns"},
		},
		{
			name:       "No relevant env vars",
			envVars:    map[string]string{"FOO": "BAR"},
			expectMeta: map[attr.Name]string{},
		},
		{
			name:       "Improper resource attributes, no key - value pairs",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace,otel-ns"},
			expectMeta: map[attr.Name]string{},
		},
		{
			name:       "Unresolved values in name and namespace",
			envVars:    map[string]string{"OTEL_RESOURCE_ATTRIBUTES": "service.namespace=${test-ns},service.name=$(otel-ns)"},
			expectMeta: map[attr.Name]string{},
		},
		{
			name: "Pre-set metadata is preserved over env resource attributes",
			envVars: map[string]string{
				"OTEL_RESOURCE_ATTRIBUTES": "deployment.environment=prod,custom.attr=from-env",
			},
			expectMeta: map[attr.Name]string{
				"deployment.environment": "staging",
				"custom.attr":            "from-env",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := New(Init{})
			if tt.name == "Pre-set metadata is preserved over env resource attributes" {
				fi.SetMetadata(map[attr.Name]string{
					"deployment.environment": "staging",
				})
			}
			fi.ApplyEnvVariables(tt.envVars)
			snap := fi.ServiceAttrs()
			if got := snap.UID.Name; got != tt.expectName {
				t.Errorf("UID.Name = %q, want %q", got, tt.expectName)
			}
			if got := snap.UID.Namespace; got != tt.expectNS {
				t.Errorf("UID.Namespace = %q, want %q", got, tt.expectNS)
			}
			if !reflect.DeepEqual(snap.EnvVars, tt.envVars) {
				t.Errorf("EnvVars = %#v, want %#v", snap.EnvVars, tt.envVars)
			}
			if !reflect.DeepEqual(snap.Metadata, tt.expectMeta) {
				t.Errorf("Metadata = %#v, want %#v", snap.Metadata, tt.expectMeta)
			}
		})
	}
}
