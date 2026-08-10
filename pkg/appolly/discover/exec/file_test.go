// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"context"
	"errors"
	"reflect"
	"testing"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestFileInfoIDIncludesDeviceAndInode(t *testing.T) {
	fi := New(Init{Dev: 7, Ino: 42})

	if got, want := fi.ID(), (FileID{Dev: 7, Ino: 42}); got != want {
		t.Fatalf("ID() = %+v, want %+v", got, want)
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
