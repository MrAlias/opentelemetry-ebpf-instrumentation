// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/docker"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func TestAppendDockerMetadataDoesNotLoseConcurrentAdmission(t *testing.T) {
	const versionKey = attr.Name("service.version")
	fi := exec.New(exec.Init{})
	container := docker.ContainerMeta{ID: "container-id", Name: "container-a"}

	// Capture the empty pre-admission snapshot used by the former RMW path,
	// then force the decorator to publish only after provisional fields exist.
	stale := fi.ServiceAttrs()
	require.Empty(t, stale.UID.Name)
	require.Nil(t, stale.Metadata)
	ready := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(ready)
		<-release
		appendDockerMetadata(fi, container)
		close(done)
	}()
	<-ready

	receipt := fi.BeginServiceMetadataAdmission("derived", versionKey, "1.2.3")
	require.NotNil(t, receipt)
	close(release)
	<-done

	provisional := fi.ServiceAttrs()
	assert.Equal(t, "container-a", provisional.UID.Name,
		"Docker naming must supersede the lower-precedence provisional name")
	assert.Equal(t, "1.2.3", provisional.Metadata[versionKey])
	assert.Equal(t, "container-a", provisional.Metadata[attr.ContainerName])
	assert.Equal(t, "container-id", provisional.Metadata[attr.ContainerID])
	assert.True(t, fi.AutoName())
	receipt.Rollback()

	got := fi.ServiceAttrs()
	assert.Equal(t, "container-a", got.UID.Name)
	assert.NotContains(t, got.Metadata, versionKey)
	assert.Equal(t, "container-a", got.Metadata[attr.ContainerName])
	assert.Equal(t, "container-id", got.Metadata[attr.ContainerID])
	assert.Equal(t, "container-a", got.UID.Instance)
	assert.True(t, fi.AutoName())
}

func TestAppendDockerMetadataProvisionalNamePrecedenceOnCommit(t *testing.T) {
	const versionKey = attr.Name("service.version")
	fi := exec.New(exec.Init{})
	receipt := fi.BeginServiceMetadataAdmission("derived", versionKey, "1.2.3")
	require.NotNil(t, receipt)

	appendDockerMetadata(fi, docker.ContainerMeta{
		ID:   "container-id",
		Name: "container-a",
	})
	receipt.Commit()

	got := fi.ServiceAttrs()
	assert.Equal(t, "container-a", got.UID.Name,
		"commit must not restore the lower-precedence provisional name")
	assert.Equal(t, "1.2.3", got.Metadata[versionKey])
	assert.True(t, fi.AutoName())
}
