// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

type dummyCloser struct {
	closed bool
}

func (d *dummyCloser) Close() error {
	d.closed = true
	return nil
}

func TestInstrumetedLibsT(t *testing.T) {
	libs := make(InstrumentedLibsT)

	id := exec.FileID{Dev: 1, Ino: 10}

	assert.Nil(t, libs.Find(id))

	module := libs.At(id)

	assert.NotNil(t, module)

	closer := &dummyCloser{closed: false}
	module.Closers = append(module.Closers, closer)

	removeRef := func(id exec.FileID) *LibModule {
		m, _ := libs.RemoveRef(id)
		return m
	}

	assert.NotNil(t, libs.Find(id))

	assert.Equal(t, uint64(0), module.References)

	assert.Equal(t, module, libs.AddRef(id))
	assert.Equal(t, uint64(1), module.References)

	assert.Equal(t, module, libs.AddRef(id))
	assert.Equal(t, uint64(2), module.References)

	assert.Equal(t, module, libs.Find(id))

	assert.Equal(t, module, removeRef(id))
	assert.Equal(t, uint64(1), module.References)
	assert.False(t, closer.closed)

	assert.Equal(t, module, removeRef(id))
	assert.Equal(t, uint64(0), module.References)
	assert.True(t, closer.closed)

	assert.Nil(t, libs.Find(id))
}

func TestInstrumentedLibsSeparateSameInodeOnDifferentDevices(t *testing.T) {
	libs := make(InstrumentedLibsT)
	first := exec.FileID{Dev: 1, Ino: 10}
	second := exec.FileID{Dev: 2, Ino: 10}

	firstModule := libs.AddRef(first)
	secondModule := libs.AddRef(second)

	require.NotSame(t, firstModule, secondModule)
	assert.Same(t, firstModule, libs.Find(first))
	assert.Same(t, secondModule, libs.Find(second))

	_, err := libs.RemoveRef(first)
	require.NoError(t, err)
	assert.Nil(t, libs.Find(first))
	assert.Same(t, secondModule, libs.Find(second))
}
