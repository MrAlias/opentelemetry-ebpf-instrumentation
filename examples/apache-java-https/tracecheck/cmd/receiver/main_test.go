// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/examples/apache-java-https/tracecheck"
)

type gatedReadCloser struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *gatedReadCloser) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	return 0, io.EOF
}

func (*gatedReadCloser) Close() error { return nil }

func TestResetResponseMatchesSubsequentSnapshotContinuity(t *testing.T) {
	handler := &receiver{store: tracecheck.NewStore(10, 1024, 4096)}
	before := handler.store.Snapshot("").ReceiverContinuity
	recorder := httptest.NewRecorder()
	handler.reset(recorder, httptest.NewRequest(http.MethodPost, "/reset", nil))

	require.Equal(t, http.StatusOK, recorder.Code)
	var resetFields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &resetFields))
	assert.Contains(t, resetFields, "receiver_instance_id")
	assert.Contains(t, resetFields, "reset_generation")

	var response resetResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response))
	assert.Equal(t, "reset", response.Status)
	assert.Equal(t, before.ReceiverInstanceID, response.ReceiverInstanceID)
	assert.Equal(t, before.ResetGeneration+1, response.ResetGeneration)

	snapshotRecorder := httptest.NewRecorder()
	handler.snapshot(snapshotRecorder, httptest.NewRequest(http.MethodGet, "/snapshot", nil))
	require.Equal(t, http.StatusOK, snapshotRecorder.Code)
	var snapshot tracecheck.Snapshot
	require.NoError(t, json.Unmarshal(snapshotRecorder.Body.Bytes(), &snapshot))
	assert.Equal(t, response.ReceiverContinuity, snapshot.ReceiverContinuity)
}

func TestTraceRequestAdmittedBeforeResetCannotRepopulateStore(t *testing.T) {
	handler := &receiver{store: tracecheck.NewStore(10, 1024, 4096)}
	body := &gatedReadCloser{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/traces", body)
	request.Header.Set("Content-Type", "application/x-protobuf")
	recorder := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		handler.traces(recorder, request)
	}()

	select {
	case <-body.started:
	case <-time.After(time.Second):
		t.Fatal("trace handler did not begin reading the request body")
	}
	reset := handler.store.Reset()
	close(body.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("trace handler did not finish after the request body was released")
	}

	assert.Equal(t, http.StatusOK, recorder.Code)
	snapshot := handler.store.Snapshot("")
	assert.Equal(t, reset, snapshot.ReceiverContinuity)
	assert.Zero(t, snapshot.ReceivedBatches)
	assert.Zero(t, snapshot.ReceivedSpans)
	assert.Empty(t, snapshot.Spans)
}

func TestEnvBoundedIntUsesDefaultAndEnforcesMaximum(t *testing.T) {
	t.Setenv("RECEIVER_TEST_BOUND", "")
	value, err := envBoundedInt("RECEIVER_TEST_BOUND", 7, 10)
	require.NoError(t, err)
	assert.Equal(t, 7, value)

	t.Setenv("RECEIVER_TEST_BOUND", "10")
	value, err = envBoundedInt("RECEIVER_TEST_BOUND", 7, 10)
	require.NoError(t, err)
	assert.Equal(t, 10, value)

	for _, invalid := range []string{"0", "11", "invalid"} {
		t.Setenv("RECEIVER_TEST_BOUND", invalid)
		_, err = envBoundedInt("RECEIVER_TEST_BOUND", 7, 10)
		require.Error(t, err)
	}
}
