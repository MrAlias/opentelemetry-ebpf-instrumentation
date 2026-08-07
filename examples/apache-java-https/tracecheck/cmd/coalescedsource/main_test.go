// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDiagnostics = "cfg_on=1,cfg_off=0"

func TestExecuteUsesOneConnectionAndOnePlaintextWrite(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	writes := make(chan []byte, 1)
	wantPayload := coalescedPlaintext("first", "second")
	go func() {
		payload := make([]byte, len(wantPayload))
		_, _ = io.ReadFull(server, payload)
		writes <- payload
		for index, marker := range []string{"first", "second"} {
			diagnostics := ""
			if index == 1 {
				diagnostics = "X-OBI-Java-Diagnostics: " + testDiagnostics + "\r\n"
			}
			body := `{"marker":"` + marker + `"}`
			_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: "+
				strconv.Itoa(len(body))+"\r\n"+diagnostics+"\r\n"+body)
		}
	}()
	dial := func(context.Context) (net.Conn, string, error) {
		return client, "TLSv1.3", nil
	}

	result, err := execute(context.Background(), dial, "first", "second")
	require.NoError(t, err)
	payload := <-writes
	assert.Equal(t, wantPayload, payload)
	assert.Equal(t, 1, result.BackendTLSConnections)
	assert.Equal(t, 1, result.PlaintextWriteCalls)
	assert.Equal(t, 2, result.RequestBoundaries)
	assert.Zero(t, result.TraceparentHeaderCount)
	assert.Equal(t, testDiagnostics, result.JavaDiagnosticsAfter)
	assert.Contains(t, string(payload), "X-OBI-Demo-ID: first")
	assert.Contains(t, string(payload), "X-OBI-Demo-ID: second")
	assert.NotContains(t, strings.ToLower(string(payload)), "traceparent:")
}

func TestHandlerRejectsDuplicateOrMalformedMarkersBeforeDial(t *testing.T) {
	dials := 0
	dial := func(context.Context) (net.Conn, string, error) {
		dials++
		return nil, "", nil
	}
	handler := newHandler(dial)
	for _, test := range []struct {
		name   string
		first  string
		second string
	}{
		{name: "duplicate", first: "same", second: "same"},
		{name: "bad first", first: "bad marker", second: "second"},
		{name: "bad second", first: "first", second: "bad marker"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodGet,
				requestPath+"?second_marker="+url.QueryEscape(test.second),
				nil,
			)
			request.Header.Set("x-obi-demo-id", test.first)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assert.Equal(t, http.StatusBadRequest, response.Code)
		})
	}
	assert.Zero(t, dials)
}

func TestHandlerReturnsBoundedLiveEvidence(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	wantPayload := coalescedPlaintext("first", "second")
	go func() {
		buffer := make([]byte, len(wantPayload))
		_, _ = io.ReadFull(server, buffer)
		for index, marker := range []string{"first", "second"} {
			diagnostics := ""
			if index == 1 {
				diagnostics = "X-OBI-Java-Diagnostics: " + testDiagnostics + "\r\n"
			}
			body := `{"marker":"` + marker + `"}`
			_, _ = io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: "+
				strconv.Itoa(len(body))+"\r\n"+diagnostics+"\r\n"+body)
		}
	}()
	handler := newHandler(func(context.Context) (net.Conn, string, error) {
		return client, "TLSv1.2", nil
	})
	request := httptest.NewRequest(http.MethodGet, requestPath+"?second_marker=second", nil)
	request.Header.Set("x-obi-demo-id", "first")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "live", response.Header().Get("X-OBI-Coalesced-Source"))
	var result sourceResult
	require.NoError(t, json.NewDecoder(bytes.NewReader(response.Body.Bytes())).Decode(&result))
	assert.Equal(t, []string{"first", "second"}, result.ChildMarkers)
	assert.Equal(t, "TLSv1.2", result.TLSProtocol)
}

func TestExecuteRejectsResponseHeadersBeyondTheAggregateBound(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\nX-Oversized: " +
		strings.Repeat("x", maximumResponseSetBytes) + "\r\nContent-Length: 0\r\n\r\n"
	dial, backendDone := scriptedBackend(response)

	_, err := execute(context.Background(), dial, "first", "second")

	require.ErrorContains(t, err, "read backend response 1")
	awaitBackend(t, backendDone)
}

func TestExecuteRejectsOversizedDiagnostics(t *testing.T) {
	firstBody := `{"marker":"first"}`
	secondBody := `{"marker":"second"}`
	response := "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(firstBody)) +
		"\r\n\r\n" + firstBody +
		"HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(secondBody)) +
		"\r\nX-OBI-Java-Diagnostics: " + strings.Repeat("x", maximumDiagnosticsBytes+1) +
		"\r\n\r\n" + secondBody
	dial, backendDone := scriptedBackend(response)

	_, err := execute(context.Background(), dial, "first", "second")

	require.ErrorContains(t, err, "omitted bounded diagnostics")
	awaitBackend(t, backendDone)
}

func scriptedBackend(response string) (dialBackend, <-chan struct{}) {
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		request := make([]byte, len(coalescedPlaintext("first", "second")))
		_, _ = io.ReadFull(server, request)
		_, _ = io.WriteString(server, response)
	}()
	return func(context.Context) (net.Conn, string, error) {
		return client, "TLSv1.3", nil
	}, done
}

func awaitBackend(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scripted backend did not release its connection")
	}
}

func TestExecuteRejectsShortSingleWrite(t *testing.T) {
	connection := &shortWriteConnection{}
	_, err := execute(context.Background(), func(context.Context) (net.Conn, string, error) {
		return connection, "TLSv1.3", nil
	}, "first", "second")
	require.ErrorContains(t, err, "single plaintext write was short")
}

type shortWriteConnection struct{}

func (*shortWriteConnection) Read([]byte) (int, error)         { return 0, io.EOF }
func (*shortWriteConnection) Write(buffer []byte) (int, error) { return len(buffer) - 1, nil }
func (*shortWriteConnection) Close() error                     { return nil }
func (*shortWriteConnection) LocalAddr() net.Addr              { return testAddress("local") }
func (*shortWriteConnection) RemoteAddr() net.Addr             { return testAddress("remote") }
func (*shortWriteConnection) SetDeadline(time.Time) error      { return nil }
func (*shortWriteConnection) SetReadDeadline(time.Time) error  { return nil }
func (*shortWriteConnection) SetWriteDeadline(time.Time) error { return nil }

type testAddress string

func (address testAddress) Network() string { return "test" }
func (address testAddress) String() string  { return string(address) }
