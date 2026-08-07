// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	defaultListenAddress    = "127.0.0.1:18081"
	defaultBackendAddress   = "127.0.0.1:18444"
	defaultCAPath           = "/run/obi-demo/certs/ca.crt"
	requestPath             = "/api/coalesced-source"
	backendPath             = "/api/coalesced-bridge"
	maximumResponseBytes    = 64 << 10
	maximumHeaderBytes      = 16 << 10
	maximumResponseSetBytes = 2 * (maximumResponseBytes + maximumHeaderBytes)
	maximumDiagnosticsBytes = 4 << 10
	maximumPlaintextBytes   = 8 << 10
	operationTimeout        = 5 * time.Second
)

var markerPattern = regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,128}$`)

type config struct {
	listenAddress  string
	backendAddress string
	caPath         string
	tlsProtocol    string
}

type backendResult struct {
	Marker string `json:"marker"`
}

type sourceResult struct {
	TriggerMarker          string            `json:"trigger_marker"`
	ChildMarkers           []string          `json:"child_markers"`
	BackendTLSConnections  int               `json:"backend_tls_connections"`
	PlaintextWriteCalls    int               `json:"plaintext_write_calls"`
	PlaintextWriteBytes    int               `json:"plaintext_write_bytes"`
	PlaintextSHA256        string            `json:"plaintext_sha256"`
	RequestBoundaries      int               `json:"request_boundaries"`
	TraceparentHeaderCount int               `json:"traceparent_header_count"`
	TLSProtocol            string            `json:"tls_protocol"`
	Responses              []json.RawMessage `json:"responses"`
	JavaDiagnosticsAfter   string            `json:"java_diagnostics_after"`
}

type dialBackend func(context.Context) (net.Conn, string, error)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	dial, err := tlsDialer(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	server := &http.Server{
		Addr:              cfg.listenAddress,
		Handler:           newHandler(dial),
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       operationTimeout,
		WriteTimeout:      operationTimeout,
		IdleTimeout:       operationTimeout,
	}
	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "coalesced source: %v\n", err)
		os.Exit(1)
	}
}

func loadConfig() (config, error) {
	cfg := config{
		listenAddress:  environment("LISTEN_ADDRESS", defaultListenAddress),
		backendAddress: environment("BACKEND_ADDRESS", defaultBackendAddress),
		caPath:         environment("CA_PATH", defaultCAPath),
		tlsProtocol:    environment("BACKEND_TLS_PROTOCOL", "TLSv1.3"),
	}
	if _, _, err := net.SplitHostPort(cfg.listenAddress); err != nil {
		return config{}, fmt.Errorf("invalid LISTEN_ADDRESS: %w", err)
	}
	if _, _, err := net.SplitHostPort(cfg.backendAddress); err != nil {
		return config{}, fmt.Errorf("invalid BACKEND_ADDRESS: %w", err)
	}
	if cfg.tlsProtocol != "TLSv1.2" && cfg.tlsProtocol != "TLSv1.3" {
		return config{}, errors.New("BACKEND_TLS_PROTOCOL must be TLSv1.2 or TLSv1.3")
	}
	return cfg, nil
}

func environment(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok && value != "" {
		return value
	}
	return fallback
}

func tlsDialer(cfg config) (dialBackend, error) {
	certificate, err := os.ReadFile(cfg.caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		return nil, errors.New("CA certificate contains no PEM certificate")
	}
	version := uint16(tls.VersionTLS13)
	if cfg.tlsProtocol == "TLSv1.2" {
		version = tls.VersionTLS12
	}
	tlsConfig := &tls.Config{
		MinVersion: version,
		MaxVersion: version,
		RootCAs:    roots,
		ServerName: "localhost",
	}
	return func(ctx context.Context) (net.Conn, string, error) {
		dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}
		raw, err := dialer.DialContext(ctx, "tcp", cfg.backendAddress)
		if err != nil {
			return nil, "", err
		}
		connection := tls.Client(raw, tlsConfig.Clone())
		if deadline, ok := ctx.Deadline(); ok {
			if err := connection.SetDeadline(deadline); err != nil {
				_ = raw.Close()
				return nil, "", err
			}
		}
		if err := connection.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, "", err
		}
		return connection, tlsVersionName(connection.ConnectionState().Version), nil
	}, nil
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return "unknown"
	}
}

func newHandler(dial dialBackend) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		response.Header().Set("Cache-Control", "no-store")
		response.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(response, "ok\n")
	})
	mux.HandleFunc(requestPath, func(response http.ResponseWriter, request *http.Request) {
		handleCoalesced(response, request, dial)
	})
	return mux
}

func handleCoalesced(response http.ResponseWriter, request *http.Request, dial dialBackend) {
	if request.Method != http.MethodGet {
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	first := request.Header.Get("x-obi-demo-id")
	secondValues := request.URL.Query()["second_marker"]
	if !markerPattern.MatchString(first) || len(secondValues) != 1 ||
		!markerPattern.MatchString(secondValues[0]) || first == secondValues[0] {
		http.Error(response, "invalid distinct markers", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), operationTimeout)
	defer cancel()
	result, err := execute(ctx, dial, first, secondValues[0])
	if err != nil {
		http.Error(response, "coalesced backend request failed", http.StatusBadGateway)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-OBI-Coalesced-Source", "live")
	if err := json.NewEncoder(response).Encode(result); err != nil {
		return
	}
}

func execute(
	ctx context.Context,
	dial dialBackend,
	firstMarker string,
	secondMarker string,
) (sourceResult, error) {
	connection, protocol, err := dial(ctx)
	if err != nil {
		return sourceResult{}, fmt.Errorf("dial backend: %w", err)
	}
	defer connection.Close()

	plaintext := coalescedPlaintext(firstMarker, secondMarker)
	if len(plaintext) > maximumPlaintextBytes {
		return sourceResult{}, errors.New("coalesced plaintext exceeds fixture bound")
	}
	written, err := connection.Write(plaintext)
	if err != nil {
		return sourceResult{}, fmt.Errorf("write coalesced plaintext: %w", err)
	}
	if written != len(plaintext) {
		return sourceResult{}, fmt.Errorf("single plaintext write was short: wrote %d of %d", written, len(plaintext))
	}

	limitedResponses := &io.LimitedReader{R: connection, N: int64(maximumResponseSetBytes)}
	reader := bufio.NewReaderSize(limitedResponses, maximumHeaderBytes)
	requests := []*http.Request{
		{Method: http.MethodGet},
		{Method: http.MethodGet},
	}
	responses := make([]json.RawMessage, 2)
	diagnostics := ""
	for index := range responses {
		backendResponse, readErr := http.ReadResponse(reader, requests[index])
		if readErr != nil {
			return sourceResult{}, fmt.Errorf("read backend response %d: %w", index+1, readErr)
		}
		body, bodyErr := io.ReadAll(io.LimitReader(backendResponse.Body, maximumResponseBytes+1))
		_ = backendResponse.Body.Close()
		if bodyErr != nil {
			return sourceResult{}, fmt.Errorf("read backend response %d body: %w", index+1, bodyErr)
		}
		if len(body) > maximumResponseBytes || backendResponse.StatusCode != http.StatusOK {
			return sourceResult{}, fmt.Errorf("backend response %d was invalid", index+1)
		}
		var decoded backendResult
		if json.Unmarshal(body, &decoded) != nil || decoded.Marker != []string{firstMarker, secondMarker}[index] {
			return sourceResult{}, fmt.Errorf("backend response %d marker mismatch", index+1)
		}
		responses[index] = append(json.RawMessage(nil), body...)
		diagnosticValues := backendResponse.Header.Values("X-OBI-Java-Diagnostics")
		if index == 0 && len(diagnosticValues) != 0 {
			return sourceResult{}, errors.New("first backend response exposed diagnostics")
		}
		if index == 1 {
			if len(diagnosticValues) != 1 {
				return sourceResult{}, errors.New("second backend response omitted bounded diagnostics")
			}
			diagnostics = diagnosticValues[0]
			if diagnostics == "" || len(diagnostics) > maximumDiagnosticsBytes ||
				strings.ContainsAny(diagnostics, "\r\n") {
				return sourceResult{}, errors.New("second backend response omitted bounded diagnostics")
			}
		}
	}
	digest := sha256.Sum256(plaintext)
	return sourceResult{
		TriggerMarker:          firstMarker,
		ChildMarkers:           []string{firstMarker, secondMarker},
		BackendTLSConnections:  1,
		PlaintextWriteCalls:    1,
		PlaintextWriteBytes:    len(plaintext),
		PlaintextSHA256:        hex.EncodeToString(digest[:]),
		RequestBoundaries:      2,
		TraceparentHeaderCount: countHeader(plaintext, "traceparent"),
		TLSProtocol:            protocol,
		Responses:              responses,
		JavaDiagnosticsAfter:   diagnostics,
	}, nil
}

func coalescedPlaintext(firstMarker, secondMarker string) []byte {
	var plaintext strings.Builder
	writeRequest := func(marker string, sequence int, closeConnection, diagnostics bool) {
		path := backendPath
		if diagnostics {
			path += "?bridge_diagnostics=1"
		}
		fmt.Fprintf(&plaintext, "GET %s HTTP/1.1\r\n", path)
		plaintext.WriteString("Host: localhost\r\n")
		fmt.Fprintf(&plaintext, "X-OBI-Demo-ID: %s\r\n", marker)
		fmt.Fprintf(&plaintext, "X-OBI-Coalesced-Sequence: %d\r\n", sequence)
		if closeConnection {
			plaintext.WriteString("Connection: close\r\n\r\n")
		} else {
			plaintext.WriteString("Connection: keep-alive\r\n\r\n")
		}
	}
	writeRequest(firstMarker, 1, false, false)
	writeRequest(secondMarker, 2, true, true)
	return []byte(plaintext.String())
}

func countHeader(plaintext []byte, name string) int {
	wanted := strings.ToLower(name) + ":"
	count := 0
	for _, line := range strings.Split(strings.ToLower(string(plaintext)), "\r\n") {
		if strings.HasPrefix(line, wanted) {
			count++
		}
	}
	return count
}
