package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"
)

func TestApprovalAndFixedAttachment(t *testing.T) {
	dir := t.TempDir()
	e := &experiment{dir: dir, approval: filepath.Join(dir, "approval"), audit: filepath.Join(dir, "audit"), runID: "incident"}
	calls := [][]string{}
	e.run = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args)
		if args[0] == "inspect" {
			return []byte(`{"id":"container","pid":12,"started_at":"now","running":true}`), nil
		}
		return nil, nil
	}
	v, err := e.attach(context.Background())
	if err != nil || v["state"] != "approval_required" || len(calls) != 0 {
		t.Fatalf("unauthorized attachment: %v %v %v", v, err, calls)
	}
	if err := os.WriteFile(e.approval, []byte("different-incident"), 0600); err != nil {
		t.Fatal(err)
	}
	_, _ = e.attach(context.Background())
	if len(calls) != 0 {
		t.Fatal("wrong incident authorized attachment")
	}
	if err := os.WriteFile(e.approval, []byte(e.runID), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = e.attach(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(calls[1], " ")
	if !strings.Contains(args, "--project-name obi-ai-investigation") || !strings.HasSuffix(args, "up -d --no-deps --no-build --pull never obi profiler") {
		t.Fatalf("unsafe command: %s", args)
	}
	if len(calls) != 3 {
		t.Fatalf("unexpected commands: %v", calls)
	}
}
func TestIdentityChangeFails(t *testing.T) {
	dir := t.TempDir()
	approval := filepath.Join(dir, "approval")
	_ = os.WriteFile(approval, []byte("run"), 0600)
	e := &experiment{dir: dir, approval: approval, audit: filepath.Join(dir, "audit"), runID: "run"}
	inspects := 0
	e.run = func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "inspect" {
			inspects++
			return json.Marshal(identity{ID: "same", PID: inspects, Running: true})
		}
		return nil, nil
	}
	if _, err := e.attach(context.Background()); err == nil {
		t.Fatal("changed process identity accepted")
	}
}
func TestNormalizeIDs(t *testing.T) {
	for _, input := range []string{"ABCDEF0123456789", "q83vASNFZ4k="} {
		got, err := normalizeID(input, 8)
		if err != nil || got != "abcdef0123456789" {
			t.Fatalf("%s: %s %v", input, got, err)
		}
	}
	for _, bad := range []string{"", "bad", "0000000000000000", "abcdef01234567890"} {
		if _, err := normalizeID(bad, 8); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
func TestFlameGraphAccounting(t *testing.T) {
	f, err := parseFlameGraph([]string{"total", "caller", "hot"}, [][]integer{{0, 10, 0, 0}, {0, 10, 2, 1}, {0, 8, 8, 2}}, 10)
	if err != nil || f[0].Name != "hot" || f[0].Self != 8 || f[0].Cumulative != 8 {
		t.Fatalf("%v %v", f, err)
	}
	for _, levels := range [][][]integer{{{0, 10, 10}}, {{0, 10, 10, 99}}, {{0, 10, 11, 0}}, {{0, 10, 9, 0}}} {
		if _, err := parseFlameGraph([]string{"total"}, levels, 10); err == nil {
			t.Fatalf("accepted %v", levels)
		}
	}
}
func TestBackendAndEmptyEvidence(t *testing.T) {
	q := interval{Start: "2026-10-05T12:00:00Z", End: "2026-10-05T12:01:00Z"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "SelectMergeStacktraces") {
			_, _ = w.Write([]byte(`{"flamegraph":{"total":"0"}}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	e := &experiment{grafana: server.URL}
	v, err := e.exemplars(context.Background(), q)
	if err != nil || v["state"] != "no_span_exemplars" {
		t.Fatalf("%v %v", v, err)
	}
	v, err = e.profile(context.Background(), spanQuery{interval: q, SpanIDs: []string{"abcdef0123456789"}})
	if err != nil || v["state"] != "no_matching_samples" {
		t.Fatalf("%v %v", v, err)
	}
	server.Close()
	if _, err := e.exemplars(context.Background(), q); err == nil {
		t.Fatal("backend failure became empty evidence")
	}
	e.run = func(context.Context, ...string) ([]byte, error) { return nil, errors.New("unavailable") }
	e.audit = filepath.Join(t.TempDir(), "audit")
	if e.status(context.Background())["backend_state"] != "unavailable" {
		t.Fatal("backend state")
	}
}
func TestInvalidIntervalAndSpanQuery(t *testing.T) {
	for _, q := range []interval{{}, {Start: "2026-10-05T12:00:00Z", End: "2026-10-05T11:59:00Z"}, {Start: "2026-10-05T12:00:00Z", End: "2026-10-05T13:00:00Z"}} {
		if _, _, err := q.bounds(); err == nil {
			t.Fatal("invalid interval accepted")
		}
	}
	e := &experiment{}
	q := spanQuery{interval: interval{Start: "2026-10-05T12:00:00Z", End: "2026-10-05T12:01:00Z"}}
	if _, err := e.profile(context.Background(), q); err == nil {
		t.Fatal("unfiltered span query accepted")
	}
}

func TestEvidenceLinks(t *testing.T) {
	q := interval{Start: "2026-10-05T12:00:00Z", End: "2026-10-05T12:01:00Z"}
	e := &experiment{grafana: "http://localhost:3001"}
	u, err := url.Parse(e.profileLink(q, []string{"abcdef0123456789"}))
	if err != nil || u.Query().Get("from") != "1791201600000" || u.Query().Get("var-spanSelector") != "abcdef0123456789" {
		t.Fatalf("invalid browser profile link: %s %v", u, err)
	}
}

func TestDockerIdentityTemplate(t *testing.T) {
	e := &experiment{}
	e.run = func(_ context.Context, args ...string) ([]byte, error) {
		format, err := template.New("inspect").Funcs(template.FuncMap{"json": func(v any) string { b, _ := json.Marshal(v); return string(b) }}).Parse(args[3])
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		v := map[string]any{"Id": "existing", "State": map[string]any{"Pid": 10, "StartedAt": "now", "Running": true}}
		if err := format.Execute(&out, v); err != nil {
			t.Fatal(err)
		}
		return out.Bytes(), nil
	}
	got, err := e.inspect(context.Background(), "app")
	if err != nil || got.ID != "existing" || !got.Running {
		t.Fatalf("%v %v", got, err)
	}
}

func TestProfileAPIUsesExactNormalizedIDs(t *testing.T) {
	q := interval{Start: "2026-10-05T12:00:00Z", End: "2026-10-05T12:01:00Z"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			SpanSelector  []string `json:"spanSelector"`
			LabelSelector string   `json:"labelSelector"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body.SpanSelector) != 1 || body.SpanSelector[0] != "abcdef0123456789" || body.LabelSelector != `{service_name="obi-ai-demo"}` {
			t.Errorf("unsafe or incorrect selection: %+v", body)
		}
		_, _ = w.Write([]byte(`{"flamegraph":{"names":["total","hot"],"levels":[{"values":[0,10,0,0]},{"values":[0,10,10,1]}],"total":"10"}}`))
	}))
	defer server.Close()
	e := &experiment{grafana: server.URL}
	v, err := e.profile(context.Background(), spanQuery{interval: q, SpanIDs: []string{"ABCDEF0123456789", "q83vASNFZ4k="}})
	if err != nil || v["total_ns"] != integer(10) || v["state"] != "samples" {
		t.Fatalf("%v %v", v, err)
	}
}

func TestBackendHTTPFailureIsNotMissingEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "backend failed", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	e := &experiment{grafana: server.URL}
	_, err := e.exemplars(context.Background(), interval{Start: "2026-10-05T12:00:00Z", End: "2026-10-05T12:01:00Z"})
	if err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("%v", err)
	}
}

func TestCollectionWindowExcludesRetainedAndLateData(t *testing.T) {
	attached, _ := time.Parse(time.RFC3339, "2026-10-05T12:00:00Z")
	e := &experiment{collectionStart: attached}
	for _, q := range []interval{
		{Start: "2026-10-05T11:59:59Z", End: "2026-10-05T12:01:00Z"},
		{Start: "2026-10-05T12:00:00Z", End: "2026-10-05T12:02:01Z"},
	} {
		if _, _, err := e.collectionBounds(q); err == nil {
			t.Fatalf("accepted interval outside collection: %v", q)
		}
	}
	if _, _, err := e.collectionBounds(interval{Start: "2026-10-05T12:00:00Z", End: "2026-10-05T12:02:00Z"}); err != nil {
		t.Fatal(err)
	}
}

func TestStatusDistinguishesDatasourceFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "pyroscope") {
			http.Error(w, "profile backend down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"status":"OK"}`))
	}))
	defer server.Close()
	e := &experiment{grafana: server.URL, audit: filepath.Join(t.TempDir(), "audit")}
	e.run = func(context.Context, ...string) ([]byte, error) { return nil, errors.New("no container") }
	got := e.status(context.Background())
	if got["backend_state"] != "partial" {
		t.Fatalf("Grafana health hid a datasource failure: %v", got)
	}
}
