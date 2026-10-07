package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const serviceName = "obi-ai-demo"
const profileType = "process_cpu:cpu:nanoseconds:cpu:nanoseconds"
const projectName = "obi-ai-investigation"
const collectionLimit = 2 * time.Minute

type experiment struct {
	dir, grafana, approval, runID, audit string
	run                                  func(context.Context, ...string) ([]byte, error)
	mu                                   sync.RWMutex
	collectionStart                      time.Time
}
type interval struct {
	Start string `json:"start" jsonschema:"Start of the incident query interval in RFC3339 format"`
	End   string `json:"end" jsonschema:"End of the query interval in RFC3339 format"`
}
type spanQuery struct {
	interval
	SpanIDs []string `json:"span_ids" jsonschema:"Exact span IDs obtained from recorded exemplars or Tempo; never infer IDs from timestamps"`
}

func (e *experiment) record(event string, data any) {
	f, err := os.OpenFile(e.audit, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("audit: %v", err)
		return
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(map[string]any{"time": time.Now().UTC(), "event": event, "run_id": e.runID, "data": data}); err != nil {
		log.Printf("audit: %v", err)
	}
}
func (e *experiment) compose(ctx context.Context, args ...string) ([]byte, error) {
	fixed := []string{"compose", "--project-name", projectName, "--project-directory", e.dir, "-f", filepath.Join(e.dir, "docker-compose.yml"), "-f", filepath.Join(e.dir, "docker-compose.ai.yml")}
	return e.run(ctx, append(fixed, args...)...)
}

type identity struct {
	ID        string `json:"id"`
	PID       int    `json:"pid"`
	StartedAt string `json:"started_at"`
	Running   bool   `json:"running"`
}

func (e *experiment) inspect(ctx context.Context, name string) (identity, error) {
	out, err := e.run(ctx, "inspect", name, "--format", `{"id":{{json .Id}},"pid":{{.State.Pid}},"started_at":{{json .State.StartedAt}},"running":{{.State.Running}}}`)
	if err != nil {
		return identity{}, fmt.Errorf("inspect failed: %w: %.400s", err, out)
	}
	var v identity
	err = json.Unmarshal(out, &v)
	if err != nil {
		return v, fmt.Errorf("invalid inspect response %q: %w", out, err)
	}
	return v, err
}
func (e *experiment) status(ctx context.Context) map[string]any {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out := map[string]any{"service": serviceName, "grafana_url": e.grafana, "current_time": time.Now().UTC().Format(time.RFC3339Nano), "collection_note": "No historical evidence is recovered by attachment. Query only this incident's interval."}
	app, err := e.inspect(ctx, projectName+"-app-1")
	if err != nil {
		out["application_state"] = "unavailable"
		out["application_error"] = err.Error()
	} else {
		out["application"] = app
	}
	agents := map[string]string{}
	collectionStart := ""
	for _, name := range []string{"obi", "profiler"} {
		v, err := e.inspect(ctx, projectName+"-"+name+"-1")
		if err != nil || !v.Running {
			agents[name] = "not_running"
		} else {
			agents[name] = "running"
			out[name+"_started_at"] = v.StartedAt
			if v.StartedAt > collectionStart {
				collectionStart = v.StartedAt
			}
		}
	}
	out["agents"] = agents
	e.mu.RLock()
	if !e.collectionStart.IsZero() {
		collectionStart = e.collectionStart.UTC().Format(time.RFC3339Nano)
	}
	e.mu.RUnlock()
	if agents["obi"] == "running" && agents["profiler"] == "running" {
		out["collection_start"] = collectionStart
		start, _ := time.Parse(time.RFC3339Nano, collectionStart)
		out["collection_deadline"] = start.Add(collectionLimit).Format(time.RFC3339Nano)
		out["collection_state"] = "agents_running_discovery_and_export_may_be_pending"
	} else {
		out["collection_state"] = "diagnostic_agents_missing"
	}
	var health map[string]any
	if err := e.request(ctx, "GET", "/api/health", nil, &health); err != nil {
		out["backend_state"] = "unavailable"
		out["backend_error"] = err.Error()
	} else {
		out["backend_state"] = "available"
	}
	backends := map[string]any{}
	for _, uid := range []string{"tempo", "pyroscope"} {
		var health map[string]any
		err := e.request(ctx, "GET", "/api/datasources/uid/"+uid+"/health", nil, &health)
		if err != nil {
			backends[uid] = map[string]any{"state": "unavailable", "error": err.Error()}
		} else if health["status"] != "OK" {
			backends[uid] = map[string]any{"state": "unhealthy", "health": health}
		} else {
			backends[uid] = map[string]any{"state": "available"}
		}
		if err != nil || health["status"] != "OK" {
			if out["backend_state"] == "available" {
				out["backend_state"] = "partial"
			}
		}
	}
	out["telemetry_backends"] = backends
	e.record("status", out)
	return out
}
func (e *experiment) attach(ctx context.Context) (map[string]any, error) {
	e.record("attachment_requested", nil)
	approval, err := os.ReadFile(e.approval)
	if err != nil || strings.TrimSpace(string(approval)) != e.runID {
		return map[string]any{"state": "approval_required", "message": "Request explicit operator approval to attach OBI and the profiler. The operator must authorize this run outside the assistant. No agents were started."}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	before, err := e.inspect(ctx, projectName+"-app-1")
	if err != nil || !before.Running {
		return nil, fmt.Errorf("application must already be running")
	}
	e.record("approval_verified", map[string]any{"application": before})
	output, err := e.compose(ctx, "up", "-d", "--no-deps", "--no-build", "--pull", "never", "obi", "profiler")
	if err != nil {
		return nil, fmt.Errorf("diagnostic attachment failed: %w: %s", err, output)
	}
	after, err := e.inspect(ctx, projectName+"-app-1")
	if err != nil {
		return nil, err
	}
	if before != after {
		return nil, fmt.Errorf("application identity changed during attachment")
	}
	e.mu.Lock()
	if e.collectionStart.IsZero() {
		e.collectionStart = time.Now().UTC()
	}
	start := e.collectionStart
	e.mu.Unlock()
	result := map[string]any{"state": "agents_started", "collection_start": start.Format(time.RFC3339Nano), "collection_deadline": start.Add(collectionLimit).Format(time.RFC3339Nano), "application_before": before, "application_after": after, "message": "Allow discovery and export time. Poll telemetry for at most two minutes; no samples is not a diagnosis."}
	e.record("attachment_completed", result)
	return result, nil
}
func (e *experiment) collectionBounds(q interval) (int64, int64, error) {
	start, end, err := q.bounds()
	if err != nil {
		return 0, 0, err
	}
	e.mu.RLock()
	attached := e.collectionStart
	e.mu.RUnlock()
	if !attached.IsZero() && (start < attached.UnixMilli() || end > attached.Add(collectionLimit).UnixMilli()) {
		return 0, 0, fmt.Errorf("query must stay within collection_start and collection_deadline; inspect status and use the recorded interval")
	}
	return start, end, nil
}
func main() {
	e := &experiment{}
	listen := flag.String("listen", "", "Optional loopback HTTP listen address")
	flag.StringVar(&e.dir, "example-dir", "", "Absolute path to the example")
	flag.StringVar(&e.grafana, "grafana-url", "http://localhost:3001", "Example Grafana URL")
	flag.StringVar(&e.approval, "approval-file", "", "Operator-owned authorization file")
	flag.StringVar(&e.runID, "run-id", "", "Incident run ID")
	flag.StringVar(&e.audit, "audit-file", "", "Tool evidence JSONL file")
	flag.Parse()
	if !filepath.IsAbs(e.dir) || e.approval == "" || e.runID == "" || e.audit == "" {
		log.Fatal("example-dir, approval-file, run-id and audit-file are required")
	}
	e.grafana = strings.TrimRight(e.grafana, "/")
	e.run = func(ctx context.Context, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, "docker", args...)
		output, err := cmd.CombinedOutput()
		log.Printf("docker %s: path=%s bytes=%d error=%v", args[0], cmd.Path, len(output), err)
		return output, err
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "obi-incident", Version: "0.1.0"}, nil)
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true}
	mcp.AddTool(server, &mcp.Tool{Name: "diagnostic_status", Description: "Inspect this experiment's application identity, agent state and Grafana availability. Does not expose fixture configuration.", Annotations: readOnly}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		return nil, e.status(ctx), nil
	})
	mcp.AddTool(server, &mcp.Tool{Name: "attach_diagnostics", Description: "Request attachment of OBI and the profiler to the already-running demo. Requires separate operator authorization for this incident. Does not alter the application.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false}}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		v, err := e.attach(ctx)
		return nil, v, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "span_exemplars", Description: "Discover real Pyroscope CPU sample links for this service. Returns trace/span IDs, values in nanoseconds and browser evidence. Empty results do not prove absence of execution.", Annotations: readOnly}, func(ctx context.Context, _ *mcp.CallToolRequest, q interval) (*mcp.CallToolResult, any, error) {
		v, err := e.exemplars(ctx, q)
		e.record("span_exemplars", map[string]any{"query": q, "result": v, "error": errorText(err)})
		return nil, v, err
	})
	mcp.AddTool(server, &mcp.Tool{Name: "span_profile", Description: "Query CPU execution for exact span IDs. Returns deterministic totals and ranked functions with self and cumulative nanoseconds. CPU samples do not measure waiting or total latency.", Annotations: readOnly}, func(ctx context.Context, _ *mcp.CallToolRequest, q spanQuery) (*mcp.CallToolResult, any, error) {
		v, err := e.profile(ctx, q)
		e.record("span_profile", map[string]any{"query": q, "result": v, "error": errorText(err)})
		return nil, v, err
	})
	if *listen != "" {
		host, _, err := net.SplitHostPort(*listen)
		if err != nil || host != "127.0.0.1" || os.Getenv("INCIDENT_MCP_TOKEN") == "" {
			log.Fatal("HTTP requires 127.0.0.1 and INCIDENT_MCP_TOKEN")
		}
		handler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server { return server }, nil)
		httpServer := &http.Server{Addr: *listen, ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+os.Getenv("INCIDENT_MCP_TOKEN") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			handler.ServeHTTP(w, r)
		})}
		log.Fatal(httpServer.ListenAndServe())
	}
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
func errorText(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
