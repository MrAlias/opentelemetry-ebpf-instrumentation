package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxResponseBytes = 8 << 20
const maxFunctions = 30
const maxExemplars = 100

type integer int64

func (n *integer) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	v, err := strconv.ParseInt(s, 10, 64)
	*n = integer(v)
	return err
}
func (q interval) bounds() (int64, int64, error) {
	start, err := time.Parse(time.RFC3339Nano, q.Start)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start: %w", err)
	}
	end, err := time.Parse(time.RFC3339Nano, q.End)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end: %w", err)
	}
	if !end.After(start) || end.Sub(start) > 15*time.Minute {
		return 0, 0, fmt.Errorf("interval must be positive and at most 15 minutes")
	}
	return start.UnixMilli(), end.UnixMilli(), nil
}
func normalizeID(s string, size int) (string, error) {
	if b, err := hex.DecodeString(s); err == nil && len(b) == size {
		if bytes.Equal(b, make([]byte, size)) {
			return "", fmt.Errorf("zero ID")
		}
		return hex.EncodeToString(b), nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != size || bytes.Equal(b, make([]byte, size)) {
		return "", fmt.Errorf("invalid %d-byte ID", size)
	}
	return hex.EncodeToString(b), nil
}
func (e *experiment) request(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, e.grafana+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("backend unavailable: %w", err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("backend response exceeds limit")
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("backend HTTP %d: %.400s", res.StatusCode, data)
	}
	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("invalid backend response: %w", err)
	}
	return nil
}
func (e *experiment) profileLink(q interval, ids []string) string {
	start, end, _ := q.bounds()
	params := url.Values{"var-serviceName": {serviceName}, "var-dataSource": {"pyroscope"}, "var-profileMetricId": {profileType}, "explorationType": {"flame-graph"}, "from": {strconv.FormatInt(start, 10)}, "to": {strconv.FormatInt(end, 10)}, "showSpanHeatmap": {"true"}}
	// Drilldown supports a single selected span; multi-span queries remain explicit in tool evidence.
	if len(ids) == 1 {
		params.Set("var-spanSelector", ids[0])
	}
	return e.grafana + "/a/grafana-pyroscope-app/explore?" + params.Encode()
}
func (e *experiment) traceLink(id string, q interval) string {
	panes := map[string]any{"trace": map[string]any{"datasource": "tempo", "queries": []any{map[string]any{"refId": "A", "queryType": "traceql", "query": id}}, "range": map[string]string{"from": q.Start, "to": q.End}}}
	data, _ := json.Marshal(panes)
	return e.grafana + "/explore?schemaVersion=1&orgId=1&panes=" + url.QueryEscape(string(data))
}

type exemplar struct {
	Timestamp integer `json:"timestamp"`
	SpanID    string  `json:"spanId"`
	TraceID   string  `json:"traceId"`
	Value     integer `json:"value"`
	ProfileID string  `json:"profileId"`
}

func (e *experiment) exemplars(ctx context.Context, q interval) (map[string]any, error) {
	start, end, err := e.collectionBounds(q)
	if err != nil {
		return nil, err
	}
	input := map[string]any{"profileTypeID": profileType, "labelSelector": `{service_name="` + serviceName + `"}`, "start": start, "end": end, "step": 5, "queryType": "HEATMAP_QUERY_TYPE_SPAN", "exemplarType": "EXEMPLAR_TYPE_SPAN"}
	var response struct {
		Series []struct {
			Slots []struct {
				Exemplars []exemplar `json:"exemplars"`
			} `json:"slots"`
		} `json:"series"`
	}
	err = e.request(ctx, "POST", "/api/datasources/proxy/uid/pyroscope/querier.v1.QuerierService/SelectHeatmap", input, &response)
	if err != nil {
		return nil, err
	}
	items := []map[string]any{}
	seen := map[string]bool{}
	missingTrace := 0
	invalid := 0
	for _, s := range response.Series {
		for _, slot := range s.Slots {
			for _, x := range slot.Exemplars {
				sid, err := normalizeID(x.SpanID, 8)
				if err != nil {
					invalid++
					continue
				}
				tid, err := normalizeID(x.TraceID, 16)
				if err != nil {
					missingTrace++
					tid = ""
				}
				key := fmt.Sprintf("%s/%s/%d", sid, x.ProfileID, x.Timestamp)
				if seen[key] {
					continue
				}
				seen[key] = true
				item := map[string]any{"span_id": sid, "trace_id": tid, "timestamp_ms": x.Timestamp, "value_ns": x.Value, "profile_id": x.ProfileID, "profile_url": e.profileLink(q, []string{sid})}
				if tid != "" {
					item["trace_url"] = e.traceLink(tid, q)
				}
				items = append(items, item)
			}
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["value_ns"].(integer) > items[j]["value_ns"].(integer) })
	count := len(items)
	if len(items) > maxExemplars {
		items = items[:maxExemplars]
	}
	state := "linked_samples"
	if count == 0 {
		state = "no_span_exemplars"
	}
	return map[string]any{"state": state, "interval": q, "unit": "nanoseconds", "exemplars": items, "returned": len(items), "available": count, "truncated": count > maxExemplars, "missing_trace_ids": missingTrace, "invalid_span_ids": invalid, "note": "Exemplars are a bounded selection of recorded samples, not an exhaustive request list. No exemplars can mean export delay, no samples, or absent correlation."}, nil
}

type functionValue struct {
	Name       string `json:"name"`
	Self       int64  `json:"self_ns"`
	Cumulative int64  `json:"cumulative_ns"`
}

func parseFlameGraph(names []string, levels [][]integer, total int64) ([]functionValue, error) {
	byName := map[string]*functionValue{}
	var selfSum int64
	for _, level := range levels {
		if len(level)%4 != 0 {
			return nil, fmt.Errorf("invalid flame graph level")
		}
		for i := 0; i < len(level); i += 4 {
			cumulative, self, index := int64(level[i+1]), int64(level[i+2]), int(level[i+3])
			if index < 0 || index >= len(names) || self < 0 || cumulative < self {
				return nil, fmt.Errorf("invalid flame graph node")
			}
			selfSum += self
			name := names[index]
			f := byName[name]
			if f == nil {
				f = &functionValue{Name: name}
				byName[name] = f
			}
			f.Self += self
			f.Cumulative += cumulative
		}
	}
	if selfSum != total {
		return nil, fmt.Errorf("flame graph self sum %d differs from total %d", selfSum, total)
	}
	functions := make([]functionValue, 0, len(byName))
	for _, f := range byName {
		functions = append(functions, *f)
	}
	sort.Slice(functions, func(i, j int) bool {
		if functions[i].Self == functions[j].Self {
			return functions[i].Name < functions[j].Name
		}
		return functions[i].Self > functions[j].Self
	})
	return functions, nil
}
func (e *experiment) profile(ctx context.Context, q spanQuery) (map[string]any, error) {
	start, end, err := e.collectionBounds(q.interval)
	if err != nil {
		return nil, err
	}
	if len(q.SpanIDs) == 0 || len(q.SpanIDs) > 100 {
		return nil, fmt.Errorf("provide 1 to 100 exact span IDs")
	}
	ids := []string{}
	seen := map[string]bool{}
	for _, id := range q.SpanIDs {
		n, err := normalizeID(id, 8)
		if err != nil {
			return nil, err
		}
		if !seen[n] {
			ids = append(ids, n)
			seen[n] = true
		}
	}
	input := map[string]any{"profileTypeID": profileType, "labelSelector": `{service_name="` + serviceName + `"}`, "start": start, "end": end, "spanSelector": ids, "format": "PROFILE_FORMAT_FLAMEGRAPH"}
	var response struct {
		Flamegraph struct {
			Names  []string `json:"names"`
			Levels []struct {
				Values []integer `json:"values"`
			} `json:"levels"`
			Total integer `json:"total"`
		} `json:"flamegraph"`
	}
	if err := e.request(ctx, "POST", "/api/datasources/proxy/uid/pyroscope/querier.v1.QuerierService/SelectMergeStacktraces", input, &response); err != nil {
		return nil, err
	}
	levels := [][]integer{}
	for _, l := range response.Flamegraph.Levels {
		levels = append(levels, l.Values)
	}
	functions, err := parseFlameGraph(response.Flamegraph.Names, levels, int64(response.Flamegraph.Total))
	if err != nil {
		return nil, err
	}
	count := len(functions)
	if len(functions) > maxFunctions {
		functions = functions[:maxFunctions]
	}
	state := "samples"
	if response.Flamegraph.Total == 0 {
		state = "no_matching_samples"
	}
	return map[string]any{"state": state, "interval": q.interval, "span_ids": ids, "unit": "nanoseconds", "total_ns": response.Flamegraph.Total, "functions": functions, "truncated": count > maxFunctions, "profile_url": e.profileLink(q.interval, ids), "note": "Sampled CPU execution is not wall-clock latency. Empty profiles do not prove a span did not run; cumulative values can overlap and must not be summed."}, nil
}
