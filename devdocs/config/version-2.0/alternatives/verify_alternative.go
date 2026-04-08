// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type mode string

const (
	modeInline        mode = "inline-refinement"
	modePolicies      mode = "policies"
	modeWorkloadRules mode = "workload-rules"
)

func main() {
	var selectedMode string
	var configPath string
	var currentPath string

	flag.StringVar(&selectedMode, "mode", "", "Alternative mode: inline-refinement, policies, or workload-rules")
	flag.StringVar(&configPath, "config", "", "Path to the alternative default config YAML")
	flag.StringVar(&currentPath, "current", "devdocs/config/version-2.0/.verify/default-config-current.yaml", "Path to current default config YAML")
	flag.Parse()

	if selectedMode == "" || configPath == "" {
		fmt.Println("usage: verify_alternative.go --mode <inline-refinement|policies|workload-rules> --config <path>")
		os.Exit(2)
	}

	m := mode(selectedMode)
	switch m {
	case modeInline, modePolicies, modeWorkloadRules:
	default:
		fmt.Printf("unsupported mode: %s\n", selectedMode)
		os.Exit(2)
	}

	curBytes, err := os.ReadFile(currentPath)
	if err != nil {
		panic(err)
	}
	exBytes, err := os.ReadFile(configPath)
	if err != nil {
		panic(err)
	}

	var cur map[string]any
	var ex map[string]any
	if err := yaml.Unmarshal(curBytes, &cur); err != nil {
		panic(err)
	}
	if err := yaml.Unmarshal(exBytes, &ex); err != nil {
		panic(err)
	}

	checks := []struct {
		cur []string
		ex  []string
	}{
		{[]string{"ebpf", "batch_length"}, obiPath(m, "operations", "capture", "batching", "batch_length")},
		{[]string{"ebpf", "batch_timeout"}, obiPath(m, "operations", "capture", "batching", "batch_timeout")},
		{[]string{"ebpf", "wakeup_len"}, obiPath(m, "operations", "capture", "batching", "wakeup_len")},
		{[]string{"ebpf", "traffic_control_backend"}, obiPath(m, "operations", "capture", "traffic", "control_backend")},
		{[]string{"ebpf", "bpf_fs_path"}, obiPath(m, "operations", "capture", "bpf_filesystem", "path")},
		{[]string{"ebpf", "max_transaction_time"}, obiPath(m, "operations", "capture", "transactions", "max_duration")},
		{[]string{"discovery", "bpf_pid_filter_off"}, obiPath(m, "operations", "capture", "pid_filter", "disabled")},
		{[]string{"ebpf", "dns_request_timeout"}, obiPath(m, "instrumentation", "dns", "request_timeout")},
		{[]string{"ebpf", "payload_extraction", "http", "graphql", "enabled"}, obiPath(m, "instrumentation", "http", "payload_extraction", "graphql", "enabled")},
		{[]string{"ebpf", "payload_extraction", "http", "sqlpp", "enabled"}, obiPath(m, "instrumentation", "http", "payload_extraction", "sqlpp", "enabled")},
		{[]string{"ebpf", "log_enricher", "cache_ttl"}, obiPath(m, "correlation", "log_trace_annotation", "cache", "ttl")},
		{[]string{"ebpf", "log_enricher", "cache_size"}, obiPath(m, "correlation", "log_trace_annotation", "cache", "size")},
		{[]string{"ebpf", "log_enricher", "async_writer_workers"}, obiPath(m, "correlation", "log_trace_annotation", "async_writer", "workers")},
		{[]string{"ebpf", "log_enricher", "async_writer_channel_len"}, obiPath(m, "correlation", "log_trace_annotation", "async_writer", "channel_len")},
		{[]string{"ebpf", "buffer_sizes", "http"}, obiPath(m, "instrumentation", "http", "buffer_size")},
		{[]string{"ebpf", "heuristic_sql_detect"}, obiPath(m, "instrumentation", "sql", "heuristic_detect")},
		{[]string{"ebpf", "buffer_sizes", "mysql"}, obiPath(m, "instrumentation", "sql", "mysql", "buffer_size")},
		{[]string{"ebpf", "mysql_prepared_statements_cache_size"}, obiPath(m, "instrumentation", "sql", "mysql", "prepared_statements_cache_size")},
		{[]string{"ebpf", "buffer_sizes", "postgres"}, obiPath(m, "instrumentation", "sql", "postgres", "buffer_size")},
		{[]string{"ebpf", "postgres_prepared_statements_cache_size"}, obiPath(m, "instrumentation", "sql", "postgres", "prepared_statements_cache_size")},
		{[]string{"ebpf", "redis_db_cache", "enabled"}, obiPath(m, "instrumentation", "redis", "db_cache", "enabled")},
		{[]string{"ebpf", "buffer_sizes", "kafka"}, obiPath(m, "instrumentation", "kafka", "buffer_size")},
		{[]string{"network", "enable"}, obiPath(m, "network", "capture", "enabled")},
		{[]string{"network", "source"}, obiPath(m, "network", "capture", "source")},
		{[]string{"network", "agent_ip"}, obiPath(m, "network", "capture", "endpoint_identity", "agent_ip")},
		{[]string{"network", "agent_ip_iface"}, obiPath(m, "network", "capture", "endpoint_identity", "agent_ip_interface")},
		{[]string{"network", "agent_ip_type"}, obiPath(m, "network", "capture", "endpoint_identity", "agent_ip_family")},
		{[]string{"network", "cache_max_flows"}, obiPath(m, "network", "capture", "flow_lifecycle", "max_tracked_flows")},
		{[]string{"network", "cache_active_timeout"}, obiPath(m, "network", "capture", "flow_lifecycle", "active_timeout")},
		{[]string{"network", "deduper"}, obiPath(m, "network", "capture", "flow_lifecycle", "deduplication", "strategy")},
		{[]string{"network", "deduper_fc_ttl"}, obiPath(m, "network", "capture", "flow_lifecycle", "deduplication", "first_come_ttl")},
		{[]string{"network", "sampling"}, obiPath(m, "network", "capture", "flow_lifecycle", "sampling")},
		{[]string{"network", "direction"}, obiPath(m, "network", "capture", "selection", "direction")},
		{[]string{"network", "listen_interfaces"}, obiPath(m, "network", "capture", "interface_discovery", "mode")},
		{[]string{"network", "listen_poll_period"}, obiPath(m, "network", "capture", "interface_discovery", "poll_interval")},
		{[]string{"network", "geo_ip", "cache_expiry"}, obiPath(m, "network", "capture", "enrichment", "geo_ip", "cache", "ttl")},
		{[]string{"network", "reverse_dns", "cache_expiry"}, obiPath(m, "network", "capture", "enrichment", "reverse_dns", "cache", "ttl")},
		{[]string{"network", "print_flows"}, obiPath(m, "network", "capture", "diagnostics", "print_flows")},
		{[]string{"discovery", "min_process_age"}, selectionEvaluationPath(m, "min_process_age")},
		{[]string{"discovery", "route_harvester_timeout"}, obiPath(m, "instrumentation", "http", "routes", "discovery", "timeout")},
		{[]string{"discovery", "disabled_route_harvesters"}, obiPath(m, "instrumentation", "http", "routes", "discovery", "disabled_languages")},
		{[]string{"discovery", "route_harvester_advanced", "java_harvest_delay"}, obiPath(m, "instrumentation", "http", "routes", "discovery", "java", "delay")},
		{[]string{"name_resolver", "cache_len"}, obiPath(m, "enrich", "service_name", "cache", "size")},
		{[]string{"name_resolver", "cache_expiry"}, obiPath(m, "enrich", "service_name", "cache", "ttl")},
		{[]string{"attributes", "metric_span_names_limit"}, obiPath(m, "operations", "limits", "metric_span_names")},
		{[]string{"attributes", "rename_unresolved_hosts"}, obiPath(m, "enrich", "service_name", "unresolved_hosts", "names", "default")},
		{[]string{"attributes", "kubernetes", "informers_sync_timeout"}, obiPath(m, "enrich", "enrichers", "kubernetes", "informers", "initial_sync_timeout")},
		{[]string{"attributes", "kubernetes", "informers_resync_period"}, obiPath(m, "enrich", "enrichers", "kubernetes", "informers", "resync_period")},
		{[]string{"routes", "unmatched"}, obiPath(m, "instrumentation", "http", "routes", "unmatched")},
		{[]string{"routes", "wildcard_char"}, obiPath(m, "instrumentation", "http", "routes", "wildcard_char")},
		{[]string{"routes", "max_path_segment_cardinality"}, obiPath(m, "instrumentation", "http", "routes", "max_path_segment_cardinality")},
		{[]string{"otel_metrics_export", "histogram_aggregation"}, []string{"meter_provider", "readers", "0", "periodic", "exporter", "otlp_grpc", "default_histogram_aggregation"}},
		{[]string{"otel_metrics_export", "reporters_cache_len"}, obiPath(m, "operations", "telemetry", "metrics", "reporters_cache_len")},
		{[]string{"otel_metrics_export", "ttl"}, obiPath(m, "operations", "telemetry", "metrics", "ttl")},
		{[]string{"otel_metrics_export", "extra_span_resource_attributes"}, obiPath(m, "operations", "telemetry", "metrics", "prometheus", "extra_span_resource_attributes")},
		{[]string{"otel_traces_export", "max_queue_size"}, []string{"tracer_provider", "processors", "0", "batch", "max_queue_size"}},
		{[]string{"otel_traces_export", "reporters_cache_len"}, obiPath(m, "operations", "telemetry", "traces", "reporters_cache_len")},
		{[]string{"prometheus_export", "port"}, []string{"meter_provider", "readers", "1", "pull", "exporter", "prometheus/development", "port"}},
		{[]string{"prometheus_export", "service_cache_size"}, obiPath(m, "operations", "telemetry", "metrics", "prometheus", "span_metrics_service_cache_size")},
		{[]string{"prometheus_export", "allow_service_graph_self_references"}, obiPath(m, "operations", "telemetry", "metrics", "prometheus", "allow_service_graph_self_references")},
		{[]string{"prometheus_export", "extra_resource_attributes"}, obiPath(m, "operations", "telemetry", "metrics", "prometheus", "extra_resource_attributes")},
		{[]string{"prometheus_export", "extra_span_resource_attributes"}, obiPath(m, "operations", "telemetry", "metrics", "prometheus", "extra_span_resource_attributes")},
		{[]string{"log_config"}, obiPath(m, "operations", "logging", "format")},
		{[]string{"log_level"}, obiPath(m, "operations", "logging", "level")},
		{[]string{"trace_printer"}, obiPath(m, "operations", "logging", "debug_trace_output")},
		{[]string{"shutdown_timeout"}, obiPath(m, "operations", "shutdown", "timeout")},
		{[]string{"profile_port"}, obiPath(m, "operations", "profiling", "port")},
		{[]string{"enforce_sys_caps"}, obiPath(m, "operations", "safety", "enforce_system_capabilities")},
		{[]string{"channel_buffer_len"}, obiPath(m, "operations", "runtime", "channels", "buffer_len")},
		{[]string{"channel_send_timeout"}, obiPath(m, "operations", "runtime", "channels", "send_timeout")},
		{[]string{"channel_send_timeout_panic"}, obiPath(m, "operations", "runtime", "channels", "panic_on_send_timeout")},
		{[]string{"internal_metrics", "exporter"}, obiPath(m, "operations", "internal_metrics", "exporter")},
		{[]string{"internal_metrics", "prometheus", "path"}, obiPath(m, "operations", "internal_metrics", "prometheus", "path")},
		{[]string{"internal_metrics", "bpf_metric_scrape_interval"}, obiPath(m, "operations", "internal_metrics", "bpf", "scrape_interval")},
		{[]string{"nodejs", "enabled"}, obiPath(m, "runtimes", "nodejs", "enabled")},
		{[]string{"javaagent", "enabled"}, obiPath(m, "runtimes", "java", "enabled")},
		{[]string{"javaagent", "debug"}, obiPath(m, "runtimes", "java", "debug", "enabled")},
		{[]string{"javaagent", "debug_instrumentation"}, obiPath(m, "runtimes", "java", "debug", "bytecode_instrumentation")},
		{[]string{"javaagent", "attach_timeout"}, obiPath(m, "runtimes", "java", "attach_timeout")},
	}

	failures := 0
	for _, c := range checks {
		if err := mustEq(cur, ex, c.cur, c.ex); err != nil {
			fmt.Println("FAIL:", err)
			failures++
		}
	}

	if err := mustEqDurationToMilliseconds(cur, ex, []string{"otel_traces_export", "batch_timeout"}, []string{"tracer_provider", "processors", "0", "batch", "schedule_delay"}); err != nil {
		fmt.Println("FAIL:", err)
		failures++
	}
	if failures > 0 {
		fmt.Printf("verification failed: %d mismatches\n", failures)
		os.Exit(1)
	}

	excludedSystemPathFn := func(ex map[string]any) ([]any, error) {
		return selectionRules(ex, m)
	}
	if err := mustMapExcludedSystemPaths(cur, ex, excludedSystemPathFn); err != nil {
		exitVerify(err, failures+1)
	}
	if err := mustMapAlreadyInstrumentedExclusion(cur, ex, excludedSystemPathFn); err != nil {
		exitVerify(err, failures+1)
	}
	if err := mustMapGoSpecificTracers(cur, ex, m); err != nil {
		exitVerify(err, failures+1)
	}
	if err := mustMapApplicationFiltersPerInstrumentation(cur, ex, m); err != nil {
		exitVerify(err, failures+1)
	}
	if err := mustMapNetworkFiltersPerSignal(cur, ex, m); err != nil {
		exitVerify(err, failures+1)
	}

	fmt.Printf("%s parity verification passed: %d mapped default checks\n", selectedMode, len(checks)+6)
}

func exitVerify(err error, total int) {
	fmt.Println("FAIL:", err)
	fmt.Printf("verification failed: %d mismatches\n", total)
	os.Exit(1)
}

func obiPath(m mode, segs ...string) []string {
	root := []string{"obi"}
	if m == modeWorkloadRules {
		root = append(root, "defaults")
	}
	return append(root, segs...)
}

func selectionRulesPath(m mode) []string {
	if m == modeWorkloadRules {
		return []string{"obi", "workloads", "rules"}
	}
	return []string{"obi", "selection", "rules"}
}

func selectionEvaluationPath(m mode, segs ...string) []string {
	root := []string{"obi"}
	if m == modeWorkloadRules {
		root = append(root, "workloads", "evaluation")
	} else {
		root = append(root, "selection", "evaluation")
	}
	return append(root, segs...)
}

func selectionRules(ex map[string]any, m mode) ([]any, error) {
	rulesValue, ok := get(ex, selectionRulesPath(m)...)
	if !ok {
		return nil, fmt.Errorf("missing example key %v", selectionRulesPath(m))
	}
	rules, ok := rulesValue.([]any)
	if !ok {
		return nil, fmt.Errorf("example %v is not a list", selectionRulesPath(m))
	}
	return rules, nil
}

func asMap(v any) map[string]any {
	if v == nil {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return m
}

func get(root map[string]any, path ...string) (any, bool) {
	cur := any(root)
	for i, p := range path {
		if arr, ok := cur.([]any); ok {
			idx, err := strconv.Atoi(p)
			if err != nil || idx < 0 || idx >= len(arr) {
				return nil, false
			}
			cur = arr[idx]
			continue
		}

		m := asMap(cur)
		if m == nil {
			return nil, false
		}
		if i == 0 && p == "obi" {
			if _, ok := m["obi"]; !ok {
				extensionsAny, ok := m["extensions"]
				if ok {
					extensionsMap := asMap(extensionsAny)
					if extensionsMap != nil {
						if obiAny, ok := extensionsMap["obi"]; ok {
							cur = obiAny
							continue
						}
					}
				}
			}
		}
		n, ok := m[p]
		if !ok {
			return nil, false
		}
		cur = n
	}
	return cur, true
}

func mustEq(cur map[string]any, ex map[string]any, curPath []string, exPath []string) error {
	cv, ok := get(cur, curPath...)
	if !ok {
		return fmt.Errorf("missing current key %v", curPath)
	}
	ev, ok := get(ex, exPath...)
	if !ok {
		return fmt.Errorf("missing example key %v", exPath)
	}
	if fmt.Sprintf("%v", cv) != fmt.Sprintf("%v", ev) {
		return fmt.Errorf("mismatch current %v=%v example %v=%v", curPath, cv, exPath, ev)
	}
	return nil
}

func mustEqDurationToMilliseconds(cur map[string]any, ex map[string]any, curPath []string, exPath []string) error {
	cv, ok := get(cur, curPath...)
	if !ok {
		return fmt.Errorf("missing current key %v", curPath)
	}
	ev, ok := get(ex, exPath...)
	if !ok {
		return fmt.Errorf("missing example key %v", exPath)
	}

	curDuration, err := time.ParseDuration(fmt.Sprintf("%v", cv))
	if err != nil {
		return fmt.Errorf("invalid current duration %v=%v", curPath, cv)
	}

	var exMillis int64
	switch value := ev.(type) {
	case int:
		exMillis = int64(value)
	case int64:
		exMillis = value
	case float64:
		exMillis = int64(value)
	case string:
		parsed, parseErr := strconv.ParseInt(value, 10, 64)
		if parseErr != nil {
			return fmt.Errorf("invalid example milliseconds %v=%v", exPath, ev)
		}
		exMillis = parsed
	default:
		return fmt.Errorf("unsupported example milliseconds type for %v=%v", exPath, ev)
	}
	if curDuration.Milliseconds() != exMillis {
		return fmt.Errorf("mismatch current %v=%vms example %v=%v", curPath, curDuration.Milliseconds(), exPath, exMillis)
	}
	return nil
}

func toStringSlice(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, fmt.Sprintf("%v", item))
	}
	return out
}

func mustMapExcludedSystemPaths(cur map[string]any, ex map[string]any, rulesFn func(map[string]any) ([]any, error)) error {
	currentPathsValue, ok := get(cur, "discovery", "excluded_linux_system_paths")
	if !ok {
		return errors.New("missing current key [discovery excluded_linux_system_paths]")
	}
	currentPaths := toStringSlice(currentPathsValue)
	if len(currentPaths) == 0 {
		return errors.New("current discovery.excluded_linux_system_paths is empty or not a list")
	}
	rules, err := rulesFn(ex)
	if err != nil {
		return err
	}
	foundGlobs := map[string]bool{}
	for _, ruleAny := range rules {
		rule, ok := ruleAny.(map[string]any)
		if !ok || fmt.Sprintf("%v", rule["action"]) != "exclude" {
			continue
		}
		match, ok := rule["match"].(map[string]any)
		if !ok {
			continue
		}
		process, ok := match["process"].(map[string]any)
		if !ok {
			continue
		}
		for _, g := range toStringSlice(process["exe_path_glob"]) {
			foundGlobs[g] = true
		}
	}
	for _, p := range currentPaths {
		expectedGlob := strings.TrimSuffix(p, "/") + "/*"
		if !foundGlobs[expectedGlob] {
			return fmt.Errorf("missing scope rule glob for excluded system path: expected %s", expectedGlob)
		}
	}
	return nil
}

func mustMapAlreadyInstrumentedExclusion(cur map[string]any, ex map[string]any, rulesFn func(map[string]any) ([]any, error)) error {
	currentValue, ok := get(cur, "discovery", "exclude_otel_instrumented_services")
	if !ok {
		return errors.New("missing current key [discovery exclude_otel_instrumented_services]")
	}
	wantExclude := fmt.Sprintf("%v", currentValue) == "true"
	defaultPortValue, ok := get(cur, "discovery", "default_otlp_grpc_port")
	if !ok {
		return errors.New("missing current key [discovery default_otlp_grpc_port]")
	}
	wantPort := fmt.Sprintf("%v", defaultPortValue)
	rules, err := rulesFn(ex)
	if err != nil {
		return err
	}
	found := false
	for _, ruleAny := range rules {
		rule, ok := ruleAny.(map[string]any)
		if !ok || fmt.Sprintf("%v", rule["action"]) != "exclude" {
			continue
		}
		match, ok := rule["match"].(map[string]any)
		if !ok {
			continue
		}
		process, ok := match["process"].(map[string]any)
		if !ok {
			continue
		}
		exportsOTLP, ok := process["exports_otlp"].(map[string]any)
		if !ok {
			continue
		}
		if fmt.Sprintf("%v", exportsOTLP["port"]) != wantPort {
			return fmt.Errorf("mismatch discovery.default_otlp_grpc_port=%s vs process.exports_otlp.port=%v", wantPort, exportsOTLP["port"])
		}
		if fmt.Sprintf("%v", exportsOTLP["protocol"]) == "" {
			return errors.New("missing process.exports_otlp.protocol in already-instrumented exclusion rule")
		}
		found = true
		break
	}
	if wantExclude && !found {
		return errors.New("missing selection rule for already-instrumented exclusion")
	}
	if !wantExclude && found {
		return errors.New("unexpected already-instrumented exclusion rule while source default is false")
	}
	return nil
}

func mustMapGoSpecificTracers(cur map[string]any, ex map[string]any, m mode) error {
	currentValue, ok := get(cur, "discovery", "skip_go_specific_tracers")
	if !ok {
		return errors.New("missing current key [discovery skip_go_specific_tracers]")
	}
	currentSkip := fmt.Sprintf("%v", currentValue) == "true"
	goEnabled, ok := get(ex, obiPath(m, "runtimes", "go", "enabled")...)
	if !ok {
		return fmt.Errorf("missing example key %v", obiPath(m, "runtimes", "go", "enabled"))
	}
	enableGo := fmt.Sprintf("%v", goEnabled) == "true"
	wantEnabled := !currentSkip
	if enableGo != wantEnabled {
		return fmt.Errorf("mismatch discovery.skip_go_specific_tracers=%v vs go.enabled=%v", currentSkip, enableGo)
	}
	return nil
}

func mustMapApplicationFiltersPerInstrumentation(cur map[string]any, ex map[string]any, m mode) error {
	currentValue, ok := get(cur, "filter", "application")
	if !ok {
		return errors.New("missing current key [filter application]")
	}
	protocols := []string{"http", "grpc", "sql", "redis", "kafka", "mongo", "couchbase", "dns", "gpu"}
	signals := []string{"traces", "metrics"}
	for _, protocol := range protocols {
		for _, signal := range signals {
			exampleValue, ok := get(ex, obiPath(m, "instrumentation", protocol, "filters", signal)...)
			if !ok {
				return fmt.Errorf("missing example key %v", obiPath(m, "instrumentation", protocol, "filters", signal))
			}
			if fmt.Sprintf("%v", currentValue) != fmt.Sprintf("%v", exampleValue) {
				return fmt.Errorf("filter.application mismatch for protocol %s signal %s", protocol, signal)
			}
		}
	}
	return nil
}

func mustMapNetworkFiltersPerSignal(cur map[string]any, ex map[string]any, m mode) error {
	currentValue, ok := get(cur, "filter", "network")
	if !ok {
		return errors.New("missing current key [filter network]")
	}
	signals := []string{"traces", "metrics"}
	for _, signal := range signals {
		exampleValue, ok := get(ex, obiPath(m, "network", "capture", "filters", signal)...)
		if !ok {
			return fmt.Errorf("missing example key %v", obiPath(m, "network", "capture", "filters", signal))
		}
		if fmt.Sprintf("%v", currentValue) != fmt.Sprintf("%v", exampleValue) {
			return fmt.Errorf("filter.network mismatch for signal %s", signal)
		}
	}
	return nil
}
