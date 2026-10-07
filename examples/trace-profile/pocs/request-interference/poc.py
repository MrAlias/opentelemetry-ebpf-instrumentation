#!/usr/bin/env python3
"""Collect or replay a bounded request-interference experiment."""

import argparse
import base64
import concurrent.futures
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import time
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
PROJECT = "obi-poc-interference"
SERVICE = PROJECT
GRAFANA = "http://localhost:3103"
APP = "http://localhost:8183"
PROFILE = "process_cpu:cpu:nanoseconds:cpu:nanoseconds"
MODES = ("obi", "profiler", "combined")
CASES = ("shared-lock", "control")
OBI_REVISION = "6d873d705d77e9764adab67502d65695df986e93"
MAX_RESPONSE = 16 * 1024 * 1024


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def now_ms():
    return time.time_ns() // 1_000_000


def timestamp(value):
    return datetime.datetime.fromtimestamp(value / 1000, datetime.timezone.utc).isoformat()


def compose(*args, scenario="shared-lock", correlation=True):
    command = ["docker", "compose", "--project-name", PROJECT, "--project-directory", str(HERE),
               "--file", str(HERE / "compose.yaml"), "--profile", "diagnostics", *args]
    return subprocess.check_output(command, text=True, env=dict(os.environ,
        SCENARIO=scenario, OBI_PROCESS_CTX=str(correlation).lower()))


def identity():
    cid = compose("ps", "-q", "app").strip()
    if not cid:
        raise RuntimeError("application is not running")
    data = json.loads(subprocess.check_output(["docker", "inspect", cid], text=True))[0]
    return {"container_id": data["Id"], "pid": data["State"]["Pid"],
            "started_at": data["State"]["StartedAt"], "pid_mode": data["HostConfig"]["PidMode"]}


def normalize_id(value, size, allow_short_hex=False):
    if not isinstance(value, str):
        raise ValueError("invalid ID type")
    if allow_short_hex and re.fullmatch(r"[0-9a-fA-F]+", value) and len(value) <= size * 2:
        value = value.zfill(size * 2)
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        decoded = b""
    if len(decoded) != size:
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            raise ValueError("invalid ID") from None
    if len(decoded) != size or not any(decoded):
        raise ValueError("invalid or zero ID")
    return decoded.hex()


def flame_summary(response):
    graph = response.get("flamegraph", {})
    total = int(graph.get("total", 0))
    names = graph.get("names", [])
    values = {}
    self_sum = 0
    for level in graph.get("levels", []):
        row = level.get("values", [])
        if len(row) % 4:
            raise ValueError("invalid flame graph level")
        for i in range(0, len(row), 4):
            cumulative, own, index = map(int, row[i + 1:i + 4])
            if own < 0 or cumulative < own or index < 0 or index >= len(names):
                raise ValueError("invalid flame graph node")
            item = values.setdefault(names[index], {"name": names[index], "self_ns": 0, "cumulative_ns": 0})
            item["self_ns"] += own
            item["cumulative_ns"] += cumulative
            self_sum += own
    if self_sum != total:
        raise ValueError(f"self sum {self_sum} does not equal total {total}")
    return {"state": "samples" if total else "no_matching_samples", "total_ns": total,
            "self_sum_ns": self_sum, "functions": sorted(values.values(), key=lambda x: -x["self_ns"]),
            "unit": "nanoseconds", "note": "Cumulative values overlap; do not sum them. Sampled CPU is not elapsed time."}


def trace_spans(data):
    for batch in data.get("batches", data.get("resourceSpans", [])):
        for scope in batch.get("scopeSpans", batch.get("instrumentationLibrarySpans", [])):
            yield from scope.get("spans", [])


def span_description(span):
    attributes = {a["key"]: a.get("value", {}) for a in span.get("attributes", [])}
    return {"span_id": normalize_id(span.get("spanId", span.get("spanID", "")), 8),
            "name": span.get("name"), "kind": span.get("kind"), "attributes": attributes,
            "duration_ms": (int(span.get("endTimeUnixNano", 0)) - int(span.get("startTimeUnixNano", 0))) / 1_000_000}


def profile_link(start, end, sid=None):
    params = {"var-serviceName": SERVICE, "var-dataSource": "pyroscope", "var-profileMetricId": PROFILE,
              "explorationType": "flame-graph", "from": str(start), "to": str(end), "showSpanHeatmap": "true"}
    if sid:
        params["var-spanSelector"] = sid
    return GRAFANA + "/a/grafana-pyroscope-app/explore?" + urllib.parse.urlencode(params)


def trace_link(tid, start, end):
    panes = {"trace": {"datasource": "tempo", "queries": [{"refId": "A", "queryType": "traceql", "query": tid}],
                       "range": {"from": timestamp(start), "to": timestamp(end)}}}
    return GRAFANA + "/explore?" + urllib.parse.urlencode({"schemaVersion": "1", "orgId": "1", "panes": json.dumps(panes)})


def request(path, payload=None, base=GRAFANA, deadline=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json", "Connect-Protocol-Version": "1"})
    timeout = 15
    if deadline is not None:
        timeout = min(timeout, deadline - time.monotonic())
        if timeout <= 0:
            raise TimeoutError("collection deadline reached")
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise RuntimeError("backend response too large")
    return json.loads(raw)


def captured(out, label, path, payload=None, deadline=None):
    save(out / "raw" / (label + ".request.json"), {"path": path, "body": payload})
    try:
        response = request(path, payload, deadline=deadline)
    except (OSError, ValueError) as exc:
        response = {"collection_error": str(exc)}
    save(out / "raw" / (label + ".json"), response)
    return response


def collect(out, start, end, mode, deadline=None):
    selector = {"profileTypeID": PROFILE, "labelSelector": '{service_name="' + SERVICE + '"}', "start": start, "end": end}
    aggregate = captured(out, "aggregate", "/api/datasources/proxy/uid/pyroscope/querier.v1.QuerierService/SelectMergeStacktraces", selector, deadline=deadline)
    heatmap = captured(out, "heatmap", "/api/datasources/proxy/uid/pyroscope/querier.v1.QuerierService/SelectHeatmap",
        dict(selector, step=5, queryType="HEATMAP_QUERY_TYPE_SPAN", exemplarType="EXEMPLAR_TYPE_SPAN"), deadline=deadline)
    query = urllib.parse.urlencode({"q": '{resource.service.name="' + SERVICE + '"}',
                                   "start": start // 1000, "end": (end + 999) // 1000, "limit": 200})
    search = captured(out, "search", "/api/datasources/proxy/uid/tempo/api/search?" + query, deadline=deadline)
    linked = []
    seen = set()
    invalid = 0
    for series in heatmap.get("series", []):
        for slot in series.get("slots", []):
            for item in slot.get("exemplars", []):
                try:
                    sid = normalize_id(item.get("spanId", ""), 8)
                    tid = normalize_id(item.get("traceId", ""), 16)
                except ValueError:
                    invalid += 1
                    continue
                if (sid, tid) in seen:
                    continue
                seen.add((sid, tid))
                linked.append({"span_id": sid, "trace_id": tid, "value_ns": int(item.get("value", 0)),
                               "timestamp_ms": int(item.get("timestamp", 0))})
    available = len(linked)
    linked = sorted(linked, key=lambda x: -x["value_ns"])[:12]
    ids = {item["trace_id"] for item in linked}
    for item in search.get("traces", [])[:8]:
        ids.add(normalize_id(item["traceID"], 16, allow_short_hex=True))
    traces = {}
    for tid in sorted(ids):
        traces[tid] = captured(out, "trace-" + tid, "/api/datasources/proxy/uid/tempo/api/traces/" + tid, deadline=deadline)
    for item in linked:
        spans = list(trace_spans(traces[item["trace_id"]]))
        matched = [span for span in spans if normalize_id(span.get("spanId", span.get("spanID", "")), 8) == item["span_id"]
                   and normalize_id(span.get("traceId", span.get("traceID", "")), 16) == item["trace_id"]]
        item["exact_span_found"] = bool(matched)
        item["span"] = span_description(matched[0]) if matched else None
        item["trace_spans"] = [span_description(span) for span in spans]
        item["profile_url"] = profile_link(start, end, item["span_id"])
        item["trace_url"] = trace_link(item["trace_id"], start, end)
        raw = captured(out, "span-" + item["span_id"], "/api/datasources/proxy/uid/pyroscope/querier.v1.QuerierService/SelectMergeStacktraces",
                       dict(selector, spanSelector=[item["span_id"]]), deadline=deadline)
        item["cpu"] = flame_summary(raw) if "collection_error" not in raw else raw
    summary = {"mode": mode, "interval": {"start_ms": start, "end_ms": end, "start": timestamp(start), "end": timestamp(end)},
               "aggregate": flame_summary(aggregate) if "collection_error" not in aggregate else aggregate,
               "trace_search": search, "exemplars": linked, "available_unique_exemplars": available,
               "fetched_traces": [{"trace_id": tid, "trace_url": trace_link(tid, start, end),
                                   "spans": [span_description(span) for span in trace_spans(raw)]}
                                  for tid, raw in traces.items()],
               "returned_exemplars": len(linked), "truncated": available > len(linked), "invalid_ids": invalid,
               "trace_search_limit": 200,
               "profile_url": profile_link(start, end),
               "causal_state": "unresolved_missing_resource_and_owner_events",
               "note": "Exact CPU/span identity does not establish mutex ownership, waiting, or interference. Exemplars are a bounded selection."}
    save(out / "summary.json", summary)
    return summary


def one_request(path):
    started = now_ms()
    before = time.monotonic()
    row = {"path": path, "start_ms": started}
    try:
        with urllib.request.urlopen(APP + path, timeout=15) as response:
            row["status"] = response.status
            response.read()
    except OSError as exc:
        row["error"] = str(exc)
    row.update(end_ms=now_ms(), duration_ms=(time.monotonic() - before) * 1000)
    return row


def traffic(pairs):
    records = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        for _ in range(pairs):
            report = pool.submit(one_request, "/report")
            time.sleep(0.1)
            work = pool.submit(one_request, "/work")
            records.extend((report.result(), work.result()))
            time.sleep(0.1)
    return records


def traffic_summary(rows):
    result = {}
    for path in ("/work", "/report"):
        selected = [row for row in rows if row["path"] == path]
        result[path] = {"completed": sum(row.get("status") == 200 for row in selected),
                        "errors": sum("error" in row or row.get("status") != 200 for row in selected),
                        "median_ms": statistics.median(row["duration_ms"] for row in selected) if selected else None}
    return result


def retain_best_partial(out):
    current = json.loads((out / "summary.json").read_text())
    def quality(summary):
        return (len(summary["trace_search"].get("traces", [])),
                sum(item.get("exact_span_found", False) for item in summary["exemplars"]),
                summary["aggregate"].get("total_ns", 0))
    candidates = [(current, out)]
    for path in (out / "collection-attempts").glob("*/summary.json"):
        candidates.append((json.loads(path.read_text()), path.parent))
    best, source = max(candidates, key=lambda item: quality(item[0]))
    if source != out:
        archived = out / "deadline-response"
        if not archived.exists():
            shutil.copytree(out / "raw", archived / "raw")
            save(archived / "summary.json", current)
        shutil.rmtree(out / "raw")
        shutil.copytree(source / "raw", out / "raw")
        best["partial_selection"] = {"source": str(source.relative_to(out)),
                                     "note": "Retained actually collected partial evidence instead of overwriting it with deadline errors; capture completeness is not established."}
        save(out / "summary.json", best)
    return best


def wait_ready():
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            request("/api/health")
            with urllib.request.urlopen(APP + "/health", timeout=3) as response:
                if response.status == 200:
                    return
        except (OSError, ValueError):
            pass
        time.sleep(2)
    raise RuntimeError("backend/application readiness exceeded two minutes")


def run(args):
    args.output.mkdir(parents=True, exist_ok=False)
    with open("/tmp/obi-diagnostic-poc-live.lock", "a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another diagnostic PoC owns the live host slot; retry later") from None
        try:
            if args.build:
                compose("build", "app")
            config = json.loads(compose("config", "--format", "json"))
            images = {}
            for name in ("app", "obi", "profiler", "lgtm"):
                tag = config["services"][name]["image"]
                inspected = json.loads(subprocess.check_output(["docker", "image", "inspect", tag], text=True))[0]
                images[name] = {"image_id": inspected["Id"], "repo_digests": inspected.get("RepoDigests", [])}
            save(args.output / "metadata.json", {"started_ms": now_ms(), "reference_obi_revision": OBI_REVISION,
                 "checkout_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=HERE, text=True).strip(),
                 "operator_declared_obi_build_revision": os.environ.get("OBI_BUILD_REVISION"),
                 "obi_revision_note": "Reference revision describes the default previously validated image. Image ID/tag does not prove a build revision; a custom image's build revision is unknown unless independently recorded by its operator.",
                 "images": images, "configured_images": {name: config["services"][name]["image"] for name in images},
                 "kernel": os.uname().release, "compose": subprocess.check_output(["docker", "compose", "version", "--short"], text=True).strip(),
                 "docker": subprocess.check_output(["docker", "version", "--format", "{{.Client.Version}} / {{.Server.Version}}"], text=True).strip(),
                 "python": sys.version, "fixture_sha256": hashlib.sha256((HERE / "app" / "main.go").read_bytes()).hexdigest(),
                 "background_containers": subprocess.check_output(["docker", "ps", "--format", "{{.Names}}"], text=True).splitlines(),
                 "profile_type": PROFILE, "sampling_rate_hz": 97, "fixture_ground_truth": "scenario selection and source are operator ground truth, not diagnostic evidence"})
            compose("stop", "obi", "profiler")
            compose("up", "-d", "--no-deps", "lgtm")
            results = []
            for case in args.cases:
                compose("stop", "obi", "profiler", scenario=case)
                compose("up", "-d", "--no-deps", "--force-recreate", "app", scenario=case)
                wait_ready()
                for mode in args.modes:
                    out = args.output / (case + "-" + mode)
                    out.mkdir()
                    compose("stop", "obi", "profiler", scenario=case)
                    before = identity()
                    baseline = traffic(2)
                    services = ["obi", "profiler"] if mode == "combined" else [mode]
                    attached = now_ms()
                    compose("up", "-d", "--no-deps", "--no-build", "--pull", "never", *services, scenario=case, correlation=mode == "combined")
                    if before["pid_mode"]:
                        raise RuntimeError("application must use ordinary container PID namespace")
                    warmup = traffic(6)
                    start = now_ms()
                    rows = traffic(args.pairs)
                    end = now_ms()
                    save(out / "traffic.json", {"before_attachment": baseline, "during_attachment": warmup, "after_attachment": rows})
                    app_logs = compose("logs", "--no-color", "--no-log-prefix", "app", scenario=case)
                    truth = []
                    for line in app_logs.splitlines():
                        try:
                            event = json.loads(line)
                            when = datetime.datetime.fromisoformat(event["time"].replace("Z", "+00:00")).timestamp() * 1000
                            if start <= when <= end:
                                truth.append(event)
                        except (ValueError, KeyError, TypeError):
                            pass
                    save(out / "fixture-ground-truth.json", {"excluded_from_diagnostic_evidence": True, "events": truth})
                    after = identity()
                    continuity = {"before": before, "after": after, "unchanged": before == after, "attachment_ms": attached,
                                  "before_traffic": traffic_summary(baseline), "after_traffic": traffic_summary(rows),
                                  "attachment_traffic": traffic_summary(warmup),
                                  "note": "Small observation, not an overhead benchmark. Scenario changes recreate app between experiments; attachment does not."}
                    save(out / "continuity.json", continuity)
                    save(out / "window.json", {"start_ms": start, "end_ms": end, "mode": mode,
                                               "started_services": services, "obi_process_ctx": mode == "combined"})
                    time.sleep(12)
                    deadline = time.monotonic() + 108
                    attempt = 0
                    expected_traces = sum(row.get("status") == 200 for row in rows)
                    while True:
                        summary = collect(out, start, end, mode, deadline=deadline)
                        trace_count = len(summary["trace_search"].get("traces", []))
                        expected = ((mode == "profiler" or trace_count > 0)
                                    and (mode == "obi" or summary["aggregate"].get("total_ns", 0) > 0)
                                    and (mode != "combined" or summary["available_unique_exemplars"] > 0))
                        if expected or time.monotonic() >= deadline:
                            break
                        shutil.copytree(out / "raw", out / "collection-attempts" / str(attempt) / "raw")
                        save(out / "collection-attempts" / str(attempt) / "summary.json", summary)
                        attempt += 1
                        time.sleep(min(5, max(0, deadline - time.monotonic())))
                    summary = retain_best_partial(out)
                    trace_count = len(summary["trace_search"].get("traces", []))
                    save(out / "collection.json", {"attempts": attempt + 1, "expected_data_available": bool(expected),
                                                   "expected_http_completions": expected_traces, "trace_search_count": trace_count,
                                                   "trace_count_matches_completions": trace_count >= expected_traces if mode != "profiler" else None,
                                                   "retry_limit_seconds": 120, "note": "Only the fixed saved interval was queried; later traffic cannot supply an answer."})
                    results.append({"scenario_ground_truth": case, "mode": mode, "continuity": continuity,
                                    "cpu_ns": summary["aggregate"].get("total_ns"), "trace_count": len(summary["trace_search"].get("traces", [])),
                                    "linked_exemplars": summary["available_unique_exemplars"], "causal_state": summary["causal_state"]})
                    save(out / "agent-logs.json", {"logs": compose("logs", "--no-color", "obi", "profiler", scenario=case)})
                    print(json.dumps(results[-1]), flush=True)
                    if not continuity["unchanged"]:
                        raise RuntimeError("application changed during diagnostic attachment")
            save(args.output / "results.json", results)
            save(args.output / "completed.json", {"completed_ms": now_ms(), "phases": len(results)})
        except BaseException as exc:
            save(args.output / "failure.json", {"time_ms": now_ms(), "error": str(exc), "exception_type": type(exc).__name__})
            raise
        finally:
            compose("stop", "obi", "profiler")
            if args.cleanup:
                compose("down")


def replay(args):
    out = args.output
    summary = json.loads((out / "summary.json").read_text())
    raw = json.loads((out / "raw" / "aggregate.json").read_text())
    if "collection_error" not in raw:
        assert flame_summary(raw) == summary["aggregate"], "aggregate replay mismatch"
    for item in summary["exemplars"]:
        raw = json.loads((out / "raw" / ("trace-" + item["trace_id"] + ".json")).read_text())
        found = any(normalize_id(span.get("spanId", span.get("spanID", "")), 8) == item["span_id"]
                    and normalize_id(span.get("traceId", span.get("traceID", "")), 16) == item["trace_id"] for span in trace_spans(raw))
        assert found == item["exact_span_found"], "exact span verification replay mismatch"
        raw_profile = json.loads((out / "raw" / ("span-" + item["span_id"] + ".json")).read_text())
        if "collection_error" not in raw_profile:
            assert flame_summary(raw_profile) == item["cpu"], "span accounting replay mismatch"
    print(json.dumps({"replayed": str(out), "exemplars": len(summary["exemplars"]), "causal_state": summary["causal_state"]}))


def verify_fixture(args):
    events = json.loads((args.output / "fixture-ground-truth.json").read_text())["events"]
    def event_time(event):
        return datetime.datetime.fromisoformat(event["time"].replace("Z", "+00:00")).timestamp()
    reports = {}
    work = {}
    for event in events:
        target = reports if event["path"] == "/report" else work
        target.setdefault(event["request"], {})[event["event"]] = event
    shared = independent = 0
    waits = []
    for row in work.values():
        waiting = row.get("waiting")
        resumed = row.get("acquired", row.get("resumed"))
        if not waiting or not resumed:
            continue
        waits.append((event_time(resumed) - event_time(waiting)) * 1000)
        resource = waiting.get("resource")
        if resource is None:
            independent += 1
            continue
        for report in reports.values():
            acquired, releasing = report.get("acquired"), report.get("releasing")
            if acquired and releasing and acquired.get("resource") == resource and resumed.get("resource") == resource:
                if event_time(acquired) <= event_time(waiting) < event_time(releasing) <= event_time(resumed):
                    shared += 1
                    break
    result = {"excluded_from_diagnostic_evidence": True, "work_waits": len(waits),
              "waits_during_report_holding_same_resource": shared, "independent_waits": independent,
              "median_wait_ms": statistics.median(waits) if waits else None,
              "note": "Application ground truth only. No application request sequence was associated with an OTel span by timing."}
    save(args.output / "fixture-check.json", result)
    print(json.dumps(result))


def browser_links(args):
    links = []
    for case in CASES:
        source = args.output / (case + "-combined") / "summary.json"
        if not source.exists():
            continue
        summary = json.loads(source.read_text())
        candidates = [item for item in summary["exemplars"] if item["exact_span_found"]
                      and any(function["name"] == "main.prepareReport" and function["self_ns"] > 0
                              for function in item["cpu"].get("functions", []))]
        if not candidates:
            continue
        item = candidates[0]
        links.extend([{"name": case + "-profile", "url": item["profile_url"], "expected_text": SERVICE,
                       "trace_id": item["trace_id"], "span_id": item["span_id"]},
                      {"name": case + "-trace", "url": item["trace_url"], "expected_text": "GET /report",
                       "trace_id": item["trace_id"], "span_id": item["span_id"]}])
    if not links:
        raise RuntimeError("no verified report exemplars available for browser evidence")
    save(args.output / "browser-links.json", links)
    print(json.dumps({"links": len(links), "file": str(args.output / "browser-links.json")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    execute = commands.add_parser("run")
    execute.add_argument("--output", type=Path, required=True)
    execute.add_argument("--pairs", type=int, default=10)
    execute.add_argument("--modes", nargs="+", choices=MODES, default=list(MODES))
    execute.add_argument("--cases", nargs="+", choices=CASES, default=list(CASES))
    execute.add_argument("--build", action="store_true")
    execute.add_argument("--cleanup", action="store_true", help="Remove only this project's containers; preserve backend volume")
    saved = commands.add_parser("replay")
    saved.add_argument("--output", type=Path, required=True, help="One saved case-mode directory")
    recover = commands.add_parser("recover-partial")
    recover.add_argument("--output", type=Path, required=True, help="Retain the best saved partial response after an expired retry")
    fixture = commands.add_parser("verify-fixture")
    fixture.add_argument("--output", type=Path, required=True, help="Verify operator ground truth separately from diagnostic evidence")
    browser = commands.add_parser("browser-links")
    browser.add_argument("--output", type=Path, required=True, help="Generate browser links from verified combined phase exemplars")
    query = commands.add_parser("collect")
    query.add_argument("--output", type=Path, required=True)
    query.add_argument("--start-ms", type=int, required=True)
    query.add_argument("--end-ms", type=int, required=True)
    query.add_argument("--mode", choices=MODES, required=True)
    args = parser.parse_args()
    if args.command == "run":
        if args.pairs < 2 or args.pairs > 60:
            parser.error("pairs must be between 2 and 60")
        run(args)
    elif args.command == "replay":
        replay(args)
    elif args.command == "recover-partial":
        result = retain_best_partial(args.output)
        collection = json.loads((args.output / "collection.json").read_text())
        collection["trace_search_count"] = len(result["trace_search"].get("traces", []))
        collection["partial_selection"] = result.get("partial_selection")
        save(args.output / "collection.json", collection)
        replay(args)
    elif args.command == "verify-fixture":
        verify_fixture(args)
    elif args.command == "browser-links":
        browser_links(args)
    else:
        if args.end_ms <= args.start_ms or args.end_ms - args.start_ms > 900_000:
            parser.error("query interval must be positive and no longer than fifteen minutes")
        args.output.mkdir(parents=True, exist_ok=False)
        collect(args.output, args.start_ms, args.end_ms, args.mode)


if __name__ == "__main__":
    main()
