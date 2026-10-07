#!/usr/bin/env python3
"""Collect three isolated diagnostic modes; preserve real responses and exact links."""
import argparse
import base64
import concurrent.futures
import datetime
import fcntl
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import threading
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
PROJECT = "obi-poc-waiting"
GRAFANA = "http://localhost:3102"
SERVICE = "obi-poc-waiting"


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def compose(*args):
    return subprocess.check_output(["docker", "compose", "-p", PROJECT, "-f", str(ROOT / "compose.yaml"), *args], text=True)


def identity():
    return json.loads(subprocess.check_output(["docker", "inspect", PROJECT + "-app-1", "--format",
        '{"id":{{json .Id}},"pid":{{.State.Pid}},"started_at":{{json .State.StartedAt}},"pid_mode":{{json .HostConfig.PidMode}}}'], text=True))


def image_metadata():
    config = json.loads(compose("config", "--format", "json"))
    result = {}
    for service in ("app", "obi", "profiler", "lgtm"):
        image = config["services"][service]["image"]
        inspected = subprocess.run(["docker", "image", "inspect", image, "--format",
            '{"id":{{json .Id}},"digests":{{json .RepoDigests}},"labels":{{json .Config.Labels}}}'], capture_output=True, text=True)
        result[service] = {"configured_image": image, "inspection": json.loads(inspected.stdout) if inspected.returncode == 0 else None,
            "state": "available" if inspected.returncode == 0 else "not_present_yet"}
    return result


def request(path, body=None):
    payload = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(GRAFANA + path, payload,
        {"Content-Type": "application/json", "Connect-Protocol-Version": "1", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=25) as response:
        return json.load(response)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def normalized(value, size, short_hex=False):
    if short_hex and 0 < len(value) <= size * 2 and all(character in "0123456789abcdefABCDEF" for character in value):
        value = value.zfill(size * 2)
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raw = base64.b64decode(value, validate=True)
    if len(raw) != size or not any(raw):
        raise ValueError("invalid telemetry ID")
    return raw.hex()


def spans(data):
    found = []
    if isinstance(data, dict):
        if "spanId" in data and "name" in data:
            found.append(data)
        for value in data.values():
            found.extend(spans(value))
    elif isinstance(data, list):
        for value in data:
            found.extend(spans(value))
    return found


def accounting(graph):
    functions = {}
    total = int(graph.get("total", 0))
    self_sum = 0
    for level in graph.get("levels", []):
        values = level["values"]
        if len(values) % 4:
            raise ValueError("invalid flamegraph level")
        for index in range(0, len(values), 4):
            _, cumulative, own, name_index = map(int, values[index:index + 4])
            if own < 0 or cumulative < own:
                raise ValueError("invalid profile accounting")
            name = graph["names"][name_index]
            entry = functions.setdefault(name, {"function": name, "self_ns": 0, "cumulative_ns": 0})
            entry["self_ns"] += own
            entry["cumulative_ns"] += cumulative
            self_sum += own
    if self_sum != total:
        raise ValueError(f"self sum {self_sum} differs from total {total}")
    return {"unit": "nanoseconds", "total_ns": total, "self_sum_ns": self_sum,
        "functions": sorted(functions.values(), key=lambda row: (-row["cumulative_ns"], row["function"]))}


def profile_link(profile_type, start, end, span=None):
    params = {"var-serviceName": SERVICE, "var-dataSource": "pyroscope", "var-profileMetricId": profile_type,
        "explorationType": "flame-graph", "from": str(start), "to": str(end), "showSpanHeatmap": "true"}
    if span:
        params["var-spanSelector"] = span
    return GRAFANA + "/a/grafana-pyroscope-app/explore?" + urllib.parse.urlencode(params)


def trace_link(trace_id, start, end):
    panes = {"trace": {"datasource": "tempo", "queries": [{"refId": "A", "queryType": "traceql", "query": trace_id}],
        "range": {"from": str(start), "to": str(end)}}}
    return GRAFANA + "/explore?" + urllib.parse.urlencode({"schemaVersion": "1", "orgId": "1", "panes": json.dumps(panes)})


def query_window(folder, start, end):
    pyroscope = "/api/datasources/proxy/uid/pyroscope/querier.v1.QuerierService/"
    selector = '{service_name="' + SERVICE + '"}'
    types_response = request(pyroscope + "ProfileTypes", {"start": start, "end": end})
    save(folder / "profile-types.json", types_response)
    profile_types = [entry["ID"] if "ID" in entry else entry["id"] for entry in types_response.get("profileTypes", [])]
    query = urllib.parse.urlencode({"q": '{ resource.service.name = "' + SERVICE + '" }', "start": start // 1000,
        "end": end // 1000, "limit": 100})
    search = request("/api/datasources/proxy/uid/tempo/api/search?" + query)
    save(folder / "trace-search.json", search)
    summary = {"start_ms": start, "end_ms": end, "profile_types": profile_types, "profiles": [], "traces": [],
        "trace_search_limit": 100, "trace_retrieval_limit": 30, "trace_search_returned": len(search.get("traces", [])),
        "trace_retrieval_truncated": len(search.get("traces", [])) > 30,
        "note": "Heatmap exemplars and trace search are bounded selections; no exact links is missing evidence, not proof of no wait."}
    trace_cache = {}
    for entry in search.get("traces", [])[:30]:
        trace_id = normalized(entry["traceID"], 16, short_hex=True)
        trace = request("/api/datasources/proxy/uid/tempo/api/traces/" + trace_id)
        save(folder / ("trace-" + trace_id + ".json"), trace)
        trace_cache[trace_id] = trace
        summary["traces"].append({"trace_id": trace_id, "trace_url": trace_link(trace_id, start, end), "spans": spans(trace)})
    for profile_type in profile_types:
        if not ("cpu" in profile_type or "off" in profile_type) or profile_type.split(":")[2] != "nanoseconds":
            continue
        body = {"profileTypeID": profile_type, "labelSelector": selector, "start": start, "end": end,
            "format": "PROFILE_FORMAT_FLAMEGRAPH"}
        aggregate = request(pyroscope + "SelectMergeStacktraces", body)
        stem = profile_type.replace(":", "-")
        save(folder / (stem + "-aggregate.json"), aggregate)
        record = {"profile_type": profile_type, "aggregate": accounting(aggregate.get("flamegraph", {})),
            "profile_url": profile_link(profile_type, start, end), "links": []}
        heatmap = request(pyroscope + "SelectHeatmap", {"profileTypeID": profile_type, "labelSelector": selector,
            "start": start, "end": end, "step": 5, "queryType": "HEATMAP_QUERY_TYPE_SPAN", "exemplarType": "EXEMPLAR_TYPE_SPAN"})
        save(folder / (stem + "-heatmap.json"), heatmap)
        seen = set()
        for series in heatmap.get("series", []):
            for slot in series.get("slots", []):
                for exemplar in slot.get("exemplars", []):
                    try:
                        span_id = normalized(exemplar.get("spanId", ""), 8)
                        trace_id = normalized(exemplar.get("traceId", ""), 16)
                    except (ValueError, TypeError):
                        continue
                    if span_id in seen:
                        continue
                    seen.add(span_id)
                    if trace_id not in trace_cache:
                        trace_cache[trace_id] = request("/api/datasources/proxy/uid/tempo/api/traces/" + trace_id)
                        save(folder / ("trace-" + trace_id + ".json"), trace_cache[trace_id])
                    matches = [span for span in spans(trace_cache[trace_id]) if normalized(span["spanId"], 8) == span_id]
                    selected = request(pyroscope + "SelectMergeStacktraces", dict(body, spanSelector=[span_id]))
                    save(folder / (stem + "-span-" + span_id + ".json"), selected)
                    selected_accounting = accounting(selected.get("flamegraph", {}))
                    verified = len(matches) == 1 and selected_accounting["total_ns"] > 0
                    match = matches[0] if len(matches) == 1 else {}
                    parent_id = normalized(match["parentSpanId"], 8) if match.get("parentSpanId") else None
                    parent = next((span for span in spans(trace_cache[trace_id]) if parent_id and normalized(span["spanId"], 8) == parent_id), {})
                    duration = int(match["endTimeUnixNano"]) - int(match["startTimeUnixNano"]) if match else None
                    record["links"].append({"span_id": span_id, "trace_id": trace_id, "exemplar": exemplar,
                        "route_parent": parent.get("name"), "span_duration_ns": duration,
                        "offcpu_exceeds_wall": profile_type.startswith("off_cpu:") and duration is not None and selected_accounting["total_ns"] > duration,
                        "state": "verified_exact_span" if verified else "unverified_or_missing_selected_samples",
                        "exact_span_matches": matches, "profile": accounting(selected.get("flamegraph", {})),
                        "profile_url": profile_link(profile_type, start, end, span_id), "trace_url": trace_link(trace_id, start, end)})
        record["state"] = "exact_links" if any(link["state"] == "verified_exact_span" for link in record["links"]) else "unverified_exemplars" if record["links"] else "no_exemplars"
        summary["profiles"].append(record)
    save(folder / "summary.json", summary)
    return summary


def traffic(stop, path, output, lock):
    while not stop.is_set():
        started = time.monotonic()
        row = {"start": now(), "path": path}
        try:
            with urllib.request.urlopen("http://localhost:8182" + path, timeout=10) as response:
                response.read()
                row["status"] = response.status
        except OSError as exc:
            row["error"] = str(exc)
        row.update(end=now(), latency_seconds=time.monotonic() - started)
        with lock, output.open("a") as stream:
            stream.write(json.dumps(row) + "\n")


def traffic_summary(out):
    rows = [json.loads(line) for line in (out / "traffic.jsonl").read_text().splitlines()]
    result = {}
    windows = [(mode.name, json.loads((mode / "window.json").read_text()))
        for mode in out.iterdir() if mode.is_dir() and (mode / "window.json").exists()]
    first_attach = min(datetime.datetime.fromisoformat(window["attached_at"]).timestamp() * 1000 for _, window in windows)
    windows.append(("before_first_attachment", {"start_ms": 0, "end_ms": first_attach}))
    for name, window in windows:
        selected = [row for row in rows if datetime.datetime.fromisoformat(row["start"]).timestamp() * 1000 >= window["start_ms"]
            and datetime.datetime.fromisoformat(row["end"]).timestamp() * 1000 <= window["end_ms"]]
        result[name] = {}
        for path in ("/syscall", "/runtime", "/downstream"):
            samples = [row for row in selected if row["path"] == path]
            times = sorted(row["latency_seconds"] for row in samples if row.get("status") == 200)
            result[name][path] = {"completed": len(times), "errors": len(samples) - len(times),
                "latency_unit": "seconds", "median": statistics.median(times) if times else None,
                "p95": times[min(len(times) - 1, int(len(times) * .95))] if times else None}
    save(out / "traffic-summary.json", result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--keep", action="store_true", help="Keep this project's containers for browser viewing")
    args = parser.parse_args()
    if not 30 <= args.seconds <= 300:
        parser.error("--seconds must be 30 to 300")
    out = args.output or ROOT / "evidence" / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out.mkdir(parents=True, exist_ok=False)
    with open("/tmp/obi-diagnostic-poc-live.lock", "a") as live_lock:
        print("Waiting for the host diagnostic lock", flush=True)
        fcntl.flock(live_lock, fcntl.LOCK_EX)
        stop, output_lock = threading.Event(), threading.Lock()
        pool = None
        try:
            compose("config")
            compose("build", "app")
            compose("up", "-d", "--no-deps", "app", "lgtm")
            for _ in range(90):
                try:
                    request("/api/health")
                    urllib.request.urlopen("http://localhost:8182/ready", timeout=2).close()
                    break
                except OSError:
                    time.sleep(1)
            else:
                raise RuntimeError("backend or fixture did not become ready")
            before = identity()
            if before["pid_mode"]:
                raise RuntimeError("fixture must use its ordinary container PID namespace")
            images = subprocess.check_output(["docker", "compose", "-p", PROJECT, "-f", str(ROOT / "compose.yaml"), "images", "--format", "json"], text=True)
            save(out / "metadata.json", {"created_at": now(), "platform": platform.platform(), "checkout_revision":
                subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "application_before": before,
                "reference_obi_revision": "6d873d705d77e9764adab67502d65695df986e93", "configured_images": image_metadata(),
                "images": images, "docker_version": subprocess.check_output(["docker", "version", "--format", "{{json .}}"], text=True),
                "other_containers": subprocess.check_output(["docker", "ps", "--format", "{{.Names}}"], text=True)})
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=6)
            futures = [pool.submit(traffic, stop, path, out / "traffic.jsonl", output_lock)
                for path in ("/syscall", "/runtime", "/downstream") for _ in range(2)]
            time.sleep(5)
            for mode in ("obi-only", "profiler-only", "combined"):
                print("Collecting " + mode, flush=True)
                compose("stop", "obi", "profiler")
                services = ["obi"] if mode == "obi-only" else ["profiler"] if mode == "profiler-only" else ["obi", "profiler"]
                os.environ["OBI_PROCESS_CTX"] = "false" if mode == "profiler-only" else "true"
                attached_at = now()
                compose("up", "-d", "--no-deps", "--no-build", "--pull", "never", *services)
                time.sleep(12)
                start = int(time.time() * 1000)
                time.sleep(args.seconds)
                end = int(time.time() * 1000)
                folder = out / mode
                folder.mkdir()
                save(folder / "window.json", {"attached_at": attached_at, "start_ms": start, "end_ms": end,
                    "application": identity(), "application_unchanged": identity() == before})
                time.sleep(20)
                try:
                    query_window(folder, start, end)
                except Exception as exc:
                    save(folder / "query-error.json", {"error": str(exc), "time": now()})
                    print("Query incomplete: " + str(exc), flush=True)
                (folder / "agent-logs.txt").write_text(compose("logs", "--no-color", "obi", "profiler"))
            save(out / "continuity.json", {"before": before, "after": identity(), "unchanged": before == identity()})
            save(out / "final-images.json", image_metadata())
            with output_lock:
                traffic_summary(out)
        finally:
            stop.set()
            if pool:
                pool.shutdown(wait=True)
            if not args.keep:
                compose("down")
        print("Evidence: " + str(out), flush=True)


if __name__ == "__main__":
    main()
