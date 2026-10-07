#!/usr/bin/env python3
"""Run a two-turn Codex investigation using only MCP telemetry tools."""
import argparse
import atexit
import concurrent.futures
import datetime
import json
import hashlib
import os
from pathlib import Path
import statistics
import secrets
import socket
import subprocess
import threading
import tempfile
import time
import tomllib
import urllib.request
import uuid

EXAMPLE = Path(__file__).resolve().parents[1]
PROJECT = "obi-ai-investigation"


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def compose(*args, scenario="cpu"):
    return subprocess.run(["docker", "compose", "-p", PROJECT, "--project-directory", str(EXAMPLE),
        "-f", str(EXAMPLE / "docker-compose.yml"), "-f", str(EXAMPLE / "docker-compose.ai.yml"), *args],
        env=dict(os.environ, DEMO_SCENARIO=scenario), check=True, capture_output=True, text=True).stdout


def identity():
    return json.loads(subprocess.check_output(["docker", "inspect", PROJECT + "-app-1", "--format",
        '{"id":{{json .Id}},"pid":{{.State.Pid}},"started_at":{{json .State.StartedAt}},"pid_mode":{{json .HostConfig.PidMode}}}'], text=True))


def traffic(stop, path, output, lock):
    while not stop.is_set():
        start = time.monotonic()
        row = {"start": now(), "path": path}
        try:
            with urllib.request.urlopen("http://localhost:8081" + path, timeout=15) as response:
                response.read()
                row["status"] = response.status
        except OSError as exc:
            row["error"] = str(exc)
        row.update(end=now(), latency_seconds=time.monotonic() - start)
        with lock, output.open("a") as stream:
            stream.write(json.dumps(row) + "\n")
        stop.wait(0.2)


def configuration(out, grafana, port, token):
    servers = {
        "incident": {"url": f"http://127.0.0.1:{port}/mcp", "http_headers": {"Authorization": "Bearer " + token},
            "default_tools_approval_mode": "approve", "tool_timeout_sec": 60,
            "enabled_tools": ["diagnostic_status", "attach_diagnostics", "span_exemplars", "span_profile"]},
        "grafana": {"command": str(grafana), "args": ["-t", "stdio", "--enabled-tools", "datasource,pyroscope,tempo,navigation",
            "--disable-write", "--usage-stats", "disabled"], "tool_timeout_sec": 30,
            "enabled_tools": ["list_datasources", "get_datasource_by_uid", "list_pyroscope_profile_types",
                "list_pyroscope_label_names", "list_pyroscope_label_values", "query_pyroscope", "search_tempo_traces",
                "get_tempo_trace", "get_tempo_traceql_docs", "generate_deeplink"],
            "env": {"GRAFANA_URL": "http://localhost:3001"}},
    }
    lines = []
    for name, config in servers.items():
        lines.append(f"[mcp_servers.{name}]")
        lines += [f"{key} = {json.dumps(value)}" for key, value in config.items() if not isinstance(value, dict)]
        for key, value in config.items():
            if isinstance(value, dict):
                lines.append(f"[mcp_servers.{name}.{key}]")
                lines += [f"{subkey} = {json.dumps(subvalue)}" for subkey, subvalue in value.items()]
    (out / "mcp.config.toml").write_text("\n".join(lines) + "\n")
    (out / "mcp.config.toml").chmod(0o600)
    return servers


def invoke(out, servers, model, prompt, phase, session=None):
    command = ["codex", "-m", model, "--disable", "shell_tool", "--disable", "apps",
               "-c", 'web_search="disabled"', "-c", "features.multi_agent=false"]
    for name, config in servers.items():
        for key, value in config.items():
            if isinstance(value, dict):
                for subkey, subvalue in value.items():
                    command += ["-c", f"mcp_servers.{name}.{key}.{subkey}={json.dumps(subvalue)}"]
            else:
                command += ["-c", f"mcp_servers.{name}.{key}={json.dumps(value)}"]
    command += ["exec", "--ignore-user-config"]
    if session:
        command += ["resume", session, "--skip-git-repo-check", "--ignore-user-config"]
    else:
        command += ["--skip-git-repo-check", "--sandbox", "read-only", "--cd", str((out / "workspace").resolve())]
    command += ["--json", "--output-last-message", str(out / f"{phase}.md"), "-"]
    with (out / f"{phase}.jsonl").open("w") as log, (out / f"{phase}.stderr").open("w") as errors:
        try:
            result = subprocess.run(command, input=prompt, text=True, stdout=log, stderr=errors,
                cwd=(out / "workspace").resolve(), check=False, timeout=600)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Codex timed out; see {phase}.jsonl") from None
        if result.returncode != 0:
            raise RuntimeError(f"Codex failed; see {phase}.stderr")
    for event in read_lines(out / f"{phase}.jsonl"):
        if event.get("type") == "thread.started":
            session = event["thread_id"]
    if not session:
        raise RuntimeError("Codex did not return an investigation session")
    return session


def read_lines(path):
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def summarize(out, before, started):
    rows, audit = read_lines(out / "traffic.jsonl"), read_lines(out / "tools.jsonl")
    attached = next((x["time"] for x in audit if x["event"] == "attachment_completed"), None)
    after = identity()
    result = {"application_before": before, "application_after": after, "application_unchanged": before == after,
        "attachment_time": attached, "elapsed_seconds": time.time() - started}
    for label, samples in [("before_attachment", [x for x in rows if attached and x["end"] < attached]),
                           ("after_attachment", [x for x in rows if attached and x["start"] > attached])]:
        result[label] = {}
        for route in ["/work", "/report"]:
            selected = [x for x in samples if x["path"] == route]
            latency = [x["latency_seconds"] for x in selected]
            result[label][route] = {"completed": sum(x.get("status") == 200 for x in selected),
                "errors": sum("error" in x or x.get("status", 200) != 200 for x in selected),
                "median_seconds": statistics.median(latency) if latency else None,
                "max_seconds": max(latency) if latency else None}
    violations = [x["item"] for phase in ["initial", "investigation"] for x in read_lines(out / f"{phase}.jsonl")
        if x.get("item", {}).get("type") in {"command_execution", "file_change", "web_search"}]
    result["non_telemetry_tool_violations"] = violations
    result["valid_run"] = not violations and result["application_unchanged"] and attached is not None
    (out / "continuity.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=["cpu", "waiting"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--incident-binary", type=Path, required=True)
    parser.add_argument("--grafana-binary", type=Path, required=True)
    parser.add_argument("--approve-attachment", action="store_true", help="Operator authorization to start this run's diagnostic agents after the assistant requests them")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / "workspace").symlink_to(Path(tempfile.mkdtemp(prefix="obi-investigation-")), target_is_directory=True)
    home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    model = tomllib.loads((home / "config.toml").read_text())["model"]
    run_id = uuid.uuid4().hex
    token = secrets.token_hex(32)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    server_log = (out / "incident-server.stderr").open("w")
    server = subprocess.Popen([str(args.incident_binary.resolve()), "--listen", f"127.0.0.1:{port}",
        "--example-dir", str(EXAMPLE), "--run-id", run_id, "--approval-file", str(out / "approval"),
        "--audit-file", str(out / "tools.jsonl")], env=dict(os.environ, INCIDENT_MCP_TOKEN=token), stderr=server_log)
    def close_server():
        server.terminate()
        server.wait(timeout=10)
        server_log.close()
    atexit.register(close_server)
    servers = configuration(out, args.grafana_binary.resolve(), port, token)
    compose("stop", "obi", "profiler", scenario=args.scenario)
    compose("up", "-d", "--no-deps", "--force-recreate", "app", scenario=args.scenario)
    before = identity()
    if before["pid_mode"]:
        raise RuntimeError("AI fixture must use its ordinary PID namespace")
    started, incident_start = time.time(), now()
    images = json.loads(compose("--profile", "diagnostics", "config", "--format", "json", scenario=args.scenario))["services"]
    image_records = {}
    for name in ["obi", "profiler", "lgtm"]:
        tag = images[name]["image"]
        image_records[name] = {"configured_image": tag, "identity": json.loads(subprocess.check_output(
            ["docker", "image", "inspect", tag, "--format", '{"id":{{json .Id}},"digests":{{json .RepoDigests}}}'], text=True))}
    (out / "metadata.json").write_text(json.dumps({"run_id": run_id, "started": incident_start, "model": model,
        "client": subprocess.check_output(["codex", "--version"], text=True).strip(),
        "obi_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=EXAMPLE, text=True).strip(),
        "operator_authorized_attachment": args.approve_attachment, "images": image_records,
        "kernel": os.uname().release,
        "docker": subprocess.check_output(["docker", "version", "--format", "{{.Client.Version}} / {{.Server.Version}}"], text=True).strip(),
        "compose": subprocess.check_output(["docker", "compose", "version", "--short"], text=True).strip(), "grafana_mcp_version": subprocess.check_output([str(args.grafana_binary.resolve()), "--version"], text=True).strip(),
        "grafana_mcp_sha256": hashlib.sha256(args.grafana_binary.read_bytes()).hexdigest(),
        "incident_mcp_sha256": hashlib.sha256(args.incident_binary.read_bytes()).hexdigest()}, indent=2))
    stop, lock = threading.Event(), threading.Lock()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        workers = [pool.submit(traffic, stop, route, out / "traffic.jsonl", lock) for route in ["/work", "/report"]]
        try:
            time.sleep(12)
            prompt = f'''Investigate elevated latency for GET /work in service obi-ai-demo, incident starting {incident_start}.
Use only the provided MCP telemetry and diagnostic tools. Do not access files, source code, shell, web search, or fixture settings. You have no ground-truth answer.
First inspect evidence and agent state. If diagnostic collection is missing, request attachment through attach_diagnostics; if approval is required, stop and ask the operator. You are not authorized until the operator grants it.
After authorized attachment, allow discovery/export time and query fresh evidence. Bound telemetry retries to two minutes after attachment. Use diagnostic_status.current_time to set absolute query windows; cap the end at collection_deadline. Reject traces outside the collection window even if search returns them. After attachment, set query start to the returned collection_start or later, excluding all earlier retained data. All profile queries must use service_name=obi-ai-demo and this incident's interval. Datasource UIDs are pyroscope and tempo. Use recorded exemplar IDs to connect samples to traces, and query exact span profiles when assessing /work. Other concurrent requests may exist.
Your final response must separate observed facts, a supported hypothesis, remaining uncertainty and next evidence needed. Include clickable profile and trace evidence using the exact URLs returned by tools. For Tempo Explore link generation use queryType=traceql with the actual trace ID as query. Ensure browser links use the Grafana origin reported by diagnostic_status, correcting backend-default origins if necessary. CPU samples measure execution, not waiting. Missing samples are not a diagnosis. Do not modify the application or apply mitigation.'''
            (out / "prompt.txt").write_text(prompt)
            session = invoke(out, servers, model, prompt, "initial")
            if not any(x["event"] == "attachment_requested" for x in read_lines(out / "tools.jsonl")):
                raise RuntimeError("Assistant did not request attachment; preserve result as unsuccessful")
            if not args.approve_attachment:
                print("Operator approval required. No agents started.")
                return
            with (out / "tools.jsonl").open("a") as stream:
                stream.write(json.dumps({"time": now(), "event": "operator_approval", "run_id": run_id,
                    "scope": "Start this experiment's OBI and profiler only"}) + "\n")
            (out / "approval").write_text(run_id)
            (out / "approval").chmod(0o600)
            invoke(out, servers, model, "The operator has now explicitly authorized attaching OBI and the profiler for this incident. Invoke attach_diagnostics and continue the evidence-backed investigation. Application modification is not authorized.", "investigation", session)
        finally:
            stop.set()
            for worker in workers:
                worker.result()
            summarize(out, before, started)
            close_server()
            atexit.unregister(close_server)


if __name__ == "__main__":
    main()
