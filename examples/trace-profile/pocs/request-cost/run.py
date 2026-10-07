#!/usr/bin/env python3
"""Collect isolated modes, then compare request cohorts using exact recorded span IDs."""
import argparse
import base64
import concurrent.futures
import datetime
import fcntl
import json
import os
import re
import traceback
from pathlib import Path
import statistics
import subprocess
import threading
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
PROJECT = 'obi-poc-cost'
GRAFANA = 'http://localhost:3101'
PROFILE = 'process_cpu:cpu:nanoseconds:cpu:nanoseconds'
SERVICE = 'obi-poc-cost'
REVISION = '6d873d705d77e9764adab67502d65695df986e93'


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def compose(*args, correlation=True):
    return subprocess.check_output(['docker', 'compose', '-p', PROJECT, '-f', str(ROOT/'compose.yaml'), *args],
                                   env=dict(os.environ, OBI_PROCESS_CTX=str(correlation).lower()), text=True)


def request(path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(GRAFANA+path, data=data,
        headers={'Content-Type': 'application/json', 'Connect-Protocol-Version': '1'})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def identity():
    return json.loads(subprocess.check_output(['docker', 'inspect', PROJECT+'-app-1', '--format',
        '{"id":{{json .Id}},"pid":{{.State.Pid}},"started_at":{{json .State.StartedAt}},"pid_mode":{{json .HostConfig.PidMode}}}'], text=True))


def ready(url, seconds=120):
    deadline = time.monotonic()+seconds
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as res:
                if res.status == 200:
                    return
        except OSError:
            pass
        time.sleep(2)
    raise RuntimeError('Readiness deadline exceeded: '+url)


def traffic(stop, route, rows, mutex):
    while not stop.is_set():
        started = time.time()
        row = {'path': route, 'start_ms': int(started*1000)}
        try:
            with urllib.request.urlopen('http://localhost:8181'+route, timeout=15) as res:
                res.read()
                row['status'] = res.status
        except OSError as exc:
            row['error'] = str(exc)
        row.update(end_ms=int(time.time()*1000), latency_seconds=time.time()-started)
        with mutex:
            rows.append(row)
        stop.wait(0.15)


def traffic_summary(rows, start, end):
    result = {}
    for route in ['/work','/report']:
        selected = [r for r in rows if r['path']==route and r['start_ms'] >= start and r['end_ms'] <= end]
        latencies = sorted(r['latency_seconds'] for r in selected)
        result[route] = {'completed':sum(r.get('status')==200 for r in selected),
                         'errors':sum('error' in r or r.get('status',200)!=200 for r in selected),
                         'median_seconds':statistics.median(latencies) if latencies else None,
                         'p95_seconds':latencies[min(len(latencies)-1,int(len(latencies)*.95))] if latencies else None}
    return result


def normalize(value, size):
    try:
        if not re.fullmatch(r'[0-9a-fA-F]{1,'+str(size*2)+'}',value):
            raise ValueError('Not a width-compatible hex ID')
        raw = bytes.fromhex(value.zfill(size*2))
    except ValueError:
        raw = base64.b64decode(value, validate=True)
    if len(raw) != size or not any(raw):
        raise ValueError('Invalid or zero telemetry ID')
    return raw.hex()


def attributes(span):
    return {a['key']: next(iter(a.get('value', {}).values()), None) for a in span.get('attributes', [])}


def spans(trace):
    result = []
    for batch in trace.get('batches', trace.get('resourceSpans', [])):
        for scope in batch.get('scopeSpans', batch.get('instrumentationLibrarySpans', [])):
            result.extend(scope.get('spans', []))
    return result


def trace_link(trace_id, start, end):
    pane = {'trace': {'datasource': 'tempo', 'queries': [{'refId':'A', 'queryType':'traceql', 'query':trace_id}],
                     'range': {'from':str(start), 'to':str(end)}}}
    return GRAFANA+'/explore?schemaVersion=1&orgId=1&panes='+urllib.parse.quote(json.dumps(pane))


def profile_link(start, end, span_id=None):
    params = {'var-serviceName': SERVICE, 'var-dataSource':'pyroscope', 'var-profileMetricId':PROFILE,
              'explorationType':'flame-graph', 'from':str(start), 'to':str(end), 'showSpanHeatmap':'true'}
    if span_id:
        params['var-spanSelector'] = span_id
    return GRAFANA+'/a/grafana-pyroscope-app/explore?'+urllib.parse.urlencode(params)


def profile(start, end, ids=None):
    body = {'profileTypeID':PROFILE, 'labelSelector':'{service_name="'+SERVICE+'"}', 'start':start,
            'end':end, 'format':'PROFILE_FORMAT_FLAMEGRAPH'}
    if ids is not None:
        body['spanSelector'] = ids
    raw = request('/api/datasources/proxy/uid/pyroscope/querier.v1.QuerierService/SelectMergeStacktraces', body)
    return raw, summarize_profile(raw)


def summarize_profile(raw):
    graph = raw.get('flamegraph', {})
    values = {}
    total = int(graph.get('total', 0))
    for level in graph.get('levels', []):
        entries = level.get('values', [])
        if len(entries)%4:
            raise ValueError('Malformed flamegraph level')
        for i in range(0, len(entries), 4):
            _, cumulative, own, name = map(int, entries[i:i+4])
            if own < 0 or cumulative < own:
                raise ValueError('Invalid flamegraph values')
            function = graph['names'][name]
            item = values.setdefault(function, {'name':function, 'self_ns':0, 'cumulative_ns':0})
            item['self_ns'] += own
            item['cumulative_ns'] += cumulative
    if sum(v['self_ns'] for v in values.values()) != total:
        raise ValueError('Self CPU accounting differs from profile total')
    return {'unit':'nanoseconds', 'total_ns':total,
                 'functions':sorted(values.values(), key=lambda x:-x['self_ns'])}


def collect(out, mode, start, end):
    prefix = '/api/datasources/proxy/uid/tempo'
    query = urllib.parse.urlencode({'q':'{ resource.service.name = "'+SERVICE+'" }',
                                   'start':start//1000, 'end':end//1000, 'limit':1000})
    search = request(prefix+'/api/search?'+query)
    save(out/'trace-search.json', search)
    records = []
    trace_dir = out/'traces'
    trace_dir.mkdir(exist_ok=True)
    for hit in search.get('traces', []):
        tid = normalize(hit['traceID'],16)
        raw = request(prefix+'/api/traces/'+tid)
        save(trace_dir/(tid+'.json'), raw)
        all_spans = spans(raw)
        servers = [s for s in all_spans if s.get('name') == 'GET /work']
        for server in servers:
            first, last = int(server['startTimeUnixNano'])//1_000_000, int(server['endTimeUnixNano'])//1_000_000
            if first < start or last > end:
                continue
            sid = normalize(server['spanId'],8)
            processing = [s for s in all_spans if s.get('name') == 'processing'
                          and normalize(s.get('parentSpanId',''),8) == sid]
            if len(processing) != 1:
                continue
            linked = normalize(processing[0]['spanId'],8)
            records.append({'trace_id':tid, 'server_span_id':sid, 'processing_span_id':linked,
                            'duration_ms':last-first, 'cohort':'slow' if last-first >= 400 else 'ordinary',
                            'trace_url':trace_link(tid,start,end), 'profile_url':profile_link(start,end,linked)})
    save(out/'requests.json', records)
    aggregate_raw, aggregate = profile(start,end)
    save(out/'aggregate-profile.json', aggregate_raw)
    save(out/'aggregate-summary.json', aggregate)
    heatmap = request('/api/datasources/proxy/uid/pyroscope/querier.v1.QuerierService/SelectHeatmap',
        {'profileTypeID':PROFILE,'labelSelector':'{service_name="'+SERVICE+'"}', 'start':start,'end':end,
         'step':5,'queryType':'HEATMAP_QUERY_TYPE_SPAN','exemplarType':'EXEMPLAR_TYPE_SPAN'})
    save(out/'span-exemplars.json',heatmap)
    exact_links = []
    invalid_exemplars = 0
    for series in heatmap.get('series',[]):
        for slot in series.get('slots',[]):
            for item in slot.get('exemplars',[]):
                if not item.get('traceId'):
                    continue
                try:
                    sid,tid = normalize(item['spanId'],8),normalize(item['traceId'],16)
                except ValueError:
                    invalid_exemplars += 1
                    continue
                matched = next((r for r in records if r['trace_id']==tid and r['processing_span_id']==sid),None)
                if matched:
                    exact_links.append(dict(item, normalized_trace_id=tid, normalized_span_id=sid,
                                            trace_url=matched['trace_url'],profile_url=matched['profile_url']))
    save(out/'verified-exemplars.json',exact_links)
    cohorts = {}
    for name in ['ordinary','slow']:
        chosen = [r for r in records if r['cohort']==name]
        if not chosen:
            cohorts[name] = {'state':'no_traces','requests':0}
            continue
        # Span selectors are limited to 100. Report truncation and avoid pretending exhaustive coverage.
        selected = chosen[:100]
        raw, totals = profile(start,end,[r['processing_span_id'] for r in selected])
        save(out/(name+'-profile.json'),raw)
        sampled = 0
        per_request=[]
        for record in selected:
            single_raw,single = profile(start,end,[record['processing_span_id']])
            save(out/('span-'+record['processing_span_id']+'-profile.json'),single_raw)
            sampled += single['total_ns'] > 0
            per_request.append(dict(record,total_cpu_ns=single['total_ns']))
        if sum(r['total_cpu_ns'] for r in per_request) != totals['total_ns']:
            raise ValueError('Merged cohort profile differs from individual span totals')
        save(out/(name+'-requests.json'),per_request)
        totals.update(requests=len(selected),traces_available=len(chosen),truncated=len(chosen)>100,
                      requests_with_samples=sampled, mean_cpu_ns_per_request=totals['total_ns']/len(selected),
                      mean_wall_ms=statistics.mean(r['duration_ms'] for r in selected),
                      median_wall_ms=statistics.median(r['duration_ms'] for r in selected))
        for function in totals['functions']:
            function['self_ns_per_request'] = function['self_ns']/len(selected)
        cohorts[name]=totals
    summary = {'mode':mode,'trace_state': 'obi_not_running' if mode=='profiler-only' else ('traces' if records else 'no_target_traces'),
               'profile_state':'profiler_not_running' if mode=='obi-only' else ('samples' if aggregate['total_ns'] else 'no_samples'),
               'correlation_state':'disabled' if mode in ['profiler-only','no-correlation'] else ('exact_links' if exact_links else 'no_verified_exemplars'),
               'interval_ms':{'start':start,'end':end},'aggregate':aggregate,'cohorts':cohorts,
               'invalid_exemplar_ids':invalid_exemplars,'verified_work_exemplars':len(exact_links),'trace_search_limit':1000,
               'trace_search_truncated':len(search.get('traces',[]))>=1000,'profile_url':profile_link(start,end),
               'scope':'Whole completed /work spans within the window; slow >=400ms, ordinary <400ms. '
                       'CPU is sampled execution, not wall time. Request averages include selected spans without samples. '
                       'The cohorts exclude partial spans and traces without one exact processing child. '
                       'Exemplars are a bounded selection, not an exhaustive request census.'}
    save(out/'summary.json',summary)
    return summary


def collect_until_visible(out, mode, start, end, traffic_rows):
    expected = sum(r['path']=='/work' and r.get('status')==200 and r['start_ms'] >= start
                   and r['end_ms'] <= end for r in traffic_rows)
    deadline = time.monotonic()+90
    attempts = []
    while True:
        summary = collect(out,mode,start,end)
        available = sum(c.get('traces_available',0) for c in summary['cohorts'].values())
        needs_traces = mode != 'profiler-only'
        needs_profiles = mode != 'obi-only'
        satisfied = (not needs_traces or available >= expected) and (not needs_profiles or summary['aggregate']['total_ns'] > 0)
        attempts.append({'queried_ms':int(time.time()*1000),'target_traces':available,
                         'aggregate_cpu_ns':summary['aggregate']['total_ns'],
                         'cohorts':{name:{key:c.get(key) for key in ['requests','requests_with_samples','mean_cpu_ns_per_request']}
                                    for name,c in summary['cohorts'].items()}})
        summary['visibility']={'expected_completed_work_requests':expected,'target_traces':available,
                               'state':'available' if satisfied else 'incomplete',
                               'attempts':len(attempts),'note':'Traffic completions are an operational coverage check; '
                               'client and server interval boundaries can differ. Export/index delay can hide recent traces. '
                               'Missing traces or samples after the bounded wait are uncertainty, not a diagnosis.'}
        save(out/'summary.json',summary)
        save(out/'collection-history.json',attempts)
        if satisfied or time.monotonic() >= deadline:
            return summary
        time.sleep(min(10,max(0,deadline-time.monotonic())))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--seconds',type=int,default=45)
    parser.add_argument('--modes',nargs='+',choices=['obi-only','profiler-only','combined','no-correlation'],
                        default=['obi-only','profiler-only','combined','no-correlation'])
    parser.add_argument('--keep-running',action='store_true',help='Keep only this project for browser inspection')
    args=parser.parse_args()
    if not 20 <= args.seconds <= 180:
        parser.error('--seconds must be 20..180')
    output=args.output.resolve()
    output.mkdir(parents=True,exist_ok=False)
    with open('/tmp/obi-diagnostic-poc-live.lock','a') as lock:
        print('Waiting for isolated diagnostic live slot...',flush=True)
        fcntl.flock(lock,fcntl.LOCK_EX)
        try:
            compose('--profile','diagnostics','config')
            compose('up','-d','--build','app','lgtm')
            ready('http://localhost:8181/health')
            ready(GRAFANA+'/api/health')
            before=identity()
            if before['pid_mode']:
                raise RuntimeError('Application must have ordinary PID namespace')
            images={}
            configuration=json.loads(compose('--profile','diagnostics','config','--format','json'))
            for name,service in configuration['services'].items():
                images[name]=json.loads(subprocess.check_output(['docker','image','inspect',service['image'],
                    '--format','{"id":{{json .Id}},"digests":{{json .RepoDigests}}}'],text=True))
            save(output/'metadata.json',{'reference_obi_revision':REVISION,'checkout_revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'kernel':os.uname().release,'images':images,
                'docker':subprocess.check_output(['docker','version','--format','{{.Client.Version}} / {{.Server.Version}}'],text=True).strip(),
                'python':subprocess.check_output(['python3','--version'],text=True).strip(),'application_before':before,
                'configured_images':{name:service['image'] for name,service in configuration['services'].items()},
                'background_containers':subprocess.check_output(['docker','ps','--format','{{.Names}}'],text=True).splitlines()})
            rows,mutex,stop=[],threading.Lock(),threading.Event()
            windows={}
            baseline_start=int(time.time()*1000)
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                workers=[pool.submit(traffic,stop,route,rows,mutex) for route in ['/work','/report','/report']]
                try:
                    time.sleep(10)
                    windows['before_attachment']=(baseline_start,int(time.time()*1000))
                    for mode in args.modes:
                        out=output/mode
                        out.mkdir()
                        compose('stop','obi','profiler')
                        agents=['obi'] if mode=='obi-only' else ['profiler'] if mode=='profiler-only' else ['obi','profiler']
                        attached=int(time.time()*1000)
                        compose('--profile','diagnostics','up','-d','--no-deps','--no-build','--force-recreate',*agents,
                                correlation=mode not in ['no-correlation', 'profiler-only'])
                        time.sleep(20)
                        start=int(time.time()*1000)
                        print(mode+' collecting '+str(args.seconds)+' seconds',flush=True)
                        time.sleep(args.seconds)
                        end=int(time.time()*1000)
                        windows[mode]=(start,end)
                        save(out/'interval.json',{'start_ms':start,'end_ms':end,'attachment_ms':attached})
                        time.sleep(15)
                        # Query only the recorded completed window; the export wait cannot add evidence from another window.
                        try:
                            with mutex:
                                snapshot=list(rows)
                            summary=collect_until_visible(out,mode,start,end,snapshot)
                        except Exception as exc:
                            save(out/'failure.json',{'state':'collection_failed','error':str(exc),
                                'interval_ms':{'start':start,'end':end},'traceback':traceback.format_exc()})
                            raise
                        save(out/'continuity.json',{'attachment_ms':attached,'application_after':identity(),
                            'application_unchanged':identity()==before})
                        (out/'agent-logs.txt').write_text(compose('logs','--no-color','--tail','120','obi','profiler'))
                        print(json.dumps({'mode':mode,'cohorts':{k:{a:v.get(a) for a in ['requests','requests_with_samples','mean_cpu_ns_per_request','median_wall_ms']} for k,v in summary['cohorts'].items()},'verified_exemplars':summary['verified_work_exemplars']}),flush=True)
                finally:
                    stop.set()
                    for worker in workers:
                        worker.result()
                    save(output/'traffic.json',rows)
                    save(output/'traffic-summary.json',{name:{'interval_ms':{'start':bounds[0],'end':bounds[1]},'routes':traffic_summary(rows,*bounds)} for name,bounds in windows.items()})
                    save(output/'continuity.json',{'before':before,'after':identity(),'unchanged':before==identity()})
        finally:
            if args.keep_running:
                compose('stop','obi','profiler')
            else:
                compose('--profile','diagnostics','down','--volumes')


if __name__=='__main__':
    main()
