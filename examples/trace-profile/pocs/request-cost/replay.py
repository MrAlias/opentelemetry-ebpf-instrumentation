#!/usr/bin/env python3
"""Verify and summarize saved telemetry without Docker, source inspection, or backend access."""
import argparse
import json
from pathlib import Path
import run


def read(path):
    return json.loads(path.read_text())


def verify(directory):
    summary = read(directory/'summary.json')
    records = read(directory/'requests.json')
    selected = {(r['trace_id'],r['processing_span_id']):r for r in records}
    for record in records:
        trace = read(directory/'traces'/(record['trace_id']+'.json'))
        all_spans = run.spans(trace)
        server = next(s for s in all_spans if run.normalize(s['spanId'],8)==record['server_span_id'])
        processing = next(s for s in all_spans if run.normalize(s['spanId'],8)==record['processing_span_id'])
        if server['name'] != 'GET /work' or processing['name'] != 'processing':
            raise ValueError('Recorded request spans do not represent /work processing')
        if run.normalize(processing['parentSpanId'],8) != record['server_span_id']:
            raise ValueError('Processing span is not a child of the selected server span')
        if any(run.normalize(s['traceId'],16) != record['trace_id'] for s in [server,processing]):
            raise ValueError('Trace payload ID differs from request record')
    aggregate = run.summarize_profile(read(directory/'aggregate-profile.json'))
    if aggregate['total_ns'] != summary['aggregate']['total_ns']:
        raise ValueError('Aggregate summary disagrees with raw profile')
    for name,cohort in summary['cohorts'].items():
        if not cohort.get('requests'):
            continue
        raw = run.summarize_profile(read(directory/(name+'-profile.json')))
        rows = read(directory/(name+'-requests.json'))
        if raw['total_ns'] != cohort['total_ns'] or sum(r['total_cpu_ns'] for r in rows) != raw['total_ns']:
            raise ValueError('Cohort CPU accounting disagrees with individual requests')
        for record in rows:
            raw = run.summarize_profile(read(directory/('span-'+record['processing_span_id']+'-profile.json')))
            if raw['total_ns'] != record['total_cpu_ns']:
                raise ValueError('Individual CPU total disagrees with raw profile')
    exemplars=read(directory/'verified-exemplars.json')
    heatmap=read(directory/'span-exemplars.json')
    actual=set()
    for series in heatmap.get('series',[]):
        for slot in series.get('slots',[]):
            for exemplar in slot.get('exemplars',[]):
                try:
                    actual.add((run.normalize(exemplar.get('traceId',''),16),run.normalize(exemplar.get('spanId',''),8),str(exemplar['timestamp'])))
                except ValueError:
                    continue
    for exemplar in exemplars:
        tid,sid=exemplar['normalized_trace_id'],exemplar['normalized_span_id']
        if (tid,sid) not in selected or (tid,sid,str(exemplar['timestamp'])) not in actual:
            raise ValueError('Verified link is absent from raw telemetry')
    print(summary['mode'], 'aggregate CPU seconds:',round(aggregate['total_ns']/1e9,3),
          'verified /work exemplars:',len(exemplars))
    for name,cohort in summary['cohorts'].items():
        if not cohort.get('requests'):
            print(' ',name,'no matching traces')
            continue
        top=next((f['name'] for f in cohort['functions'] if f['self_ns']>0),None)
        print(' ',name, 'requests:',cohort['requests'],'with samples:',cohort['requests_with_samples'],
              'mean sampled CPU ms/request:',round(cohort['mean_cpu_ns_per_request']/1e6,3),'top self function:',top)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence',type=Path)
    args=parser.parse_args()
    for directory in sorted(args.evidence.iterdir()):
        if directory.is_dir() and (directory/'summary.json').exists():
            verify(directory)
    print('Saved IDs, exact span relationships, exemplars, and CPU accounting verified.')


if __name__=='__main__':
    main()
