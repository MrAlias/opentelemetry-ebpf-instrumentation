# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

"""Check the TLS wire headers and exported OBI/SDK span relationships."""

import argparse
import concurrent.futures
import json
import time
import urllib.request


def read(path):
    with urllib.request.urlopen('http://127.0.0.1:18082/' + path, timeout=10) as response:
        return json.load(response) or []


def call(number, supplied=False):
    trace_id = f'{number:032x}'
    incoming = f'00-{trace_id}-{number + 1000:016x}-01'
    headers = {'traceparent': incoming, 'X-Id': str(number)}
    explicit = f'00-{trace_id}-3333333333333333-01' if supplied else None
    if explicit:
        headers['X-Supplied-Traceparent'] = explicit
    request = urllib.request.Request('http://127.0.0.1:18080/call', headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.load(response)
    assert body['body'] == f'body-{number}', body
    assert body['unrelated'] == 'keep-me', body
    return {'id': str(number), 'incoming': incoming, 'supplied': explicit, 'response': body}


def wait_for_attachment(base, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        call(base - 1)
        if any(s['traceId'] == f'{base - 1:032x}' and s['kind'] == 'SPAN_KIND_CLIENT'
               for s in read('spans')):
            return
        time.sleep(2)
    raise AssertionError('OBI did not export a TLS client span before the attachment deadline')


def validate(mode, calls, records, spans):
    selected = {c['id']: [r for r in records if r['id'] == c['id']] for c in calls}
    for c in calls:
        assert len(selected[c['id']]) == 1, (c, selected[c['id']])
        record = selected[c['id']][0]
        values = record['traceparents'] or []
        assert record['protocol'] == 'HTTP/1.1', record
        assert record['body'] == 'body-' + c['id'], record
        assert record['unrelated'] == 'keep-me', record
        if c['supplied']:
            assert values == [c['supplied']], record
        elif mode == 'enabled':
            assert len(values) == 1, record
            assert values[0].split('-')[1] == c['incoming'].split('-')[1], record
        else:
            assert values == [], record

        trace_id = c['incoming'].split('-')[1]
        ss = [s for s in spans if s['traceId'] == trace_id]
        servers = [s for s in ss if s['kind'] == 'SPAN_KIND_SERVER' and s['name'] == 'GET /call']
        clients = [s for s in ss if s['kind'] == 'SPAN_KIND_CLIENT' and s['name'] == 'POST /echo']
        assert len(servers) == 1 and len(clients) == 1, (c, ss)
        server, client = servers[0], clients[0]
        assert server['parentId'] == c['incoming'].split('-')[2], (c, server)
        parents = {s['spanId']: s for s in ss}
        parent = parents[client['parentId']]
        if parent['name'] == 'processing':
            parent = parents[parent['parentId']]
        assert parent['spanId'] == server['spanId'], (c, ss)

        downstream = [s for s in spans if s['name'] == 'downstream/' + c['id']]
        assert len(downstream) == 1, (c, downstream)
        if mode == 'enabled':
            assert values == [f"00-{trace_id}-{client['spanId']}-01"], (c, record, client)
            assert downstream[0]['traceId'] == trace_id, (c, downstream)
            assert downstream[0]['parentId'] == client['spanId'] == values[0].split('-')[2], (c, ss)
        elif c['supplied']:
            assert downstream[0]['traceId'] == trace_id, (c, downstream)
            assert downstream[0]['parentId'] == c['supplied'].split('-')[2], (c, downstream)
        else:
            assert downstream[0]['traceId'] != trace_id, (c, downstream)
            assert downstream[0]['parentId'] == '0000000000000000', (c, downstream)

    pooled = [selected[c['id']][0]['remote'] for c in calls[:3]]
    assert len(set(pooled)) == 1, ('sequential calls did not reuse the TLS connection', pooled)
    concurrent = [selected[c['id']][0]['remote'] for c in calls[3:19]]
    assert len(set(concurrent)) > 1, ('concurrent calls did not overlap', concurrent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['baseline', 'enabled', 'disabled'])
    parser.add_argument('--base', type=int, default=10000)
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    wait_for_attachment(args.base, args.timeout)
    calls = [call(n) for n in range(args.base, args.base + 3)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        calls += list(executor.map(call, range(args.base + 3, args.base + 19)))
    calls += [call(args.base + 19, supplied=True)]
    deadline = time.monotonic() + args.timeout
    while True:
        evidence = {'mode': args.mode, 'calls': calls, 'records': read('records'), 'spans': read('spans')}
        with open(args.output, 'w', encoding='utf-8') as output:
            json.dump(evidence, output, indent=2)
        try:
            validate(args.mode, calls, evidence['records'], evidence['spans'])
            break
        except (AssertionError, KeyError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)
    print(f'{args.mode}: 20 requests passed; headers, bodies, pooling, concurrency, and span parents verified')


if __name__ == '__main__':
    main()
