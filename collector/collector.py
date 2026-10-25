#!/usr/bin/env python3
"""Long-running Hubble Relay -> dashboard event bridge. JSON-lines / no extra Python deps."""
import json
import os
import ipaddress
import queue
import subprocess
import sys
import threading
import time
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

RELAY = os.environ.get('HUBBLE_SERVER', 'hubble-relay.kube-system.svc.cluster.local:80')
DASHBOARD = os.environ.get('DASHBOARD_URL', 'http://https-dashboard.opencode.svc.cluster.local:8080').rstrip('/')
TOKEN = os.environ.get('INGEST_TOKEN', '').strip()
PORTS = {int(n) for n in os.environ.get('FILTER_PORTS', '').split(',') if n.strip().isdigit()}
ALLOW_NS = {n.strip() for n in os.environ.get('FILTER_NAMESPACES', '').split(',') if n.strip()}
USE_TLS = os.environ.get('HUBBLE_TLS', 'false').lower() == 'true'
COUNTERS = {'observed': 0, 'forwarded': 0, 'skipped': 0, 'post_errors': 0}
STATE = {'state': 'starting', 'last_error': '', 'last_event_ts': None}
LOCK = threading.Lock()


def parse_time(value):
    if not value:
        return int(time.time())
    if isinstance(value, dict) and 'seconds' in value:
        return int(value['seconds'])
    if isinstance(value, (float, int)):
        return int(value)
    try:
        return int(datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp())
    except (ValueError, OverflowError):
        return int(time.time())


def parse_time_ms(value):
    if isinstance(value, dict) and 'seconds' in value:
        return int(value['seconds']) * 1000 + int(value.get('nanos',0)) // 1000000
    if isinstance(value, (int,float)):
        return int(float(value)*1000)
    try:
        return int(datetime.fromisoformat(str(value).replace('Z','+00:00')).timestamp()*1000)
    except (ValueError,OverflowError,TypeError):
        return int(time.time()*1000)


def flow_to_event(data):
    """Only IP TCP/UDP Hubble flow events; supports common protobuf JSON casing."""
    if not isinstance(data, dict):
        return None
    flow = data.get('flow') or data
    if not isinstance(flow, dict):
        return None
    ip = flow.get('IP') or flow.get('ip') or {}
    l4 = flow.get('l4') or flow.get('L4') or {}
    if not isinstance(ip, dict) or not isinstance(l4, dict):
        return None
    proto, layer = next(((p, l4.get(p) or l4.get(p.lower())) for p in ('TCP', 'UDP')
                         if (l4.get(p) or l4.get(p.lower()))), (None, None))
    if not proto or not isinstance(layer, dict):
        return None
    try:
        src = str(ipaddress.ip_address(ip.get('source', '')))
        dst = str(ipaddress.ip_address(ip.get('destination', '')))
        port = int(layer.get('destination_port') or layer.get('destinationPort') or 0)
        src_port = int(layer.get('source_port') or layer.get('sourcePort') or 0)
        if not 1 <= port <= 65535:
            return None
    except (ValueError, TypeError):
        return None
    source = flow.get('source') or {}
    destination = flow.get('destination') or {}
    if not isinstance(source, dict): source = {}
    if not isinstance(destination, dict): destination = {}
    src_ns = source.get('namespace') or flow.get('source_namespace') or 'external'
    dst_ns = destination.get('namespace') or flow.get('destination_namespace') or 'external'
    if PORTS and port not in PORTS:
        return None
    if ALLOW_NS and src_ns not in ALLOW_NS and dst_ns not in ALLOW_NS:
        return None
    verdict = str(flow.get('verdict', 'UNKNOWN')).upper()
    result = 'denied' if verdict == 'DROPPED' else ('success' if verdict in ('FORWARDED','REDIRECTED','TRACED','AUDIT') else 'error')
    flags = layer.get('flags') or {}
    if not isinstance(flags,dict): flags = {}
    tcp_flags = [name for name in ('SYN','ACK','PSH','FIN','RST','URG','ECE','CWR')
                 if flags.get(name) is True or flags.get(name.lower()) is True]
    tvalue = flow.get('time') or data.get('time')
    timestamp_ms = parse_time_ms(tvalue)
    drop = flow.get('drop_reason_desc') or flow.get('dropReasonDesc') or flow.get('drop_reason') or ''
    if isinstance(drop,dict): drop = json.dumps(drop,ensure_ascii=False)
    trace_point = flow.get('trace_observation_point') or flow.get('traceObservationPoint') or ''
    return {'ts': timestamp_ms//1000, 'ts_ms': timestamp_ms,
            'tcp_flags': tcp_flags if proto=='TCP' else [],
            'drop_reason': str(drop)[:240],
            'node_name': str(flow.get('node_name') or flow.get('nodeName') or '')[:160],
            'observation_point': str(trace_point)[:120], 'verdict': verdict,
            'src': src, 'dst': dst, 'src_port': src_port, 'dst_port': port,
            'proto': proto, 'src_namespace': str(src_ns)[:128], 'dst_namespace': str(dst_ns)[:128],
            'result': result, 'bytes_in': 0, 'bytes_out': 0, 'duration_ms': 0}


def send(path, body):
    req = Request(DASHBOARD + path, data=json.dumps(body).encode('utf-8'),
        headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + TOKEN}, method='POST')
    with urlopen(req, timeout=10) as resp:
        if resp.status != 202 and not (path.endswith('/heartbeat') and resp.status == 200):
            raise RuntimeError('Unexpected dashboard status: ' + str(resp.status))


def status(state=None, err=None):
    with LOCK:
        if state is not None: STATE['state'] = state
        if err is not None: STATE['last_error'] = str(err)[:500]


def heartbeat():
    while True:
        with LOCK:
            payload = dict(COUNTERS, **STATE, relay=RELAY, mode='all TCP/UDP' if not PORTS else 'port filter')
        try:
            send('/api/collector/heartbeat', payload)
        except Exception as exc:
            print('heartbeat failed:', repr(exc), file=sys.stderr, flush=True)
        time.sleep(10)


def enqueue_lines(process, items):
    try:
        for line in process.stdout:
            items.put(line)
    finally:
        items.put(None)


def log_stderr(process):
    for line in process.stderr:
        print('[hubble]', line.rstrip(), file=sys.stderr, flush=True)


def start_stream():
    flags = ['--tls'] if USE_TLS else []
    check = subprocess.run(['hubble', 'status', '--server', RELAY] + flags,
                           capture_output=True, text=True, timeout=20)
    if check.returncode:
        raise RuntimeError('Hubble Relay unavailable: ' + (check.stderr or check.stdout)[-450:])
    status('connected', '')
    print('Hubble Relay connected:', RELAY, flush=True)
    cmd = ['hubble', 'observe', '--server', RELAY] + flags + ['--follow', '--last', '0', '--output', 'json']
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    lines = queue.Queue(maxsize=10000)
    threading.Thread(target=enqueue_lines, args=(proc, lines), daemon=True).start()
    threading.Thread(target=log_stderr, args=(proc,), daemon=True).start()
    pending = []
    last_flush = time.monotonic()
    try:
        while True:
            try:
                line = lines.get(timeout=0.5)
            except queue.Empty:
                line = ''
            if line is None:
                break
            if line:
                with LOCK: COUNTERS['observed'] += 1
                try:
                    evt = flow_to_event(json.loads(line))
                except (ValueError, TypeError):
                    evt = None
                if evt:
                    pending.append(evt)
                else:
                    with LOCK: COUNTERS['skipped'] += 1
            if pending and (len(pending) >= 50 or time.monotonic() - last_flush >= 1):
                try:
                    send('/api/events', pending)
                    with LOCK:
                        COUNTERS['forwarded'] += len(pending)
                        STATE['last_event_ts'] = int(time.time())
                    if COUNTERS['forwarded'] % 500 < len(pending):
                        print('Posted events:', COUNTERS['forwarded'], flush=True)
                except Exception as exc:
                    with LOCK: COUNTERS['post_errors'] += 1
                    print('Post failed:', repr(exc), file=sys.stderr, flush=True)
                pending = []
                last_flush = time.monotonic()
        if pending:
            send('/api/events', pending)
            with LOCK: COUNTERS['forwarded'] += len(pending)
        code = proc.wait(timeout=5)
        raise RuntimeError('hubble observe exited with code ' + str(code))
    finally:
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill()


def main():
    if not TOKEN:
        raise SystemExit('Missing INGEST_TOKEN')
    threading.Thread(target=heartbeat, daemon=True).start()
    while True:
        try:
            status('connecting', '')
            start_stream()
        except Exception as exc:
            status('error', str(exc))
            print('Collector restart in 5s:', repr(exc), file=sys.stderr, flush=True)
            time.sleep(5)


if __name__ == '__main__':
    main()
