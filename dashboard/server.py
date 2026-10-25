#!/usr/bin/env python3
"""Local-first HTTPS session-EVENT dashboard. No packet capture, TLS decryption, or proxy built in."""
import hmac
import ipaddress
import json
import os
import hashlib
import sqlite3
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from tcp_analysis import tcp_flags, sessionize, summary as tcp_summary, analyze as tcp_analyze

DB_PATH = os.environ.get("DB_PATH", "/data/sessions.sqlite3")
TOKEN = os.environ.get("INGEST_TOKEN", "").strip()  # tolerate CR/LF from externally generated secrets
STATIC = Path(__file__).resolve().parent / "index.html"
SCRIPT = Path(__file__).resolve().parent / "main.js"
TCP_SCRIPT = Path(__file__).resolve().parent / "tcp.js"
MAX_BODY = 65536
MAX_BATCH = 100


def connect():
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("""CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts INTEGER NOT NULL,
          src TEXT NOT NULL,
          dst TEXT NOT NULL,
          dst_port INTEGER NOT NULL,
          result TEXT NOT NULL,
          bytes_in INTEGER NOT NULL,
          bytes_out INTEGER NOT NULL,
          duration_ms INTEGER NOT NULL
        )""")
        # Preserve schema compatibility when an existing database is restored.
        existing = {r[1] for r in db.execute("PRAGMA table_info(events)")}
        for name, ddl in {
            'src_namespace': "TEXT NOT NULL DEFAULT 'unknown'",
            'dst_namespace': "TEXT NOT NULL DEFAULT 'unknown'",
            'proto': "TEXT NOT NULL DEFAULT 'TCP'",
            'src_port': "INTEGER NOT NULL DEFAULT 0",
            'ts_ms': "INTEGER NOT NULL DEFAULT 0",
            'tcp_flags': "TEXT NOT NULL DEFAULT ''",
            'drop_reason': "TEXT NOT NULL DEFAULT ''",
            'node_name': "TEXT NOT NULL DEFAULT ''",
            'observation_point': "TEXT NOT NULL DEFAULT ''",
            'verdict': "TEXT NOT NULL DEFAULT ''",
        }.items():
            if name not in existing:
                db.execute(f"ALTER TABLE events ADD COLUMN {name} {ddl}")
        db.execute("UPDATE events SET ts_ms=ts*1000 WHERE ts_ms=0")
        db.execute("CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts)")
        db.execute("CREATE INDEX IF NOT EXISTS ix_tcp_src_time ON events(proto,src,ts_ms)")
        db.execute("CREATE INDEX IF NOT EXISTS ix_tcp_dst_time ON events(proto,dst,ts_ms)")
        db.execute("""CREATE TABLE IF NOT EXISTS collector_state (
          name TEXT PRIMARY KEY, updated_at INTEGER NOT NULL, payload TEXT NOT NULL
        )""")


def validate_event(event):
    if not isinstance(event, dict):
        raise ValueError("event must be a JSON object")
    try:
        src = str(ipaddress.ip_address(event["src"]))
        dst = str(ipaddress.ip_address(event["dst"]))
        port = int(event.get("dst_port", 443))
        result = event.get("result", "success")
        incoming = int(event.get("bytes_in", 0))
        outgoing = int(event.get("bytes_out", 0))
        duration = int(event.get("duration_ms", 0))
        source_ns = str(event.get('src_namespace', 'unknown'))[:128]
        dest_ns = str(event.get('dst_namespace', 'unknown'))[:128]
        proto = str(event.get('proto', 'TCP')).upper()
        src_port = int(event.get('src_port', 0))
        ts_ms = int(event.get('ts_ms', 0))
        flags = tcp_flags(event.get('tcp_flags', ''))
        drop_reason = str(event.get('drop_reason') or '')[:240]
        node_name = str(event.get('node_name') or '')[:160]
        observation_point = str(event.get('observation_point') or '')[:120]
        verdict = str(event.get('verdict') or '')[:60]
        supplied_ts = event.get("ts", None)
        if supplied_ts is None:
            timestamp = int(time.time())
        elif isinstance(supplied_ts, (float, int)):
            timestamp = int(supplied_ts)
        else:
            # Accept RFC3339 with an explicit time zone only
            parsed = datetime.fromisoformat(str(supplied_ts).replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError("ts requires timezone")
            timestamp = int(parsed.timestamp())
    except (ValueError, TypeError, KeyError, OverflowError) as exc:
        raise ValueError(f"invalid event: {exc}") from exc
    if not 1 <= port <= 65535 or not 0 <= src_port <= 65535 or proto not in ('TCP','UDP') or result not in ("success", "denied", "error"):
        raise ValueError("dst_port or result invalid")
    if not (0 <= incoming <= 10**15 and 0 <= outgoing <= 10**15 and 0 <= duration <= 10**9):
        raise ValueError("bytes/duration out of range")
    if not ts_ms:
        ts_ms = timestamp * 1000
    if abs(ts_ms / 1000 - timestamp) > 2:
        raise ValueError("ts_ms must agree with ts")
    if abs(timestamp - time.time()) > 86400 * 31:
        raise ValueError("timestamp outside 31-day import window")
    return (timestamp, src, dst, port, result, incoming, outgoing, duration,
            source_ns, dest_ns, proto, src_port, ts_ms, flags, drop_reason, node_name, observation_point, verdict)


def get_collector():
    with connect() as db:
        row = db.execute("SELECT updated_at, payload FROM collector_state WHERE name='hubble'").fetchone()
    if not row:
        return {'state':'not-installed', 'age_seconds':None, 'last_error':'수집기 상태 수신 이력 없음'}
    try:
        value = json.loads(row['payload'])
    except (ValueError, TypeError):
        value = {}
    value['age_seconds'] = max(0, int(time.time()) - row['updated_at'])
    if value['age_seconds'] > 35:
        value['state'] = 'offline'
    return value


def query_stats(minutes, namespace='', port=0):
    since = int(time.time()) - minutes * 60
    where = ['ts >= ?']
    args = [since]
    if namespace:
        where.append('(src_namespace = ? OR dst_namespace = ?)')
        args.extend((namespace, namespace))
    if port:
        where.append('dst_port = ?')
        args.append(port)
    expression = ' AND '.join(where)
    with connect() as db:
        total = db.execute(f"""SELECT COUNT(*) AS total,
              COALESCE(SUM(result = 'success'),0) AS success,
              COALESCE(SUM(result = 'denied'),0) AS denied,
              COALESCE(SUM(result = 'error'),0) AS error,
              COALESCE(SUM(bytes_in + bytes_out),0) AS bytes_total
              FROM events WHERE {expression}""", args).fetchone()
        edges = db.execute(f"""SELECT src,dst,dst_port,proto,src_namespace,dst_namespace,
                 COUNT(*) AS count, SUM(result != 'success') AS failures
                 FROM events WHERE {expression}
                 GROUP BY src,dst,dst_port,proto,src_namespace,dst_namespace
                 ORDER BY count DESC LIMIT 12""", args).fetchall()
        latest = db.execute(f"""SELECT ts,src,dst,src_namespace,dst_namespace,dst_port,
                  proto,result,bytes_in,bytes_out,duration_ms FROM events WHERE {expression}
                  ORDER BY ts DESC, id DESC LIMIT 50""", args).fetchall()
        slots = db.execute(f"""SELECT CAST(ts/60 AS INTEGER) AS minute, COUNT(*) AS count
                  FROM events WHERE {expression} GROUP BY minute ORDER BY minute""", args).fetchall()
        namespaces = db.execute("""SELECT namespace FROM (
            SELECT src_namespace AS namespace FROM events WHERE ts >= ?
            UNION SELECT dst_namespace AS namespace FROM events WHERE ts >= ?
        ) WHERE namespace NOT IN ('', 'unknown') ORDER BY namespace LIMIT 300""",(int(time.time())-86400,)*2).fetchall()
        ns_count = db.execute(f"""SELECT COUNT(DISTINCT src_namespace) AS n
                             FROM events WHERE {expression}""", args).fetchone()['n']
    return {'window_minutes': minutes, 'generated_at': int(time.time()),
       'metrics': dict(total, namespaces=ns_count), 'edges':[dict(r) for r in edges],
       'latest':[dict(r) for r in latest], 'timeline':[dict(r) for r in slots],
       'namespaces':[r[0] for r in namespaces], 'collector':get_collector(),
       'note':'Counts are observed Hubble TCP/UDP flow events, not concurrent TCP/TLS sessions.'}


def prometheus_metrics():
    """Rolling observed-flow gauges, NOT concurrent sessions, plus collector heartbeat."""
    cutoff=int(time.time())-300
    with connect() as db:
        rows=db.execute("SELECT result,COUNT(*) AS count FROM events WHERE ts>=? GROUP BY result", (cutoff,)).fetchall()
        nsrows=db.execute("""SELECT namespace,COUNT(*) AS count FROM (
            SELECT src_namespace AS namespace FROM events WHERE ts>=?
            UNION ALL SELECT dst_namespace AS namespace FROM events WHERE ts>=?
        ) WHERE namespace NOT IN ('','unknown','external')
        GROUP BY namespace ORDER BY count DESC LIMIT 60""",(cutoff,cutoff)).fetchall()
        total=db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    collector=get_collector()
    lines=['# HELP opencode_hubble_events_ingested_total Flow events retained in SQLite (reset on database reset)',
           '# TYPE opencode_hubble_events_ingested_total gauge',f'opencode_hubble_events_ingested_total {total}',
           '# HELP opencode_hubble_flow_events_last5m Observed network flow events during last five minutes',
           '# TYPE opencode_hubble_flow_events_last5m gauge']
    results={row['result']:row['count'] for row in rows}
    for result in ('success','denied','error'):
        lines.append(f'opencode_hubble_flow_events_last5m{{result="{result}"}} {results.get(result,0)}')
    lines.extend(['# HELP opencode_hubble_namespace_events_last5m Observed source and destination namespace event appearances in last five minutes',
                  '# TYPE opencode_hubble_namespace_events_last5m gauge'])
    for r in nsrows:
        label=r['namespace'].replace('\\','\\\\').replace('"','\\"').replace('\n',' ')
        lines.append(f'opencode_hubble_namespace_events_last5m{{namespace="{label}"}} {r["count"]}')
    lines += ['# HELP opencode_hubble_collector_connected 1 only when heartbeat is recent and relay connected',
              '# TYPE opencode_hubble_collector_connected gauge',
              f'opencode_hubble_collector_connected {int(collector.get("state")=="connected" and collector.get("age_seconds") is not None and collector["age_seconds"]<35)}']
    return ('\n'.join(lines)+'\n').encode('utf-8')


def tcp_search(ip, minutes=60, peer='', port=0):
    # Respect an individual IP filter. Never scan every session in the cluster.
    target = str(ipaddress.ip_address(ip))
    other = str(ipaddress.ip_address(peer)) if peer else ''
    since = int(time.time()) - minutes * 60
    q = """SELECT id,ts,ts_ms,src,src_port,dst,dst_port,proto,result,tcp_flags,drop_reason,node_name,observation_point
           FROM events WHERE proto='TCP' AND ts>=? AND (src=? OR dst=?)"""
    args = [since, target, target]
    if other:
        q += ' AND (src=? OR dst=?)'
        args.extend((other,other))
    if port:
        q += ' AND (src_port=? OR dst_port=?)'
        args.extend((port,port))
    q += ' ORDER BY ts_ms DESC,id DESC LIMIT 15000'
    with connect() as db:
        rows = [dict(r) for r in db.execute(q, args).fetchall()]
    episodes = sessionize(rows)
    return {'connections':[tcp_summary(g) for g in episodes[:80]],
            'matching_events':len(rows), 'truncated':len(rows)==15000,
            'note':'4-tuple/time heuristic grouping; incomplete observation is not a failure.',
            '_episodes':episodes}


def grafana_graph(minutes=5):
    """Infinity Node Graph-compatible JSON. Node IDs stable across refreshes."""
    stats=query_stats(minutes)
    nodes={}
    edges=[]
    for row in stats['edges'][:12]:
        left='src:'+row['src_namespace']+'/'+row['src']
        right='dst:'+row['dst_namespace']+'/'+row['dst']+':'+str(row['dst_port'])
        for key,title,ns in ((left,row['src'],row['src_namespace']), (right,row['dst']+':'+str(row['dst_port']),row['dst_namespace'])):
            nodes.setdefault(key,{'id':hashlib.sha1(key.encode()).hexdigest()[:16], 'title':title[:70], 'subTitle':ns[:70]})
        edges.append({'id':'e'+str(len(edges)), 'source':nodes[left]['id'], 'target':nodes[right]['id'],
                      'mainStat':str(row['count'])+' events', 'secondaryStat':row['proto'],
                      'detail__failures':row['failures']})
    return {'nodes':list(nodes.values()), 'edges':edges}


class Handler(BaseHTTPRequestHandler):
    def send(self, code, content, content_type="application/json; charset=utf-8", attachment=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'")
        if attachment:
            self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
        self.end_headers()
        self.wfile.write(content)

    def json_response(self, code, payload):
        self.send(code, json.dumps(payload, ensure_ascii=False).encode("utf-8"))

    def do_GET(self):
        parsed = urlsplit(self.path)
        if parsed.path == "/healthz":
            self.json_response(200, {"status": "ok"})
        elif parsed.path in ("/", "/index.html"):
            self.send(200, STATIC.read_bytes(), "text/html; charset=utf-8")
        elif parsed.path == "/main.js":
            self.send(200, SCRIPT.read_bytes(), "text/javascript; charset=utf-8")
        elif parsed.path == "/tcp.js":
            self.send(200, TCP_SCRIPT.read_bytes(), "text/javascript; charset=utf-8")
        elif parsed.path in ('/api/tcp/connections', '/api/tcp/lifecycle'):
            try:
                opt = parse_qs(parsed.query)
                ip = opt.get('ip', [''])[0]
                minutes = int(opt.get('minutes', ['60'])[0])
                port = int(opt.get('port', ['0'])[0])
                peer = opt.get('peer', [''])[0]
                if minutes not in (5,15,60,180,1440): raise ValueError('unsupported time window')
                if port and not 1 <= port <= 65535: raise ValueError('invalid port')
                found = tcp_search(ip, minutes, peer, port)
                if parsed.path.endswith('/connections'):
                    found.pop('_episodes')
                    self.json_response(200, found)
                else:
                    anchor = int(opt.get('anchor_id',['0'])[0])
                    group = next((g for g in found['_episodes'] if int(g[0]['id']) == anchor), None)
                    if group is None:
                        self.json_response(404, {'error':'해당 연결이 검색 기간에서 관측되지 않습니다.'})
                    else:
                        self.json_response(200, tcp_analyze(group))
            except (ValueError,TypeError) as exc:
                self.json_response(400, {'error':str(exc)})
        elif parsed.path == '/metrics':
            self.send(200, prometheus_metrics(), 'text/plain; version=0.0.4; charset=utf-8')
        elif parsed.path == '/api/grafana/graph':
            try:
                minutes=int(parse_qs(parsed.query).get('minutes',['5'])[0])
                if minutes not in (5,15,60,180,1440): raise ValueError('bad window')
                self.json_response(200,grafana_graph(minutes))
            except ValueError as e:
                self.json_response(400,{'error':str(e)})
        elif parsed.path == "/api/summary":
            try:
                minutes = int(parse_qs(parsed.query).get("minutes", ["60"])[0])
                if minutes not in (5, 15, 60, 180, 1440):
                    raise ValueError("window must be 5,15,60,180,1440")
                options = parse_qs(parsed.query)
                namespace = options.get('namespace', [''])[0][:128]
                port = int(options.get('port', ['0'])[0])
                if port and not 1 <= port <= 65535:
                    raise ValueError('invalid port')
                stats = query_stats(minutes, namespace, port)
            except (ValueError, TypeError) as e:
                self.json_response(400, {"error": str(e)})
                return
            self.json_response(200, stats)
        else:
            self.json_response(404, {"error": "not found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ('/api/events','/api/collector/heartbeat'):
            self.json_response(404, {"error": "not found"})
            return
        auth = self.headers.get("Authorization", "")
        if not TOKEN or not hmac.compare_digest(auth, "Bearer " + TOKEN):
            self.json_response(401, {"error": "invalid ingest token"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_BODY:
                raise ValueError("request body too large or empty")
            payload = json.loads(self.rfile.read(length))
            if path == '/api/collector/heartbeat':
                if not isinstance(payload, dict):
                    raise ValueError('heartbeat must be an object')
                # Cap size and store only operational counters and diagnostics.
                limited = {k:payload.get(k) for k in
                           ('state','last_error','last_event_ts','relay','mode','observed',
                            'forwarded','skipped','post_errors')}
                with connect() as db:
                    db.execute("""INSERT INTO collector_state(name,updated_at,payload)
                         VALUES('hubble',?,?) ON CONFLICT(name) DO UPDATE
                         SET updated_at=excluded.updated_at,payload=excluded.payload""",
                         (int(time.time()),json.dumps(limited,ensure_ascii=False)))
                self.json_response(200, {'status':'ok'})
                return
            items = payload if isinstance(payload, list) else [payload]
            if not 1 <= len(items) <= MAX_BATCH:
                raise ValueError("batch must be 1..100 events")
            events = [validate_event(item) for item in items]
            with connect() as db:
                db.executemany("""INSERT INTO events
                   (ts,src,dst,dst_port,result,bytes_in,bytes_out,duration_ms,
                    src_namespace,dst_namespace,proto,src_port,ts_ms,tcp_flags,drop_reason,node_name,observation_point,verdict)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", events)
            self.json_response(202, {"accepted": len(events)})
        except (ValueError, UnicodeError, json.JSONDecodeError) as e:
            self.json_response(400, {"error": str(e)})
        except sqlite3.Error:
            self.json_response(500, {"error": "database write failure"})


def main():
    if not TOKEN:
        raise SystemExit("INGEST_TOKEN must be set; refusing insecure startup")
    init_db()
    port = int(os.environ.get("PORT", "8080"))
    print(f"HTTPS session event dashboard listening on 0.0.0.0:{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
