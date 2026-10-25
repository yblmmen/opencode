"""Evidence-only Hubble TCP flow timeline. Hubble events are NOT packet captures."""
from collections import defaultdict

MAX_CONNECTION_EVENTS = 4000


def tcp_flags(value):
    if isinstance(value, dict):
        names = (k.upper() for k, v in value.items() if v is True or str(v).lower() == 'true')
    elif isinstance(value, list):
        names = (str(x).upper() for x in value)
    else:
        names = (x.strip().upper() for x in str(value or '').replace('|', ',').split(','))
    accepted = set(names) & {'SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG', 'ECE', 'CWR', 'NS'}
    return ','.join(n for n in ('SYN','ACK','PSH','FIN','RST','URG','ECE','CWR','NS') if n in accepted)


def key_for(row):
    return tuple(sorted(((row['src'], int(row['src_port'])), (row['dst'], int(row['dst_port'])))))


def sessionize(rows):
    """Heuristic 4-tuple grouping. Pure SYN begins a new episode; long silence may split one connection."""
    groups = defaultdict(list)
    for r in sorted(rows, key=lambda x: (int(x['ts_ms']), int(x['id']))):
        k = key_for(r)
        episodes = groups[k]
        f = set(tcp_flags(r.get('tcp_flags')).split(',')) - {''}
        if not episodes:
            episodes.append([])
        else:
            prev = episodes[-1]
            prev_flags = [set(tcp_flags(x.get('tcp_flags')).split(',')) for x in prev]
            # Do not mistake repeated SYN at a trace point for a new connection.
            established = any('ACK' in z and 'SYN' not in z for z in prev_flags)
            repeated_syn = f == {'SYN'} and any(z == {'SYN'} for z in prev_flags) and not established
            if (int(r['ts_ms']) - int(prev[-1]['ts_ms']) > 1200000 or
               (f == {'SYN'} and not repeated_syn and established)):
                episodes.append([])
        episodes[-1].append(r)
    return sorted((g for es in groups.values() for g in es if g),
                  key=lambda g: (int(g[-1]['ts_ms']), int(g[-1]['id'])), reverse=True)


def labels(group):
    # A pure SYN indicates the initiator; otherwise identify direction as inferred.
    first_syn = next((x for x in group if set(tcp_flags(x.get('tcp_flags')).split(',')) == {'SYN'}), None)
    r = first_syn or group[0]
    return ((r['src'], int(r['src_port'])), (r['dst'], int(r['dst_port'])), first_syn is not None)


def summary(group):
    client, server, inferred = labels(group)
    flags = [set(tcp_flags(x.get('tcp_flags')).split(',')) for x in group]
    status = '차단 관측' if any(x.get('result') == 'denied' for x in group) else (
        'RST 관측' if any('RST' in f for f in flags) else (
        'FIN 양방향' if len({(x['src'], x['src_port']) for x, f in zip(group, flags) if 'FIN' in f}) >= 2 else
        '진행/미관측'))
    return {'anchor_id': int(group[0]['id']), 'client_ip': client[0], 'client_port': client[1],
            'server_ip': server[0], 'server_port': server[1], 'initiator_observed': inferred,
            'start_ms': int(group[0]['ts_ms']), 'end_ms': int(group[-1]['ts_ms']),
            'event_count': len(group), 'drop_count': sum(x.get('result') == 'denied' for x in group),
            'rst_count': sum('RST' in f for f in flags), 'status': status}


def analyze(group):
    if not group:
        raise ValueError('No observed events')
    group = sorted(group, key=lambda x: (int(x['ts_ms']),int(x['id'])))
    client, server, initiator_observed = labels(group)
    flags = [(r, set(tcp_flags(r.get('tcp_flags')).split(',')) - {''}) for r in group]
    def from_endpoint(r):
        return 'client' if (r['src'], int(r['src_port'])) == client else 'server'
    def is_client(r): return from_endpoint(r) == 'client'
    syn = next((r for r, f in flags if 'SYN' in f and 'ACK' not in f and is_client(r)), None)
    synack = next((r for r, f in flags if 'SYN' in f and 'ACK' in f and not is_client(r) and (not syn or r['ts_ms'] >= syn['ts_ms'])), None)
    ack = next((r for r, f in flags if 'ACK' in f and 'SYN' not in f and is_client(r) and synack and r['ts_ms'] >= synack['ts_ms']), None)
    fin_client = next((r for r,f in flags if 'FIN' in f and is_client(r)), None)
    fin_server = next((r for r,f in flags if 'FIN' in f and not is_client(r)), None)
    fin_first = next((r for r, f in flags if 'FIN' in f), None)
    fin_first_is_client = is_client(fin_first) if fin_first else None
    ack_to_fin = next((r for r,f in flags if fin_first and 'ACK' in f and 'FIN' not in f and 'SYN' not in f
                       and is_client(r) != fin_first_is_client and r['ts_ms'] >= fin_first['ts_ms']), None)
    fin_second = next((r for r,f in flags if fin_first and 'FIN' in f and is_client(r) != fin_first_is_client
                       and r['ts_ms'] >= fin_first['ts_ms']), None)
    final_ack = next((r for r,f in flags if fin_second and 'ACK' in f and 'FIN' not in f and 'SYN' not in f
                      and is_client(r) == fin_first_is_client and r['ts_ms'] >= fin_second['ts_ms']), None)
    resets = [r for r,f in flags if 'RST' in f]
    drops = [r for r,f in flags if r.get('result') == 'denied']
    syn_attempts = [r for r,f in flags if 'SYN' in f and 'ACK' not in f and is_client(r)]
    stages = [
      {'label':'3-Way ① SYN', 'found':bool(syn), 'ts_ms':syn['ts_ms'] if syn else None, 'note':'클라이언트 연결 시도' if syn else '미관측'},
      {'label':'3-Way ② SYN/ACK', 'found':bool(synack), 'ts_ms':synack['ts_ms'] if synack else None, 'note':'서버 연결 응답' if synack else '미관측'},
      {'label':'3-Way ③ ACK', 'found':bool(ack), 'ts_ms':ack['ts_ms'] if ack else None, 'note':'후속 ACK 관측 (번호 검증 없음)' if ack else '미관측'},
      {'label':'4-Way ① FIN', 'found':bool(fin_first), 'ts_ms':fin_first['ts_ms'] if fin_first else None,
       'note':('클라이언트' if fin_first_is_client else '서버')+' FIN 관측' if fin_first else '미관측'},
      {'label':'4-Way ② ACK', 'found':bool(ack_to_fin), 'ts_ms':ack_to_fin['ts_ms'] if ack_to_fin else None,
       'note':'반대측 ACK 관측 (해당 FIN 확인 응답인지 번호 검증 불가)' if ack_to_fin else '미관측 또는 FIN+ACK 병합'},
      {'label':'4-Way ③ FIN', 'found':bool(fin_second), 'ts_ms':fin_second['ts_ms'] if fin_second else None,
       'note':'반대측 FIN 관측' if fin_second else '미관측'},
      {'label':'4-Way ④ ACK', 'found':bool(final_ack), 'ts_ms':final_ack['ts_ms'] if final_ack else None,
       'note':'최종 ACK 관측 (번호 검증 없음)' if final_ack else '미관측'},
    ]
    issues = []
    for r in drops[:8]:
        issues.append({'severity':'critical', 'kind':'POLICY_DROP', 'ts_ms':int(r['ts_ms']),
                       'message':'Hubble 차단 관측', 'evidence':
                       f"{r.get('drop_reason') or '사유 미제공'} / 관측 노드 {r.get('node_name') or '알 수 없음'} / 지점 {r.get('observation_point') or '미제공'}"})
    for r in resets[:8]:
        who = '클라이언트' if is_client(r) else '서버'
        issues.append({'severity':'warning','kind':'RST', 'ts_ms':int(r['ts_ms']),
                       'message':f'{who}에서 RST 관측', 'evidence':
                       f"전송 IP {r['src']}:{r['src_port']} / 노드 {r.get('node_name') or '미제공'} (RST가 항상 장애를 뜻하지는 않음)"})
    if len(syn_attempts) >= 2 and not synack:
        issues.append({'severity':'warning','kind':'REPEATED_SYN','ts_ms':int(syn_attempts[-1]['ts_ms']),
                       'message':'SYN 반복, SYN/ACK 미관측',
                       'evidence':'응답 부재·차단·관측 누락 모두 가능. PCAP 또는 상대편 로그로 확인 필요'})
    if not issues and not (syn and synack and ack):
        issues.append({'severity':'info', 'kind':'INCOMPLETE_OBSERVATION', 'ts_ms':int(group[0]['ts_ms']),
                       'message':'3-way 단계 일부 미관측', 'evidence':'Hubble 샘플링·관측 지점 또는 수집 시작 시점 영향 가능. 장애 확정 아님'})
    if syn and synack and ack:
        handshake = 'SYN / SYN+ACK / ACK 관측 (시퀀스·ACK 번호 미검증)'
    else:
        handshake = '불완전한 관측 — 패킷 누락 또는 수집 시작 시점일 수 있음'
    if resets:
        termination = 'RST 관측 — 비정상 종료일 수도 있고 의도된 종료일 수도 있음'
    elif fin_client and fin_server:
        termination = '양방향 FIN 관측 — 4-way ACK 번호 확인은 PCAP 필요'
    elif fin_client or fin_server:
        termination = '한쪽 FIN만 관측 — 반대쪽 종료 미관측'
    else:
        termination = '종료 이벤트 미관측'
    events = []
    for r, f in flags[:240]:
        events.append({'id':int(r['id']), 'ts_ms':int(r['ts_ms']), 'side':from_endpoint(r),
                       'src':r['src'], 'src_port':int(r['src_port']), 'dst':r['dst'], 'dst_port':int(r['dst_port']),
                       'flags':tcp_flags(r.get('tcp_flags')), 'result':r.get('result','success'),
                       'node_name':r.get('node_name',''), 'drop_reason':r.get('drop_reason',''),
                       'observation_point':r.get('observation_point','')})
    return {'connection':summary(group), 'handshake':handshake, 'termination':termination,
            'stages':stages, 'issues':issues, 'events':events,
            'truncated':len(group) > len(events), 'total_events':len(group),
            'notes':['Hubble 관측 이벤트 기반. 패킷 전체 캡처가 아니므로 미관측=장애가 아닙니다.',
                     '같은 4-tuple 재사용과 긴 유휴 연결은 시간 기반 분리로 오차가 발생할 수 있습니다.',
                     'ACK 번호·재전송·TCP 상태 천이의 확정 검증은 PCAP/tshark를 사용하십시오.',
                     'Cloudflare 외부 TLS 핸드셰이크는 내부 HTTP NodePort에서 관측되지 않습니다.']}
