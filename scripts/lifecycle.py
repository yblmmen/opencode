#!/usr/bin/env python3
"""Observed PCAP -> SVG TCP/TLS lifecycle sequence. Offline tshark only, no inference of missing messages."""
import argparse
import html
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

FIELDS = ('frame.time_epoch','ip.src','ipv6.src','tcp.srcport','ip.dst','ipv6.dst','tcp.dstport',
          'tcp.flags.syn','tcp.flags.ack','tcp.flags.fin','tcp.flags.reset','tcp.len',
          'tls.handshake.type','tls.record.content_type')


def flag(raw):
    return raw.strip() in ('1','True','true')


def parse_line(line):
    v=line.rstrip('\n').split('\t')
    if len(v)<len(FIELDS): v += ['']*(len(FIELDS)-len(v))
    val=dict(zip(FIELDS,v))
    try:
        return {'when':float(val['frame.time_epoch']),
                'src':val['ip.src'] or val['ipv6.src'],
                'dst':val['ip.dst'] or val['ipv6.dst'],
                'sp':int(val['tcp.srcport']), 'dp':int(val['tcp.dstport']),
                'syn':flag(val['tcp.flags.syn']),'ack':flag(val['tcp.flags.ack']),
                'fin':flag(val['tcp.flags.fin']),'rst':flag(val['tcp.flags.reset']),
                'length':int(val['tcp.len'] or 0),
                'tls_handshakes':[int(x) for x in val['tls.handshake.type'].split(',') if x.isdigit()],
                'records':[int(x) for x in val['tls.record.content_type'].split(',') if x.isdigit()]}
    except (ValueError,TypeError):
        return None


def read_packets(pcap,stream):
    cmd=['tshark','-r',str(pcap),'-Y',f'tcp.stream == {stream}',
         '-T','fields','-E','header=n','-E','quote=n','-E','occurrence=a']
    for f in FIELDS: cmd.extend(['-e',f])
    try: proc=subprocess.run(cmd,capture_output=True,text=True,timeout=90,check=False)
    except FileNotFoundError: raise RuntimeError('tshark가 없습니다. wireshark-cli 또는 tshark 패키지를 설치하세요.')
    except subprocess.TimeoutExpired: raise RuntimeError('tshark 분석 시간 초과 (90초)')
    if proc.returncode: raise RuntimeError('tshark error: '+proc.stderr[-400:])
    packets=sorted((p for line in proc.stdout.splitlines() if (p:=parse_line(line)) is not None),key=lambda x:x['when'])
    if not packets: raise RuntimeError('지정 TCP stream에서 패킷을 찾지 못했습니다. --list로 stream 번호를 확인하세요.')
    return packets


def stages(packets):
    # Initiator from actual SYN-only packet; otherwise fallback is NOT authoritative.
    syn=next((p for p in packets if p['syn'] and not p['ack']),None)
    initiator=syn or packets[0]
    client=(initiator['src'],initiator['sp']); server=(initiator['dst'],initiator['dp'])
    rows=[]; states={'syn':False,'synack':False,'ack':False,'ch':False,'sh':False,'app':False,'fin_c':False,'fin_s':False,'rst':False}
    counted=defaultdict(lambda:[0,0,0]); first=packets[0]['when']
    def add(p,kind,label):
        direction='c2s' if (p['src'],p['sp'])==client else 's2c'
        rows.append({'when':p['when']-first,'kind':kind,'direction':direction,'label':label})
    for p in packets:
        outgoing=(p['src'],p['sp'])==client
        if p['syn'] and not p['ack'] and outgoing and not states['syn']:
            states['syn']=True;add(p,'tcp','SYN (연결 요청)')
        elif p['syn'] and p['ack'] and not outgoing and not states['synack']:
            states['synack']=True;add(p,'tcp','SYN, ACK (연결 수락)')
        elif p['ack'] and not p['syn'] and not p['fin'] and outgoing and states['synack'] and not states['ack']:
            states['ack']=True;add(p,'tcp','ACK (3-way handshake)')
        if 1 in p['tls_handshakes'] and not states['ch']:
            states['ch']=True;add(p,'tls','TLS ClientHello (관측됨)')
        if 2 in p['tls_handshakes'] and not states['sh']:
            states['sh']=True;add(p,'tls','TLS ServerHello (관측됨)')
        if p['length']>0 and 23 in p['records']:
            key='tls_c' if outgoing else 'tls_s'
            c=counted[key]; c[0]+=1;c[1]+=p['length'];c[2]=p['when'] if not c[2] else c[2]
        if p['fin']:
            key='fin_c' if outgoing else 'fin_s'
            if not states[key]:states[key]=True;add(p,'close','FIN'+(', ACK' if p['ack'] else '')+' (종료 신호)')
        if p['rst'] and not states['rst']:
            states['rst']=True;add(p,'close','RST (연결 강제 종료)')
    # Aggregate TLS encrypted records: could contain encrypted TLS1.3 handshake, not necessarily HTTP application data.
    for key in ('tls_c','tls_s'):
        c=counted[key]
        if c[0]:
            states['app']=True
            rows.append({'when':c[2]-first,'kind':'data','direction':'c2s' if key=='tls_c' else 's2c',
                         'label':f'TLS 암호화 레코드 {c[0]}개 (TCP payload {c[1]:,}B)'})
    rows.sort(key=lambda r:r['when'])
    missing=[]
    if not all(states[k] for k in ('syn','synack','ack')):missing.append('TCP 3-way 핸드셰이크 완전 관측 안 됨')
    if not states['ch']: missing.append('TLS ClientHello 관측 안 됨')
    if not states['sh']: missing.append('TLS ServerHello 관측 안 됨')
    if not states['app']: missing.append('TLS 암호화 레코드 관측 안 됨')
    if not (states['fin_c'] and states['fin_s']): missing.append('TCP 양방향 FIN 완전 관측 안 됨 (4-way 종료 확인 불가)')
    if states['rst']:missing.append('RST 관측됨: 정상 FIN 종료와 구분 필요')
    missing.append('TLS 1.3 암호화 핸드셰이크·HTTP 콘텐츠는 키 없이 식별 불가')
    return client,server,rows,missing


def render_svg(client,server,rows,missing):
    import xml.etree.ElementTree as ET
    NS='http://www.w3.org/2000/svg'; ET.register_namespace('',NS)
    def tag(name,attrs=None,parent=None,text=None):
        el=ET.SubElement(parent if parent is not None else root,'{%s}%s'%(NS,name),attrs or {})
        if text is not None:el.text=text
        return el
    height=max(350,155+len(rows)*47+42)
    root=ET.Element('{%s}svg'%NS,{'width':'1060','height':str(height),'viewBox':f'0 0 1060 {height}','xmlns':NS})
    tag('rect',{'width':'1060','height':str(height),'fill':'#0f172a'})
    tag('text',{'x':'32','y':'40','fill':'#f8fafc','font-size':'23','font-weight':'bold'},text='Observed HTTPS TCP/TLS Lifecycle')
    tag('text',{'x':'252','y':'88','fill':'#7dd3fc','font-size':'15','text-anchor':'middle'},text=f'{client[0]}:{client[1]}')
    tag('text',{'x':'810','y':'88','fill':'#86efac','font-size':'15','text-anchor':'middle'},text=f'{server[0]}:{server[1]}')
    for x in ('252','810'):
        tag('line',{'x1':x,'y1':'104','x2':x,'y2':str(height-50),'stroke':'#64748b','stroke-dasharray':'7 7'})
    palette={'tcp':'#38bdf8','tls':'#c4b5fd','data':'#fbbf24','close':'#fb7185'}
    for i,r in enumerate(rows):
        y=130+i*47; forward=r['direction']=='c2s';start,end=(252,810) if forward else (810,252)
        color=palette[r['kind']]
        tag('line',{'x1':str(start),'y1':str(y),'x2':str(end),'y2':str(y),'stroke':color,'stroke-width':'2'})
        direction=-1 if forward else 1
        tip=f'{end},{y} {end+direction*9},{y-5} {end+direction*9},{y+5}'
        tag('polygon',{'points':tip,'fill':color})
        tag('rect',{'x':'325','y':str(y-27),'width':'410','height':'22','fill':'#0f172a'})
        label=f'+{r["when"]:.4f}s  {r["label"]}'
        tag('text',{'x':'530','y':str(y-11),'font-size':'13','fill':color,'text-anchor':'middle'},text=label[:75])
    if not rows:
        tag('text',{'x':'530','y':'145','fill':'#fbbf24','text-anchor':'middle'},text='관측된 단계가 없습니다')
    tag('text',{'x':'32','y':str(height-20),'fill':'#94a3b8','font-size':'12'},text='실제 PCAP 관측 기반 · 패킷 누락/암호화 단계 추정 금지 · TLS 레코드 ≠ 반드시 HTTP 애플리케이션 데이터')
    return ET.tostring(root,encoding='unicode',xml_declaration=False)


def analyze(pcap,stream,out):
    packets=read_packets(pcap,stream)
    client,server,rows,missing=stages(packets)
    svg=render_svg(client,server,rows,missing)
    path=Path(out);path.parent.mkdir(parents=True,exist_ok=True)
    if path.suffix.lower() not in ('.svg','.html'):path=path.with_suffix('.svg')
    if path.suffix.lower()=='.html':
        warnings=''.join(f'<li>{html.escape(x)}</li>' for x in missing)
        page='<!doctype html><html lang="ko"><meta charset="utf-8"><title>HTTPS lifecycle</title><body style="margin:0;background:#0f172a;color:#ddd;font:15px system-ui">'+svg+'<div style="padding:20px"><h3>미관측/해석 제한</h3><ul>'+warnings+'</ul></div></body></html>'
        path.write_text(page,encoding='utf-8')
    else:path.write_text(svg,encoding='utf-8')
    print('PCAP:',pcap,'TCP stream:',stream,'Packets:',len(packets),'Observed stages:',len(rows))
    print('Output:',path)
    for x in missing:print('NOTE:',x)
    return path


def main():
    ap=argparse.ArgumentParser(description='CLI PCAP->Observed TCP/TLS connection sequence SVG')
    ap.add_argument('pcap',type=Path,help='실제 tcpdump/pcapng 캡처 파일')
    ap.add_argument('stream',type=int,nargs='?',default=0,help='tshark tcp.stream 번호 (기본 0)')
    ap.add_argument('--out',default=None,help='결과 .svg 또는 .html 경로')
    ap.add_argument('--list',action='store_true',help='캡처에 포함된 TCP stream 목록')
    args=ap.parse_args()
    if not args.pcap.is_file():ap.error('pcap file not found: '+str(args.pcap))
    if args.list:
        result=subprocess.run(['tshark','-r',str(args.pcap),'-T','fields','-e','tcp.stream'],capture_output=True,text=True)
        if result.returncode:raise SystemExit(result.stderr)
        vals=sorted({int(x.strip()) for x in result.stdout.splitlines() if x.strip().isdigit()})
        print('TCP stream IDs:',', '.join(map(str,vals[:200])))
        return
    if args.stream<0:ap.error('stream >= 0')
    try: analyze(args.pcap,args.stream,args.out or str(args.pcap.with_name(args.pcap.stem+'-stream'+str(args.stream)+'.html')))
    except RuntimeError as e:raise SystemExit('분석 오류: '+str(e))

if __name__=='__main__':main()
