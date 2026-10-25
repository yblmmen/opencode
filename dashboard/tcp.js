/* TCP 4-tuple lifecycle explorer. Pure browser render; no external libraries. */
(() => {
'use strict';
const $ = id => document.getElementById(id);
let search = null, anchor = null, inFlight = false;
function elt(tag, cls='', text='') {const node=document.createElement(tag);if(cls)node.className=cls;node.textContent=text;return node;}
function fmt(ms){return new Date(ms).toLocaleString('ko-KR',{hour12:false,month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',fractionalSecondDigits:3});}
function clear(node){node.replaceChildren();}
const flagBadge = flags => flags||'(플래그 미제공)';
function renderConnections(data){
  const host=$('tcp-connections');clear(host);
  $('tcp-matches').textContent=`검색 범위 ${data.matching_events.toLocaleString()}건 관측 · 연결 구간 ${data.connections.length}개${data.truncated?' · 일부 결과 제한':''}`;
  if(!data.connections.length){host.append(elt('div','tcp-empty','검색한 IP의 TCP 이벤트가 없습니다. 검색기간 또는 IP를 확인하세요.')); return;}
  data.connections.forEach(c=>{
    const btn=elt('button','tcp-connection'+(anchor===c.anchor_id?' active':''));
    btn.type='button';
    btn.append(elt('strong','',`${c.client_ip}:${c.client_port} → ${c.server_ip}:${c.server_port}`));
    btn.append(elt('small','',`${fmt(c.start_ms)} · ${c.event_count}건 · ${c.status}${!c.initiator_observed?' · 시작 방향 추정':''}`));
    btn.addEventListener('click',()=>{anchor=c.anchor_id;renderConnections(data);loadLifecycle();});
    host.append(btn);
  });
  if(anchor===null || !data.connections.some(x=>x.anchor_id===anchor)){anchor=data.connections[0].anchor_id;renderConnections(data);loadLifecycle();}
}
function stageText(stage){return `${stage.label} — ${stage.note}${stage.found?' · '+fmt(stage.ts_ms):''}`;}
function renderLifecycle(d){
  const host=$('tcp-life');clear(host);
  const header=elt('div','tcp-overview');
  header.append(elt('h3','',`${d.connection.client_ip}:${d.connection.client_port} ↔ ${d.connection.server_ip}:${d.connection.server_port}`));
  header.append(elt('div','',`3-way: ${d.handshake}`));
  header.append(elt('div','',`종료: ${d.termination}`));
  host.append(header);
  const phases=elt('div','tcp-stages');d.stages.forEach(s=>phases.append(elt('div','tcp-stage '+(s.found?'found':'missing'),stageText(s))));host.append(phases);
  if(d.issues.length){const issues=elt('div','tcp-issues');
    for(const x of d.issues){const line=elt('div','tcp-issue '+x.severity);
      line.append(elt('strong','',`${fmt(x.ts_ms)} · ${x.message}`));line.append(elt('p','',x.evidence));issues.append(line);}
    host.append(issues);}
  const tip=elt('p','tcp-note','아래 화살표는 관측된 Hubble TCP 이벤트만 표시합니다. 동일 패킷이 여러 관측 지점에서 나타날 수 있습니다.');host.append(tip);
  const seq=elt('div','tcp-sequence');
  seq.append(elt('div','tcp-seq-head','CLIENT                                      SERVER'));
  for(const e of d.events){
    const row=elt('div','tcp-seq-row'+(e.result==='denied'?' denied':(e.flags.includes('RST')?' reset':'')));
    row.append(elt('span','tcp-seq-time',fmt(e.ts_ms)));
    row.append(elt('span','tcp-seq-arrow',e.side==='client'?'────────→':'←────────'));
    row.append(elt('span','tcp-seq-flags',`${flagBadge(e.flags)} ${e.result==='denied'?'· DROPPED':''}`));
    const detail=elt('span','tcp-seq-detail',`${e.src}:${e.src_port} → ${e.dst}:${e.dst_port} · ${e.node_name||'-'}${e.drop_reason?' · '+e.drop_reason:''}`);
    row.title=detail.textContent;row.append(detail);seq.append(row);
  }
  host.append(seq);
  d.notes.forEach(n=>host.append(elt('p','tcp-note',n)));
  if(d.truncated)host.append(elt('p','tcp-note','연결 이벤트가 많아 처음 240건만 표시했습니다.'));
}
async function getJson(path){const r=await fetch(path,{cache:'no-store'});const data=await r.json();if(!r.ok)throw Error(data.error||`HTTP ${r.status}`);return data;}
async function loadLifecycle(){if(anchor===null || !search)return;
  try {const q=new URLSearchParams({...search,anchor_id:String(anchor)});
    const d=await getJson('/api/tcp/lifecycle?'+q);
    if(anchor===d.connection.anchor_id)renderLifecycle(d);
  }catch(err){$('tcp-life').textContent='연결 상세 조회 실패: '+err.message;}
}
async function reload(){if(!search||inFlight)return;inFlight=true;
  try{const q=new URLSearchParams(search);const d=await getJson('/api/tcp/connections?'+q);renderConnections(d);
       if(anchor!==null)await loadLifecycle();$('tcp-error').textContent='';}
  catch(err){$('tcp-error').textContent='IP 검색 실패: '+err.message;}
  finally{inFlight=false;}
}
$('tcp-search-form').addEventListener('submit',e=>{e.preventDefault();
  const ip=$('tcp-ip').value.trim(),peer=$('tcp-peer').value.trim(),port=$('tcp-port').value.trim();
  search={ip,peer,port:port||'0',minutes:$('tcp-window').value};anchor=null;
  if(!ip){$('tcp-error').textContent='검색할 IP를 입력하세요.';return;}
  reload();
});
$('tcp-window').addEventListener('change',()=>{if(search){search.minutes=$('tcp-window').value;anchor=null;reload();}});
setInterval(()=>{if(search)reload();},10000);
})();
