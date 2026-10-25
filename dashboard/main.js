'use strict';
const NS='http://www.w3.org/2000/svg';
const by=id=>document.getElementById(id);
const nice=n=>new Intl.NumberFormat('ko-KR').format(n||0);
const bytes=n=>{let val=n||0;for(const unit of ['B','KB','MB','GB','TB']){if(val<1024)return val.toFixed(unit==='B'?0:1)+' '+unit;val/=1024;}return val.toFixed(1)+' PB'};
const el=(tag,props={},txt)=>{const n=document.createElement(tag);Object.entries(props).forEach(([k,v])=>n.setAttribute(k,v));if(txt!==undefined)n.textContent=txt;return n};
const svg=(tag,attrs={},txt)=>{const n=document.createElementNS(NS,tag);Object.entries(attrs).forEach(([k,v])=>n.setAttribute(k,v));if(txt!==undefined)n.textContent=txt;return n};
function topology(edges){
  const canvas=by('topology');canvas.replaceChildren();const shown=edges.slice(0,8);
  if(!shown.length){canvas.append(svg('text',{x:470,y:190,fill:'#9cb0cb','text-anchor':'middle','font-size':16},'관측된 이벤트가 없습니다'));return;}
  const sources=[...new Set(shown.map(x=>x.src))];const targets=[...new Set(shown.map(x=>`${x.dst}:${x.dst_port}`))];
  const slots=Math.max(4,sources.length,targets.length);
  const height=Math.max(380,slots*61+45);canvas.setAttribute('viewBox',`0 0 940 ${height}`);
  const ypos=(i,amount)=>66 + (height-115)*(i+.5)/amount;
  shown.forEach(e=>{
    const srcy=ypos(sources.indexOf(e.src),sources.length),dsty=ypos(targets.indexOf(`${e.dst}:${e.dst_port}`),targets.length);
    const path=svg('path',{d:`M 262 ${srcy} C 420 ${srcy}, 530 ${dsty}, 678 ${dsty}`,stroke:e.failures?'#fb7185':'#61d6ad','stroke-width':Math.min(8,2+Math.log2(e.count+1)),fill:'none',opacity:.8});
    path.append(svg('title',{},`${e.src} → ${e.dst}:${e.dst_port}, ${e.count}건 (비성공 ${e.failures}건)`));canvas.append(path);
    canvas.append(svg('polygon',{points:`678,${dsty-5} 687,${dsty} 678,${dsty+5}`,fill:e.failures?'#fb7185':'#61d6ad'}));
  });
  function node(text,x,y,fill){canvas.append(svg('rect',{x,y:y-19,width:238,height:38,rx:9,fill,stroke:'#567096'}));canvas.append(svg('text',{x:x+119,y:y+5,'text-anchor':'middle',fill:'#e5effc','font-size':13},text.length>28?text.slice(0,27)+'…':text));}
  sources.forEach((s,i)=>node(s,24,ypos(i,sources.length),'#1d3b64'));
  targets.forEach((s,i)=>node(s,688,ypos(i,targets.length),'#23584e'));
  canvas.append(svg('text',{x:143,y:24,'text-anchor':'middle',fill:'#93a7c4','font-size':13},'SOURCE / CLIENT'));
  canvas.append(svg('text',{x:809,y:24,'text-anchor':'middle',fill:'#93a7c4','font-size':13},'DESTINATION / TCP·UDP'));
}
function renderTimeline(records,at){const slotMap=new Map(records.map(r=>[r.minute,r.count]));const start=Math.floor(at/60)-29;const pts=Array.from({length:30},(_,i)=>slotMap.get(start+i)||0),max=Math.max(1,...pts);const wrap=by('timeline');wrap.replaceChildren();pts.forEach((v,i)=>{const d=el('div',{class:'hbar',style:`height:${Math.max(2,v/max*100)}%`,title:`${new Date((start+i)*60000).toLocaleTimeString('ko-KR')} · ${v}건`});wrap.append(d)});}
function renderTable(records){const body=by('events');body.replaceChildren();if(!records.length){const tr=el('tr');const td=el('td',{colspan:'7',class:'placeholder'},'표시할 흐름 이벤트가 없습니다');tr.append(td);body.append(tr);return;}
  records.forEach(r=>{const tr=el('tr');const values=[r.src_namespace,r.src,r.dst_namespace,`${r.dst}:${r.dst_port}`,r.proto,r.result];values.forEach((v,i)=>{const td=el('td');if(i===5){td.append(el('span',{class:`pill${r.result==='success'?'':' error'}`},v))}else td.textContent=v;tr.append(td)});body.append(tr);});}
function renderCollector(c){const label=by('collector'),detail=by('collector-detail');const state=c?.state||'not-installed';const age=c?.age_seconds;const messages={'connected':'● Hubble Relay 연결됨','connecting':'● Hubble Relay 연결 중','starting':'● 수집기 시작 중','error':'● Relay 연결 오류','offline':'● 수집기 응답 없음','not-installed':'● 수집기 미연결'};
  label.textContent=messages[state]||`● ${state}`;label.className=state==='connected'?'ok':'bad';
  detail.textContent=`최근 상태 ${age===null||age===undefined?'없음':age+'초 전'} · 수신 ${nice(c?.observed)} · 저장 ${nice(c?.forwarded)} · 건너뜀 ${nice(c?.skipped)} · 전송오류 ${nice(c?.post_errors)}`+(c?.last_error?` · 오류: ${c.last_error}`:'');}
async function update(){const minutes=by('window').value, ns=by('namespace').value, port=by('port').value;
  const q=new URLSearchParams({minutes,namespace:ns,port});
  try{const response=await fetch('/api/summary?'+q,{cache:'no-store'});if(!response.ok)throw Error(`HTTP ${response.status}`);const data=await response.json();const m=data.metrics;
    by('total').textContent=nice(m.total);by('success').textContent=nice(m.success);by('failures').textContent=nice(m.denied+m.error);by('bytes').textContent=nice(m.namespaces);
    renderCollector(data.collector);topology(data.edges);renderTimeline(data.timeline,data.generated_at);renderTable(data.latest);
    const select=by('namespace'),old=select.value,options=data.namespaces||[];
    if(select.options.length!==options.length+1||options.some((n,i)=>select.options[i+1]?.value!==n)){
      select.replaceChildren(el('option',{value:''},'전체 네임스페이스'));
      options.forEach(n=>select.append(el('option',{value:n},n)));
      select.value=options.includes(old)?old:'';
    }
    by('status').textContent='● 화면 API 정상 · '+new Date(data.generated_at*1000).toLocaleTimeString('ko-KR');by('status').className='ok';
  }catch(err){by('status').textContent='● API 로드 실패: '+err.message;by('status').className='bad';}}
by('refresh').addEventListener('click',update);by('window').addEventListener('change',update);by('namespace').addEventListener('change',update);by('port').addEventListener('change',update);update();setInterval(update,5000);
