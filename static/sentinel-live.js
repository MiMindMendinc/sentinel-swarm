(() => {
  const esc = s => String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
  const labels = {observed:'OBSERVED',analysis:'ANALYSIS',challenge:'EVIDENCE CHECK',remediation:'REMEDIATED',verified:'VERIFIED',report:'REPORT'};

  async function status(){
    try {
      const r=await fetch('/api/status'); if(!r.ok) throw new Error();
      const s=await r.json();
      const el=document.querySelector('[data-backend-status]');
      if(el) el.textContent='BACKEND ONLINE';
      return s;
    } catch {
      const el=document.querySelector('[data-backend-status]');
      if(el) el.textContent='BACKEND OFFLINE';
      return null;
    }
  }

  function add(kind, body, agent=''){
    const log=document.querySelector('#chatLog'); if(!log) return;
    const row=document.createElement('div'); row.className=`msg ${kind}`;
    row.innerHTML=`${agent?`<div class="agent">${esc(agent)}</div>`:''}<div class="bubble">${body}</div>`;
    log.appendChild(row); log.scrollTop=log.scrollHeight;
  }

  function evidence(e){
    if(!e) return '';
    return `<pre class="evidence">${esc(e.path)}${e.line?':'+e.line:''}\nSHA256 ${esc(e.sha256)}\n${esc(e.excerpt)}</pre>`;
  }

  function run(task){
    task=(task||'Audit the built-in SSH misconfiguration demo').trim();
    add('user',esc(task));
    const state=document.querySelector('#state'); if(state) state.textContent='SWARM WORKING';
    const proto=location.protocol==='https:'?'wss':'ws';
    const ws=new WebSocket(`${proto}://${location.host}/ws/mission`);
    ws.onopen=()=>ws.send(JSON.stringify({task}));
    ws.onmessage=m=>{
      const d=JSON.parse(m.data);
      if(d.type==='event'){
        const e=d.event;
        add('agent-msg',`<strong>${labels[e.kind]||e.kind.toUpperCase()}</strong><br>${esc(e.message)}${evidence(e.evidence)}`,e.agent);
      } else if(d.type==='complete'){
        if(state) state.textContent='VERIFIED COMPLETE';
        const report=document.querySelector('#reportPath'); if(report) report.textContent=d.report_path;
      }
    };
    ws.onerror=()=>{ if(state) state.textContent='BACKEND OFFLINE'; };
  }

  window.addEventListener('DOMContentLoaded',()=>{
    status();
    const input=document.querySelector('#msgInput');
    document.querySelector('#sendBtn')?.addEventListener('click',()=>run(input?.value||''));
    input?.addEventListener('keydown',e=>{if(e.key==='Enter') run(input.value)});
    document.querySelector('#demoBtn')?.addEventListener('click',()=>run('Audit the built-in SSH misconfiguration demo'));
  });
})();
