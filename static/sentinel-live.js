(() => {
  const esc = value => String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[char]));
  const labels = {
    observed: 'OBSERVED', analysis: 'ANALYSIS', challenge: 'EVIDENCE CHECK',
    remediation: 'REMEDIATED', verified: 'VERIFIED', report: 'REPORT'
  };
  let running = false;

  function setRunning(value) {
    running = value;
    document.querySelectorAll('#sendBtn,#demoBtn').forEach(button => {
      button.disabled = value;
      button.style.opacity = value ? '.55' : '1';
      button.style.cursor = value ? 'not-allowed' : 'pointer';
    });
  }

  async function status() {
    const el = document.querySelector('[data-backend-status]');
    try {
      const response = await fetch('/api/status', {cache: 'no-store'});
      if (!response.ok) throw new Error(`status ${response.status}`);
      const payload = await response.json();
      if (el) el.textContent = `BACKEND ONLINE · v${payload.version}`;
      return payload;
    } catch {
      if (el) el.textContent = 'BACKEND OFFLINE';
      return null;
    }
  }

  function add(kind, body, agent = '') {
    const log = document.querySelector('#chatLog');
    if (!log) return;
    const row = document.createElement('div');
    row.className = `msg ${kind}`;
    row.innerHTML = `${agent ? `<div class="agent">${esc(agent)}</div>` : ''}<div class="bubble">${body}</div>`;
    log.appendChild(row);
    log.scrollTop = log.scrollHeight;
  }

  function evidence(item) {
    if (!item) return '';
    return `<pre class="evidence">${esc(item.path)}${item.line ? ':' + item.line : ''}\nSHA256 ${esc(item.sha256)}\n${esc(item.excerpt)}</pre>`;
  }

  function run(task) {
    if (running) return;
    task = (task || 'Audit the built-in SSH misconfiguration demo').trim();
    if (!task) return;

    setRunning(true);
    add('user', esc(task));
    const state = document.querySelector('#state');
    if (state) state.textContent = 'SWARM WORKING';

    const protocol = location.protocol === 'https:' ? 'wss' : 'ws';
    const socket = new WebSocket(`${protocol}://${location.host}/ws/mission`);
    let completed = false;

    socket.onopen = () => socket.send(JSON.stringify({task}));
    socket.onmessage = message => {
      const data = JSON.parse(message.data);
      if (data.type === 'event') {
        const event = data.event;
        add(
          'agent-msg',
          `<strong>${labels[event.kind] || esc(event.kind).toUpperCase()}</strong><br>${esc(event.message)}${evidence(event.evidence)}`,
          event.agent
        );
      } else if (data.type === 'complete') {
        completed = true;
        if (state) state.textContent = 'VERIFIED COMPLETE';
        const report = document.querySelector('#reportPath');
        if (report) report.textContent = data.report_path;
        add('agent-msg', `<strong>MISSION COMPLETE</strong><br>Evidence and report persisted locally for mission <code>${esc(data.mission_id)}</code>.`, 'SYSTEM');
        setRunning(false);
        socket.close(1000);
      } else if (data.type === 'error') {
        if (state) state.textContent = 'MISSION ERROR';
        add('agent-msg', `<strong>SAFE FAILURE</strong><br>${esc(data.message || 'Mission failed.')}`, 'SYSTEM');
        setRunning(false);
      }
    };
    socket.onerror = () => {
      if (state) state.textContent = 'BACKEND OFFLINE';
      add('agent-msg', '<strong>CONNECTION ERROR</strong><br>The local backend could not be reached.', 'SYSTEM');
      setRunning(false);
    };
    socket.onclose = event => {
      if (!completed && event.code !== 1000) {
        if (state && state.textContent === 'SWARM WORKING') state.textContent = 'MISSION ENDED';
      }
      setRunning(false);
    };
  }

  window.addEventListener('DOMContentLoaded', () => {
    status();
    const input = document.querySelector('#msgInput');
    document.querySelector('#sendBtn')?.addEventListener('click', () => run(input?.value || ''));
    input?.addEventListener('keydown', event => {
      if (event.key === 'Enter') run(input.value);
    });
    document.querySelector('#demoBtn')?.addEventListener('click', () => run('Audit the built-in SSH misconfiguration demo'));
  });
})();
