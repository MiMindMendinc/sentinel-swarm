(() => {
  const defaultNote = 'Audit the built-in SSH misconfiguration demo';
  const labels = {
    observed: 'OBSERVED',
    analysis: 'ANALYSIS',
    challenge: 'EVIDENCE CHECK',
    remediation: 'REMEDIATED',
    verified: 'VERIFIED',
    report: 'REPORT'
  };
  let running = false;
  let timeoutId;

  function setRunning(value) {
    running = value;
    document.querySelectorAll('#sendBtn,#demoBtn').forEach(button => {
      button.disabled = value;
    });
  }

  async function status() {
    const element = document.querySelector('[data-backend-status]');
    try {
      const response = await fetch('/api/status', {cache: 'no-store'});
      if (!response.ok) throw new Error(`status ${response.status}`);
      const payload = await response.json();
      if (element) element.textContent = `BACKEND ONLINE · v${payload.version}`;
      return payload;
    } catch {
      if (element) element.textContent = 'BACKEND OFFLINE';
      return null;
    }
  }

  function addMessage(kind, text, agent = '', label = '', evidence = null) {
    const log = document.querySelector('#chatLog');
    if (!log) return;

    const row = document.createElement('div');
    row.classList.add('msg');
    if (kind) row.classList.add(kind);

    if (agent) {
      const agentElement = document.createElement('div');
      agentElement.className = 'agent';
      agentElement.textContent = agent;
      row.appendChild(agentElement);
    }

    const bubble = document.createElement('div');
    bubble.className = 'bubble';
    if (label) {
      const strong = document.createElement('strong');
      strong.textContent = label;
      bubble.appendChild(strong);
      bubble.appendChild(document.createElement('br'));
    }
    bubble.appendChild(document.createTextNode(text));

    if (evidence) {
      const details = document.createElement('pre');
      details.className = 'evidence';
      const line = evidence.line ? `:${evidence.line}` : '';
      details.textContent = `${evidence.path}${line}\nSHA256 ${evidence.sha256}\n${evidence.excerpt}`;
      bubble.appendChild(details);
    }
    row.appendChild(bubble);
    log.appendChild(row);
    log.scrollTop = log.scrollHeight;
  }

  function finish(stateText) {
    window.clearTimeout(timeoutId);
    const state = document.querySelector('#state');
    if (state && stateText) state.textContent = stateText;
    setRunning(false);
  }

  function run(note) {
    if (running) return;
    const normalizedNote = (note || defaultNote).trim();
    if (!normalizedNote) return;

    setRunning(true);
    addMessage('user', normalizedNote);
    const state = document.querySelector('#state');
    if (state) state.textContent = 'SWARM WORKING';

    const protocol = location.protocol === 'https:' ? 'wss' : 'ws';
    const socket = new WebSocket(`${protocol}://${location.host}/ws/mission`);
    let completed = false;

    timeoutId = window.setTimeout(() => {
      if (socket.readyState < WebSocket.CLOSING) socket.close(1000, 'Client timeout');
      addMessage('agent-msg', 'The mission stream exceeded the 30-second client timeout.', 'SYSTEM', 'SAFE TIMEOUT');
      finish('MISSION TIMED OUT');
    }, 30000);

    socket.onopen = () => socket.send(JSON.stringify({
      scenario_id: 'ssh-misconfig',
      task: normalizedNote
    }));

    socket.onmessage = message => {
      let data;
      try {
        data = JSON.parse(message.data);
      } catch {
        addMessage('agent-msg', 'The backend returned an unreadable message.', 'SYSTEM', 'PROTOCOL ERROR');
        socket.close(1002, 'Invalid JSON');
        return;
      }

      if (data.type === 'event') {
        const event = data.event;
        addMessage(
          'agent-msg',
          event.message,
          event.agent,
          labels[event.kind] || String(event.kind).toUpperCase(),
          event.evidence
        );
      } else if (data.type === 'complete') {
        completed = true;
        const report = document.querySelector('#reportPath');
        if (report) report.textContent = data.report_path;
        const anchor = data.manifest_sha256 ? ` Manifest SHA-256: ${data.manifest_sha256}.` : '';
        addMessage(
          'agent-msg',
          `Evidence and report persisted locally for mission ${data.mission_id}.${anchor}`,
          'SYSTEM',
          data.verified ? 'MISSION VERIFIED' : 'MISSION UNVERIFIED'
        );
        finish(data.verified ? 'VERIFIED COMPLETE' : 'VERIFICATION FAILED');
        socket.close(1000);
      } else if (data.type === 'error') {
        addMessage('agent-msg', data.message || 'Mission failed.', 'SYSTEM', 'SAFE FAILURE');
        finish('MISSION ERROR');
      }
    };

    socket.onerror = () => {
      addMessage('agent-msg', 'The local backend could not be reached.', 'SYSTEM', 'CONNECTION ERROR');
      finish('BACKEND OFFLINE');
    };

    socket.onclose = event => {
      if (!completed && event.code !== 1000 && state?.textContent === 'SWARM WORKING') {
        state.textContent = 'MISSION ENDED';
      }
      window.clearTimeout(timeoutId);
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
    document.querySelector('#demoBtn')?.addEventListener('click', () => {
      if (input) input.value = defaultNote;
      run(defaultNote);
    });
  });
})();
