from app.main import app
from app.mission import ROOT, run_mission
from fastapi.testclient import TestClient

client = TestClient(app)

def test_status_truthful():
    r = client.get('/api/status')
    assert r.status_code == 200
    truth = r.json()['truth']
    assert truth['fixture_analysis'] is True
    assert truth['network_scan'] is False
    assert truth['shell'] is False

def test_mission_real_patch_and_report():
    out = run_mission('test fixture')
    assert out.status == 'completed'
    assert [e.agent for e in out.events] == ['RECON','EXPLOIT-ANALYSIS','THREAT-MODEL','SECURE-CODING','RECON','REPORT-WRITER']
    report = ROOT / out.report_path
    assert report.exists()
    target = report.parent / 'sshd_config'
    text = target.read_text()
    assert 'PermitRootLogin no' in text
    assert 'PasswordAuthentication no' in text
    assert 'PermitRootLogin yes' not in text

def test_websocket_streams_real_mission():
    with client.websocket_connect('/ws/mission') as ws:
        ws.send_json({'task':'websocket test'})
        events=[]
        while True:
            msg=ws.receive_json()
            if msg['type']=='event':
                events.append(msg['event'])
            elif msg['type']=='complete':
                assert msg['report_path'].endswith('/report.md')
                break
        assert len(events)==6
        assert events[-1]['agent']=='REPORT-WRITER'
