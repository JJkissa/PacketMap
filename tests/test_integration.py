"""Real HTTP capture round-trip; run after the sample generator."""
import json
import threading
import urllib.request
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def test_demo_and_upload_agree():
    import app
    server = app.create_server(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f'http://127.0.0.1:{server.server_port}'
    try:
        with urllib.request.urlopen(base + '/api/demo') as response:
            demo = json.load(response)
        with urllib.request.urlopen(base + '/api/config') as response:
            token = json.load(response)['token']
        for filename in ('demo.pcap', 'demo.pcapng'):
            request = urllib.request.Request(base + '/api/analyze', data=(ROOT / 'examples' / filename).read_bytes(), headers={'X-PacketMap-Token': token})
            with urllib.request.urlopen(request) as response:
                result = json.load(response)
            assert result['summary']['packets'] == demo['summary']['packets'] > 0
            assert result['summary']['connections'] == demo['summary']['connections'] > 0
            assert result['dns']
        for asset in ('/', '/app.js', '/style.css'):
            with urllib.request.urlopen(base + asset) as response:
                assert response.status == 200
                assert len(response.read()) > 100
    finally:
        server.shutdown()
        server.server_close()
