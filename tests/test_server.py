import importlib.util
import json
import threading
import urllib.request
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_server_serves_local_config_and_rejects_untrusted_requests():
    assert (ROOT / 'app.py').exists(), 'Local app server has not been implemented'
    spec = importlib.util.spec_from_file_location('packetmap_server', ROOT / 'app.py')
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    server = app.create_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_port}'
    try:
        with urllib.request.urlopen(base + '/api/config') as response:
            config = json.load(response)
            assert len(config['token']) >= 32
            assert response.headers['Cache-Control'] == 'no-store'
        for headers in ({}, {'X-PacketMap-Token': config['token'], 'Origin': 'https://evil.example'}):
            request = urllib.request.Request(base + '/api/analyze', data=b'bad', headers=headers)
            try:
                urllib.request.urlopen(request)
                assert False, 'Untrusted upload accepted'
            except urllib.error.HTTPError as error:
                assert error.code == 403
        request = urllib.request.Request(base + '/api/config', headers={'Host': 'evil.example'})
        try:
            urllib.request.urlopen(request)
            assert False, 'Untrusted Host accepted'
        except urllib.error.HTTPError as error:
            assert error.code == 403
        request = urllib.request.Request(base + '/api/analyze', data=b'not a capture', headers={'X-PacketMap-Token': config['token']})
        try:
            urllib.request.urlopen(request)
            assert False, 'Invalid capture accepted'
        except urllib.error.HTTPError as error:
            assert error.code == 400
            assert json.load(error)['error']
    finally:
        server.shutdown()
        server.server_close()
