"""Opt-in native Snap Firefox check, isolated from personal browser profiles.

Start: geckodriver --host 127.0.0.1 --port 4444
Run: .venv/bin/python tests/probe_system_firefox.py /path/to/capture.pcapng
For a browser-blocked file, append --expect-read-error.
Captures stay local and are never modified.
"""
import argparse
import json
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app
from analyzer import analyze

BASE = 'http://127.0.0.1:4444'


def call(method, path, data=None):
    req = urllib.request.Request(
        BASE + path, data=None if data is None else json.dumps(data).encode(),
        method=method, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=40) as response:
        return json.load(response)['value']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--expect-read-error', action='store_true')
    args = parser.parse_args()
    capture = args.capture.resolve(strict=True)
    expected_packets = cast(dict[str, Any], analyze(capture))['summary']['packets']
    print('Driver ready:', call('GET', '/status'), flush=True)
    server = app.create_server(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    session = None
    try:
        session = call('POST', '/session', {'capabilities': {'alwaysMatch': {
            'browserName': 'firefox',
            'moz:firefoxOptions': {'args': ['-headless']},
        }}})['sessionId']
        prefix = '/session/' + session
        call('POST', prefix + '/url', {'url': f'http://127.0.0.1:{server.server_port}'})
        element = call('POST', prefix + '/element', {'using': 'css selector', 'value': '#capture-file'})
        element_id = element['element-6066-11e4-a52e-4f735466cecf']
        call('POST', prefix + '/element/' + element_id + '/value', {'text': str(capture)})
        state = {}
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            state = call('POST', prefix + '/execute/sync', {'script': """
                return {
                    name:document.getElementById('capture-name').textContent,
                    packets:document.getElementById('metric-packets').textContent,
                    error:document.getElementById('error').textContent,
                    busy:document.getElementById('capture-file').disabled,
                    statusHidden:document.getElementById('status').hidden,
                };
            """, 'args': []})
            if not state['busy']:
                break
            time.sleep(0.1)
        print(state, flush=True)
        assert not state['busy'] and state['statusHidden'], state
        if args.expect_read_error:
            assert 'browser could not read' in state['error'], state
            assert 'owned by your user' in state['error'], state
            assert state['name'] == 'No capture loaded', state
        else:
            assert state['name'] == capture.name and not state['error'], state
            # UI uses en-US integer grouping.
            assert int(state['packets'].replace(',', '')) == expected_packets, state
        print('PASS', flush=True)
    finally:
        if session:
            call('DELETE', '/session/' + session)
        server.shutdown()
        server.server_close()
