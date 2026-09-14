"""Opt-in real-file browser regression; the private capture is never committed.

PACKETMAP_TEST_CAPTURE=/absolute/path.pcapng .venv/bin/python -m pytest \
    tests/test_local_capture.py -q
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest


@pytest.mark.skipif(not os.environ.get('PACKETMAP_TEST_CAPTURE'),
                    reason='Set PACKETMAP_TEST_CAPTURE to test a local capture')
def test_cold_server_browser_upload(tmp_path):
    from playwright.sync_api import sync_playwright, expect

    root = Path(__file__).resolve().parents[1]
    capture = Path(os.environ['PACKETMAP_TEST_CAPTURE']).resolve(strict=True)
    # A separate process tests cold-start imports, unlike an in-process server
    # whose analyzer may already have been imported by another test.
    server = subprocess.Popen(
        [sys.executable, '-u', str(root / 'app.py'), '--no-browser', '--port', '0'],
        cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        import selectors
        with selectors.DefaultSelector() as selector:
            selector.register(server.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=10), 'Server did not start within 10 seconds'
        line = server.stdout.readline().strip()
        assert line.startswith('PacketMap: http://127.0.0.1:'), line
        url = line.removeprefix('PacketMap: ')
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(accept_downloads=True)
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(url)
            started = time.perf_counter()
            page.locator('#capture-file').set_input_files(capture)
            expect(page.locator('#capture-name')).to_have_text(capture.name, timeout=10000)
            expect(page.locator('#demo-button')).to_be_enabled()
            expect(page.locator('#error')).to_be_hidden()
            assert not errors, errors
            with page.expect_download() as pending:
                page.locator('#export-button').click()
            report = json.loads(Path(pending.value.path()).read_text())
            assert report['summary']['packets'] > 0
            print(f"Cold browser upload: {time.perf_counter() - started:.3f}s; "
                  f"{report['summary']['packets']} packets")
            browser.close()
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
        server.stdout.close()
        server.stderr.close()
