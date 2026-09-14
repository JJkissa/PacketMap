"""Real Chromium regression; temporary loopback server and synthetic captures only.
Run: .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_timeline_browser.py
"""
import json
import re
import pytest
import threading
from pathlib import Path

import app
from playwright.sync_api import sync_playwright, expect
from test_timeline import capture_result


@pytest.mark.parametrize('times,width', [([0, 4_000_000_000], 1), ([*range(2001), 4_000_000_000], 2)])
def test_sparse_timeline_browser(tmp_path, times, width):
    result = capture_result(tmp_path, times)
    server = app.create_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(accept_downloads=True)
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(f'http://127.0.0.1:{server.server_port}')
            expect(page.locator('#demo-button')).to_be_enabled()
            page.locator('#capture-file').set_input_files(tmp_path / 'timeline.pcap')
            expect(page.locator('#capture-name')).to_have_text('timeline.pcap')
            path = page.locator('#timeline-chart path[fill="none"]')
            # Inspect actual SVG geometry, not a mocked chart or helper call.
            vertices = path.evaluate("e => e.getAttribute('d').match(/-?\\d+(?:\\.\\d+)?(?:e[+-]?\\d+)?/gi).map(Number)")
            points = list(zip(vertices[::2], vertices[1::2]))
            assert any(y1 == y2 == 104 and x1 < 330 < x2
                       for (x1, y1), (x2, y2) in zip(points, points[1:])), 'Idle gap must be a zero-traffic SVG segment'
            assert len(points) == 4 * len(result['timeline']) <= 8000
            assert page.locator('#timeline-chart circle').count() == len(result['timeline']) <= 2000
            expect(page.locator('#timeline-chart')).to_contain_text(f'{width} seconds per interval')
            expect(page.locator('#timeline-chart svg')).to_have_attribute('aria-label', re.compile(f'{width} seconds per interval'))
            # Each horizontal top covers precisely the exported interval width.
            span = result['timeline'][-1]['time'] + width - result['timeline'][0]['time']
            assert points[2][0] - points[1][0] == pytest.approx(648 * width / span)
            with page.expect_download() as pending:
                page.locator('#export-button').click()
            exported = json.loads(Path(pending.value.path()).read_text())
            assert exported == result
            assert not errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
