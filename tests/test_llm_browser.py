import json
import threading
from pathlib import Path
import pytest
from playwright.sync_api import sync_playwright, expect
import app
import llm_client
import os
import time


@pytest.mark.skipif(os.environ.get('PACKETMAP_TEST_LLM') != '1', reason='Opt-in real model GUI test')
def test_actual_model_through_gui(page_server, tmp_path):
    page = page_server
    page.locator('#demo-button').click()
    expect(page.locator('#explain-button')).to_be_enabled()
    page.locator('#protocol-filter').select_option('service:SSH')
    started = time.perf_counter()
    with page.expect_response(lambda r: r.url.endswith('/api/explain'), timeout=120000) as pending:
        page.locator('#explain-button').click()
    response = pending.value
    result = response.json()
    assert response.status == 200, result
    expect(page.locator('#ai-status')).to_contain_text('2 / 2',timeout=180000)
    expect(page.locator('#ai-result')).to_contain_text('Interpretations')
    expect(page.locator('#ai-result')).to_contain_text('E1')
    assert result['context']['counts_scope'] == 'selected service port hints'
    assert result['context']['evidence'][0]['packets'] == 15
    page.locator('#ai-result details summary').first.click()
    expect(page.locator('#ai-result')).to_contain_text('192.0.2.10')
    print(json.dumps({'elapsed_seconds': time.perf_counter()-started, 'result': result}))
    with page.expect_download() as exported:
        page.locator('#ai-export').click()
    export_path=tmp_path/'local-llm-verification.json'
    exported.value.save_as(export_path)
    batch=json.loads(export_path.read_text())
    assert batch['completed_nodes']==batch['scope_node_count']==2
    assert batch['incomplete'] is False and len(batch['results'])==2
    for entry in batch['results']:
        assert entry['result']['answer']['next_checks']==entry['result']['context']['recommended_checks']
    page.screenshot(path=tmp_path/'local-explanation-geo.png', full_page=True)
    page.set_viewport_size({'width': 390, 'height': 844})
    assert page.evaluate('() => document.documentElement.scrollWidth <= window.innerWidth')


def test_mixed_service_gui_counts_only_selected_packets(page_server, tmp_path):
    from test_scoped_traffic import packet
    from scapy.utils import wrpcap
    capture = tmp_path / 'mixed.pcap'
    wrpcap(str(capture), [packet(45000, 22), packet(22, 45000, True), packet(45001, 443)])
    page = page_server
    page.locator('#capture-file').set_input_files(capture)
    expect(page.locator('#capture-name')).to_have_text(capture.name)
    page.locator('#protocol-filter').select_option('service:SSH')
    expect(page.locator('#connections-body td.numeric').nth(0)).to_have_text('2')
    expect(page.locator('#connections-body td.numeric').nth(1)).to_have_text('108 B')
    expect(page.locator('#metric-packets')).to_have_text('3')
    expect(page.locator('#connections-count')).to_contain_text('service-filtered')



@pytest.fixture
def page_server():
    server = app.create_server(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(f'http://127.0.0.1:{server.server_port}')
            yield page
            browser.close()
    finally:
        server.shutdown()
        server.server_close()


def test_explicit_explanation_plain_text_evidence_and_scope_reset(page_server, monkeypatch):
    calls = []
    def fake(data, settings=None):
        context = llm_client.build_context(data)
        calls.append(data)
        return {'model': 'fixture-model', 'context': context, 'answer': {
            'summary': '<img src=x onerror=alert(1)>',
            'observations': [{'text': 'Port hints only.', 'evidence_ids': ['E1']}],
            'uncertainties': ['No payload inspection.']}}
    monkeypatch.setattr(llm_client, 'explain', fake)
    page = page_server
    expect(page.locator('#explain-button')).to_be_disabled()
    page.locator('#demo-button').click()
    expect(page.locator('#explain-button')).to_be_enabled()
    assert calls == []
    page.locator('#protocol-filter').select_option('service:HTTPS')
    page.locator('#explain-button').click()
    expect(page.locator('#ai-result')).to_contain_text('Port hints only.')
    expect(page.locator('#ai-result img')).to_have_count(0)
    expect(page.locator('#ai-result')).to_contain_text('<img src=x onerror=alert(1)>')
    expect(page.locator('#ai-result')).to_contain_text('E1')
    assert calls[0]['filter'] == 'service:HTTPS'
    assert page.locator('.ai-panel').bounding_box()['height'] <= 430
    assert len(calls[0]['connections']) <= 20
    assert all('names' not in edge and 'macs' not in edge for edge in calls[0]['connections'])
    page.locator('#protocol-filter').select_option('service:SSH')
    expect(page.locator('#ai-result')).to_be_empty()


def test_local_model_failure_is_recoverable(page_server, monkeypatch):
    def fail(data, settings=None):
        raise ValueError('Local model unavailable')
    monkeypatch.setattr(llm_client, 'explain', fail)
    page = page_server
    page.locator('#demo-button').click()
    expect(page.locator('#explain-button')).to_be_enabled()
    page.locator('#explain-button').click()
    expect(page.locator('#ai-status')).to_contain_text('Local model unavailable')
    expect(page.locator('#explain-button')).to_be_enabled()
    expect(page.locator('#demo-button')).to_be_enabled()
    expect(page.locator('#ai-result')).to_be_empty()


def test_local_request_deadline_releases_gui(page_server):
    page = page_server
    page.locator('#demo-button').click()
    expect(page.locator('#explain-button')).to_be_enabled()
    page.evaluate("""() => {
        const original = window.fetch;
        window.fetch = (url, options) => url === '/api/explain'
            ? new Promise((resolve, reject) => {
                window.aiStarted = true;
                options.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
              })
            : original(url, options);
    }""")
    page.clock.install()
    page.locator('#explain-button').click()
    page.wait_for_function('() => window.aiStarted === true')
    page.clock.fast_forward(171000)
    expect(page.locator('#ai-status')).to_contain_text('timed out')
    expect(page.locator('#explain-button')).to_be_enabled()
    expect(page.locator('#ai-result')).to_be_empty()


def test_cancel_discards_late_reply_and_capture_controls_stay_usable(page_server, monkeypatch):
    started, release = threading.Event(), threading.Event()
    def slow(data, settings=None):
        started.set()
        release.wait(5)
        return {'model': 'fixture', 'context': llm_client.build_context(data), 'answer': {
            'summary': 'LATE ANSWER', 'observations': [], 'uncertainties': []}}
    monkeypatch.setattr(llm_client, 'explain', slow)
    page = page_server
    page.locator('#demo-button').click()
    expect(page.locator('#explain-button')).to_be_enabled()
    page.locator('#explain-button').click()
    try:
        assert started.wait(3)
        expect(page.locator('#demo-button')).to_be_enabled()
        expect(page.locator('#protocol-filter')).to_be_enabled()
        page.locator('#ai-cancel').click()
        expect(page.locator('#ai-status')).to_contain_text('Cancelled')
        expect(page.locator('#explain-button')).to_be_enabled()
    finally:
        release.set()
    expect(page.locator('#ai-result')).to_be_empty()
