"""Browser regression for file-backed request streams stalling in Firefox."""
import threading
from contextlib import contextmanager
from pathlib import Path

import app
from playwright.sync_api import sync_playwright, expect
import pytest


@contextmanager
def upload_page(script):
    server = app.create_server(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page()
            page.add_init_script(script)
            page.goto(f'http://127.0.0.1:{server.server_port}')
            try:
                yield page
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize('stage', ['config', 'upload', 'response'])
def test_stalled_http_aborts_and_unlocks_controls(stage):
    script = """window.stage = STAGE;
        const original = window.fetch.bind(window);
        window.fetch = async (url, options) => {
            const target = window.stage === 'config' ? '/api/config' : '/api/analyze';
            if (url !== target) return original(url, options);
            window.requestStarted = true;
            options?.signal?.addEventListener('abort', () => { window.requestAborted = true; });
            if (window.stage === 'response') return {ok:true, json:()=>new Promise(()=>{})};
            return new Promise(()=>{});
        };""".replace('STAGE', repr(stage))
    with upload_page(script) as page:
        page.clock.install()
        page.locator('#capture-file').set_input_files(
            Path(__file__).resolve().parents[1] / 'examples/demo.pcap')
        page.wait_for_function('window.requestStarted === true')
        page.clock.fast_forward(181000)
        expect(page.locator('#error')).to_contain_text('timed out')
        expect(page.locator('#capture-file')).to_be_enabled()
        expect(page.locator('#demo-button')).to_be_enabled()
        expect(page.locator('#status')).to_be_hidden()
        assert page.evaluate('window.requestAborted === true')
        page.locator('#demo-button').click()
        expect(page.locator('#capture-name')).to_contain_text('Synthetic demo')
        expect(page.locator('#error')).to_be_hidden()


def test_stalled_disk_read_recovers_without_loading_late_result():
    with upload_page("""const read = Blob.prototype.arrayBuffer;
        Blob.prototype.arrayBuffer = function() {
            return new Promise(resolve => { window.finishRead = () => read.call(this).then(resolve); });
        };""") as page:
        page.clock.install()
        page.locator('#capture-file').set_input_files(
            Path(__file__).resolve().parents[1] / 'examples/demo.pcap')
        expect(page.locator('#status')).to_have_text('Reading capture from disk…')
        page.clock.fast_forward(31000)
        expect(page.locator('#error')).to_contain_text('Reading the capture timed out')
        expect(page.locator('#capture-file')).to_be_enabled()
        expect(page.locator('#demo-button')).to_be_enabled()
        expect(page.locator('#status')).to_be_hidden()
        page.evaluate('window.finishRead()')
        expect(page.locator('#capture-name')).to_have_text('No capture loaded')
        expect(page.locator('#error')).to_be_visible()


def test_unreadable_file_explains_recovery_and_allows_retry():
    with upload_page("""window.attempts = 0;
        const read = Blob.prototype.arrayBuffer;
        Blob.prototype.arrayBuffer = function() {
            if (++window.attempts === 1) return Promise.reject(new DOMException('The operation was aborted.', 'AbortError'));
            return read.call(this);
        };""") as page:
        capture = Path(__file__).resolve().parents[1] / 'examples/demo.pcap'
        page.locator('#capture-file').set_input_files(capture)
        expect(page.locator('#error')).to_contain_text('browser could not read')
        expect(page.locator('#error')).to_contain_text('owned by your user')
        expect(page.locator('#capture-file')).to_be_enabled()
        expect(page.locator('#status')).to_be_hidden()
        page.locator('#capture-file').set_input_files(capture)
        expect(page.locator('#capture-name')).to_have_text(capture.name)
        expect(page.locator('#error')).to_be_hidden()


def test_upload_materializes_file_before_starting_http_request():
    server = app.create_server(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page()
            # Model the native file-backed fetch failure at the browser seam.
            # Keep real local file reading, HTTP, analyzer, and rendering intact.
            page.add_init_script("""(() => {
                const original = window.fetch.bind(window);
                window.fetch = (url, options) => {
                    if (options?.body instanceof Blob) {
                        return Promise.reject(new TypeError('File-backed fetch stream unavailable'));
                    }
                    return original(url, options);
                };
            })();""")
            page.goto(f'http://127.0.0.1:{server.server_port}')
            page.locator('#capture-file').set_input_files(
                Path(__file__).resolve().parents[1] / 'examples/demo.pcapng')
            expect(page.locator('#capture-name')).to_have_text('demo.pcapng', timeout=5000)
            expect(page.locator('#error')).to_be_hidden()
            expect(page.locator('#demo-button')).to_be_enabled()
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
