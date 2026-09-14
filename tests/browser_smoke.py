"""End-to-end browser checks against a running local PacketMap server.
Run: .venv/bin/python tests/browser_smoke.py [http://127.0.0.1:8765]
Requires developer-only Playwright and its Chromium browser.
"""
import json
from pathlib import Path
import sys
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
URL = sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8765'
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page(viewport={'width': 1440, 'height': 1100}, accept_downloads=True)
    errors = []
    page.on('pageerror', lambda error: errors.append(str(error)))
    page.goto(URL)
    page.locator('#demo-button').click()
    expect(page.locator('#metric-packets')).not_to_have_text('—', timeout=30000)
    assert page.locator('#network-svg [tabindex="0"]').count() > 1
    packets = page.locator('#metric-packets').inner_text()
    page.locator('#network-svg [tabindex="0"]').first.click()
    assert len(page.locator('#node-details').inner_text()) > 30
    page.locator('#zoom-in').click()
    assert page.locator('#zoom-level').inner_text() != '100%'
    page.locator('#reset-view').click()
    page.locator('#graph-search').fill('no-such-endpoint.invalid')
    assert page.locator('#network-svg [tabindex="0"]').count() == 0
    page.locator('#graph-search').fill('')
    assert page.locator('#network-svg [tabindex="0"]').count() > 1
    page.locator('#protocol-filter').select_option('TCP')
    assert page.locator('#network-svg [tabindex="0"]').count() > 0
    page.locator('#protocol-filter').select_option('')
    with page.expect_download() as pending:
        page.locator('#export-button').click()
    download = pending.value
    report = json.loads(Path(download.path()).read_text())
    assert report['summary']['packets'] > 0
    for name in ('demo.pcap', 'demo.pcapng'):
        page.locator('#capture-file').set_input_files(ROOT / 'examples' / name)
        expect(page.locator('#capture-name')).to_contain_text(name, timeout=30000)
        expect(page.locator('#demo-button')).to_be_enabled(timeout=30000)
        assert page.locator('#metric-packets').inner_text() == packets
        assert not page.locator('#error').is_visible()
    page.screenshot(path=str(ROOT / 'tests' / 'desktop-screenshot.png'), full_page=True)
    page.set_viewport_size({'width': 390, 'height': 844})
    page.screenshot(path=str(ROOT / 'tests' / 'mobile-screenshot.png'), full_page=True)
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth + 1'), 'Page overflows on mobile'
    page.locator('#capture-file').set_input_files({'name': 'broken.pcap', 'mimeType': 'application/octet-stream', 'buffer': b'not a packet capture'})
    page.locator('#error').wait_for(state='visible')
    assert 'capture' in page.locator('#error').inner_text().lower()
    # Packet-derived names must remain text, even if they resemble HTML.
    import tempfile
    from scapy.all import Ether, IP, UDP, DNS, DNSRR, PcapWriter, wrpcap
    with tempfile.TemporaryDirectory() as folder:
        capture = Path(folder) / 'unicode-測試.pcap'
        hostile_name = '<img src=x onerror=alert(1)>.example'
        packet = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src='192.0.2.53', dst='192.0.2.10') / UDP(sport=53, dport=41000) / DNS(qr=1, an=DNSRR(rrname=hostile_name, rdata='192.0.2.10'))
        wrpcap(str(capture), [packet])
        page.locator('#capture-file').set_input_files(capture)
        expect(page.locator('#capture-name')).to_have_text(capture.name, timeout=30000)
        page.locator('#network-svg [aria-label^="Inspect 192.0.2.10"]').click()
        expect(page.locator('#node-details')).to_contain_text(hostile_name)
        assert page.locator('#node-details img').count() == 0
        empty = Path(folder) / 'empty.pcap'
        with PcapWriter(str(empty), linktype=1) as writer:
            writer.write_header(None)
        page.locator('#capture-file').set_input_files(empty)
        expect(page.locator('#capture-name')).to_have_text('empty.pcap', timeout=30000)
        expect(page.locator('#metric-packets')).to_have_text('0')
        assert page.locator('#network-svg [tabindex="0"]').count() == 0
        assert page.locator('#warnings').is_visible()
    assert not errors, errors
    print(json.dumps({'status': 'passed', 'demo_packets_display': packets, 'export_packets': report['summary']['packets'], 'checks': ['demo', 'node selection', 'zoom/reset', 'search', 'protocol filter', 'JSON export', 'PCAP upload', 'PCAPNG upload', 'mobile overflow', 'invalid file error', 'Unicode filename', 'hostile DNS rendered as text', 'empty capture', 'no JS exceptions']}))
    browser.close()
