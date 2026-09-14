"""Inspector acceptance verification using synthetic capture only."""
import threading
import app
import analyzer
from scapy.all import Ether, IP, TCP, wrpcap
from playwright.sync_api import sync_playwright, expect


def test_inspector_vendor_warning_and_literal_untrusted_text(tmp_path, monkeypatch):
    from mac_vendor import VendorDatabase
    csv_path = tmp_path / 'vendors.csv'
    csv_path.write_text('Mac Prefix,Vendor Name,Private,Block Type\n00:00:0C,<img src=x onerror=window.macXss=1> Cisco,false,MA-L\n')
    db = VendorDatabase(csv_path)
    monkeypatch.setattr(analyzer, 'get_database', lambda: db)
    capture = tmp_path / 'synthetic.pcap'
    wrpcap(str(capture), [Ether(src='00:00:0c:00:00:01',dst='02:00:00:00:00:01') / IP(src='8.8.8.8',dst='192.0.2.1') / TCP()])
    server = app.create_server(0, settings_path=tmp_path/'model.json')
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(f'http://127.0.0.1:{server.server_port}')
            page.locator('#capture-file').set_input_files(str(capture))
            page.get_by_role('button', name='Inspect 8.8.8.8', exact=True).press('Enter')
            details = page.locator('#node-details')
            expect(details).to_contain_text('00:00:0c:00:00:01 · <img src=x onerror=window.macXss=1> Cisco · low confidence: Vendor suggests network equipment')
            expect(details).to_contain_text('gateway/next-hop')
            expect(details).to_contain_text('MACLookup')
            assert details.locator('img').count() == 0
            assert page.evaluate('window.macXss === undefined')
            page.set_viewport_size({'width':390,'height':844})
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
