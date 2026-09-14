"""Real captures through HTTP and GUI: no mocked analysis responses."""
import threading

import pytest
from playwright.sync_api import sync_playwright, expect
from scapy.all import Ether, IP, TCP, UDP, PcapWriter, PcapNgWriter
import app

SERVICES = {
    'RDP': (TCP, 3389), 'SSH': (TCP, 22), 'Telnet': (TCP, 23),
    'HTTP': (TCP, 80), 'HTTPS': (TCP, 443), 'DNS': (UDP, 53),
    'FTP': (TCP, 21), 'SMTP': (TCP, 25), 'IMAP': (TCP, 143),
    'POP3': (TCP, 110), 'SMB': (TCP, 445), 'NTP': (UDP, 123),
    'SNMP': (UDP, 161), 'LDAP': (TCP, 389), 'DHCP': (UDP, 67),
    'mDNS': (UDP, 5353),
}


@pytest.mark.parametrize('browser_name', ['chromium', 'firefox'])
@pytest.mark.parametrize('extension', ['pcap', 'pcapng'])
def test_service_dropdown_filters_real_capture(tmp_path, browser_name, extension):
    capture = tmp_path / ('services.' + extension)
    writer_class = PcapWriter if extension == 'pcap' else PcapNgWriter
    with writer_class(str(capture)) as writer:
        for index, (transport, port) in enumerate(SERVICES.values(), 1):
            # Alternate request/reply to verify source as well as destination ports.
            layer = transport(sport=port if index % 2 else 45000,
                              dport=45000 if index % 2 else port)
            writer.write(Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') /
                         IP(src='192.0.2.100', dst=f'198.51.100.{index}') / layer)
    server = app.create_server(0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with sync_playwright() as playwright:
            browser = getattr(playwright, browser_name).launch()
            page = browser.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(f'http://127.0.0.1:{server.server_port}')
            page.locator('#capture-file').set_input_files(capture)
            expect(page.locator('#capture-name')).to_have_text(capture.name)
            dropdown = page.locator('#protocol-filter')
            expect(dropdown.locator('option[value="service:RDP"]')).to_have_count(1)
            expect(dropdown).to_be_enabled()
            for index, name in enumerate(SERVICES, 1):
                dropdown.select_option('service:' + name)
                expect(page.locator('#connections-body tr')).to_have_count(1)
                expect(page.locator('#connections-body')).to_contain_text(f'198.51.100.{index}')
                expect(page.locator('.network-edge')).to_have_count(1)
                expect(page.locator('.network-node')).to_have_count(2)
                expect(page.locator('#metric-packets')).to_have_text(str(len(SERVICES)))
            dropdown.select_option('service:SSH')
            page.locator('#graph-search').fill('no-match')
            expect(page.locator('.network-edge')).to_have_count(0)
            expect(page.locator('#connections-body')).to_contain_text('No matching connections')
            page.locator('#reset-view').click()
            expect(dropdown).to_have_value('')
            expect(page.locator('#connections-body tr')).to_have_count(len(SERVICES))
            dropdown.select_option('TCP')
            expect(page.locator('#connections-body tr')).to_have_count(
                sum(transport is TCP for transport, _ in SERVICES.values()))
            assert not errors, errors
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
