from pathlib import Path
from urllib.parse import urlparse
from playwright.sync_api import expect
from test_llm_browser import page_server
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap


def test_offline_geography_public_coordinates_scope_and_mobile(page_server,tmp_path):
    capture=tmp_path/'GeoIP-synthetic-verification.pcap'
    packets=[]
    for peer,port in [('8.8.8.8',22),('1.1.1.1',443)]:
        for i in range(6):
            packet=Ether()/IP(src='10.0.0.8',dst=peer)/TCP(sport=45000+i,dport=port)/Raw(b'verification fixture')
            packet.time=1700000000+i
            packets.append(packet)
    wrpcap(str(capture),packets)
    page=page_server;requests=[];errors=[]
    page.on('request',lambda request:requests.append(request.url))
    page.on('pageerror',lambda error:errors.append(str(error)))
    page.set_viewport_size({'width':1366,'height':1000})
    page.locator('#capture-file').set_input_files(capture)
    expect(page.locator('#capture-name')).to_have_text(capture.name)
    page.locator('#map-view').select_option('geography')
    expect(page.locator('#geo-count')).to_have_text('3 scoped endpoints · 2 located · 1 unmapped · 2 location markers')
    expect(page.locator('#geo-svg .geo-land')).to_have_count(177)
    expect(page.locator('#geo-svg [data-geo-marker]')).to_have_count(2)
    assert not page.evaluate('() => document.documentElement.scrollWidth > innerWidth')
    page.screenshot(path=tmp_path/'geo-desktop.png',full_page=True)
    before=page.locator('#geo-svg').get_attribute('viewBox')
    page.locator('#geo-in').click()
    assert page.locator('#geo-svg').get_attribute('viewBox')!=before
    page.locator('#geo-fit').click()
    assert page.locator('#geo-svg').get_attribute('viewBox')==before
    page.locator('#geo-node-list button').filter(has_text='8.8.8.8').click()
    page.locator('#analysis-scope').select_option('selected')
    expect(page.locator('#geo-count')).to_have_text('1 scoped endpoints · 1 located · 0 unmapped · 1 location markers')
    page.set_viewport_size({'width':390,'height':844})
    assert not page.evaluate('() => document.documentElement.scrollWidth > innerWidth')
    page.screenshot(path=tmp_path/'geo-mobile.png',full_page=True)
    assert errors==[]
    assert all(urlparse(url).hostname=='127.0.0.1' for url in requests)
