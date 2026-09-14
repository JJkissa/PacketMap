import csv
import importlib.util


def database(tmp_path, rows):
    path = tmp_path / 'vendors.csv'
    with path.open('w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['Mac Prefix', 'Vendor Name', 'Private', 'Block Type', 'Last Updated'])
        w.writerows(rows)
    return path


def test_analyzer_annotations_do_not_change_counters(tmp_path, monkeypatch):
    import analyzer
    from mac_vendor import get_database
    from scapy.all import Ether, IP, TCP, wrpcap
    path = database(tmp_path, [['00:00:0C', 'Cisco Systems, Inc', 'false', 'MA-L', '2026/01/01']])
    capture = tmp_path / 'synthetic.pcap'
    packet = Ether(src='00:00:0c:00:00:01', dst='02:00:00:00:00:02') / IP(src='8.8.8.8', dst='192.0.2.1') / TCP()
    wrpcap(str(capture), [packet, packet])
    baseline = analyzer.analyze(capture)
    assert all('mac_vendor' in n for n in baseline['nodes']), 'annotations missing'
    monkeypatch.setattr(analyzer, 'get_database', lambda: get_database(path))
    result = analyzer.analyze(capture)
    for key in ('summary', 'edges', 'protocols', 'timeline', 'warnings'):
        assert result[key] == baseline[key]
    for a, b in zip(baseline['nodes'], result['nodes']):
        assert {k:v for k,v in a.items() if k != 'mac_vendor'} == {k:v for k,v in b.items() if k != 'mac_vendor'}
        assert len(b['mac_vendor']) == len(b['macs']) <= 32
    r = result['nodes'][0]['mac_vendor'][0]
    assert r['vendor'] == 'Cisco Systems, Inc'
    assert 'next-hop' in r['warning'] and 'remote endpoint' in r['warning']


def test_longest_prefix(tmp_path):
    assert importlib.util.find_spec('mac_vendor'), 'offline resolver is missing'
    from mac_vendor import get_database
    path = database(tmp_path, [
        ['00:11:22', 'Large', 'false', 'MA-L', '2026/01/01'],
        ['00-11-22-3', 'Medium', 'false', 'MA-M', '2026/01/01'],
        ['00:11:22:33:4', 'Small, Inc.', 'false', 'MA-S', '2026/01/01'],
    ])
    db = get_database(path)
    for mac, vendor, bits in [('00:11:22:33:44:55', 'Small, Inc.', 36), ('00-11-22-35-44-55', 'Medium', 28), ('001122454455', 'Large', 24)]:
        record = db.lookup(mac)
        assert record['vendor'] == vendor
        assert record['prefix_bits'] == bits
        assert record['mac'] == ':'.join(mac.replace(':', '').replace('-', '').upper()[i:i+2] for i in range(0,12,2))
        assert 'next-hop' in record['warning']
    assert get_database(path) is db


def test_unsafe_addresses_privacy_and_missing_database(tmp_path):
    from mac_vendor import get_database
    path = database(tmp_path, [
        ['00:11:22', 'Apple, Inc.', 'false', 'MA-L', '2026/01/01'],
        ['00:11:22:3', 'Secret', 'true', 'MA-M', '2026/01/01'],
        ['00:33:44', 'CID Company', 'false', 'CID', '2026/01/01'],
        ['00:50:56', 'VMware, Inc.', 'false', 'MA-L', '2026/01/01'],
        ['00:44:55', 'Cisco Systems', 'false', 'MA-L', '2026/01/01'],
    ])
    db = get_database(path)
    for mac, status in [('00:11:22:33:44:55','private'), ('00:33:44:00:00:01','cid'), ('02:11:22:33:44:55','local_admin'), ('01:11:22:33:44:55','multicast'), ('ff:ff:ff:ff:ff:ff','broadcast'), ('00:99:88:00:00:01','unknown')]:
        r = db.lookup(mac)
        assert r['status'] == status
        assert r['vendor'] is None and r['device_hint'] is None
    for mac in ['', '001122', '00:11:22:33:44', '00:11-22:33:44:55', '00:11:22:33:44:GG', ' 001122334455', None, 123, '00.11.22.33.44.55', '00112233445566']:
        assert db.lookup(mac)['status'] == 'invalid'
    apple = db.lookup('00:11:22:44:55:66')
    assert 'consumer' in apple['device_hint'] and 'iPhone' not in apple['device_hint']
    assert apple['hint_confidence'] == 'low'
    assert 'virtual' in db.lookup('00:50:56:00:00:01')['device_hint']
    assert 'network equipment' in db.lookup('00:44:55:00:00:01')['device_hint']
    assert get_database(tmp_path / 'missing.csv').lookup('00:11:22:44:55:66')['status'] == 'database_unavailable'
    path.write_text('bad header\n', encoding='utf-8')
    assert get_database(path).lookup('00:11:22:44:55:66')['status'] == 'database_unavailable'
