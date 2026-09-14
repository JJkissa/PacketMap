import json
import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap
from analyzer import analyze


def packet(sport, dport, reverse=False):
    a, b = ('192.0.2.1', '192.0.2.2')
    if reverse:
        a, b = b, a
    return Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src=a, dst=b) / TCP(sport=sport, dport=dport)


def test_port_pair_totals_keep_services_separate_and_combine_replies(tmp_path):
    path = tmp_path / 'mixed.pcap'
    packets = [packet(45000, 22), packet(22, 45000, True), packet(45001, 443), packet(22, 22)]
    wrpcap(str(path), packets)
    result = analyze(path)
    edge, = result['edges']
    assert edge['packets'] == len(packets)
    assert edge['protocol_bytes']['TCP'] == edge['bytes']
    assert edge['bytes'] == sum(len(p) for p in packets)
    assert edge['traffic_complete'] is True
    groups = {tuple(g['ports']): g for g in edge['port_traffic']}
    assert groups[('TCP/22', 'TCP/45000')]['packets'] == 2
    assert groups[('TCP/22', 'TCP/45000')]['bytes'] == sum(len(p) for p in packets[:2])
    assert groups[('TCP/443', 'TCP/45001')]['packets'] == 1
    assert groups[('TCP/22',)]['packets'] == 1
    assert sum(g['packets'] for g in groups.values()) == edge['packets']
    json.dumps(result, allow_nan=False)


@pytest.mark.parametrize('constant', ['MAX_TRAFFIC_GROUPS', 'MAX_TRAFFIC_PER_EDGE'])
def test_breakdown_caps_preserve_totals_and_keep_counting_known_groups(tmp_path, monkeypatch, constant):
    monkeypatch.setattr('analyzer.' + constant, 1, raising=False)
    path = tmp_path / 'capped.pcap'
    packets = [packet(45000, 22), packet(45001, 443), packet(22, 45000, True)]
    wrpcap(str(path), packets)
    result = analyze(path)
    edge, = result['edges']
    assert len(edge['port_traffic']) == 1
    assert edge['port_traffic'][0]['packets'] == 2
    assert edge['traffic_complete'] is False
    assert edge['packets'] == 3
    assert edge['bytes'] == sum(len(p) for p in packets)
    assert any('Service traffic detail limit' in warning for warning in result['warnings'])
