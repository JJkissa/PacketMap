"""Synthetic sparse timeline contract regressions."""
from scapy.all import Ether, IP, UDP, wrpcap
from analyzer import analyze


def capture_result(tmp_path, times):
    packets = []
    for time in times:
        packet = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src='192.0.2.1', dst='192.0.2.2') / UDP()
        packet.time = time
        packets.append(packet)
    path = tmp_path / 'timeline.pcap'
    wrpcap(str(path), packets)
    return analyze(path)


def test_adaptive_width_preserves_every_aggregate_and_stays_sparse(tmp_path):
    # Force real production widening, then introduce a huge gap and out-of-order frame.
    times = [*range(2001), 4_000_000_000, 1]
    result = capture_result(tmp_path, times)
    assert result['timeline_bucket_width'] == 2
    expected = {}
    for time in times:
        key = time // 2 * 2
        bucket = expected.setdefault(key, dict(time=key, packets=0, bytes=0))
        bucket['packets'] += 1
        bucket['bytes'] += 42
    assert result['timeline'] == list(expected.values())
    assert len(result['timeline']) <= 2000
    assert sum(b['packets'] for b in result['timeline']) == result['summary']['packets'] == len(times)
    assert sum(b['bytes'] for b in result['timeline']) == result['summary']['bytes'] == 42 * len(times)
    assert result['protocols'] == [dict(name='UDP', packets=len(times), bytes=42 * len(times))]
    assert result['edges'][0]['packets'] == len(times)
    assert all(node['bytes'] == 42 * len(times) for node in result['nodes'])


def test_sparse_two_packets_export_explicit_width_without_filling_gap(tmp_path):
    result = capture_result(tmp_path, [0, 4_000_000_000])
    assert result.get('timeline_bucket_width') == 1, 'Export seconds per interval explicitly'
    assert result['timeline'] == [dict(time=t, packets=1, bytes=42) for t in (0, 4_000_000_000)]
    assert result['summary']['packets'] == 2
    assert result['summary']['bytes'] == 84
    assert {'summary', 'nodes', 'edges', 'protocols', 'timeline', 'dns', 'warnings'} <= result.keys()
