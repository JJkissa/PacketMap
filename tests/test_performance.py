"""Deterministic performance guard: reading must not rebuild packet bytes."""
from unittest.mock import patch

from scapy.all import Ether, IP, UDP, Raw, PcapNgWriter, wrpcap
from scapy.packet import Packet

from analyzer import analyze


def test_analysis_does_not_reserialize_captured_packets(tmp_path):
    packet = (Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') /
              IP(src='192.0.2.1', dst='192.0.2.2') /
              UDP(sport=1234, dport=4321) / Raw(b'x' * 1000))
    captured_size = len(packet)
    # Preserve wire length for snaplen-truncated records in both formats.
    packet.wirelen = captured_size + 50
    for extension in ('pcap', 'pcapng'):
        path = tmp_path / ('capture.' + extension)
        if extension == 'pcap':
            wrpcap(str(path), [packet] * 10)
        else:
            with PcapNgWriter(str(path)) as writer:
                writer.write([packet] * 10)
        # This guard measures unnecessary work without flaky wall-clock limits.
        with patch.object(Packet, '__bytes__', side_effect=AssertionError(
                'Analysis must use captured bytes, not rebuild every packet')):
            result = analyze(path)
        assert result['summary']['packets'] == 10
        assert result['summary']['bytes'] == (captured_size + 50) * 10
        assert any('Truncated packet' in warning for warning in result['warnings'])
