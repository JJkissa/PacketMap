import json
import tempfile
import unittest
from pathlib import Path
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSRR, DNSQR, Raw, wrpcap, PcapWriter, PcapNgWriter


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'capture.pcap'

    def analyze_packets(self, packets):
        wrpcap(str(self.path), packets)
        from analyzer import analyze
        result = analyze(self.path)
        json.dumps(result, allow_nan=False)
        return result

    def test_shared_address_space_is_not_public(self):
        result = self.analyze_packets([Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src='100.64.0.1', dst='1.1.1.1') / UDP()])
        kinds = {node['id']: node['kind'] for node in result['nodes']}
        self.assertEqual(kinds['100.64.0.1'], 'local')
        self.assertEqual(kinds['1.1.1.1'], 'public')

    def test_ipv6_dns_udp_icmp_and_arp(self):
        packets = [
            Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IPv6(src='2001:db8::1', dst='2001:db8::53')/UDP(sport=53,dport=41000)/DNS(qr=1, an=[DNSRR(rrname='demo.example.',type='A',rdata='192.0.2.1'), DNSRR(rrname='demo.example.',type='AAAA',rdata='2001:db8::1')]),
            Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src='192.0.2.1',dst='224.0.0.1')/ICMP(),
            Ether(src='02:00:00:00:00:01',dst='ff:ff:ff:ff:ff:ff')/ARP(psrc='192.0.2.1',pdst='192.0.2.2',hwsrc='02:00:00:00:00:01'),
            Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IPv6(src='2001:db8::1',dst='ff02::1')/__import__('scapy.all',fromlist=['ICMPv6EchoRequest']).ICMPv6EchoRequest(),
        ]
        r = self.analyze_packets(packets)
        self.assertEqual({p['name'] for p in r['protocols']}, {'UDP','ICMP','ARP','ICMPv6'})
        self.assertEqual(r['dns'], [{'name':'demo.example','address':'192.0.2.1'}, {'name':'demo.example','address':'2001:db8::1'}])
        n = {n['id']:n for n in r['nodes']}
        self.assertEqual(n['2001:db8::1']['names'], ['demo.example'])
        self.assertEqual(n['224.0.0.1']['kind'], 'multicast')
        self.assertIn('02:00:00:00:00:01', n['192.0.2.1']['macs'])
        self.assertEqual(r['summary']['connections'], 4)

    def test_invalid_and_empty_captures(self):
        from analyzer import analyze, CaptureError
        for data in (b'', b'not a capture', b'\xd4\xc3\xb2\xa1'):
            self.path.write_bytes(data)
            with self.assertRaisesRegex(CaptureError, '(?i)capture'):
                analyze(self.path)
        with PcapWriter(str(self.path), linktype=1) as writer:
            writer.write_header(None)
        r = analyze(self.path)
        self.assertEqual(r['summary']['packets'], 0)
        self.assertIsNone(r['summary']['start'])
        self.assertTrue(r['warnings'])

    def test_limits_truncation_and_unsupported_frames(self):
        from analyzer import analyze
        from unittest.mock import patch
        packets = [Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='192.0.2.1', dst=f'198.51.100.{i}')/UDP(sport=40000,dport=53) for i in range(1,5)]
        wrpcap(str(self.path), packets)
        for constant, limit, field in [('MAX_PACKETS',2,'packets'), ('MAX_NODES',2,'ip_entities'), ('MAX_EDGES',1,'connections')]:
            with patch('analyzer.'+constant, limit):
                r = analyze(self.path)
            self.assertLessEqual(r['summary'][field], limit)
            self.assertTrue(any('limit' in w.lower() for w in r['warnings']))
        truncated = packets[0]
        truncated.wirelen = len(truncated)+50
        wrpcap(str(self.path), [truncated])
        r = analyze(self.path)
        self.assertEqual(r['summary']['bytes'], len(truncated)+50)
        self.assertTrue(any('truncat' in w.lower() for w in r['warnings']))
        r = self.analyze_packets([Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02',type=0x88b5)/Raw(b'unknown')])
        self.assertTrue(any('unsupported' in w.lower() for w in r['warnings']))
        self.assertEqual({n['kind'] for n in r['nodes']}, {'link'})
        self.assertEqual(r['summary']['ip_entities'], 0)

    def test_bounded_metadata_and_self_loop_counts(self):
        from unittest.mock import patch
        packets = [Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:01')/IP(src='192.0.2.1',dst='192.0.2.1')/UDP(sport=53,dport=41000+i)/DNS(qr=1,an=DNSRR(rrname=f'name{i}.example.',rdata='192.0.2.1')) for i in range(5)]
        with patch('analyzer.MAX_DNS', 2), patch('analyzer.MAX_PORTS', 2), patch('analyzer.MAX_TIMELINE', 2):
            for i,p in enumerate(packets):
                p.time = i*10
            r = self.analyze_packets(packets)
        self.assertEqual(len(r['dns']), 2)
        self.assertEqual(len(r['edges'][0]['ports']), 2)
        self.assertLessEqual(len(r['timeline']), 2)
        self.assertEqual(sum(b['packets'] for b in r['timeline']), 5)
        self.assertEqual(r['nodes'][0]['packets'], 5)
        self.assertTrue(r['warnings'])

    def test_demo_generator_both_formats(self):
        from examples.make_demo import generate
        from analyzer import analyze
        generate(Path(self.tmp.name))
        results = [analyze(Path(self.tmp.name)/name) for name in ('demo.pcap','demo.pcapng')]
        self.assertEqual(results[0]['summary'], results[1]['summary'])
        self.assertGreater(results[0]['summary']['packets'], 50)
        self.assertTrue(results[0]['dns'])
        self.assertTrue(any(':' in n['id'] for n in results[0]['nodes']))
        self.assertTrue({'ARP','TCP','UDP','ICMP','ICMPv6'} <= {p['name'] for p in results[0]['protocols']})
        self.assertEqual(results[0]['warnings'], [])

    def test_link_edges_and_mac_cap_warning(self):
        from unittest.mock import patch
        packets = [Ether(src=f'02:00:00:00:00:0{i}',dst='02:00:00:00:00:09')/IP(src='192.0.2.1',dst='198.51.100.1')/UDP(sport=100,dport=200) for i in range(1,4)]
        with patch('analyzer.MAX_MACS', 1):
            r = self.analyze_packets(packets)
        self.assertTrue(any('MAC' in w for w in r['warnings']))
        r = self.analyze_packets([Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02',type=0x88b5)/Raw(b'unknown')])
        self.assertEqual(len(r['edges']), 1)
        self.assertTrue(r['edges'][0]['source'].startswith('mac:'))

    def test_damaged_tail_retains_valid_frames(self):
        from analyzer import analyze
        wrpcap(str(self.path), [Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='192.0.2.1',dst='192.0.2.2')/UDP(sport=1,dport=2)])
        with self.path.open('ab') as file:
            file.write(b'broken')
        r = analyze(self.path)
        self.assertEqual(r['summary']['packets'], 1)
        self.assertTrue(any('truncat' in w.lower() or 'damaged' in w.lower() for w in r['warnings']))

    def test_non_ip_arp_uses_link_fallback(self):
        r = self.analyze_packets([Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='192.0.2.1',dst='192.0.2.2')/UDP(), Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/ARP(ptype=0x1234,plen=4,psrc=b'abcd',pdst=b'efgh')])
        self.assertEqual(r['summary']['packets'], 2)
        self.assertTrue(r['warnings'])
        self.assertTrue(any(n['kind']=='link' for n in r['nodes']))

    def test_malformed_dns_answer_retains_capture(self):
        packet = Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='192.0.2.53',dst='192.0.2.1')/UDP(sport=53,dport=41000)/DNS(qr=1,ancount=1)/Raw(b'\xc0')
        r = self.analyze_packets([packet])
        self.assertEqual(r['summary']['packets'], 1)
        self.assertTrue(r['warnings'])

    def test_bidirectional_ipv4_connection(self):
        a = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src='192.0.2.1', dst='198.51.100.2') / TCP(sport=45000, dport=443)
        b = Ether(src=a.dst, dst=a.src) / IP(src='198.51.100.2', dst='192.0.2.1') / TCP(sport=443, dport=45000)
        a.time, b.time = 1000, 1002
        r = self.analyze_packets([a, b])
        self.assertEqual(r['summary'], dict(packets=2, bytes=len(a)+len(b), duration=2, start=1000, end=1002, ip_entities=2, connections=1))
        self.assertEqual(r['edges'][0]['packets'], 2)
        self.assertEqual(r['edges'][0]['protocols'], {'TCP': 2})
        self.assertTrue(any('443' in p and 'HTTPS' in p for p in r['edges'][0]['ports']))
        self.assertEqual(r['nodes'][0]['packets'], 2)
        self.assertEqual(r['nodes'][0]['macs'], ['02:00:00:00:00:01'])
        self.assertEqual(r['protocols'], [dict(name='TCP', packets=2, bytes=len(a)+len(b))])
        self.assertEqual(len(r['timeline']), 2)
        self.assertEqual(r['dns'], [])
        self.assertEqual(r['warnings'], [])
