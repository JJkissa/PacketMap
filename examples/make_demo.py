"""Generate ARTIFICIAL demo traffic, never transmit or resolve anything.

All unicast IPs use RFC 5737 / RFC 3849 documentation ranges; names use
.example. Locally administered MACs simulate a client-side capture: remote
servers share the gateway MAC, illustrating why observed MAC != IP ownership.
Payloads are artificial, including those on conventionally encrypted ports.
Run: .venv/bin/python examples/make_demo.py
"""
from pathlib import Path
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply, ARP, DNS, DNSQR, DNSRR, Raw, PcapWriter, PcapNgWriter


def generate(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    client, gateway = '02:00:00:00:00:10', '02:00:00:00:00:01'
    outbound, inbound = Ether(src=client, dst=gateway), Ether(src=gateway, dst=client)
    packets = [
        Ether(src=client,dst='ff:ff:ff:ff:ff:ff')/ARP(op=1,hwsrc=client,psrc='192.0.2.10',pdst='192.0.2.1'),
        inbound/ARP(op=2,hwsrc=gateway,hwdst=client,psrc='192.0.2.1',pdst='192.0.2.10'),
    ]
    for name, address, v6 in [('portal.example','198.51.100.20','2001:db8:2::20'),('api.example','203.0.113.40','2001:db8:3::40'),('files.example','198.51.100.80','2001:db8:2::80')]:
        packets += [
            outbound/IP(src='192.0.2.10',dst='192.0.2.53')/UDP(sport=53000,dport=53)/DNS(id=len(packets),qd=DNSQR(qname=name)),
            inbound/IP(src='192.0.2.53',dst='192.0.2.10')/UDP(sport=53,dport=53000)/DNS(id=len(packets),qr=1,qd=DNSQR(qname=name),an=[DNSRR(rrname=name,type='A',rdata=address),DNSRR(rrname=name,type='AAAA',rdata=v6)]),
        ]
    for flow, (host, port) in enumerate([('198.51.100.20',443),('203.0.113.40',443),('198.51.100.80',22),('203.0.113.123',80)]):
        sport = 44000 + flow
        up, down = IP(src='192.0.2.10',dst=host), IP(src=host,dst='192.0.2.10')
        packets += [outbound/up/TCP(sport=sport,dport=port,flags='S',seq=100),inbound/down/TCP(sport=port,dport=sport,flags='SA',seq=900,ack=101),outbound/up/TCP(sport=sport,dport=port,flags='A',seq=101,ack=901)]
        for burst in range(5):
            payload = b'ARTIFICIAL DEMO DATA. ' * (10+burst*4)
            packets += [outbound/up/TCP(sport=sport,dport=port,flags='PA',seq=101+burst*20,ack=901)/Raw(b'artificial request\r\n'),inbound/down/TCP(sport=port,dport=sport,flags='PA',seq=901+burst*len(payload),ack=121+burst*20)/Raw(payload)]
        packets += [outbound/up/TCP(sport=sport,dport=port,flags='FA'),inbound/down/TCP(sport=port,dport=sport,flags='FA')]
    for i in range(6):
        packets += [outbound/IP(src='192.0.2.10',dst='203.0.113.123')/UDP(sport=48000+i,dport=123)/Raw(b'artificial clock query'),inbound/IP(src='203.0.113.123',dst='192.0.2.10')/UDP(sport=123,dport=48000+i)/Raw(b'artificial clock response')]
    packets += [outbound/IP(src='192.0.2.10',dst='192.0.2.1')/ICMP(type=8),inbound/IP(src='192.0.2.1',dst='192.0.2.10')/ICMP(type=0),outbound/IPv6(src='2001:db8:1::10',dst='2001:db8:2::20')/ICMPv6EchoRequest(),inbound/IPv6(src='2001:db8:2::20',dst='2001:db8:1::10')/ICMPv6EchoReply(),outbound/IPv6(src='2001:db8:1::10',dst='2001:db8:3::40')/TCP(sport=49000,dport=443),inbound/IPv6(src='2001:db8:3::40',dst='2001:db8:1::10')/TCP(sport=443,dport=49000),Ether(src=client,dst='33:33:00:00:00:01')/IPv6(src='2001:db8:1::10',dst='ff02::1')/ICMPv6EchoRequest()]
    for i, packet in enumerate(packets):
        packet.time = 1_720_000_000 + i * 0.375
    for filename, writer_type in [('demo.pcap',PcapWriter), ('demo.pcapng',PcapNgWriter)]:
        with writer_type(str(directory/filename)) as writer:
            for packet in packets:
                writer.write(packet)
    return len(packets)


if __name__ == '__main__':
    count = generate(Path(__file__).resolve().parent)
    print(f'Created artificial demo.pcap and demo.pcapng: {count} frames each.')
