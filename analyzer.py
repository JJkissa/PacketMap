"""Offline, streaming capture analysis; no DNS or other network lookups.

Connections are unordered IP endpoint pairs, not TCP sessions. Packet/byte
counts on nodes count each participating endpoint once; summary counts frames.
Bytes use recorded wire length. Times are Unix seconds; timeline buckets are
whole Unix seconds, adaptively widened by powers of two to at most 2,000
buckets (time denotes bucket start). timeline_bucket_width exports seconds
per interval; timeline stays sparse, omitted intervals mean zero captured
traffic. Each bucket covers [time, time + width). Kind 'local' means Python ipaddress's
non-global classification, including shared/documentation/reserved ranges;
it does not prove an endpoint is on the local network. Kind 'link' is a MAC-only
endpoint. ARP uses protocol IP endpoints; non-IP Ethernet uses MAC endpoints.
Connections includes both kinds of edges; ip_entities excludes MAC-only nodes.
MAC lists describe observed link-layer associations only:
a gateway MAC next to a remote IP is NOT evidence of ownership. Port service
hints are conventional names, not application identification. DNS names are
untrusted assertions observed in capture answers, not verified identities.

The packet cap stops reading; summary then describes the retained prefix.
Node/edge caps omit new graph entries while frame/protocol totals continue.
Edges also export port_traffic (unordered transport/port-pair packet/byte
counts) and traffic_complete. These details cap at 64 groups per edge and
100,000 globally; incomplete service-filtered counts are lower bounds.
Original edge counts, ports and first/last timestamps describe all traffic.
DNS answers (10,000), ports per edge (64), MACs per node (32), and timeline
buckets (2,000) are bounded. Omitted metadata produces warnings. Empty valid
captures return zero totals with null start/end; invalid files raise CaptureError
(a ValueError). Scapy-supported raw IP and Linux cooked links retain IP flows
but do not infer missing Ethernet MACs. There is no stream reassembly, TLS
inspection, CNAME-chain resolution, or host ownership inference. Unknown
transports retain IP endpoints with an IPv4/IPv6 protocol label; unknown
Ethernet payloads retain link endpoints. Not every damaged pcapng structure
can be distinguished from clean EOF by Scapy.
"""
import ipaddress
from mac_vendor import get_database
import struct
from typing import Any
from scapy.all import PcapReader, IP, IPv6, Ether, TCP, UDP, ICMP, ARP, DNS
from scapy.error import Scapy_Exception

MAX_PACKETS = 500_000
MAX_NODES = 20_000
MAX_EDGES = 50_000
MAX_DNS = 10_000
MAX_PORTS = 64
MAX_TRAFFIC_PER_EDGE = 64
MAX_TRAFFIC_GROUPS = 100_000
MAX_MACS = 32
MAX_TIMELINE = 2_000

PORT_HINTS = {53: "DNS", 80: "HTTP", 443: "HTTPS", 22: "SSH", 123: "NTP", 5353: "mDNS"}


class CaptureError(ValueError):
    """The file cannot be read as a supported packet capture."""


def analyze(path) -> 'dict[str, Any]':
    try:
        return _analyze(path)
    except (OSError, ValueError, EOFError, TypeError, AttributeError, struct.error) as exc:
        raise CaptureError('Cannot read capture: invalid, damaged, or inaccessible pcap/pcapng file.') from exc
    except Exception as exc:
        from scapy.error import Scapy_Exception
        if isinstance(exc, Scapy_Exception):
            raise CaptureError('Cannot read capture: expected a valid pcap or pcapng file.') from exc
        raise


def _analyze(path):
    nodes, edges, protocols, timeline = {}, {}, {}, {}
    dns = set()
    traffic_groups: dict[tuple, dict[str, Any]] = {}
    warnings = set()
    count = total = 0
    start = end = None
    bucket_width = 1
    with open(path, 'rb') as capture, PcapReader(capture) as reader:
        while True:
            position = capture.tell()
            try:
                packet = reader.read_packet()
            except EOFError:
                if type(reader) is PcapReader and capture.tell() != position:
                    warnings.add('Truncated capture record header; partial analysis returned.')
                break
            except (Scapy_Exception, ValueError, struct.error, AttributeError, IndexError):
                if not count:
                    raise CaptureError('Cannot read capture: damaged packet record.')
                warnings.add('Damaged capture record; partial analysis returned.')
                break
            if count >= MAX_PACKETS:
                warnings.add('Packet limit reached; capture analysis is truncated.')
                break
            count += 1
            # PcapReader retains the original captured bytes. len(packet) would
            # rebuild every protocol layer merely to count bytes, wasting CPU
            # and potentially changing the length of malformed packet data.
            captured_size = len(packet.original)
            size = int(packet.wirelen or captured_size)
            if size > captured_size:
                warnings.add('Truncated packet data detected; recorded wire lengths are used.')
            total += size
            time = float(packet.time)
            start = time if start is None else min(start, time)
            end = time if end is None else max(end, time)
            while len(timeline) >= MAX_TIMELINE and int(time // bucket_width) * bucket_width not in timeline:
                bucket_width *= 2
                merged = {}
                for old in timeline.values():
                    key = int(old['time'] // bucket_width) * bucket_width
                    entry = merged.setdefault(key, dict(time=key, packets=0, bytes=0))
                    entry['packets'] += old['packets']
                    entry['bytes'] += old['bytes']
                timeline = merged
            key = int(time // bucket_width) * bucket_width
            bucket = timeline.setdefault(key, dict(time=key, packets=0, bytes=0))
            bucket['packets'] += 1
            bucket['bytes'] += size
            # Cache layer lookups once per frame; repeated Scapy membership
            # and indexing each walk the protocol stack again.
            ip = packet.getlayer(IP)
            ipv6 = packet.getlayer(IPv6)
            ether = packet.getlayer(Ether)
            arp = packet.getlayer(ARP)
            tcp = packet.getlayer(TCP)
            udp = packet.getlayer(UDP)
            dns_layer = packet.getlayer(DNS)
            protocol = ('ARP' if arp is not None else 'TCP' if tcp is not None else 'UDP' if udp is not None else 'ICMP' if ICMP in packet else 'ICMPv6' if ipv6 is not None and any(layer.__name__.startswith('ICMPv6') for layer in packet.layers()) else 'IPv6' if ipv6 is not None else 'IPv4' if ip is not None else 'Other')
            if protocol == 'Other':
                warnings.add('Unsupported frame protocol; link endpoints only where available.')
            if dns_layer is not None and dns_layer.qr:
                for answer in dns_layer.an:
                    if not hasattr(answer, 'type'):
                        warnings.add('Malformed DNS answer omitted.')
                        continue
                    if answer.type in (1, 28):
                        name = answer.rrname.decode('utf-8', 'replace').rstrip('.')
                        if len(dns) < MAX_DNS:
                            dns.add((name, str(answer.rdata)))
                        else:
                            warnings.add('DNS record limit reached; additional answers omitted.')
            stat = protocols.setdefault(protocol, dict(name=protocol, packets=0, bytes=0))
            stat['packets'] += 1
            stat['bytes'] += size
            if ip is not None or ipv6 is not None or arp is not None or ether is not None:
                layer = ip if ip is not None else ipv6 if ipv6 is not None else arp if arp is not None else ether
                addresses = [layer.psrc, layer.pdst] if arp is not None else [layer.src, layer.dst]
                if not (ip is not None or ipv6 is not None or arp is not None):
                    addresses = ['mac:' + address for address in addresses]
                else:
                    try:
                        if arp is not None and arp.ptype not in (0x0800, 0x86dd):
                            raise ValueError('Non-IP ARP protocol')
                        addresses = [str(ipaddress.ip_address(address)) for address in addresses]
                    except (ValueError, TypeError):
                        warnings.add('Unsupported or malformed network address; link endpoints used where available.')
                        if ether is None:
                            continue
                        addresses = ['mac:' + ether.src, 'mac:' + ether.dst]
                # At most two unique endpoints; never scan the accumulated map.
                missing = sum(address not in nodes for address in set(addresses))
                if len(nodes) + missing > MAX_NODES:
                    warnings.add('Node limit reached; additional endpoints and connections omitted.')
                    continue
                for index, address in enumerate(addresses):
                    if address not in nodes:
                        nodes[address] = dict(id=address, label=address, names=[], macs=[], kind='link' if address.startswith('mac:') else 'multicast' if ipaddress.ip_address(address).is_multicast else 'local' if not ipaddress.ip_address(address).is_global else 'public', packets=0, bytes=0)
                    node = nodes[address]
                    if index == 0 or address != addresses[0]:
                        node['packets'] += 1
                        node['bytes'] += size
                    if ether is not None:
                        mac = ether.src if index == 0 else ether.dst
                        if mac not in node['macs']:
                            if len(node['macs']) < MAX_MACS:
                                node['macs'].append(mac)
                            else:
                                warnings.add('MAC association limit reached; additional observations omitted.')
                pair = tuple(sorted(addresses))
                if pair not in edges and len(edges) >= MAX_EDGES:
                    warnings.add('Edge limit reached; additional connections omitted.')
                    continue
                edge = edges.setdefault(pair, dict(source=pair[0], target=pair[1], packets=0, bytes=0, protocols={}, protocol_bytes={}, ports=[], first=time, last=time, port_traffic=[], traffic_complete=True))
                edge['packets'] += 1
                edge['bytes'] += size
                edge['protocols'][protocol] = edge['protocols'].get(protocol, 0) + 1
                edge['protocol_bytes'][protocol] = edge['protocol_bytes'].get(protocol, 0) + size
                edge['first'], edge['last'] = min(edge['first'], time), max(edge['last'], time)
                transport = tcp if tcp is not None else udp if udp is not None else None
                if transport is not None:
                    ports = tuple(f'{protocol}/{port}' for port in sorted({int(transport.sport), int(transport.dport)}))
                    group_key = (pair, ports)
                    group = traffic_groups.get(group_key)
                    if group is None:
                        if len(traffic_groups) >= MAX_TRAFFIC_GROUPS or len(edge['port_traffic']) >= MAX_TRAFFIC_PER_EDGE:
                            edge['traffic_complete'] = False
                            warnings.add('Service traffic detail limit reached; filtered totals may be partial.')
                        else:
                            group = dict(ports=list(ports), packets=0, bytes=0)
                            traffic_groups[group_key] = group
                            edge['port_traffic'].append(group)
                    if group is not None:
                        group['packets'] += 1
                        group['bytes'] += size
                for port in (transport.sport, transport.dport) if transport else ():
                    label = f'{protocol}/{port}' + (f' ({PORT_HINTS[port]} port hint)' if port in PORT_HINTS else '')
                    if label not in edge['ports']:
                        if len(edge['ports']) < MAX_PORTS:
                            edge['ports'].append(label)
                        else:
                            warnings.add('Port hint limit reached; additional ports omitted.')
    vendor_db = get_database()  # One version check per analysis, never per packet.
    for node in nodes.values():
        node['mac_vendor'] = [vendor_db.lookup(mac) for mac in node['macs']]
    for name, address in sorted(dns):
        if address in nodes and name not in nodes[address]['names']:
            nodes[address]['names'].append(name)
    return dict(summary=dict(packets=count, bytes=total, duration=(end-start) if start is not None else 0, start=start, end=end, ip_entities=sum(not key.startswith('mac:') for key in nodes), connections=len(edges)), nodes=list(nodes.values()), edges=list(edges.values()), protocols=list(protocols.values()), timeline=sorted(timeline.values(), key=lambda bucket: bucket['time']), timeline_bucket_width=bucket_width, dns=[dict(name=name, address=address) for name, address in sorted(dns)], warnings=sorted(warnings) if count else ['Capture contains no packets.'])
