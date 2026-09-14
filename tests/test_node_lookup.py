"""Deterministic parser operation budget; standalone before/after benchmark.

Only the nodes dictionary allocation is instrumented (via AST); parsing and
aggregation execute unchanged. Timing uses the uninstrumented module and is
reported, never asserted. All captures are synthetic and temporary.
"""
import ast
import importlib.util
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

from scapy.all import Ether, IP, IPv6, UDP, ARP, Raw, wrpcap

ROOT = Path(__file__).resolve().parents[1]


def load_parser(path, counts=None):
    spec = importlib.util.spec_from_file_location('measured_analyzer', path)
    module = importlib.util.module_from_spec(spec)
    if counts is None:
        spec.loader.exec_module(module)
        return module

    class CountedNodes(dict):
        def keys(self):
            # Preserve native dict_keys subtraction behavior. Count keys
            # exposed to whole-map operations, not wall-clock time.
            counts['key_visits'] += len(self)
            return super().keys()

        def __contains__(self, key):
            counts['membership'] += 1
            return super().__contains__(key)

    def counted_dict(*args, **kwargs):
        if 'id' in kwargs:
            counts['metadata'] += 1
        return dict(*args, **kwargs)

    tree = ast.parse(Path(path).read_text())
    allocations = 0
    for item in ast.walk(tree):
        if (isinstance(item, ast.Assign) and isinstance(item.targets[0], ast.Tuple)
                and isinstance(item.targets[0].elts[0], ast.Name)
                and item.targets[0].elts[0].id == 'nodes'):
            item.value.elts[0] = ast.Call(func=ast.Name(id='CountedNodes', ctx=ast.Load()), args=[], keywords=[])
            allocations += 1
    assert allocations == 1, 'node-map instrumentation must match exactly once'
    module.CountedNodes = CountedNodes
    module.dict = counted_dict
    exec(compile(ast.fix_missing_locations(tree), str(path), 'exec'), module.__dict__)
    real_ip_address = module.ipaddress.ip_address

    class CountedAddress:
        @staticmethod
        def ip_address(value):
            counts['address_parses'] += 1
            return real_ip_address(value)

    module.ipaddress = CountedAddress
    return module


def capture(path, population, repeats):
    def frame(src, dst):
        return Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02') / IP(src=src, dst=dst) / UDP(sport=1234, dport=4321)

    packets = [frame('192.0.2.1', f'10.{i >> 16}.{(i >> 8) & 255}.{i & 255}') for i in range(1, population)]
    packets.extend(frame('192.0.2.1', '10.0.0.1') for _ in range(repeats))
    for packet in packets:
        packet.time = 1000
    wrpcap(str(path), packets)
    return len(packets)


def operations(path):
    counts = dict(key_visits=0, membership=0, metadata=0, address_parses=0)
    result = load_parser(ROOT / 'analyzer.py', counts).analyze(path)
    return counts, result


def test_node_lookup_work_is_bounded_by_packet_endpoints(tmp_path):
    for population in (16, 256):
        path = tmp_path / 'budget.pcap'
        packets = capture(path, population, 64)
        counts, result = operations(path)
        assert len(result['nodes']) == population
        assert result == load_parser(ROOT / 'analyzer.py').analyze(path)
        violations = []
        if counts['key_visits']:
            violations.append(f"scanned {counts['key_visits']} existing node keys")
        if counts['membership'] > 4 * packets:
            violations.append('more than four membership checks per packet')
        if counts['metadata'] != population:
            violations.append(f"constructed {counts['metadata']} metadata records for {population} nodes")
        if counts['address_parses'] > 2 * packets + 2 * population:
            violations.append('reclassified existing nodes')
        assert not violations, '; '.join(violations)


def benchmark(output):
    parser = load_parser(ROOT / 'analyzer.py')
    report = {'cases': []}
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / 'synthetic.pcap'
        for population in (64, 4096):
            packets = capture(path, population, 2000)
            samples = []
            for _ in range(3):
                start = time.perf_counter()
                result = parser.analyze(path)
                samples.append(time.perf_counter() - start)
            counts, instrumented = operations(path)
            assert instrumented == result
            report['cases'].append(dict(population=population, packets=packets,
                                        median_seconds=statistics.median(samples), operations=counts, result=result))
        # Mixed endpoints, self-loops, and rejected packets must retain exact
        # output and insertion order at node/edge cap boundaries.
        ether = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')
        mixed = [ether/IP(src='192.0.2.1', dst='192.0.2.1')/UDP(),
                 ether/IP(src='192.0.2.1', dst='198.51.100.1')/UDP(),
                 ether/IP(src='198.51.100.1', dst='192.0.2.1')/UDP(),
                 ether/IPv6(src='2001:db8::1', dst='ff02::1')/UDP(),
                 ether/ARP(psrc='192.0.2.1', pdst='224.0.0.1'),
                 Ether(src=ether.src, dst=ether.dst, type=0x88b5)/Raw(b'synthetic'),
                 ether/IP(src='1.1.1.1', dst='100.64.0.1')/UDP()]
        for packet in mixed:
            packet.time = 1000
        wrpcap(str(path), mixed)
        report['caps'] = {}
        for nodes in (0, 1, 2, 3, 20):
            for edges in (0, 1, 20):
                parser.MAX_NODES, parser.MAX_EDGES = nodes, edges
                report['caps'][f'{nodes}/{edges}'] = parser.analyze(path)
    with Path(output).open('x') as file:
        json.dump(report, file)
    print(json.dumps([{k: v for k, v in case.items() if k != 'result'} for case in report['cases']], indent=2))


if __name__ == '__main__':
    benchmark(sys.argv[1])
