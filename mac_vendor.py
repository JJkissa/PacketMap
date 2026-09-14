"""Offline registry attribution for observed links, never endpoint identity."""
import csv
from functools import lru_cache
from pathlib import Path
import re

DEFAULT_PATH = Path(__file__).resolve().parent / 'data/mac-vendors.csv'
SOURCE = 'https://maclookup.app/downloads/csv-database'
WARNING = 'Observed link-layer association only: this may be a gateway/next-hop MAC, not the remote endpoint. Vendor allocation does not prove device identity or model.'


class VendorDatabase:
    def __init__(self, path):
        self.records = {}
        self.available = False
        try:
            with Path(path).open(encoding='utf-8-sig', newline='') as f:
                reader = csv.DictReader(f)
                if not {'Mac Prefix', 'Vendor Name', 'Private', 'Block Type'} <= set(reader.fieldnames or []):
                    return
                for row in reader:
                    prefix = row['Mac Prefix'].replace(':', '').replace('-', '').upper()
                    bits = {'MA-L': 24, 'MA-M': 28, 'MA-S': 36, 'IAB': 36, 'CID': 24}.get(row['Block Type'])
                    if bits and re.fullmatch('[0-9A-F]{%d}' % (bits // 4), prefix):
                        self.records[prefix] = row
                self.available = bool(self.records)
        except (OSError, UnicodeError, csv.Error, AttributeError, KeyError):
            self.records.clear()

    def lookup(self, mac):
        # No per-address cache: three dictionary reads, no file IO.
        result: dict = dict(mac=mac if isinstance(mac, str) else None, vendor=None, device_hint=None,
                      hint_confidence=None, prefix_bits=None, block_type=None,
                      status='invalid', warning=WARNING, source=SOURCE)
        if not isinstance(mac, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{12}|[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}|[0-9a-fA-F]{2}(-[0-9a-fA-F]{2}){5})', mac):
            return result
        value = mac.replace(':', '').replace('-', '').upper()
        result['mac'] = ':'.join(value[i:i+2] for i in range(0,12,2))
        first = int(value[:2], 16)
        status = ('broadcast' if value == 'FFFFFFFFFFFF' else 'multicast' if first & 1 else
                  'local_admin' if first & 2 else 'unknown' if self.available else 'database_unavailable')
        result['status'] = status
        if status != 'unknown':
            return result
        row = next((self.records[value[:n]] for n in (9, 7, 6) if value[:n] in self.records), None)
        if row is None:
            return result
        result.update(prefix_bits=len(row['Mac Prefix'].replace(':', '').replace('-', ''))*4, block_type=row['Block Type'])
        if row['Private'].strip().lower() != 'false':
            result['status'] = 'private'
        elif row['Block Type'] == 'CID':
            result['status'] = 'cid'
        else:
            vendor = row['Vendor Name']
            result.update(status='registered', vendor=vendor)
            name = vendor.casefold()
            hint = ('Possible virtual machine / virtual adapter' if any(v in name for v in ('vmware', 'virtualbox', 'parallels', 'xensource', 'qemu')) else
                    'Possible general consumer device (Apple); type/model unknown' if 'apple' in name else
                    'Vendor suggests network equipment; type/model unknown' if any(v in name for v in ('cisco', 'juniper', 'ubiquiti', 'mikrotik', 'netgear', 'tp-link')) else None)
            if hint:
                result.update(device_hint=hint, hint_confidence='low')
        return result


@lru_cache(maxsize=2)
def _load(path, version):
    return VendorDatabase(path)


def get_database(path=DEFAULT_PATH):
    path = Path(path)
    try:
        stat = path.stat()
        version = (stat.st_mtime_ns, stat.st_size)
    except OSError:
        version = None
    return _load(str(path.resolve()), version)
