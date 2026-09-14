#!/usr/bin/env python3
"""Explicit GeoIP database install/update; never called during capture analysis."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import maxminddb

ROOT = Path(__file__).resolve().parents[1]


def install(month):
    import re
    if not re.fullmatch(r'20\d\d-(0[1-9]|1[0-2])', month):
        raise ValueError('Use a release month such as 2026-09.')
    url = f'https://download.db-ip.com/free/dbip-city-lite-{month}.mmdb.gz'
    folder = ROOT/'data'
    folder.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=folder) as temporary:
        gz = Path(temporary)/'city.gz'
        subprocess.run(['curl', '--fail', '--location', '--silent', '--show-error',
                        '--proto', '=https', '--proto-redir', '=https', '--max-time', '180',
                        '--max-filesize', str(150*1024*1024), '--output', str(gz), url], check=True)
        mmdb = Path(temporary)/'city.mmdb'
        with gzip.open(gz, 'rb') as source, mmdb.open('wb') as output:
            total = 0
            while chunk := source.read(1024*1024):
                total += len(chunk)
                if total > 256*1024*1024:
                    raise ValueError('Expanded database exceeds 256 MiB.')
                output.write(chunk)
        with maxminddb.open_database(str(mmdb)) as reader:
            metadata = reader.metadata()
            if 'City' not in metadata.database_type and 'city' not in metadata.database_type:
                raise ValueError('Not a city database.')
            receipt = dict(source=url, release=month, database_type=metadata.database_type,
                           build_epoch=metadata.build_epoch, bytes=total,
                           sha256=hashlib.file_digest(mmdb.open('rb'),'sha256').hexdigest(),
                           license='CC BY 4.0', attribution='https://db-ip.com')
        mmdb.replace(folder/'city.mmdb')
        (folder/'city-source.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('month', help='DB-IP Lite release month, YYYY-MM')
    install(parser.parse_args().month)
