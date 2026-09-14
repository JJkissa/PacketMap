#!/usr/bin/env python3
"""Explicit bulk update only; never sends capture data or individual MACs."""
import csv
from datetime import datetime, timezone
import hashlib
import html
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile

SOURCE = 'https://maclookup.app/downloads/csv-database'
TERMS = 'https://maclookup.app/terms-and-conditions'


def fetch_url(url):
    return subprocess.check_output(['curl', '-fLsS', '--proto', '=https', '--proto-redir', '=https',
                                    '--max-time', '90', '--max-filesize', '20000000',
                                    '-A', 'Mozilla/5.0', url])


def install(directory, fetch=fetch_url):
    page = fetch(SOURCE).decode('utf-8')
    match = re.search(r'href=[\"\'](/downloads/csv-database/get-db\?[^\"\']+)', page)
    if not match:
        raise ValueError('Current MACLookup CSV download link missing; database not changed.')
    url = 'https://maclookup.app' + html.unescape(match.group(1))
    payload = fetch(url)
    reader = csv.DictReader(io.StringIO(payload.decode('utf-8-sig')))
    required = {'Mac Prefix', 'Vendor Name', 'Private', 'Block Type'}
    if not required <= set(reader.fieldnames or []):
        raise ValueError('Invalid CSV schema; database not changed.')
    rows = list(reader)
    if not rows or any(not required <= row.keys() or any(row[k] is None for k in required) for row in rows):
        raise ValueError('Empty or damaged CSV; database not changed.')
    updated = re.search(r'Updated:\s*(?:<[^>]+>\s*)*(\d{1,2} [A-Za-z]+ \d{4})', page)
    metadata = dict(source=SOURCE, download_url=url, source_updated=updated.group(1) if updated else None,
                    downloaded_at_utc=datetime.now(timezone.utc).isoformat(), rows=len(rows), bytes=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(), terms=TERMS,
                    license_note='Free download; terms recommend MACLookup attribution. Separate bulk CSV redistribution license not confirmed: local use, do not commit database.')
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for name, content in [('mac-vendors.csv', payload), ('mac-vendors-source.json', (json.dumps(metadata, indent=2)+'\n').encode())]:
        with tempfile.NamedTemporaryFile(dir=directory, delete=False) as f:
            f.write(content)
            temporary = Path(f.name)
        temporary.replace(directory / name)
    return metadata


if __name__ == '__main__':
    print(json.dumps(install(Path(__file__).resolve().parents[1] / 'data'), indent=2))
