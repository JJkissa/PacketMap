import hashlib
import importlib.util
import json
import pytest


def test_fetch_restricts_initial_and_redirected_transport_to_https(monkeypatch):
    from scripts import install_mac_vendors
    seen = {}
    monkeypatch.setattr(install_mac_vendors.subprocess, 'check_output',
                        lambda args: seen.setdefault('args', args) or b'')
    install_mac_vendors.fetch_url('https://maclookup.app/example')
    assert seen['args'][:5] == ['curl', '-fLsS', '--proto', '=https', '--proto-redir']
    assert seen['args'][5] == '=https'


def test_installer_validates_csv_and_records_provenance(tmp_path):
    assert importlib.util.find_spec('scripts.install_mac_vendors'), 'installer missing'
    from scripts.install_mac_vendors import install
    payload = b'Mac Prefix,Vendor Name,Private,Block Type,Last Update\n00:00:0C,"Cisco Systems, Inc",false,MA-L,2015/11/17\n'
    calls = []
    def fetch(url):
        calls.append(url)
        return b'<a href="/downloads/csv-database/get-db?t=test&amp;h=test">CSV</a>Updated: 9 September 2026' if len(calls) == 1 else payload
    result = install(tmp_path, fetch=fetch)
    assert len(calls) == 2 and 'get-db?t=test&h=test' in calls[1]
    assert (tmp_path/'mac-vendors.csv').read_bytes() == payload
    meta = json.loads((tmp_path/'mac-vendors-source.json').read_text())
    assert meta == result
    assert meta['sha256'] == hashlib.sha256(payload).hexdigest()
    assert meta['rows'] == 1 and meta['downloaded_at_utc'] and meta['source_updated'] == '9 September 2026'
    with pytest.raises(ValueError):
        install(tmp_path, fetch=lambda url: b'<html>not CSV</html>')
    assert (tmp_path/'mac-vendors.csv').read_bytes() == payload
