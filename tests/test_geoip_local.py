from pathlib import Path
import importlib.util
import pytest


def module():
    assert importlib.util.find_spec('geoip_local'), 'Local GeoIP support is not implemented'
    import geoip_local
    return geoip_local


def test_geoip_keeps_nonpublic_unmapped_and_reports_missing_database(tmp_path):
    geo = module()
    result = geo.locate(['10.0.0.1', '::1', '224.0.0.1', '192.0.2.1', 'mac:aa:bb', '8.8.8.8'], tmp_path/'missing.mmdb')
    assert result['database']['available'] is False
    assert len(result['nodes']) == 6
    for node in result['nodes'][:5]:
        assert node['latitude'] is None and node['longitude'] is None
    assert result['nodes'][-1]['status'] == 'database_unavailable'
    with pytest.raises(ValueError):
        geo.locate(['bad address'])
    with pytest.raises(ValueError):
        geo.locate(['8.8.8.8'] * 20001)


def test_mmdb_normalization_preserves_zero_coordinates_and_uncertainty():
    geo = module()
    record = {'country': {'iso_code':'GB','names':{'en':'United Kingdom'}}, 'city':{'names':{'en':'London'}},
              'location':{'latitude':0.0,'longitude':0.0,'accuracy_radius':100}}
    node = geo.normalize('8.8.8.8', record)
    assert node['latitude'] == 0 and node['longitude'] == 0
    assert node['accuracy_radius_km'] == 100
    assert node['status'] == 'located'
    assert geo.normalize('8.8.8.8', {})['status'] == 'not_found'
    record['location']['latitude'] = float('nan')
    assert geo.normalize('8.8.8.8', record)['status'] == 'not_found'
