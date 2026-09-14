"""Offline MMDB lookup. Capture addresses never leave this process."""
import ipaddress
import math
from pathlib import Path

DATABASE = Path(__file__).resolve().parent / 'data' / 'city.mmdb'
MAX_NODES = 20000


def normalize(address, record):
    result = dict(id=address, status='not_found', latitude=None, longitude=None,
                  country=None, country_code=None, city=None, accuracy_radius_km=None)
    if not isinstance(record, dict):
        return result
    location = record.get('location', {})
    lat, lon = location.get('latitude'), location.get('longitude')
    if (type(lat) not in (int, float) or type(lon) not in (int, float)
            or not math.isfinite(lat) or not math.isfinite(lon)
            or not -90 <= lat <= 90 or not -180 <= lon <= 180):
        return result
    radius = location.get('accuracy_radius')
    country = record.get('country', {})
    result.update(status='located', latitude=lat, longitude=lon,
                  country=str(country.get('names', {}).get('en', ''))[:100] or None,
                  country_code=str(country.get('iso_code', ''))[:3] or None,
                  city=str(record.get('city', {}).get('names', {}).get('en', ''))[:150] or None,
                  accuracy_radius_km=radius if type(radius) in (int, float) and math.isfinite(radius) and radius >= 0 else None)
    return result


def locate(addresses, path=None):
    if not isinstance(addresses, list) or len(addresses) > MAX_NODES:
        raise ValueError('GeoIP scope must contain at most 20,000 endpoints.')
    parsed = []
    for address in dict.fromkeys(addresses):
        if not isinstance(address, str) or len(address) > 128:
            raise ValueError('Invalid GeoIP endpoint.')
        if address.startswith('mac:'):
            parsed.append((address, False))
        else:
            ip = ipaddress.ip_address(address)
            parsed.append((address, ip.is_global and not ip.is_multicast))
    reader = None
    database: dict = dict(available=False, type=None, build_epoch=None,
                    attribution='IP Geolocation by DB-IP', attribution_url='https://db-ip.com',
                    note='Approximate IP location, not device position or ownership. Anycast/VPN/proxies may differ.')
    try:
        import maxminddb
        reader = maxminddb.open_database(str(path or DATABASE))
        metadata = reader.metadata()
        database.update(available=True, type=metadata.database_type, build_epoch=metadata.build_epoch)
        if 'GeoLite' in metadata.database_type or 'GeoIP' in metadata.database_type:
            database.update(attribution='GeoLite2 data created by MaxMind', attribution_url='https://www.maxmind.com')
    except (ImportError, OSError, ValueError):
        database['note'] = 'GeoIP database missing or invalid. Install a city MMDB at data/city.mmdb.'
    nodes = []
    try:
        for address, public in parsed:
            node = normalize(address, None)
            if not public:
                node['status'] = 'non_public'
            elif reader is None:
                node['status'] = 'database_unavailable'
            else:
                try:
                    node = normalize(address, reader.get(address))
                except (ValueError, OSError):
                    node['status'] = 'lookup_failed'
            nodes.append(node)
    finally:
        if reader is not None:
            reader.close()
    return dict(database=database, nodes=nodes)
