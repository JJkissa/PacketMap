import json
import stat
import pytest


def test_settings_private_roundtrip(tmp_path):
    import model_settings as settings
    store = settings.SettingsStore(tmp_path / 'private' / 'model.json')
    assert store.public()['server_url'] == 'http://localhost:1234'
    assert store.public()['model'] == 'qwen3.8-9b-heretic-uncensored-i1'
    initial = store.public()
    result = store.save({**initial, 'api_key': 'dummy-secret'})
    assert result['has_api_key'] is True
    assert 'dummy-secret' not in json.dumps(result)
    assert 'api_key' not in result
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    store.save({**result, 'api_key': ''})
    assert settings.SettingsStore(store.path).snapshot()['api_key'] == 'dummy-secret'
    store.save({**store.public(), 'clear_api_key': True})
    assert store.snapshot()['api_key'] == ''
    assert store.public()['revision'] != initial['revision']


@pytest.mark.parametrize('url,remote', [
    ('http://example.com:1234', False), ('https://example.com', False),
    ('http://example.com', True), ('http://192.168.1.2:1234', True),
    ('http://169.254.169.254', True), ('ftp://localhost:1234', False),
    ('http://user:pass@localhost:1234', False), ('http://localhost:1234/?key=x', False),
    ('http://localhost:1234/#x', False), ('http://localhost:99999', False),
    ('http://localhost:0', False), ('http://localhost:1234/api/v1/chat', False),
    ('http://localhost:1234?', False), ('http://localhost:1234#', False),
    ('http://localhost:1234\\@evil.test', False), ('http://127.1:1234', False),
    ('http://2130706433:1234', False), ('http://localhost:1234\n', False),
])
def test_reject_unsafe_urls(tmp_path, url, remote):
    from model_settings import SettingsStore
    store = SettingsStore(tmp_path / 'settings.json')
    before = store.public()
    with pytest.raises(ValueError):
        store.save({'server_url': url, 'allow_remote': remote})
    assert store.public() == before
    assert not store.path.exists()


@pytest.mark.parametrize('url,remote', [('http://localhost:1234', False),
    ('http://127.0.0.1:1234/', False), ('http://[::1]:1234', False),
    ('https://api.example.com:443', True)])
def test_accept_explicit_connections(tmp_path, url, remote):
    from model_settings import SettingsStore
    store = SettingsStore(tmp_path / 'settings.json')
    assert store.save({'server_url':url, 'allow_remote':remote})['server_url'] == url.rstrip('/')


@pytest.mark.parametrize('data', [{'api_key':'dummy\r\ninjected'}, {'model':''},
    {'api_mode':'unknown'}, {'allow_remote':'yes'}, {'api_key':None}, {'model':None}])
def test_reject_invalid_fields(tmp_path, data):
    from model_settings import SettingsStore
    with pytest.raises(ValueError):
        SettingsStore(tmp_path / 'settings.json').save(data)


def test_changing_destination_does_not_reuse_saved_api_key(tmp_path):
    from model_settings import SettingsStore
    store = SettingsStore(tmp_path / 'settings.json')
    store.save({'server_url':'https://first.example','allow_remote':True,
                'api_key':'first-backend-secret'})
    store.save({'server_url':'https://second.example','allow_remote':True})
    assert store.snapshot()['api_key'] == ''

    store.save({'server_url':'https://third.example','allow_remote':True,
                'api_key':'third-backend-secret'})
    store.save({'server_url':'https://fourth.example','allow_remote':True,
                'api_key':''})
    assert store.snapshot()['api_key'] == ''


def test_changed_remote_destination_requires_new_explicit_authorization(tmp_path):
    from model_settings import SettingsStore
    store=SettingsStore(tmp_path/'settings.json')
    store.save({'server_url':'https://first.example','allow_remote':True})
    with pytest.raises(ValueError,match='authorization'):
        store.save({'server_url':'https://second.example'})
    assert store.public()['server_url']=='https://first.example'


@pytest.mark.parametrize('url',['https://bad..example','https://-bad.example',
    'https://bad-.example','https://127.1','https://2130706433','https://0x7f000001'])
def test_malformed_or_ambiguous_host_rejected_even_with_consent(tmp_path,url):
    from model_settings import SettingsStore
    with pytest.raises(ValueError):
        SettingsStore(tmp_path/'settings.json').save({'server_url':url,'allow_remote':True})
