"""Server-only model credentials. Public views never contain the saved key."""
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading

DEFAULTS = dict(server_url='http://localhost:1234', api_mode='native',
                model='qwen3.8-9b-heretic-uncensored-i1', api_key='', allow_remote=False)


def validate(value):
    from urllib.parse import urlsplit
    import ipaddress
    import re
    url = value.get('server_url')
    if not isinstance(url, str) or not 1 <= len(url) <= 2048 or any(ord(c) <= 32 or ord(c) >= 127 for c in url) or any(c in url for c in '\\?#@%'):
        raise ValueError('Use a server origin URL without credentials, query, fragment or whitespace.')
    try:
        parsed = urlsplit(url)
        port = parsed.port
        host = parsed.hostname
    except ValueError:
        raise ValueError('Invalid model server URL or port.') from None
    if parsed.scheme not in ('http', 'https') or not host or parsed.path not in ('', '/') or port == 0 or parsed.netloc.endswith(':'):
        raise ValueError('Use http(s)://hostname-or-IP:port without an API path.')
    try:
        address = ipaddress.ip_address(host)
        local = address.is_loopback
    except ValueError:
        labels = host.split('.')
        if len(host) > 253 or any(not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label) for label in labels) or all(re.fullmatch(r'(?:[0-9]+|0x[0-9a-f]+)', label, re.I) for label in labels):
            raise ValueError('Invalid server hostname.') from None
        local = host == 'localhost'
    if type(value.get('allow_remote')) is not bool:
        raise ValueError('Remote authorization must be an explicit checkbox choice.')
    if not local and (not value['allow_remote'] or parsed.scheme != 'https'):
        raise ValueError('Non-loopback servers require explicit remote authorization and HTTPS. LAN HTTP is not supported.')
    if value.get('api_mode') not in ('native', 'openai'):
        raise ValueError('Choose LM Studio native or OpenAI-compatible API mode.')
    for field, minimum, maximum in [('model', 1, 256), ('api_key', 0, 4096)]:
        text = value.get(field)
        if not isinstance(text, str) or not minimum <= len(text) <= maximum or any(ord(c) < 32 or ord(c) > 126 for c in text) or (field == 'model' and not text.strip()):
            raise ValueError('Invalid model name or API key.')
    return dict(value, server_url=url.rstrip('/'), remote=not local)


class SettingsStore:
    def __init__(self, path=None):
        self.path = Path(path) if path else Path.home() / '.config' / 'packetmap' / 'model.json'
        self.lock = threading.RLock()
        self.value = validate(dict(DEFAULTS, revision=secrets.token_hex(16)))
        if self.path.exists():
            self.value = validate({**self.value, **json.loads(self.path.read_text())})
            self.path.chmod(0o600)

    def snapshot(self):
        with self.lock:
            return self.value.copy()

    def public(self):
        value = self.snapshot()
        value['has_api_key'] = bool(value.pop('api_key'))
        return value

    def save(self, data):
        with self.lock:
            if not isinstance(data, dict):
                raise ValueError('Expected model connection settings.')
            value = validate({key: data.get(key, self.value[key]) for key in DEFAULTS})
            destination_changed = value['server_url'] != self.value['server_url']
            if value['remote'] and destination_changed and data.get('allow_remote') is not True:
                raise ValueError('A changed remote destination requires new explicit authorization.')
            # A missing/blank field preserves a key only for the same backend.
            # On a destination change, retain only a newly supplied non-empty key.
            submitted_key = data.get('api_key')
            if destination_changed and not submitted_key:
                value['api_key'] = ''
            elif not value['api_key']:
                value['api_key'] = self.value['api_key']
            if data.get('clear_api_key') is True:
                value['api_key'] = ''
            value['revision'] = secrets.token_hex(16)
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd, temporary = tempfile.mkstemp(dir=self.path.parent, prefix='.model-')
            try:
                with os.fdopen(fd, 'w') as stream:
                    json.dump(value, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            self.value = value
            return self.public()
