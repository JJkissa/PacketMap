import json
import threading
import urllib.request
import urllib.error
from contextlib import contextmanager
import pytest
import app
import llm_client
from test_llm import payload


@contextmanager
def server(settings_path):
    instance = app.create_server(0, settings_path=settings_path)
    threading.Thread(target=instance.serve_forever, daemon=True).start()
    try:
        yield instance, f'http://127.0.0.1:{instance.server_port}'
    finally:
        instance.shutdown()
        instance.server_close()


def test_explain_authenticated_bounded_and_independent_of_upload(monkeypatch, tmp_path):
    calls = []
    def fake(data):
        calls.append(data)
        return {'model': 'test', 'answer': {'summary': 'Fixture explanation'}}
    monkeypatch.setattr(llm_client, 'explain', fake)
    with server(tmp_path / 'model.json') as (instance, base):
        def request(body, token=instance.token, **extra):
            return urllib.request.Request(base + '/api/explain', data=body,
                headers={'X-PacketMap-Token': token, **extra})
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request(b'{}', token='wrong'))
        assert error.value.code == 403
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request(b'{}', Origin='https://evil.example'))
        assert error.value.code == 403
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request(b'x' * 32769))
        assert error.value.code == 413
        assert calls == []
        instance.analysis_lock.acquire()
        try:
            with urllib.request.urlopen(request(json.dumps(payload()).encode())) as response:
                assert json.load(response)['model'] == 'test'
        finally:
            instance.analysis_lock.release()
        assert len(calls) == 1
        instance.explanation_lock.acquire()
        try:
            with pytest.raises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request(b'{}'))
            assert error.value.code == 409
        finally:
            instance.explanation_lock.release()


def test_explain_failure_releases_lock(monkeypatch, tmp_path):
    def fail(data):
        raise ValueError('Model unavailable')
    monkeypatch.setattr(llm_client, 'explain', fail)
    with server(tmp_path / 'model.json') as (instance, base):
        request = urllib.request.Request(base + '/api/explain', data=b'{}',
                    headers={'X-PacketMap-Token': instance.token})
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        assert error.value.code == 400
        assert not instance.explanation_lock.locked()
