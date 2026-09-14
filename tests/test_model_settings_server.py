import json
import threading
import urllib.request
import urllib.error
from contextlib import contextmanager
import pytest
import app
from test_llm import payload

@contextmanager
def running(tmp_path):
    server=app.create_server(0, settings_path=tmp_path/'model.json')
    threading.Thread(target=server.serve_forever,daemon=True).start()
    def request(path='/api/model-settings', data=None, token=server.token, origin=None, revision=None):
        headers={'X-PacketMap-Token':token,'Content-Type':'application/json'}
        if origin: headers['Origin']=origin
        if revision: headers['X-PacketMap-Model-Revision']=revision
        req=urllib.request.Request(f'http://127.0.0.1:{server.server_port}'+path,
            data=None if data is None else json.dumps(data).encode(), headers=headers)
        try:
            with urllib.request.urlopen(req) as response: return response.status,json.load(response)
        except urllib.error.HTTPError as error: return error.code,json.load(error)
    try: yield server,request
    finally: server.shutdown(); server.server_close()


def test_authenticated_settings_roundtrip_without_inference(tmp_path,monkeypatch):
    import llm_client
    def forbidden(*args,**kwargs): raise AssertionError('Settings must never infer')
    monkeypatch.setattr(llm_client,'explain',forbidden)
    with running(tmp_path) as (server,request):
        for data in (None,{}):
            assert request(data=data,token='wrong')[0]==403
            assert request(data=data,origin='https://evil.example')[0]==403
        status,settings=request()
        assert status==200 and settings['server_url']=='http://localhost:1234'
        assert request(data={**settings,'api_key':'dummy-server-secret'})[0]==200
        saved=request()[1]
        assert saved['has_api_key'] and 'dummy-server-secret' not in json.dumps(saved)
        assert request(data={**saved,'api_key':''})[0]==200
        assert server.model_settings.snapshot()['api_key']=='dummy-server-secret'
        assert request(data={'server_url':'http://example.com','allow_remote':True})[0]==400
        assert request(data={'clear_api_key':True})[1]['has_api_key'] is False


def test_active_inference_rejects_settings_and_revision_stops_stale_batch(tmp_path,monkeypatch):
    import llm_client
    calls=[]
    monkeypatch.setattr(llm_client,'explain',lambda data,settings=None: calls.append(settings) or {'model':settings['model']})
    with running(tmp_path) as (server,request):
        initial=request()[1]
        server.explanation_lock.acquire()
        try: assert request(data={'model':'new'})[0]==409
        finally: server.explanation_lock.release()
        assert request('/api/explain',payload(),revision=initial['revision'])[0]==200
        assert calls[0]['model']==initial['model']
        assert request(data={'model':'new'})[0]==200
        assert request('/api/explain',payload(),revision=initial['revision'])[0]==409
        assert len(calls)==1
        assert request('/api/explain',payload())[0]==409  # Legacy requests may not send to a changed backend.
