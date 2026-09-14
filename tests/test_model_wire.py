"""Only synthetic evidence and dummy credentials; actual loopback sockets."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import pytest
import llm_client
from model_settings import DEFAULTS
from test_llm import payload

ANSWER = {'summary':'Synthetic traffic.', 'observations':[{'text':'Three packets.', 'evidence_ids':['E1']}], 'uncertainties':['No payload inspection.']}

@contextmanager
def wire(mode='native', redirect=None, status=200, answer=None, tls_context=None):
    calls=[]
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            calls.append((self.path, self.headers.get('Authorization'), body))
            self.send_response(status if redirect is None else 302)
            if redirect: self.send_header('Location', redirect)
            self.end_headers()
            value=answer or ANSWER
            result=({'output':[{'type':'message','content':json.dumps(value)}]} if mode=='native' else
                    {'choices':[{'finish_reason':'stop','message':{'content':json.dumps(value)}}]})
            self.wfile.write(json.dumps(result).encode())
        def log_message(self,*args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    if tls_context: server.socket=tls_context.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try: yield f'http://127.0.0.1:{server.server_port}',calls
    finally: server.shutdown(); server.server_close()

@pytest.mark.parametrize('mode,path', [('native','/api/v1/chat'),('openai','/v1/chat/completions')])
def test_configured_wire_and_secret_is_only_authorization(mode,path,monkeypatch):
    monkeypatch.setenv('http_proxy','http://127.0.0.1:1')
    monkeypatch.setenv('HTTP_PROXY','http://127.0.0.1:1')
    monkeypatch.setenv('NO_PROXY','')
    with wire(mode) as (url,calls):
        result=llm_client.explain(payload(), settings={**DEFAULTS,'server_url':url,'api_mode':mode,'model':'dummy-model','api_key':'dummy-wire-secret'})
    assert result['model']=='dummy-model'
    assert result['answer']==ANSWER
    assert len(calls)==1
    endpoint,auth,body=calls[0]
    assert endpoint==path and auth=='Bearer dummy-wire-secret'
    assert body['model']=='dummy-model' and body['stream'] is False
    if mode=='native':
        assert body['reasoning']=='off' and body['store'] is False and body['integrations']==[]
    else:
        assert len(body['messages'])==2 and body['max_tokens']==2400
        assert body['response_format']['type']=='json_schema'
    for secret in ('dummy-wire-secret','192.0.2.1','SECRET'):
        assert secret not in json.dumps(body)
        assert secret not in json.dumps(result)

@pytest.mark.parametrize('target',['http://169.254.169.254/latest/meta-data/','http://localhost:1/steal'])
def test_redirect_never_followed_or_credentials_forwarded(target):
    with wire(redirect=target) as (url,calls):
        with pytest.raises(ValueError,match='redirects'):
            llm_client.explain(payload(), settings={**DEFAULTS,'server_url':url,'api_key':'dummy-wire-secret'})
        assert len(calls)==1


def test_upstream_key_echo_is_discarded():
    value={**ANSWER,'summary':'The upstream echoed dummy-wire-secret'}
    with wire(answer=value) as (url,calls):
        with pytest.raises(ValueError,match='credential') as error:
            llm_client.explain(payload(), settings={**DEFAULTS,'server_url':url,'api_key':'dummy-wire-secret'})
        assert 'dummy-wire-secret' not in str(error.value)


@pytest.mark.parametrize('mode',['native','openai'])
def test_explicit_remote_https_with_verified_tls_dummy_loopback_only(tmp_path,monkeypatch,mode):
    import socket
    import ssl
    import subprocess
    cert,key=tmp_path/'cert.pem',tmp_path/'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
        '-subj','/CN=models.example.test','-addext','subjectAltName=DNS:models.example.test',
        '-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert,key)
    monkeypatch.setenv('SSL_CERT_FILE',str(cert))
    monkeypatch.setenv('https_proxy','http://127.0.0.1:1')
    resolve=socket.getaddrinfo
    destinations=[]
    def local_only(host,port,*args,**kwargs):
        destinations.append(host)
        assert host=='models.example.test', 'No real network targets allowed'
        return resolve('127.0.0.1',port,*args,**kwargs)
    monkeypatch.setattr(socket,'getaddrinfo',local_only)
    with wire(mode,tls_context=tls) as (url,calls):
        remote=url.replace('http://127.0.0.1','https://models.example.test')
        connection={**DEFAULTS,'server_url':remote,'api_mode':mode,'api_key':'dummy-tls-secret'}
        with pytest.raises(ValueError,match='authorization'):
            llm_client.explain(payload(),settings=connection)
        assert not calls and not destinations
        result=llm_client.explain(payload(),settings={**connection,'allow_remote':True})
        assert result['answer']==ANSWER
        assert calls[0][1]=='Bearer dummy-tls-secret'
        assert 'dummy-tls-secret' not in json.dumps(calls[0][2])
        assert destinations==['models.example.test']


def test_errors_do_not_claim_configured_backend_is_local():
    with wire(answer={'summary':'bad format'}) as (url,calls):
        with pytest.raises(ValueError) as error:
            llm_client.explain(payload(),settings={**DEFAULTS,'server_url':url})
        assert 'Local model' not in str(error.value)
