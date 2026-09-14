import json
import urllib.request
import urllib.error
import pytest
from test_llm_server import server


def test_geoip_http_is_local_authenticated_and_returns_every_requested_endpoint(tmp_path):
    with server(tmp_path / 'model.json') as (instance, base):
        body = json.dumps({'addresses':['8.8.8.8','10.0.0.1']}).encode()
        request = urllib.request.Request(base+'/api/geoip',data=body,headers={'X-PacketMap-Token':instance.token})
        with urllib.request.urlopen(request) as response:
            result = json.load(response)
        assert len(result['nodes']) == 2
        assert result['nodes'][1]['status'] == 'non_public'
        request = urllib.request.Request(base+'/api/geoip',data=body)
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        assert error.value.code == 403
