import json
import pytest
from test_llm import payload
import llm_client


def rich_payload():
    data=payload()
    data['node']='192.0.2.1'
    data['aggregate']={'packets':30,'bytes':1620,'peer_count':4,'connection_count':4,'first':100,'last':110}
    data['total_connections']=4
    return data


def test_node_context_uses_complete_aggregate_and_labels_sample():
    context=llm_client.build_context(rich_payload())
    assert 'node_summary' in context, 'Missing calculated node evidence'
    node=context['node_summary']
    assert node['id']=='N1' and node['host']=='Host1'
    assert node['average_packet_bytes']==54
    assert node['peer_count']==4 and node['packets']==30
    assert context['omitted_connections']==3
    assert node['sampled_connection_byte_share_percent']==10
    assert '192.0.2.1' not in json.dumps(context)


def test_inconsistent_aggregate_is_rejected():
    data=rich_payload();data['aggregate']['bytes']=1
    with pytest.raises(ValueError):llm_client.build_context(data)


def test_deeper_analysis_schema_accepts_cited_interpretations_not_unknown_ids():
    answer={'summary':'A limited SSH port hint sample.','observations':[{'text':'3 packets in E1.','evidence_ids':['E1']}],
      'uncertainties':['No authenticated session evidence.'],
      'interpretations':[{'text':'Sparse sample warrants checking capture duration.','evidence_ids':['N1'],'confidence':'low'}],
      'next_checks':['Compare other protocol filters for this node.']}
    assert llm_client.validate_answer(answer,{'E1','N1'})==answer
    answer['interpretations'][0]['evidence_ids']=['invented']
    with pytest.raises(ValueError):llm_client.validate_answer(answer,{'E1','N1'})


def test_returned_followups_use_verified_application_controls(monkeypatch):
    import io
    answer={'summary':'Metadata analysis.','observations':[{'text':'Recorded packets.','evidence_ids':['E1']}],
      'uncertainties':['No payload evidence.'],'next_checks':['Open the nonexistent TCP flag viewer.']}
    class Opener:
        def open(self,*args,**kwargs):
            return io.BytesIO(json.dumps({'output':[{'type':'message','content':json.dumps(answer)}]}).encode())
    monkeypatch.setattr(llm_client.urllib.request,'build_opener',lambda *args:Opener())
    result=llm_client.explain(rich_payload())
    assert 'recommended_checks' in result['context']
    assert result['answer']['next_checks']==result['context']['recommended_checks']
    assert 'nonexistent' not in json.dumps(result['answer'])
