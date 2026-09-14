from playwright.sync_api import expect
from test_llm_browser import page_server
import llm_client


def test_all_filtered_nodes_have_separate_analysis_and_selected_scope_is_one(page_server,monkeypatch):
    calls=[]
    def fake(data, settings=None):
        calls.append(data)
        context=llm_client.build_context(data)
        return {'model':'browser-test','context':context,'answer':{'summary':'Scoped analysis.',
          'observations':[{'text':'Recorded evidence.','evidence_ids':['E1']}],
          'uncertainties':['Capture metadata only.'],
          'interpretations':[{'text':'A service hint, not session proof.','confidence':'low','evidence_ids':['N1']}],
          'next_checks':['Compare transport filters.']}}
    monkeypatch.setattr(llm_client,'explain',fake)
    page=page_server
    page.locator('#demo-button').click()
    expect(page.locator('#capture-name')).to_contain_text('Synthetic')
    page.locator('#protocol-filter').select_option('service:SSH')
    page.locator('#explain-button').click()
    expect(page.locator('#ai-status')).to_contain_text('2 / 2')
    assert len(calls)==2 and len({c.get('node') for c in calls})==2
    assert all(c['aggregate']['connection_count']==1 for c in calls)
    expect(page.locator('#ai-result')).to_contain_text('Interpretations')
    expect(page.locator('#ai-result')).to_contain_text('Follow-up checks')
    cards=page.locator('.ai-node-result')
    expect(cards).to_have_count(2)
    first=cards.first
    expect(first.locator('.ai-reference-table')).to_be_visible()
    expect(first.locator('.ai-reference-table')).to_contain_text('Host1')
    expect(first.locator('.ai-reference-table')).to_contain_text('192.0.2.10')
    expect(first.locator('.ai-reference-table')).to_contain_text('N1')
    expect(first.locator('.ai-reference-table')).to_contain_text('E1')
    expect(first.locator('.ai-reference-table')).to_contain_text('G1')
    expect(first.locator('pre')).to_have_count(0)
    page.locator('.network-node').first.click()
    page.locator('#analysis-scope').select_option('selected')
    calls.clear()
    page.locator('#explain-button').click()
    expect(page.locator('#ai-status')).to_contain_text('1 / 1')
    assert len(calls)==1


def test_stopping_batch_preserves_completed_node_and_exports_partial_scope(page_server,monkeypatch,tmp_path):
    import threading
    import json
    calls=[];started=threading.Event();release=threading.Event()
    def fake(data, settings=None):
        calls.append(data)
        if len(calls)>1:
            started.set();release.wait(5)
        return {'model':'fixture','context':llm_client.build_context(data),'answer':{
            'summary':'Completed node analysis.','observations':[{'text':'Evidence.','evidence_ids':['E1']}],
            'uncertainties':['Metadata only.']}}
    monkeypatch.setattr(llm_client,'explain',fake)
    page=page_server;page.locator('#demo-button').click()
    expect(page.locator('#explain-button')).to_be_enabled()
    page.locator('#protocol-filter').select_option('service:SSH')
    page.locator('#explain-button').click()
    try:
        assert started.wait(4)
        expect(page.locator('#ai-result')).to_contain_text('Completed node analysis.')
        page.locator('#ai-cancel').click()
        expect(page.locator('#ai-status')).to_contain_text('Cancelled after 1')
        with page.expect_download() as download:
            page.locator('#ai-export').click()
        path=tmp_path/'partial.json';download.value.save_as(path)
        data=json.loads(path.read_text())
        assert data['scope_node_count']==2 and data['completed_nodes']==1
        assert data['incomplete'] is True and len(data['results'])==1
    finally:
        release.set()
