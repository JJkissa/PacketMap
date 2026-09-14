import json
import threading
import pytest
from playwright.sync_api import sync_playwright, expect
import app
import llm_client

@pytest.fixture
def ui(tmp_path):
    server=app.create_server(0,settings_path=tmp_path/'model.json')
    threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch()
            page=browser.new_page(viewport={'width':1280,'height':900})
            page.goto(f'http://127.0.0.1:{server.server_port}')
            page.set_default_timeout(4000)
            yield page,server
            browser.close()
    finally: server.shutdown();server.server_close()


def test_expand_moves_results_escape_restores_focus_responsive(ui,monkeypatch,tmp_path):
    page,server=ui
    def fake(data,settings=None):
        return {'model':'fixture','context':llm_client.build_context(data),'answer':{
            'summary':'Durable result','observations':[{'text':'Evidence','evidence_ids':['E1']}],
            'uncertainties':['Metadata only']}}
    monkeypatch.setattr(llm_client,'explain',fake)
    page.locator('#demo-button').click()
    page.locator('#protocol-filter').select_option('service:SSH')
    page.locator('#explain-button').click()
    expect(page.locator('#ai-status')).to_contain_text('2 / 2')
    result=page.locator('#ai-result').text_content()
    narrow=page.locator('.ai-panel').bounding_box()['width']
    page.locator('#ai-expand').click()
    expect(page.locator('#reading-dialog')).to_be_visible()
    expect(page.locator('#ai-expand')).to_have_attribute('aria-expanded','true')
    assert page.locator('.ai-panel').bounding_box()['width'] > narrow*2
    assert page.locator('#ai-result').text_content()==result
    assert page.evaluate('new Set([...document.querySelectorAll("[id]")].map(e=>e.id)).size === document.querySelectorAll("[id]").length')
    page.keyboard.press('Escape')
    expect(page.locator('#reading-dialog')).not_to_be_visible()
    expect(page.locator('#ai-expand')).to_be_focused()
    assert page.locator('#ai-result').text_content()==result
    page.set_viewport_size({'width':390,'height':844})
    page.locator('#ai-expand').click()
    assert page.locator('#reading-dialog').bounding_box()['width'] <= 390
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
    page.screenshot(path=tmp_path/'reading-mobile.png')
    page.locator('#ai-expand').click()
    expect(page.locator('#ai-expand')).to_be_focused()


def test_settings_ui_key_preserve_clear_remote_warning_no_inference(ui,monkeypatch,tmp_path):
    page,server=ui
    calls=[]
    monkeypatch.setattr(llm_client,'explain',lambda *args,**kwargs:calls.append(args))
    page.locator('#model-settings-button').click()
    expect(page.locator('#model-settings-dialog')).to_be_visible()
    expect(page.locator('#model-server')).to_have_value('http://localhost:1234')
    expect(page.locator('#model-key')).to_have_attribute('type','password')
    page.locator('#model-key').fill('dummy-browser-secret')
    page.locator('#model-save').click()
    expect(page.locator('#model-settings-status')).to_contain_text('Saved')
    assert server.model_settings.snapshot()['api_key']=='dummy-browser-secret'
    expect(page.locator('#model-key')).to_have_value('')
    assert 'dummy-browser-secret' not in page.content()
    page.locator('#model-server').fill('https://api.example.com:443')
    page.locator('#model-mode').select_option('openai')
    page.locator('#model-name').fill('dummy-remote-model')
    page.locator('#model-save').click()
    expect(page.locator('#model-settings-status')).to_contain_text('Invalid')
    page.locator('#model-remote').check()
    page.locator('#model-save').click()
    expect(page.locator('#model-settings-status')).to_contain_text('Saved')
    assert server.model_settings.snapshot()['api_key']==''
    page.locator('#model-key').fill('dummy-remote-secret')
    page.locator('#model-save').click()
    expect(page.locator('#model-settings-status')).to_contain_text('Saved')
    assert server.model_settings.snapshot()['api_key']=='dummy-remote-secret'
    page.locator('#model-close').click()
    expect(page.locator('#model-disclosure')).to_contain_text('leaves this machine')
    expect(page.locator('#model-disclosure')).to_contain_text('GeoIP')
    assert 'Local LM Studio only' not in page.inner_text('body')
    assert 'no external lookups' not in page.inner_text('body')
    page.locator('#model-settings-button').click()
    expect(page.locator('#model-key')).to_have_value('')
    page.locator('#model-clear-key').check()
    page.locator('#model-save').click()
    expect(page.locator('#model-settings-status')).to_contain_text('Saved')
    assert server.model_settings.snapshot()['api_key']==''
    assert calls==[]
    page.screenshot(path=tmp_path/'model-settings.png')
    page.keyboard.press('Escape')
    expect(page.locator('#model-settings-button')).to_be_focused()


def test_changed_connection_between_nodes_stops_batch_without_mixing(ui,monkeypatch,tmp_path):
    page,server=ui
    calls=[]
    def fake(data,settings=None):
        calls.append(settings['model'])
        return {'model':settings['model'],'context':llm_client.build_context(data),'answer':{
            'summary':'First connection result','observations':[{'text':'Evidence','evidence_ids':['E1']}],
            'uncertainties':['Metadata only']}}
    monkeypatch.setattr(llm_client,'explain',fake)
    changed=[]
    def intercept(route):
        response=route.fetch()
        if not changed:
            expect(page.locator('#model-settings-button')).to_be_disabled()
            save=page.request.post(page.url+'api/model-settings',headers={'X-PacketMap-Token':server.token},
                data={'model':'other-model'})
            assert save.status==200
            changed.append(True)
        route.fulfill(response=response)
    page.route('**/api/explain',intercept)
    page.locator('#demo-button').click()
    page.locator('#protocol-filter').select_option('service:SSH')
    page.locator('#explain-button').click()
    expect(page.locator('#ai-status')).to_contain_text('Model settings changed')
    expect(page.locator('#ai-status')).to_contain_text('1 / 2')
    assert len(calls)==1
    expect(page.locator('#ai-result')).to_contain_text('First connection result')
    with page.expect_download() as download: page.locator('#ai-export').click()
    path=tmp_path/'partial.json';download.value.save_as(path)
    exported=json.loads(path.read_text())
    assert exported['incomplete'] and exported['completed_nodes']==1
    # New connection must be disclosed and reviewed, never silently adopted.
    page.locator('#explain-button').click()
    expect(page.locator('#ai-status')).to_contain_text('Review the disclosure')
    assert len(calls)==1
