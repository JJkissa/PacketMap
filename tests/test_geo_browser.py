from playwright.sync_api import expect
from test_llm_browser import page_server


def test_geographic_map_and_scope_use_all_filtered_or_one_selected_node(page_server):
    page=page_server
    page.locator('#demo-button').click()
    expect(page.locator('#capture-name')).to_contain_text('Synthetic')
    expect(page.locator('#analysis-scope')).to_be_visible()
    page.locator('#map-view').select_option('geography')
    expect(page.locator('#geo-count')).to_contain_text('scoped endpoints')
    expect(page.locator('#geo-database')).to_contain_text('DBIP-City-Lite')
    page.locator('#protocol-filter').select_option('service:SSH')
    count=page.locator('#geo-node-list button').count()
    assert count >= 2
    address=page.locator('#geo-node-list button').first.inner_text()
    page.locator('#geo-node-list button').first.click()
    page.locator('#analysis-scope').select_option('selected')
    expect(page.locator('#geo-count')).to_contain_text('1 scoped endpoints')
    expect(page.locator('#geo-node-list button')).to_have_count(1)
    expect(page.locator('#geo-node-list button')).to_have_text(address)
    page.locator('#graph-search').fill('no-such-node')
    expect(page.locator('#geo-count')).to_contain_text('0 scoped endpoints')
    expect(page.locator('#explain-button')).to_be_disabled()
