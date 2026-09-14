from playwright.sync_api import expect
from test_llm_browser import page_server


def test_protocol_mix_follows_filters_and_metric_controls_map(page_server):
    page=page_server;page.locator('#demo-button').click()
    expect(page.locator('#capture-name')).to_contain_text('Synthetic demo')
    expect(page.locator('#protocol-chart button').first).to_be_visible()
    expect(page.locator('#protocol-metric')).to_be_visible()
    expect(page.locator('#protocol-scope')).to_contain_text('Filtered')
    page.locator('#protocol-metric').select_option('packets')
    expect(page.locator('#protocol-chart')).to_contain_text('packets')
    page.locator('#protocol-filter').select_option('service:SSH')
    expect(page.locator('#protocol-chart')).to_contain_text('SSH (port hint)')
    expect(page.locator('#protocol-chart')).not_to_contain_text('UDP')
    page.locator('#protocol-filter').select_option('')
    page.locator('#protocol-chart button').filter(has_text='TCP').click()
    expect(page.locator('#protocol-filter')).to_have_value('TCP')


def test_timeline_range_controls_change_visible_intervals_and_reset(page_server):
    page=page_server;page.locator('#demo-button').click()
    expect(page.locator('#capture-name')).to_contain_text('Synthetic demo')
    expect(page.locator('#timeline-chart circle').first).to_be_visible()
    expect(page.locator('#timeline-start')).to_be_visible()
    total=page.locator('#timeline-chart circle').count()
    page.locator('#timeline-start').fill('50')
    page.locator('#timeline-start').dispatch_event('input')
    expect(page.locator('#timeline-range-status')).to_contain_text('Showing')
    assert 0 < page.locator('#timeline-chart circle').count() < total
    page.locator('#timeline-reset').click()
    assert page.locator('#timeline-chart circle').count()==total
