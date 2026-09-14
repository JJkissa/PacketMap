'use strict';
// Saved credentials never enter this module: the server returns has_api_key only.
window.PacketModelUI = {
  create({request, onSaved, isBusy}) {
    const $ = id => document.getElementById(id);
    const panel = document.querySelector('.ai-panel');
    const anchor = document.createComment('AI panel reading-view anchor');
    panel.before(anchor);
    const reading = $('reading-dialog'), dialog = $('model-settings-dialog');
    let current = null, saving = false;
    $('ai-expand').onclick = () => {
      if (reading.open) return reading.close();
      reading.append(panel); reading.showModal();
      $('ai-expand').textContent = 'Collapse reading view';
      $('ai-expand').setAttribute('aria-expanded', 'true');
      $('ai-expand').focus();
    };
    reading.addEventListener('close', () => {
      anchor.after(panel);
      $('ai-expand').textContent = 'Expand reading view';
      $('ai-expand').setAttribute('aria-expanded', 'false');
      $('ai-expand').focus({preventScroll:true});
    });
    function display(value) {
      current = value;
      $('connection-badge').textContent = value.remote ? 'Local capture decoding · remote model enabled' : 'Local capture decoding · loopback model';
      $('model-disclosure').textContent = `${value.remote ? 'On Analyze, data leaves this machine for' : 'On Analyze, data goes to the loopback model at'} ${value.server_url} · ${value.model} (${value.api_mode === 'native' ? 'LM Studio native' : 'OpenAI-compatible'}). Each scoped node sends scope, counts, timing, service hints, pseudonymous evidence and approximate GeoIP city/country labels.${value.remote ? ' Remote retention and charges may apply.' : ''}`;
    }
    function fill(value) {
      $('model-server').value = value.server_url;
      $('model-mode').value = value.api_mode;
      $('model-name').value = value.model;
      $('model-key').value = '';
      $('model-clear-key').checked = false;
      $('model-remote').checked = value.allow_remote;
      $('model-key-status').textContent = value.has_api_key ? 'A key is saved on the server. Leave blank to keep it.' : 'No API key is saved.';
    }
    async function get() {
      const config = await request('/api/config');
      const settings = await request('/api/model-settings', {headers:{'X-PacketMap-Token':config.token}});
      return {config, settings};
    }
    const ready = get().then(({settings}) => display(settings)).catch(() => {
      $('model-disclosure').textContent = 'Connection settings unavailable. Open Model settings to retry; analysis will not start until verified.';
    });
    $('model-settings-button').onclick = async () => {
      if (isBusy()) return;
      dialog.showModal(); $('model-settings-status').textContent = 'Loading…';
      $('model-save').disabled = true;
      try {
        const {settings} = await get(); display(settings); fill(settings);
        $('model-settings-status').textContent = '';
      } catch (error) { $('model-settings-status').textContent = error.message; }
      finally { $('model-save').disabled = !current; }
    };
    $('model-close').onclick = () => dialog.close();
    dialog.addEventListener('close', () => {
      $('model-key').value = '';
      $('model-settings-button').focus({preventScroll:true});
    });
    // Changing destination requires a fresh authorization choice, not a sticky checkbox.
    $('model-server').addEventListener('input', () => { $('model-remote').checked = false; });
    $('model-settings-form').onsubmit = async event => {
      event.preventDefault();
      if (saving || isBusy()) return;
      saving = true; $('model-save').disabled = true;
      $('model-settings-status').textContent = 'Saving…';
      try {
        const config = await request('/api/config');
        const value = await request('/api/model-settings', {method:'POST',
          headers:{'Content-Type':'application/json','X-PacketMap-Token':config.token},
          body:JSON.stringify({server_url:$('model-server').value, api_mode:$('model-mode').value,
            model:$('model-name').value, api_key:$('model-key').value,
            clear_api_key:$('model-clear-key').checked, allow_remote:$('model-remote').checked})});
        // Read the exact target back before claiming the save succeeded.
        const {settings} = await get();
        display(settings); fill(settings); onSaved();
        $('model-settings-status').textContent = settings.revision === value.revision ? 'Saved. No analysis was started.' : 'Connection changed in another window. Review settings before analysis.';
      } catch (error) { $('model-settings-status').textContent = error.message; }
      finally { $('model-key').value = ''; saving = false; $('model-save').disabled = false; }
    };
    return {
      setBusy(busy) { $('model-settings-button').disabled = busy; $('model-save').disabled = busy || saving; },
      async forAnalysis() {
        await ready;
        const previous = current;
        const value = await get(); display(value.settings);
        if (!previous || previous.revision !== value.settings.revision) {
          throw new Error('Model connection changed. Review the disclosure and click Analyze again.');
        }
        return value;
      }
    };
  }
};
