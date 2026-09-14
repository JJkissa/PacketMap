const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../static/app.js');
test('MAC labels keep vendor, cautious hints and unavailable states inline', () => {
  assert.equal(typeof app.macLabels, 'function');
  const node = {macs:['00:00:0c:00:00:01', '02:00:00:00:00:01'], mac_vendor:[
    {mac:'00:00:0C:00:00:01', vendor:'<img onerror=evil>', device_hint:'Possible network equipment', hint_confidence:'low', status:'registered'},
    {mac:'02:00:00:00:00:01', status:'local_admin'}]};
  const labels = app.macLabels(node);
  assert.match(labels[0], /00:00:0c:00:00:01.*<img onerror=evil>.*low confidence.*Possible network equipment/);
  assert.match(labels[1], /locally administered.*randomized/);
  assert.match(app.macLabels({macs:['00:00:00:00:00:01']})[0], /unavailable/);
});
