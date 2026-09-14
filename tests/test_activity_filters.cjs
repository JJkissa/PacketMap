'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const app=require('../static/app.js');

test('protocol activity aggregates each filtered edge once by packets or bytes',()=>{
 const view={edges:[
  {packets:3,bytes:300,protocols:{TCP:2,UDP:1},protocol_bytes:{TCP:220,UDP:80}},
  {packets:2,bytes:120,protocols:{TCP:2},protocol_bytes:{TCP:120}}
 ]};
 assert.deepEqual(app.protocolActivity(view,'packets'),[{name:'TCP',value:4},{name:'UDP',value:1}]);
 assert.deepEqual(app.protocolActivity(view,'bytes'),[{name:'TCP',value:340},{name:'UDP',value:80}]);
});

test('service-scoped activity uses exact transformed edge totals',()=>{
 const view={edges:[{packets:2,bytes:108,protocols:{TCP:3},protocol_bytes:{TCP:162}}]};
 assert.deepEqual(app.protocolActivity(view,'bytes','SSH'),[{name:'SSH (port hint)',value:108}]);
});

test('timeline range keeps inclusive selected interval and rejects reversed bounds',()=>{
 const buckets=[{time:10,packets:1,bytes:10},{time:20,packets:2,bytes:20},{time:30,packets:3,bytes:30}];
 assert.deepEqual(app.timelineRange(buckets,15,30),buckets.slice(1));
 assert.deepEqual(app.timelineRange(buckets,31,10),[]);
});
