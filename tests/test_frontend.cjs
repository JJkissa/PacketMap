'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
let helpers = {};
try { helpers = require('../static/app.js'); } catch (e) { if (e.code !== 'MODULE_NOT_FOUND') throw e; }
// Sparse geometry must scale with occupied buckets, never elapsed seconds.
test('timeline steps cover occupied widths and leave enormous idle gaps at zero', () => {
  assert.equal(typeof helpers.timelineSteps, 'function');
  const buckets=[{time:0,bytes:42},{time:4000000000,bytes:84}];
  const before=JSON.stringify(buckets);
  assert.deepEqual(helpers.timelineSteps(buckets,1), [[0,0],[0,42],[1,42],[1,0],[4000000000,0],[4000000000,84],[4000000001,84],[4000000001,0]]);
  assert.equal(JSON.stringify(buckets),before);
});
test('adaptive timeline geometry is bounded and handles adjacent, single and empty intervals', () => {
  assert.deepEqual(helpers.timelineSteps([],2),[]);
  assert.deepEqual(helpers.timelineSteps([{time:4,bytes:5}],2),[[4,0],[4,5],[6,5],[6,0]]);
  const buckets=Array.from({length:2000},(_,i)=>({time:i*2000000,bytes:i+1}));
  const points=helpers.timelineSteps(buckets,2);
  assert.equal(points.length,8000);
  assert.deepEqual(points.slice(0,8),[[0,0],[0,1],[2,1],[2,0],[2000000,0],[2000000,2],[2000002,2],[2000002,0]]);
  assert.deepEqual(helpers.timelineSteps([{time:0,bytes:1},{time:2,bytes:2}],2),[[0,0],[0,1],[2,1],[2,0],[2,0],[2,2],[4,2],[4,0]]);
});
test('formats byte counts without fabricated missing values', () => {
  assert.equal(typeof helpers.formatBytes, 'function');
  assert.equal(helpers.formatBytes(null), '—');
  assert.equal(helpers.formatBytes(0), '0 B');
  assert.equal(helpers.formatBytes(1536), '1.5 KB');
});
test('caps the graph at 40 highest-traffic nodes and 80 strongest edges with explicit totals', () => {
  assert.equal(typeof helpers.visibleGraph, 'function');
  const nodes = Array.from({length:50},(_,i)=>({id:String(i),bytes:i}));
  const edges = Array.from({length:49},(_,i)=>({source:String(i),target:'49',bytes:i,protocols:{TCP:1}}));
  const result = helpers.visibleGraph({nodes,edges});
  assert.equal(result.nodes.length,40); assert.equal(result.totalNodes,50);
  assert.equal(result.nodes[0].id,'49'); assert.equal(result.edges.length,39);
  assert.equal(result.totalEdges,49);
  assert.equal(helpers.visibleGraph({nodes:[],edges:[]}).nodes.length,0);
});
test('pins a searched or selected low-volume endpoint ahead of high-volume peers', () => {
  const nodes = [{id:'target',bytes:45}, ...Array.from({length:45},(_,i)=>({id:`peer${i}`,bytes:1000+i}))];
  const edges = nodes.slice(1).map(n=>({source:'target',target:n.id,bytes:1,protocols:{TCP:1}}));
  for (const result of [helpers.visibleGraph({nodes,edges},'target'), helpers.visibleGraph({nodes,edges},'','','target')]) {
    assert.ok(result.nodes.some(n=>n.id==='target'));
    assert.equal(result.nodes.length,40);
    assert.equal(result.edges.length,39);
    assert.equal(result.totalEdges,45);
  }
});
test('lays out the highest-traffic hub centrally with deterministic separated radial peers', () => {
  assert.equal(typeof helpers.layoutGraph,'function');
  const nodes=Array.from({length:40},(_,i)=>({id:String(i),bytes:40-i}));
  const positions=helpers.layoutGraph(nodes);
  assert.deepEqual(positions.get('0'),{x:450,y:240});
  assert.deepEqual(helpers.layoutGraph(nodes),positions);
  assert.equal(positions.size,40);
  for(const p of positions.values()){assert.ok(p.x>=60&&p.x<=840);assert.ok(p.y>=40&&p.y<=440);}
  const peers=[...helpers.layoutGraph(nodes.slice(0,11)).values()].slice(1);
  for(let i=0;i<peers.length;i++)for(let j=i+1;j<peers.length;j++)assert.ok(Math.hypot(peers[i].x-peers[j].x,peers[i].y-peers[j].y)>80);
  assert.equal(helpers.layoutGraph([]).size,0);
});
test('formats duration and missing values clearly', () => {
  assert.equal(typeof helpers.formatDuration,'function');
  assert.equal(helpers.formatDuration(null),'—');
  assert.equal(helpers.formatDuration(0),'0 s');
  assert.equal(helpers.formatDuration(65),'1m 5s');
});
test('filters literal IP, DNS and MAC without modifying capture data', () => {
  assert.equal(typeof helpers.filterGraph, 'function');
  const nodes = [{id:'10.0.0.1',names:['<img onerror=evil>'],macs:['AA:BB'],bytes:8}, {id:'8.8.8.8',names:['Resolver.Example'],bytes:20}, {id:'other',bytes:2}];
  const edges = [{source:'10.0.0.1',target:'8.8.8.8',bytes:9,protocols:{DNS:2}},{source:'other',target:'8.8.8.8',bytes:2,protocols:{TCP:1}}];
  const data = {nodes,edges}; const before = JSON.stringify(data);
  assert.deepEqual(helpers.filterGraph(data,'aa:bb').nodes.map(n=>n.id),['8.8.8.8','10.0.0.1']);
  assert.deepEqual(helpers.filterGraph(data,'RESOLVER').nodes.map(n=>n.id),['8.8.8.8','10.0.0.1','other']);
  assert.equal(helpers.filterGraph(data,'<img').nodes.length,2);
  assert.equal(helpers.filterGraph(data,'','DNS').nodes.length,2);
  assert.equal(helpers.filterGraph(data,'','DNS').edges.length,1);
  assert.equal(helpers.filterGraph(data,'missing').nodes.length,0);
  assert.equal(helpers.filterGraph(data,'10.0.0.1').edges.length,1);
  assert.deepEqual(helpers.filterGraph(data,'RESOLVER','DNS').nodes.map(n=>n.id),['8.8.8.8','10.0.0.1']);
  assert.equal(helpers.filterGraph(data,'10.0.0.1','TCP').nodes.length,0);
  assert.equal(JSON.stringify(data),before);
});
