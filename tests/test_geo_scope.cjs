'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
let geo={};try{geo=require('../static/geo-view.js');}catch(e){if(e.code!=='MODULE_NOT_FOUND')throw e;}
test('shared scope includes all filtered nodes or exactly the selected node',()=>{
  assert.equal(typeof geo.scopeView,'function');
  const nodes=Array.from({length:65},(_,i)=>({id:`n${i}`}));
  const edges=nodes.slice(1).map(n=>({source:'n0',target:n.id,packets:1,bytes:10}));
  assert.equal(geo.scopeView({nodes,edges},'all','n0').nodes.length,65);
  const one=geo.scopeView({nodes,edges},'selected','n0');
  assert.deepEqual(one.nodes,[nodes[0]]);assert.equal(one.edges.length,64);
  assert.equal(geo.scopeView({nodes,edges},'selected','absent').nodes.length,0);
});
test('geo groups account for all co-located nodes and keep nonpublic unmapped',()=>{
  assert.equal(typeof geo.groupLocations,'function');
  const nodes=Array.from({length:65},(_,i)=>({id:`n${i}`}));
  const records=nodes.slice(0,64).map(n=>({id:n.id,status:'located',latitude:0,longitude:0}));
  const result=geo.groupLocations(nodes,records);
  assert.equal(result.groups.length,1);assert.equal(result.groups[0].nodes.length,64);
  assert.equal(result.unmapped.length,1);assert.deepEqual(geo.project(0,0),[480,240]);
});
