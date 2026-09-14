'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
let jobs;try{jobs=require('../static/analysis-jobs.js').analysisJobs;}catch(e){if(e.code!=='MODULE_NOT_FOUND')throw e;}
test('analysis jobs include every node, aggregate every edge, and explicitly bound detail only',()=>{
 assert.equal(typeof jobs,'function');
 const nodes=Array.from({length:61},(_,i)=>({id:`n${i}`}));
 const edges=nodes.slice(1).map((n,i)=>({source:'n0',target:n.id,packets:2,bytes:100,first:i,last:i+1,ports:[],traffic_complete:true}));
 const result=jobs({nodes,edges},'TCP',false);
 assert.equal(result.length,61);
 assert.equal(result[0].aggregate.peer_count,60);
 assert.equal(result[0].aggregate.bytes,6000);
 assert.equal(result[0].connections.length,8);
 assert.equal(result[0].total_connections,60);
 assert.equal(result[60].node,'n60');
 assert.equal(result[60].aggregate.bytes,100);
});
test('isolated node is accounted for without inventing evidence',()=>{
 assert.equal(typeof jobs,'function');
 const result=jobs({nodes:[{id:'isolated'}],edges:[]},'',true);
 assert.equal(result.length,1);assert.equal(result[0].connections.length,0);
});
