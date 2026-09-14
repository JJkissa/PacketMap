'use strict';
function analysisJobs(view,filter,captureLimited){
  const adjacency=new Map(view.nodes.map(n=>[n.id,[]]));
  for(const edge of view.edges){
    adjacency.get(edge.source)?.push(edge);
    if(edge.target!==edge.source)adjacency.get(edge.target)?.push(edge);
  }
  return view.nodes.map(node=>{
    const edges=adjacency.get(node.id), peers=new Set();
    let packets=0,bytes=0,first=Infinity,last=0;
    for(const e of edges){packets+=e.packets;bytes+=e.bytes;first=Math.min(first,e.first);last=Math.max(last,e.last);const peer=e.source===node.id?e.target:e.source;if(peer!==node.id)peers.add(peer);}
    return {node:node.id,filter,capture_limited:captureLimited,total_connections:edges.length,
      aggregate:{packets,bytes,peer_count:peers.size,connection_count:edges.length,first:Number.isFinite(first)?first:0,last},
      connections:edges.slice().sort((a,b)=>b.bytes-a.bytes).slice(0,8).map(e=>({
        source:e.source,target:e.target,packets:e.packets,bytes:e.bytes,
        ports:(e.ports||[]).slice(0,64),first:e.first,last:e.last,traffic_complete:e.traffic_complete!==false}))};
  });
}
if(typeof module!=='undefined')module.exports={analysisJobs};
