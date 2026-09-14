'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {filterGraph} = require('../static/app.js');

test('service-scoped connection counts exclude other traffic and count both-port matches once', () => {
  const edge={source:'a',target:'b',packets:10,bytes:1000,protocols:{TCP:10},ports:['TCP/22','TCP/443'],traffic_complete:true,port_traffic:[
    {ports:['TCP/22','TCP/45000'],packets:2,bytes:200},
    {ports:['TCP/443','TCP/45001'],packets:7,bytes:700},
    {ports:['TCP/22'],packets:1,bytes:100},
  ]};
  const data={nodes:[{id:'a'},{id:'b'}],edges:[edge]};
  const before=JSON.stringify(data);
  const [filtered]=filterGraph(data,'','service:SSH').edges;
  assert.equal(filtered.packets,3); assert.equal(filtered.bytes,300);
  assert.equal(filtered.traffic_complete,true);
  assert.equal(filterGraph(data,'','').edges[0].bytes,1000);
  assert.equal(JSON.stringify(data),before);
});

for (const [service, ports] of Object.entries({RDP:['TCP/3389','UDP/3389'],SSH:['TCP/22'],Telnet:['TCP/23'],HTTP:['TCP/80'],HTTPS:['TCP/443','UDP/443'],DNS:['TCP/53','UDP/53'],FTP:['TCP/21'],SMTP:['TCP/25'],IMAP:['TCP/143'],POP3:['TCP/110'],SMB:['TCP/445'],NTP:['UDP/123'],SNMP:['UDP/161'],LDAP:['TCP/389'],DHCP:['UDP/67'],mDNS:['UDP/5353']})) {
  test(`${service} matches observed conventional transport ports`, () => {
    const edges=ports.map((port,i)=>({source:'client',target:`server${i}`,protocols:{[port.split('/')[0]]:1},ports:[`${port} (port hint)`],bytes:10}));
    edges.push({source:'client',target:'unrelated',protocols:{TCP:1},ports:['TCP/45000'],bytes:20});
    const nodes=[{id:'client'},...edges.map(e=>({id:e.target}))];
    const data={nodes,edges}; const before=JSON.stringify(data);
    assert.deepEqual(filterGraph(data,'',`service:${service}`).edges,edges.slice(0,-1));
    assert.equal(JSON.stringify(data),before);
  });
}
test('service hints do not match substrings or wrong transports and compose with search',()=>{
  const nodes=['a','b','c','d'].map(id=>({id}));
  const edges=[
    {source:'a',target:'b',ports:['TCP/22 (SSH port hint)'],protocols:{TCP:1}},
    {source:'a',target:'c',ports:['TCP/2222'],protocols:{TCP:1}},
    {source:'a',target:'d',ports:['UDP/22'],protocols:{UDP:1}},
  ];
  assert.deepEqual(filterGraph({nodes,edges},'b','service:SSH').edges,[edges[0]]);
  assert.deepEqual(filterGraph({nodes,edges},'c','service:SSH').edges,[]);
  assert.equal(filterGraph({nodes,edges},'','TCP').edges.length,2);
  assert.deepEqual(filterGraph({nodes,edges},'','service:unknown').edges,[]);
  assert.deepEqual(filterGraph({nodes,edges:[{source:'a',target:'b'}]},'','service:SSH').edges,[]);
});
