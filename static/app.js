'use strict';
function macLabels(node) {
  const statuses = {local_admin:'locally administered; possibly randomized — no reliable vendor identity', multicast:'multicast — no device identity', broadcast:'broadcast — no device identity', private:'private registry entry — vendor withheld', cid:'CID — not a global vendor identity', unknown:'vendor unknown', invalid:'invalid 48-bit MAC', database_unavailable:'offline database unavailable'};
  return (node.macs || []).map(mac => {
    const r = (node.mac_vendor || []).find(r => String(r.mac).toLowerCase() === mac.toLowerCase());
    return `${mac} · ${r?.vendor || statuses[r?.status] || 'vendor annotation unavailable'}${r?.device_hint ? ` · low confidence: ${r.device_hint}` : ''}`;
  });
}
function formatBytes(value) {
  if (value == null || !Number.isFinite(Number(value)) || Number(value) < 0) return '—';
  if (!Number(value)) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(4, Math.floor(Math.log(Number(value)) / Math.log(1024)));
  return `${Number((Number(value) / 1024 ** i).toFixed(i ? 1 : 0))} ${units[Math.max(0, i)]}`;
}
// Conventional endpoint ports, not payload identification or session decoding.
const SERVICE_PORTS = {
  RDP:['TCP/3389','UDP/3389'], SSH:['TCP/22'], Telnet:['TCP/23'],
  HTTP:['TCP/80'], HTTPS:['TCP/443','UDP/443'],
  DNS:['TCP/53','UDP/53'], FTP:['TCP/21'], SMTP:['TCP/25'],
  IMAP:['TCP/143'], POP3:['TCP/110'], SMB:['TCP/445'],
  NTP:['UDP/123'], SNMP:['UDP/161'], LDAP:['TCP/389'],
  DHCP:['UDP/67'], mDNS:['UDP/5353'],
};
function matchesProtocol(edge, protocol) {
  if (!protocol) return true;
  if (!protocol.startsWith('service:')) return Object.hasOwn(edge.protocols || {}, protocol);
  const name=protocol.slice('service:'.length);
  if (!Object.hasOwn(SERVICE_PORTS,name)) return false;
  return (edge.ports || []).some(port => SERVICE_PORTS[name].includes(port.split(' ')[0]));
}
function filterGraph(data, query = '', protocol = '') {
  const q = query.trim().toLowerCase();
  const edges = (data.edges || []).filter(e => matchesProtocol(e, protocol) || (protocol.startsWith('service:') && (e.port_traffic || []).some(g => matchesProtocol(g,protocol)))).map(edge => {
    if (!protocol.startsWith('service:') || !Array.isArray(edge.port_traffic)) return edge;
    const groups=edge.port_traffic.filter(g => matchesProtocol(g,protocol));
    return {...edge, packets:groups.reduce((sum,g)=>sum+g.packets,0), bytes:groups.reduce((sum,g)=>sum+g.bytes,0)};
  });
  const connected = new Set(edges.flatMap(e => [e.source, e.target]));
  const matches = new Set((data.nodes || []).filter(n => (!protocol || connected.has(n.id)) && (!q || [n.id, n.label, ...(n.names || []), ...(n.macs || [])].join(' ').toLowerCase().includes(q))).map(n=>n.id));
  const related = new Set(matches);
  const selectedEdges=edges.filter(e=>!q || matches.has(e.source) || matches.has(e.target));
  selectedEdges.forEach(e=>{related.add(e.source);related.add(e.target);});
  const nodes=(data.nodes||[]).filter(n=>related.has(n.id)).slice().sort((a,b)=>b.bytes-a.bytes || a.id.localeCompare(b.id));
  const ids = new Set(nodes.map(n=>n.id));
  return {nodes, edges: selectedEdges.filter(e => ids.has(e.source) && ids.has(e.target))};
}
function visibleGraph(data, query = '', protocol = '', selected = null) {
  const filtered = filterGraph(data, query, protocol);
  const q = query.trim().toLowerCase();
  const priority = node => {
    if (node.id === selected) return 0;
    const fields = [node.id, node.label, ...(node.names || []), ...(node.macs || [])].filter(Boolean).map(s=>String(s).toLowerCase());
    if (q && fields.includes(q)) return 1;
    return q && fields.some(s=>s.includes(q)) ? 2 : 3;
  };
  const nodes = filtered.nodes.slice().sort((a,b)=>priority(a)-priority(b)).slice(0,40);
  const ids = new Set(nodes.map(n => n.id));
  const edges = filtered.edges.filter(e=>ids.has(e.source) && ids.has(e.target)).slice().sort((a,b)=>b.bytes-a.bytes).slice(0,80);
  return {nodes,edges,totalNodes:filtered.nodes.length,totalEdges:filtered.edges.length};
}
function formatDuration(value) {
  if (value == null || !Number.isFinite(Number(value)) || value < 0) return '—';
  if (value < 60) return `${Number(Number(value).toFixed(2))} s`;
  return `${Math.floor(value / 60)}m ${Math.floor(value % 60)}s`;
}
function layoutGraph(nodes) {
  const sorted=nodes.slice().sort((a,b)=>b.bytes-a.bytes || a.id.localeCompare(b.id));
  const positions=new Map();if(!sorted.length)return positions;
  positions.set(sorted[0].id,{x:450,y:240});
  const peers=sorted.slice(1);
  const rings=peers.length<=17?[{items:peers,rx:330,ry:175}]:peers.length<=28?[{items:peers.slice(0,10),rx:180,ry:95},{items:peers.slice(10),rx:375,ry:190}]:[{items:peers.slice(0,8),rx:145,ry:75},{items:peers.slice(8,21),rx:260,ry:133},{items:peers.slice(21),rx:380,ry:195}];
  rings.forEach((ring,r)=>ring.items.forEach((node,i)=>{const angle=-Math.PI/2+(i+.31*r)*2*Math.PI/ring.items.length;positions.set(node.id,{x:450+ring.rx*Math.cos(angle),y:240+ring.ry*Math.sin(angle)});}));
  return positions;
}
function timelineRange(buckets,start,end){
  if(!Number.isFinite(start)||!Number.isFinite(end)||start>end)return [];
  return (buckets||[]).filter(bucket=>bucket.time>=start&&bucket.time<=end);
}
function protocolActivity(view,metric='bytes',service=''){
  if(service){const value=(view.edges||[]).reduce((sum,edge)=>sum+(Number(edge[metric])||0),0);return value?[{name:`${service} (port hint)`,value}]:[];}
  const totals=new Map();
  for(const edge of view.edges||[]){
    const values=metric==='packets'?(edge.protocols||{}):(edge.protocol_bytes||{});
    for(const [name,value] of Object.entries(values))totals.set(name,(totals.get(name)||0)+(Number(value)||0));
  }
  return [...totals].map(([name,value])=>({name,value})).sort((a,b)=>b.value-a.value||a.name.localeCompare(b.name));
}
// Four vertices per occupied interval: gaps are a single zero-height segment.
// Input is the analyzer's sorted, non-overlapping sparse timeline.
function timelineSteps(buckets, width) {
  return buckets.flatMap(b => [[b.time,0],[b.time,b.bytes],[b.time+width,b.bytes],[b.time+width,0]]);
}
if (typeof module !== 'undefined') module.exports = {macLabels, formatBytes, filterGraph, visibleGraph, formatDuration, layoutGraph, timelineSteps, protocolActivity, timelineRange};
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
}
function boot() {
  const $ = id => document.getElementById(id);
  const NS = 'http://www.w3.org/2000/svg';
  const state = {geo:null,captureEpoch:0,data:null,selected:null,zoom:1,positions:new Map(),busy:false,aiController:null,aiEpoch:0,aiHasEvidence:false,aiResults:[],aiPage:0};
  let modelUI;
  const count = value => value == null ? '—' : Number(value).toLocaleString();
  const el = (tag, text, cls) => {const e=document.createElement(tag); if(text!=null)e.textContent=String(text); if(cls)e.className=cls; return e;};
  const svgEl = (tag, attrs={}, text) => {const e=document.createElementNS(NS,tag); Object.entries(attrs).forEach(([k,v])=>e.setAttribute(k,String(v))); if(text!=null)e.textContent=String(text);return e;};
  const date = value => {if(value==null)return '—';const d=new Date(typeof value==='number'?value*1000:value);return Number.isNaN(d.getTime())?'—':d.toLocaleString();};
  const time = value => {const d=new Date(Number(value)*1000);return Number.isNaN(d.getTime())?'—':d.toLocaleTimeString();};
  const kindName = kind => ({local:'Non-global IP',public:'Public IP',multicast:'Multicast',link:'Link-layer'}[kind] || 'Observed entity');
  const scopedView = () => PacketGeo.scopeView(filterGraph(state.data,$('graph-search').value,$('protocol-filter').value),$('analysis-scope').value,state.selected);
  const graph = () => $('analysis-scope').value==='selected' ? visibleGraph(scopedView(), '', '', state.selected) : visibleGraph(state.data,$('graph-search').value,$('protocol-filter').value,state.selected);
  const geoMap = PacketGeo.create(id=>{selectNode(id);const heading=document.querySelector('#node-details h3');if(heading){heading.tabIndex=-1;heading.focus({preventScroll:true});}});
  function renderGeo(){if(!state.data)return;const view=scopedView();geoMap.render(view,state.geo,state.selected);const geographical=$('map-view').value==='geography';$('map-title').textContent=geographical?'Geographic endpoints':'Network topology';if(geographical)$('graph-count').textContent=`${view.nodes.length} scoped nodes · ${view.edges.length} retained matching connections · all scoped nodes accounted for`;$('scope-count').textContent=`${view.nodes.length} nodes in scope${$('analysis-scope').value==='selected'&&!view.nodes.length?' · select a matching node':''}`;state.aiHasEvidence=view.nodes.length>0;updateAIButton();}
  async function locateCapture(){const epoch=++state.captureEpoch;state.geo=null;renderGeo();try{const config=await request('/api/config');const geo=await request('/api/geoip',{method:'POST',headers:{'Content-Type':'application/json','X-PacketMap-Token':config.token},body:JSON.stringify({addresses:state.data.nodes.map(n=>n.id)})});if(epoch===state.captureEpoch){state.geo=geo;renderGeo();}}catch(error){if(epoch===state.captureEpoch)$('geo-note').textContent=error.message;}}
  function setBusy(busy, message='') {
    state.busy=busy; $('status').hidden=!busy; $('status').textContent=message;
    $('demo-button').disabled=busy; $('capture-file').disabled=busy;
    ['graph-search','protocol-filter','export-button','zoom-in','zoom-out','reset-view'].forEach(id=>$(id).disabled=busy || !state.data);
    $('explore').setAttribute('aria-busy',String(busy));
    updateAIButton();
  }
  async function withDeadline(operation, milliseconds, message, onTimeout=()=>{}) {
    let timer;
    try {
      return await Promise.race([
        operation,
        new Promise((_, reject) => {
          timer=setTimeout(() => {reject(new Error(message)); onTimeout();}, milliseconds);
        }),
      ]);
    } finally {clearTimeout(timer);}
  }
  async function request(url, options={}) {
    const controller=new AbortController();
    const config=url==='/api/config';
    const message=config
      ? 'Connecting to the local server timed out. Check that PacketMap is running, then try again.'
      : 'Uploading or analyzing the capture timed out. The server may still be finishing the analysis; wait before retrying, or restart PacketMap and try a smaller capture.';
    return withDeadline((async () => {
      let response;
      try {response=await fetch(url,{...options,signal:controller.signal});}
      catch {throw new Error('Cannot reach the local PacketMap server. Check that it is running and refresh this page.');}
      let data;
      try {data=await response.json();} catch {throw new Error('The server returned an unreadable response. Please try again.');}
      if(!response.ok || data.error) throw new Error(data.error || `Request failed (${response.status}).`);
      return data;
    })(), config ? 15000 : 180000, message, () => controller.abort());
  }
  async function load(file) {
    if(state.busy)return;
    $('error').hidden=true;
    if(file && !/\.(pcap|pcapng)$/i.test(file.name)) {showError('Choose a .pcap or .pcapng capture file.');$('capture-file').value='';return;}
    cancelExplanation();
    setBusy(true,file?'Analyzing capture on this machine…':'Loading explicitly synthetic sample traffic…');
    try {
      let data;
      if(file) {
        // Materialize the file before opening HTTP: some sandboxed browsers
        // stall when fetch streams a disk-backed File despite sending its size.
        // Bound this allocation to the same limit enforced by the local server.
        if (!file.size || file.size > 256 * 1024 * 1024) throw new Error('Choose a non-empty capture up to 256 MiB.');
        setBusy(true, 'Reading capture from disk…');
        const readError = 'Your browser could not read this capture. In Snap Firefox, root-owned files or files outside allowed folders may be blocked even when their permissions allow reading. Save a copy owned by your user in your home folder, then select that copy.';
        const body = await withDeadline(
          Promise.resolve().then(() => file.arrayBuffer()).catch(() => {throw new Error(readError);}),
          30000, 'Reading the capture timed out. ' + readError);
        const config=await request('/api/config');
        if(!config.token)throw new Error('The local server did not provide an upload token. Refresh and try again.');
        setBusy(true, 'Uploading and analyzing capture on this machine…');
        data=await request('/api/analyze',{method:'POST',headers:{'Content-Type':'application/octet-stream','X-Filename':encodeURIComponent(file.name),'X-PacketMap-Token':config.token},body});
      } else data=await request('/api/demo');
      if(!data.summary || !Array.isArray(data.nodes) || !Array.isArray(data.edges))throw new Error('The analysis response is missing its summary or network data.');
      state.data=data;state.selected=null;state.zoom=1;state.positions.clear();$('analysis-scope').value='all';$('protocol-metric').value='bytes';$('timeline-start').value='0';$('timeline-end').value='100';for(const id of ['protocol-metric','timeline-start','timeline-end','timeline-reset'])$(id).disabled=false;
      $('graph-search').value='';$('protocol-filter').replaceChildren(el('option','All protocols / services'));$('protocol-filter').firstChild.value='';
      const services=el('optgroup');services.label='Services (port hints)';
      Object.entries(SERVICE_PORTS).forEach(([name,ports])=>{
        const opt=el('option',`${name} — ${ports.join(', ')}`);
        opt.value=`service:${name}`;services.append(opt);
      });
      const transports=el('optgroup');transports.label='Observed network / transport protocols';
      const names=new Set((data.protocols||[]).map(p=>p.name));data.edges.forEach(e=>Object.keys(e.protocols||{}).forEach(n=>names.add(n)));
      [...names].sort().forEach(name=>{const opt=el('option',name);opt.value=name;transports.append(opt);});
      $('protocol-filter').append(services,transports);
      $('capture-name').textContent=file?file.name:'Synthetic demo · not a real capture';
      $('capture-period').textContent=`${date(data.summary.start)} → ${date(data.summary.end)}`;
      const s=data.summary;
      $('metric-packets').textContent=count(s.packets);$('metric-bytes').textContent=formatBytes(s.bytes);$('metric-duration').textContent=formatDuration(s.duration);$('metric-nodes').textContent=count(s.ip_entities);$('metric-edges').textContent=count(s.connections);
      $('warning-list').replaceChildren(...(data.warnings||[]).map(w=>el('li',w)));$('warnings').hidden=!(data.warnings||[]).length;
      renderMap();renderDetails();renderCharts();renderTable();locateCapture();
    } catch(error) {showError(error.message || 'Unable to analyze this capture.');}
    finally {setBusy(false);$('capture-file').value='';}
  }
  function showError(message) {$('error').textContent=message;$('error').hidden=false;}
  function selectNode(id) {
    cancelExplanation();state.selected=id;
    // Peers can be inspected even if search or the visual cap hides them.
    renderMap();renderDetails();renderTable();renderGeo();renderCharts();
  }
  function renderMap() {
    if(!state.data)return;
    const view=graph();const svg=$('network-svg');svg.replaceChildren();
    state.aiHasEvidence=view.totalEdges>0;updateAIButton();
    $('graph-count').textContent=`${view.nodes.length} / ${view.totalNodes} entities (matches + peers) · ${view.edges.length} / ${view.totalEdges} matching connections · ${state.data.nodes.length} entities total`;
    $('map-empty').hidden=view.nodes.length>0;
    if(!view.nodes.length){$('map-empty').replaceChildren(el('h3',state.data.nodes.length?'No matching entities.':'No network entities found.'),el('p',state.data.nodes.length?'Try a different IP, DNS name, MAC or protocol.':'This capture contains no supported network conversations.'));}
    const layer=svgEl('g',{'data-map-layer':'true'});svg.append(layer);
    const initial=layoutGraph(view.nodes);
    view.nodes.forEach(n=>{if(!state.positions.has(n.id))state.positions.set(n.id,initial.get(n.id));});
    const edgesGroup=svgEl('g');layer.append(edgesGroup);const lines=[];
    const maxBytes=Math.max(1,...view.edges.map(e=>Number(e.bytes)||0));
    view.edges.forEach(edge=>{
      const active=state.selected&&(edge.source===state.selected||edge.target===state.selected);
      const line=svgEl('path',{class:`network-edge${active?' active':''}`,'stroke-width':.8+4*Math.sqrt((edge.bytes||0)/maxBytes)});
      line.append(svgEl('title',{},`${edge.source} ↔ ${edge.target}: ${formatBytes(edge.bytes)}`));edgesGroup.append(line);lines.push({edge,line});
    });
    const related=new Set([state.selected]);view.edges.forEach(e=>{if(e.source===state.selected)related.add(e.target);if(e.target===state.selected)related.add(e.source);});
    const maxNodeBytes=Math.max(1,...view.nodes.map(n=>n.bytes||0));
    view.nodes.forEach(node=>{
      const kind=['local','public','multicast','link'].includes(node.kind)?node.kind:'link';
      const group=svgEl('g',{class:`network-node ${kind}${state.selected===node.id?' selected':''}${state.selected&&!related.has(node.id)?' dimmed':''}`,tabindex:'0',role:'button','aria-label':`Inspect ${node.id}${node.names?.length?', '+node.names.join(', '):''}`,'aria-pressed':String(state.selected===node.id)});
      const radius=8+12*Math.sqrt((node.bytes||0)/maxNodeBytes);
      group.append(svgEl('circle',{r:radius}),svgEl('text',{x:0,y:radius+16,'text-anchor':'middle'},shortLabel(node.label||node.id,23)));
      if(node.names?.length)group.append(svgEl('text',{class:'node-name',x:0,y:radius+30,'text-anchor':'middle'},shortLabel(node.names[0],24)));
      group.append(svgEl('title',{},`${node.id}\n${(node.names||[]).join('\n')}\n${formatBytes(node.bytes)} · ${count(node.packets)} packets`));
      const move=()=>{const p=state.positions.get(node.id);group.setAttribute('transform',`translate(${p.x} ${p.y})`);};move();
      group.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();selectNode(node.id);const active=[...svg.querySelectorAll('.network-node')].find(g=>g.getAttribute('aria-label')===group.getAttribute('aria-label'));active?.focus();}});
      let drag=null;
      group.addEventListener('pointerdown',event=>{if(event.button!==0)return;drag={x:event.clientX,y:event.clientY,moved:false};group.setPointerCapture(event.pointerId);});
      group.addEventListener('pointermove',event=>{
        if(!drag)return;
        if(Math.hypot(event.clientX-drag.x,event.clientY-drag.y)>4)drag.moved=true;
        if(!drag.moved)return;
        const matrix=layer.getScreenCTM();if(!matrix)return;
        const point=new DOMPoint(event.clientX,event.clientY).matrixTransform(matrix.inverse());
        state.positions.set(node.id,{x:Math.max(35,Math.min(865,point.x)),y:Math.max(30,Math.min(445,point.y))});move();drawEdges();
      });
      group.addEventListener('pointerup',()=>{if(drag&&!drag.moved)selectNode(node.id);drag=null;});
      group.addEventListener('pointercancel',()=>{drag=null;});
      layer.append(group);
    });
    function drawEdges(){lines.forEach(({edge,line})=>{const a=state.positions.get(edge.source),b=state.positions.get(edge.target);line.setAttribute('d',edge.source===edge.target?`M ${a.x} ${a.y} c -45 -60 45 -60 0 0`:`M ${a.x} ${a.y} Q ${(a.x+b.x)/2} ${(a.y+b.y)/2-16} ${b.x} ${b.y}`);});}
    drawEdges();updateZoom();
  }
  function shortLabel(label,max){const s=String(label);return s.length>max?s.slice(0,max-1)+'…':s;}
  function updateZoom(){const layer=$('network-svg').querySelector('[data-map-layer]');if(layer)layer.setAttribute('transform',`translate(${450*(1-state.zoom)} ${250*(1-state.zoom)}) scale(${state.zoom})`);$('zoom-level').textContent=`${Math.round(state.zoom*100)}%`;}
  function renderDetails() {
    const box=$('node-details');box.replaceChildren();
    const node=state.data?.nodes.find(n=>n.id===state.selected);
    if(!node){const wrap=el('div',null,'inspector-empty');wrap.append(el('h3','Select an endpoint'),el('p','Select a node on the map to inspect its addresses, observed names and peers.'),el('p','Keyboard: Tab to a node, then Enter.','keyboard-hint'));box.append(wrap);return;}
    box.append(el('span',kindName(node.kind),'entity-kind'),el('h3',node.id,'entity-id'));
    function field(label,values){box.append(el('h4',label,'detail-label'));(values.length?values:['Not observed']).forEach(value=>box.append(el('p',value,'detail-value')));}
    field('IP / entity identifier',[node.id]);field('Observed DNS names',node.names||[]);field('Observed MAC addresses',macLabels(node));
    box.append(el('p','Observed link-layer associations may be gateway/next-hop MACs, not the remote endpoint. Vendor allocation and low-confidence hints do not establish device identity or model.','quiet'));
    box.append(el('p','Offline vendor data: MACLookup (maclookup.app), sourced from IEEE and third-party registries. Terms: maclookup.app/terms-and-conditions; no separate CSV redistribution license confirmed. Database stays local. Update: python3 scripts/install_mac_vendors.py','quiet'));
    field('Captured traffic',[`${formatBytes(node.bytes)} · ${count(node.packets)} packets`]);
    const peers=new Map();state.data.edges.forEach(e=>{if(e.source!==node.id&&e.target!==node.id)return;const id=e.source===node.id?e.target:e.source;const old=peers.get(id)||{bytes:0,packets:0};old.bytes+=Number(e.bytes)||0;old.packets+=Number(e.packets)||0;peers.set(id,old);});
    box.append(el('h4',`Peers · ${peers.size} · entire capture`,'detail-label'));const list=el('ul',null,'peer-list');
    [...peers].sort((a,b)=>b[1].bytes-a[1].bytes).forEach(([id,traffic])=>{const li=el('li');const button=el('button',id);button.addEventListener('click',()=>selectNode(id));li.append(button,el('small',`${formatBytes(traffic.bytes)} · ${count(traffic.packets)} packets`));list.append(li);});box.append(list);
  }
  function renderTable(){
    if(!state.data)return;
    const filtered=scopedView();
    const edges=filtered.edges.slice().sort((a,b)=>b.bytes-a.bytes).slice(0,100);const body=$('connections-body');body.replaceChildren();
    const service=$('protocol-filter').value.startsWith('service:');
    const legacy=service && filtered.edges.some(e=>!Array.isArray(e.port_traffic));
    const partial=service && state.data.edges.some(e=>e.traffic_complete===false);
    $('connections-count').textContent=`${edges.length} of ${filtered.edges.length} matching connections · both directions combined · ${service && !legacy ? 'service-filtered packet/byte totals' : 'whole-connection totals'}${partial ? ' · PARTIAL: service detail limit reached' : ''}${legacy ? ' · reload capture for service totals' : ''}`;
    if(!edges.length){const row=el('tr');const td=el('td','No matching connections. Try clearing the filters.','table-empty');td.colSpan=5;row.append(td);body.append(row);return;}
    edges.forEach(edge=>{const row=el('tr');[edge.source,edge.target].forEach(id=>{const td=el('td');const button=el('button',id,'table-node');button.addEventListener('click',()=>selectNode(id));td.append(button);row.append(td);});const protocol=Object.keys(edge.protocols||{}).join(', '),protocolCell=el('td',protocol||'—');if(edge.ports?.length>6){const ports=el('details');ports.append(el('summary',`${edge.ports.length} observed ports`),el('p',edge.ports.join(', ')));protocolCell.append(ports);}else if(edge.ports?.length)protocolCell.append(document.createTextNode(' / '+edge.ports.join(', ')));row.append(protocolCell,el('td',(service && edge.traffic_complete===false?'≥ ':'')+count(edge.packets),'numeric'),el('td',(service && edge.traffic_complete===false?'≥ ':'')+formatBytes(edge.bytes),'numeric'));body.append(row);});
  }
  function renderCharts(){
    if(!state.data)return;
    const view=scopedView(),metric=$('protocol-metric').value,filter=$('protocol-filter').value;
    const service=filter.startsWith('service:')?filter.slice(8):'';
    const protocols=protocolActivity(view,metric,service),chart=$('protocol-chart');chart.replaceChildren();
    const max=Math.max(1,...protocols.map(p=>p.value||0));
    $('protocol-scope').textContent=`Filtered scope · ${view.nodes.length} nodes · ${view.edges.length} matching connections · by ${metric}`;
    protocols.forEach(p=>{
      const row=el('div',null,'protocol-row'),button=el('button',p.name,'protocol-name'),track=el('div',null,'bar-track'),fill=el('div',null,'bar-fill');
      fill.style.width=`${100*(p.value||0)/max}%`;track.append(fill);
      const display=metric==='bytes'?formatBytes(p.value):`${count(p.value)} packets`;
      row.title=`${p.name}: ${display}`;button.disabled=!!service;button.title=service?'Clear the service filter before selecting a network protocol.':`Filter map to ${p.name}`;
      button.addEventListener('click',()=>{$('protocol-filter').value=p.name;applyFilters();});
      row.append(button,track,el('span',display,'protocol-value'));chart.append(row);
    });
    if(!protocols.length)chart.append(el('p','No protocol traffic matches the current scope.','quiet'));
    const box=$('timeline-chart');box.replaceChildren();const all=(state.data.timeline||[]).slice().sort((a,b)=>a.time-b.time);
    if(!all.length){$('timeline-range-status').textContent='No timestamped traffic observed.';box.append(el('p','No timestamped traffic observed.','quiet'));return;}
    const captureFirst=Number(all[0].time),captureLast=Number(all.at(-1).time),span=Math.max(0,captureLast-captureFirst);
    const startPercent=Number($('timeline-start').value),endPercent=Number($('timeline-end').value);
    const startTime=captureFirst+span*startPercent/100,endTime=captureFirst+span*endPercent/100;
    const buckets=timelineRange(all,startTime,endTime);
    $('timeline-range-status').textContent=`Showing ${date(startTime)} – ${date(endTime)} · ${buckets.length} of ${all.length} occupied intervals`;
    if(!buckets.length){box.append(el('p','No occupied intervals in this range. Adjust Start or End.','quiet'));return;}
    const width=state.data.timeline_bucket_width || 1;
    const high=Math.max(1,...buckets.map(b=>b.bytes||0));const first=Number(buckets[0].time),last=Number(buckets.at(-1).time)+width;
    const interval=`${width} seconds per interval`;
    const chartSvg=svgEl('svg',{viewBox:'0 0 660 120',role:'img','aria-label':`Traffic timeline. ${buckets.length} occupied intervals in selected range, ${interval}, maximum ${formatBytes(high)} per interval. Unoccupied intervals show zero captured traffic.`});
    [15,55,95].forEach(y=>chartSvg.append(svgEl('line',{x1:0,y1:y,x2:660,y2:y,stroke:'#e1e7db','stroke-dasharray':'3 4'})));
    const x=t=>6+(t-first)/(last-first)*648,y=bytes=>104-bytes/high*88;
    const coords=timelineSteps(buckets,width).map(([t,bytes])=>[x(t),y(bytes)]),line=coords.map((point,i)=>`${i?'L':'M'} ${point[0]} ${point[1]}`).join(' ');
    chartSvg.append(svgEl('path',{d:`${line} Z`,fill:'#e1eee2'}),svgEl('path',{d:line,fill:'none',stroke:'#167a68','stroke-width':2}));
    buckets.forEach(b=>{const point=svgEl('circle',{cx:x(b.time+width/2),cy:y(b.bytes),r:buckets.length===1?4:2,fill:'#167a68'});point.append(svgEl('title',{},`${date(b.time)} · ${interval} · ${formatBytes(b.bytes)} · ${count(b.packets)} packets`));chartSvg.append(point);});
    const labels=el('div',null,'timeline-labels');labels.append(el('span',date(first)),el('span',`Peak ${formatBytes(high)} / interval · ${interval}`),el('span',date(last)));box.append(chartSvg,labels);
  }
  function updateAIButton() {
    $('explain-button').disabled=state.busy || !!state.aiController || !state.data || !state.aiHasEvidence;
    $('explain-button').textContent=state.aiController?'Analyzing…':(!state.aiHasEvidence&&state.data?'No matching connections':'Analyze scoped nodes');
    $('ai-cancel').hidden=!state.aiController;$('ai-export').disabled=!state.aiResults.length;
    modelUI?.setBusy(!!state.aiController);
  }
  function cancelExplanation(message='') {
    state.aiEpoch++;state.aiController?.abort();state.aiController=null;state.aiResults=[];state.aiPage=0;
    $('ai-result').replaceChildren();$('ai-pages').hidden=true;$('ai-status').textContent=message;updateAIButton();
  }
  async function explainView() {
    if($('explain-button').disabled)return;
    cancelExplanation();
    const view=scopedView(),filter=$('protocol-filter').value;
    if(filter.startsWith('service:')&&view.edges.some(e=>!Array.isArray(e.port_traffic))){$('ai-status').textContent='Reload the capture to obtain accurate service counts before analysis.';return;}
    const jobs=analysisJobs(view,filter,!!state.data.warnings?.length);
    const epoch=state.aiEpoch,controller=new AbortController();state.aiController=controller;updateAIButton();renderAIResults();
    const total=jobs.length;let processed=0,failed=false;
    const status=message=>{if(epoch===state.aiEpoch)$('ai-status').textContent=message;};
    status(`Preparing ${total} nodes. One request per node; Stop preserves finished results.`);
    try{
      const {config,settings}=await modelUI.forAnalysis();
      for(const job of jobs){
        if(epoch!==state.aiEpoch||controller.signal.aborted)return;
        status(`Analyzing ${processed} / ${total} nodes · ${job.node}`);
        if(!job.connections.length){state.aiResults.push({node:job.node,status:'no_evidence',note:'No retained matching connections. No model inference was generated.'});}
        else{
          const body=JSON.stringify(job);
          if(new TextEncoder().encode(body).length>32768)throw new Error('Node evidence exceeds the request limit; narrow the service filter.');
          const timer=setTimeout(()=>controller.abort(),170000);let result;
          try{
            const response=await fetch('/api/explain',{method:'POST',signal:controller.signal,
              headers:{'Content-Type':'application/json','X-PacketMap-Token':config.token,'X-PacketMap-Model-Revision':settings.revision},body});
            result=await response.json();
            if(!response.ok||result.error)throw new Error(result.error||'Model analysis failed.');
          }finally{clearTimeout(timer);}
          if(epoch!==state.aiEpoch)return;
          state.aiResults.push({node:job.node,status:'analyzed',result,aliases:aliasesFor(job)});
        }
        processed++;renderAIResults();status(`Completed ${processed} / ${total} nodes · model analysis`);
      }
    }catch(error){failed=true;status(`Stopped: ${processed} / ${total} nodes completed; ${total-processed} not analyzed. ${controller.signal.aborted?'Model request timed out. The model may still be finishing.':error.message}`);}
    finally{if(epoch===state.aiEpoch){state.aiController=null;updateAIButton();if(!failed)status(`Completed ${processed} / ${total} nodes · ${state.aiResults.filter(r=>r.status==='analyzed').length} model analyses · ${state.aiResults.filter(r=>r.status==='no_evidence').length} without retained evidence.`);}}
  }
  function aliasesFor(job){const map=new Map([[job.node,'Host1']]);for(const e of job.connections)for(const id of [e.source,e.target])if(!map.has(id))map.set(id,`Host${map.size+1}`);return Object.fromEntries([...map].map(([id,alias])=>[alias,id]));}
  function analysisReferenceTable(entry,context){
    const table=el('table','','ai-reference-table'),thead=el('thead'),head=el('tr');
    for(const label of ['Reference','Type','Actual value','Meaning'])head.append(el('th',label));
    thead.append(head);const body=el('tbody');
    const add=(ref,type,actual,meaning)=>{const row=el('tr');row.id=`ref-${entry.node.replace(/[^a-zA-Z0-9_-]/g,'-')}-${ref}`;for(const value of [ref,type,actual,meaning])row.append(el('td',value));body.append(row);};
    const nodes=new Map((state.data?.nodes||[]).map(node=>[node.id,node]));
    for(const [alias,address] of Object.entries(entry.aliases||{})){
      const names=(nodes.get(address)?.names||[]).slice(0,3);
      add(alias,'Endpoint',address+(names.length?` · ${names.join(', ')}`:''),'Browser-side alias used only within this node analysis.');
    }
    if(context.node_summary){const n=context.node_summary,actual=entry.aliases?.[n.host]||entry.node;add(n.id,'Node aggregate',actual,`${count(n.packets)} packets · ${formatBytes(n.bytes)} · ${count(n.peer_count)} peers · ${count(n.connection_count)} connections · ${formatDuration(n.observed_window_seconds)}`);}
    for(const evidence of context.evidence||[]){
      const source=entry.aliases?.[evidence.source]||evidence.source,target=entry.aliases?.[evidence.target]||evidence.target;
      add(evidence.id,'Connection evidence',`${source} ↔ ${target}`,`${count(evidence.packets)} packets · ${formatBytes(evidence.bytes)} · ${(evidence.ports||[]).join(', ')||'no port evidence'}${evidence.partial?' · partial':''}`);
    }
    for(const geo of context.geography||[]){
      const address=entry.aliases?.[geo.host]||geo.host;
      const place=geo.status==='located'?[geo.city,geo.country].filter(Boolean).join(', ')||'Approximate location available':geo.status.replaceAll('_',' ');
      add(geo.id,'GeoIP evidence',address,`${place}${geo.approximate?' · approximate':''}`);
    }
    table.append(thead,body);return table;
  }
  function renderAIResults(){
    const wrap=$('ai-result');wrap.replaceChildren();
    $('ai-pages').hidden=state.aiResults.length<=5;$('ai-page-count').textContent=`${state.aiPage*5+1}–${Math.min(state.aiResults.length,state.aiPage*5+5)} of ${state.aiResults.length}`;
    $('ai-prev').disabled=state.aiPage===0;$('ai-next').disabled=(state.aiPage+1)*5>=state.aiResults.length;$('ai-export').disabled=!state.aiResults.length;
    for(const entry of state.aiResults.slice(state.aiPage*5,state.aiPage*5+5)){
      const article=el('article','','ai-node-result');article.append(el('h4',entry.node));
      if(!entry.result){article.append(el('p',entry.note));wrap.append(article);continue;}
      const {answer,context,model}=entry.result,partial=context.capture_limited||context.evidence.some(e=>e.partial);
      if(context.node_summary){const n=context.node_summary;article.append(el('p',`Calculated evidence: ${count(n.packets)} packets · ${formatBytes(n.bytes)} · ${n.peer_count} peers · ${n.connection_count} retained connections · mean packet ${n.average_packet_bytes??'—'} B`,'ai-badge'));}
      article.append(el('p',`${context.evidence.length} evidence connections · ${context.omitted_connections} omitted from detail · ${partial?'PARTIAL capture/detail':'retained capture evidence'} · ${model}`,'ai-badge'),el('p',answer.summary));
      const addList=(heading,items)=>{article.append(el('h4',heading));const list=el('ul');for(const value of items)list.append(el('li',value));article.append(list);};
      addList('Observed evidence',answer.observations.map(o=>`${o.text} [${o.evidence_ids.join(', ')}]`));
      if(answer.interpretations)addList('Interpretations',answer.interpretations.map(o=>`${o.text} [${o.confidence} confidence; ${o.evidence_ids.join(', ')}]`));
      if(answer.next_checks)addList('Follow-up checks · application-generated',answer.next_checks);
      addList('Limitations',answer.uncertainties);
      article.append(el('h4','Reference guide'),analysisReferenceTable(entry,context));
      const evidence=el('details');evidence.append(el('summary',`Evidence detail · ${context.evidence.length} connections · ${context.omitted_connections} omitted`));
      const list=el('ul');for(const e of context.evidence)list.append(el('li',`${e.id}: ${e.source} ↔ ${e.target}; ${e.packets} packets, ${formatBytes(e.bytes)}; ${e.ports.join(', ')||'no transport port evidence'}.`));evidence.append(list);
      article.append(evidence);wrap.append(article);
    }
  }
  $('explain-button').addEventListener('click',explainView);
  $('ai-cancel').addEventListener('click',()=>{const finished=state.aiResults.length;state.aiEpoch++;state.aiController?.abort();state.aiController=null;$('ai-status').textContent=`Cancelled after ${finished} completed nodes. Remaining nodes were not analyzed. The active generation may still finish on the configured server.`;updateAIButton();});
  $('ai-prev').onclick=()=>{state.aiPage--;renderAIResults();};$('ai-next').onclick=()=>{state.aiPage++;renderAIResults();};
  $('ai-export').onclick=()=>{const blob=new Blob([JSON.stringify({capture:$('capture-name').textContent,filter:$('protocol-filter').value,scope:$('analysis-scope').value,scope_node_count:scopedView().nodes.length,completed_nodes:state.aiResults.length,incomplete:state.aiResults.length<scopedView().nodes.length,results:state.aiResults},null,2)],{type:'application/json'});const url=URL.createObjectURL(blob),a=el('a');a.href=url;a.download='packetmap-node-analysis.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};
  modelUI=PacketModelUI.create({request,isBusy:()=>!!state.aiController,onSaved:()=>cancelExplanation('Settings saved. Previous results reset; click Analyze to start a new batch.')});
  $('demo-button').addEventListener('click',()=>load());
  $('capture-file').addEventListener('change',event=>{if(event.target.files[0])load(event.target.files[0]);});
  function applyFilters(){cancelExplanation();state.positions.clear();state.zoom=1;renderMap();renderTable();renderGeo();renderCharts();}
  $('protocol-metric').addEventListener('change',renderCharts);
  for(const id of ['timeline-start','timeline-end'])$(id).addEventListener('input',()=>{if(Number($('timeline-start').value)>Number($('timeline-end').value)){if(id==='timeline-start')$('timeline-end').value=$('timeline-start').value;else $('timeline-start').value=$('timeline-end').value;}renderCharts();});
  $('timeline-reset').addEventListener('click',()=>{$('timeline-start').value='0';$('timeline-end').value='100';renderCharts();});
  $('analysis-scope').addEventListener('change',applyFilters);
  $('map-view').addEventListener('change',()=>{$('geography-view').hidden=$('map-view').value!=='geography';$('topology-view').hidden=$('map-view').value==='geography';renderMap();renderGeo();});
  $('graph-search').addEventListener('input',applyFilters);$('protocol-filter').addEventListener('change',applyFilters);
  $('zoom-in').addEventListener('click',()=>{state.zoom=Math.min(2.5,state.zoom+.25);updateZoom();});
  $('zoom-out').addEventListener('click',()=>{state.zoom=Math.max(.5,state.zoom-.25);updateZoom();});
  $('reset-view').addEventListener('click',()=>{cancelExplanation();state.zoom=1;state.selected=null;state.positions.clear();$('graph-search').value='';$('protocol-filter').value='';$('analysis-scope').value='all';renderMap();renderDetails();renderTable();renderGeo();});
  $('export-button').addEventListener('click',()=>{if(!state.data)return;const blob=new Blob([JSON.stringify(state.data,null,2)],{type:'application/json'});const url=URL.createObjectURL(blob);const link=el('a');link.href=url;link.download='packetmap-analysis.json';document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);});
}
