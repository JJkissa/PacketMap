'use strict';
const PacketGeo = (() => {
  function scopeView(filtered, mode, selected) {
    if (mode !== 'selected') return filtered;
    const nodes=filtered.nodes.filter(n=>n.id===selected);
    return {nodes,edges:nodes.length?filtered.edges.filter(e=>e.source===selected||e.target===selected):[]};
  }
  const project=(latitude,longitude)=>[(longitude+180)*960/360,(90-latitude)*480/180];
  function groupLocations(nodes,records) {
    const index=new Map(records.map(r=>[r.id,r])), grouped=new Map(),unmapped=[];
    for(const node of nodes){
      const location=index.get(node.id);
      if(location?.status!=='located'||!Number.isFinite(location.latitude)||!Number.isFinite(location.longitude)){unmapped.push(node);continue;}
      const key=`${location.latitude.toFixed(2)},${location.longitude.toFixed(2)}`;
      if(!grouped.has(key))grouped.set(key,{latitude:location.latitude,longitude:location.longitude,nodes:[]});
      grouped.get(key).nodes.push(node);
    }
    return {groups:[...grouped.values()],unmapped};
  }
  function create(onSelect) {
    const $=id=>document.getElementById(id),ns='http://www.w3.org/2000/svg';
    const svg=$('geo-svg'),land=document.createElementNS(ns,'g'),markers=document.createElementNS(ns,'g');
    svg.append(land,markers);
    let current=[],records=new Map(),page=0,box=[0,0,960,480],drag=null;
    const text=(tag,value)=>{const e=document.createElement(tag);e.textContent=value;return e;};
    const shape=(tag,attrs)=>{const e=document.createElementNS(ns,tag);for(const [k,v] of Object.entries(attrs))e.setAttribute(k,String(v));return e;};
    const drawBox=()=>svg.setAttribute('viewBox',box.join(' '));
    function showList(){
      const list=$('geo-node-list');list.replaceChildren();
      for(const node of current.slice(page*50,page*50+50)){
        const row=text('li',''),button=text('button',node.id),loc=records.get(node.id);
        button.type='button';button.addEventListener('click',()=>onSelect(node.id));
        row.append(button,text('span',loc?.status==='located'?[loc.city,loc.country].filter(Boolean).join(', '):`Unmapped · ${(loc?.status||'pending').replaceAll('_',' ')}`));list.append(row);
      }
      $('geo-page').textContent=current.length?`${page*50+1}–${Math.min(current.length,page*50+50)} of ${current.length}`:'0 endpoints';
      $('geo-prev').disabled=page===0;$('geo-next').disabled=(page+1)*50>=current.length;
    }
    $('geo-prev').onclick=()=>{page--;showList();};$('geo-next').onclick=()=>{page++;showList();};
    $('geo-fit').onclick=()=>{box=[0,0,960,480];drawBox();};
    function zoom(factor){const w=Math.min(960,Math.max(30,box[2]*factor));const h=w/2;box=[box[0]+(box[2]-w)/2,box[1]+(box[3]-h)/2,w,h];drawBox();}
    $('geo-in').onclick=()=>zoom(.7);$('geo-out').onclick=()=>zoom(1/.7);
    svg.addEventListener('pointerdown',e=>{if(e.button!==0||e.target.closest('[data-geo-marker]'))return;drag={x:e.clientX,y:e.clientY,box:box.slice()};svg.setPointerCapture(e.pointerId);});
    svg.addEventListener('pointermove',e=>{if(!drag)return;const scale=drag.box[2]/svg.getBoundingClientRect().width;box=[drag.box[0]-(e.clientX-drag.x)*scale,drag.box[1]-(e.clientY-drag.y)*scale,...drag.box.slice(2)];drawBox();});
    for(const event of ['pointerup','pointercancel'])svg.addEventListener(event,()=>{drag=null;});
    svg.addEventListener('keydown',e=>{const delta=box[2]/10;if(e.key==='ArrowLeft')box[0]-=delta;else if(e.key==='ArrowRight')box[0]+=delta;else if(e.key==='ArrowUp')box[1]-=delta;else if(e.key==='ArrowDown')box[1]+=delta;else if(e.key==='Home')box=[0,0,960,480];else return;e.preventDefault();drawBox();});
    fetch('/world.json').then(r=>{if(!r.ok)throw Error('Map unavailable');return r.json();}).then(world=>{
      for(const feature of world.features){
        const polygons=feature.geometry.type==='Polygon'?[feature.geometry.coordinates]:feature.geometry.coordinates;
        const d=polygons.map(p=>p.map(ring=>ring.map(([lon,lat],i)=>`${i?'L':'M'}${project(lat,lon).join(' ')}`).join(' ')+' Z').join(' ')).join(' ');
        const path=shape('path',{d,class:'geo-land'});path.append(text('title',feature.properties.name));land.append(path);
      }
    }).catch(()=>{$('geo-note').textContent='Local basemap unavailable; endpoint coordinates remain listed.';});
    return {render(view,geo,selected){
      records=new Map((geo?.nodes||[]).map(n=>[n.id,n]));current=view.nodes;page=0;markers.replaceChildren();
      const {groups,unmapped}=groupLocations(view.nodes,geo?.nodes||[]);
      for(const group of groups){
        const [x,y]=project(group.latitude,group.longitude),active=group.nodes.some(n=>n.id===selected);
        const marker=shape('g',{'data-geo-marker':'true',transform:`translate(${x} ${y})`,tabindex:0,role:'button','aria-label':group.nodes.length===1?`Inspect location of ${group.nodes[0].id}`:`List ${group.nodes.length} endpoints at this location`});
        marker.append(shape('circle',{r:group.nodes.length>1?8:5,class:active?'geo-marker selected':'geo-marker'}));
        const title=shape('title',{});title.textContent=`${group.nodes.length} endpoint(s) · approximate ${group.latitude}, ${group.longitude}`;marker.append(title);
        if(group.nodes.length>1){const label=shape('text',{'text-anchor':'middle',y:3,class:'geo-count'});label.textContent=group.nodes.length;marker.append(label);}
        const activate=()=>{if(group.nodes.length===1)onSelect(group.nodes[0].id);else{current=group.nodes;page=0;showList();document.querySelector('#geo-node-list button')?.focus();}};
        marker.onclick=activate;marker.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();activate();}};markers.append(marker);
      }
      $('geo-count').textContent=`${view.nodes.length} scoped endpoints · ${view.nodes.length-unmapped.length} located · ${unmapped.length} unmapped · ${groups.length} location markers`;
      $('geo-note').textContent=geo?.database?.note||'Locations load locally after a capture is opened.';
      const credit=$('geo-credit');credit.textContent=geo?.database?.attribution||'IP Geolocation by DB-IP';credit.href=geo?.database?.attribution_url==='https://www.maxmind.com'?'https://www.maxmind.com':'https://db-ip.com';
      $('geo-database').textContent=geo?.database?.available?`${geo.database.type} · database ${new Date(geo.database.build_epoch*1000).toISOString().slice(0,10)}`:'Database unavailable';
      showList();
    }};
  }
  return {scopeView,project,groupLocations,create};
})();
if(typeof module!=='undefined')module.exports=PacketGeo;
