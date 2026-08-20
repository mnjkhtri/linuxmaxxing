/* SPDX-License-Identifier: GPL-2.0 */
/* Two raw parsers feed one normalized monotonic model; rendering never interprets capture strings. */
(function(){
'use strict';

var stamp=Date.now();
var BPF='../../shared/_captures/virt-paraio.eBPF.ndjson?v='+stamp;
var TRACE='../../shared/_captures/virt-paraio-Trace.txt?v='+stamp;
var M={meta:null,events:[],phase:'A',landmarks:{},setupMmio:0,notifyMmio:0};
var cursor=0,playTimer=null,motionTimers=[];

function $(id){return document.getElementById(id)}
function esc(value){return String(value==null?'':value).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function missing(value){return value===null||value===undefined}
function shown(value){if(missing(value))return'not sampled';if(value===true)return'true';if(value===false)return'false';return String(value)}
function hexNumber(value){if(missing(value))return null;if(typeof value==='number')return value;return parseInt(String(value),16)}

var REGISTER={0x000:'MagicValue',0x004:'Version',0x008:'DeviceID',0x00c:'VendorID',0x010:'DeviceFeatures',0x014:'DeviceFeaturesSel',0x020:'DriverFeatures',0x024:'DriverFeaturesSel',0x030:'QueueSel',0x034:'QueueSizeMax',0x038:'QueueSize',0x044:'QueueReady',0x050:'QueueNotify',0x070:'Status',0x080:'QueueDescLow',0x084:'QueueDescHigh',0x090:'QueueDriverLow',0x094:'QueueDriverHigh',0x0a0:'QueueDeviceLow',0x0a4:'QueueDeviceHigh'};
var QUEUE_OFFSETS={0x030:1,0x034:1,0x038:1,0x044:1,0x080:1,0x084:1,0x090:1,0x094:1,0x0a0:1,0x0a4:1};

function parseEbpf(text){
    var out=[];
    text.split(/\r?\n/).forEach(function(raw){
        if(!raw.trim())return;
        var record;
        try{record=JSON.parse(raw)}catch(error){throw Error('invalid NDJSON: '+error.message)}
        if(record.kind==='meta'){M.meta=record;return}
        if(record.kind!=='snapshot')return;
        out.push({source:'ebpf',name:record.event_info.event_name,timeNs:Number(record.time_ns),phase:record.event_info.phase,info:record.event_info,context:record.context||{},state:record.state||null,raw:raw,record:record});
    });
    return out;
}

function parseTrace(text){
    var out=[],lineNo=0;
    text.split(/\r?\n/).forEach(function(raw){
        lineNo++;
        var match=raw.match(/^\s*(.+?)-(\d+)\s+\[(\d+)\]\s+(\S+)\s+([0-9]+\.[0-9]+):\s+([a-zA-Z0-9_]+):\s+(.+)$/);
        if(!match)return;
        var event={source:'tracefs',name:match[6],timeNs:Math.round(Number(match[5])*1e9),phase:null,state:null,raw:raw.trim(),line:lineNo,context:{comm:match[1].trim(),pid:Number(match[2]),tid:Number(match[2]),cpu:Number(match[3])},info:{flags:match[4],body:match[7]}};
        if(event.name==='kvm_entry'){
            var entry=event.info.body.match(/vcpu\s+(\d+),\s+rip\s+(0x[0-9a-f]+)/i);
            if(entry){event.info.vcpu=Number(entry[1]);event.info.rip=entry[2]}
        }else if(event.name==='kvm_exit'){
            var exit=event.info.body.match(/vcpu\s+(\d+)\s+reason\s+([^\s]+)\s+rip\s+(0x[0-9a-f]+)/i);
            if(exit){event.info.vcpu=Number(exit[1]);event.info.reason=exit[2];event.info.rip=exit[3]}
        }else if(event.name==='kvm_userspace_exit'){
            var handoff=event.info.body.match(/reason\s+(.+?)\s+\(\d+\)$/i);
            if(handoff)event.info.reason=handoff[1];
        }else if(event.name==='kvm_mmio'){
            var mmio=event.info.body.match(/mmio\s+([^\s]+)\s+len\s+(\d+)\s+gpa\s+(0x[0-9a-f]+)\s+val\s+(0x[0-9a-f]+)/i);
            if(mmio){event.info.operation=mmio[1];event.info.length=Number(mmio[2]);event.info.address=mmio[3];event.info.value=mmio[4];event.info.offset=hexNumber(mmio[3])-0x10000000;event.info.register=REGISTER[event.info.offset]||'unknown'}
        }
        out.push(event);
    });
    return out;
}

function previousExitTime(trace,index){for(var i=index-1;i>=0;i--)if(trace[i].name==='kvm_exit')return trace[i].timeNs;return trace[index].timeNs}

function classifyTracePhases(trace){
    var firstB=null,firstC=null;
    trace.forEach(function(event,index){
        if(event.name!=='kvm_mmio'||missing(event.info.offset))return;
        if(firstB===null&&QUEUE_OFFSETS[event.info.offset])firstB=previousExitTime(trace,index);
        if(firstC===null&&event.info.offset===0x050)firstC=previousExitTime(trace,index);
    });
    trace.forEach(function(event){event.phase=firstC!==null&&event.timeNs>=firstC?'C':firstB!==null&&event.timeNs>=firstB?'B':'A'});
}

function lane(event){
    if(event.source==='ebpf')return event.name==='virtio_mmio'?'MMIO':'VIRTIO BACKEND';
    if(event.name==='kvm_entry')return'GUEST';
    if(event.name==='kvm_exit')return'GUEST → KVM';
    if(event.name==='kvm_userspace_exit')return'KVM → VMM';
    if(event.name==='kvm_mmio')return'KVM MMIO';
    return'KVM';
}

function title(event){
    if(event.source==='ebpf'&&event.name==='virtio_mmio')return event.info.mmio.register+' · '+event.info.mmio.direction;
    if(event.source==='ebpf')return event.name;
    if(event.name==='kvm_exit')return'kvm_exit · '+(event.info.reason||'unknown');
    if(event.name==='kvm_userspace_exit')return event.info.reason||event.name;
    if(event.name==='kvm_mmio')return(event.info.register||'MMIO')+' · '+(event.info.operation||'access');
    return event.name;
}

function buildModel(ebpf,trace){
    classifyTracePhases(trace);
    M.events=ebpf.concat(trace).sort(function(a,b){return a.timeNs-b.timeNs||(a.source==='tracefs'?-1:1)});
    var base=M.events.length?M.events[0].timeNs:0;
    M.events.forEach(function(event,index){event.index=index;event.timeUs=(event.timeNs-base)/1000;event.lane=lane(event);event.title=title(event)});
    M.events.forEach(function(event,index){
        if(event.source==='ebpf'&&event.name==='virtio_mmio'){
            if(event.info.mmio.register==='QueueNotify'){M.notifyMmio++;if(missing(M.landmarks.notify))M.landmarks.notify=index}else M.setupMmio++;
        }
        if(event.source==='ebpf'&&event.name==='queue_backend_begin')M.landmarks.begin=index;
        if(event.source==='ebpf'&&event.name==='queue_backend_end')M.landmarks.end=index;
        if(event.source==='tracefs'&&event.name==='kvm_userspace_exit'&&event.info.reason==='KVM_EXIT_IO')M.landmarks.success=index;
    });
    ['A','B','C'].forEach(function(phase){for(var i=0;i<M.events.length;i++)if(M.events[i].phase===phase){M.landmarks['phase'+phase]=i;break}});
}

function statusDecode(raw){
    var value=hexNumber(raw);
    if(value===null||isNaN(value))return'not sampled';
    if(value===0)return'reset';
    var bits=[];
    if(value&1)bits.push('ACKNOWLEDGE');if(value&2)bits.push('DRIVER');if(value&8)bits.push('FEATURES_OK');if(value&4)bits.push('DRIVER_OK');
    return bits.join(' | ')||'0';
}

function dlRows(host,rows){host.innerHTML=rows.map(function(row){var miss=missing(row[1]);return'<dt>'+esc(row[0])+'</dt><dd class="'+(miss?'not-sampled':'')+'" title="'+esc(shown(row[1]))+'">'+esc(shown(row[1]))+'</dd>'}).join('')}
function stateGroup(event,name){var group=event.state&&event.state[name];return group&&group.present?group:null}

function renderQueue(event){
    var descriptor=stateGroup(event,'descriptor'),avail=stateGroup(event,'avail'),used=stateGroup(event,'used'),queue=stateGroup(event,'queue'),preview=stateGroup(event,'buffer_preview');
    dlRows($('desc-fields'),descriptor?[['addr',descriptor.addr],['len',descriptor.len],['flags',descriptor.flags],['decode',descriptor.device_writable?'WRITE':'no WRITE'],['next',descriptor.next]]:[['addr',null],['len',null],['flags',null],['decode',null],['next',null]]);
    dlRows($('avail-fields'),avail?[['flags',avail.flags],['idx',avail.idx],['ring[0]',avail.ring0],['points to',avail.ring0===0?'desc[0]':'desc['+avail.ring0+']']]:[['flags',null],['idx',null],['ring[0]',null],['points to',null]]);
    dlRows($('used-fields'),used?[['flags',used.flags],['idx',used.idx],['ring[0].id',used.ring0_id],['ring[0].len',used.ring0_len],['meaning',used.idx===1?'desc[0] complete':'not published']]:[['flags',null],['idx',null],['ring[0].id',null],['ring[0].len',null],['meaning',null]]);
    var bytes=preview&&Array.isArray(preview.bytes)?preview.bytes.map(function(value){return value.toString(16).padStart(2,'0')}).join(' '):null;
    dlRows($('buffer-fields'),[['request GPA',descriptor?descriptor.addr:null],['request len',descriptor?descriptor.len:null],['preview',bytes],['type',preview?'raw random data':null]]);
    if(preview)$('buffer-fields').querySelectorAll('dd')[2].classList.add('raw-random');
    $('last-avail').textContent=queue?queue.last_avail_idx:'not sampled';
}

function eventRows(event){
    var rows=[['phase',event.phase],['source',event.source],['time',event.timeUs.toFixed(3)+' µs'],['event',event.name]];
    if(event.source==='ebpf'&&event.info.mmio.present)rows.push(['MMIO address',event.info.mmio.address],['offset',event.info.mmio.offset],['register',event.info.mmio.register],['direction',event.info.mmio.direction],['value',event.info.mmio.value]);
    if(event.source==='ebpf'&&!missing(event.info.return_value))rows.push(['return',event.info.return_value]);
    if(event.source==='tracefs'){
        if(event.info.reason)rows.push(['reason',event.info.reason]);if(event.info.rip)rows.push(['guest RIP',event.info.rip]);if(event.info.address)rows.push(['MMIO GPA',event.info.address]);if(event.info.offset!==undefined)rows.push(['offset','0x'+event.info.offset.toString(16)]);if(event.info.value)rows.push(['raw value',event.info.value]);
    }
    return rows;
}

function renderInspector(event){
    $('source-badge').textContent=event.source;$('event-kind').textContent=event.lane+' · PHASE '+event.phase;$('event-title').textContent=event.title;
    $('coherence-note').textContent=event.state?'Machine fields are from this exact eBPF snapshot.':'This raw trace boundary did not sample virtqueue memory; fields correctly show not sampled.';
    dlRows($('event-fields'),eventRows(event));
    dlRows($('context-fields'),[['pid',event.context.pid],['tid',event.context.tid],['cpu',event.context.cpu],['comm',event.context.comm]]);
    var device=stateGroup(event,'device'),queue=stateGroup(event,'queue'),descriptor=stateGroup(event,'descriptor'),avail=stateGroup(event,'avail'),used=stateGroup(event,'used');
    dlRows($('state-fields'),[['status',device?device.status:null],['status decode',device?statusDecode(device.status):null],['queue ready',queue?queue.ready:null],['last_avail_idx',queue?queue.last_avail_idx:null],['desc flags',descriptor?descriptor.flags:null],['desc decode',descriptor&&descriptor.device_writable?'VIRTQ_DESC_F_WRITE':descriptor?'no WRITE':null],['avail.idx',avail?avail.idx:null],['used.idx',used?used.idx:null]]);
    $('raw-source').textContent=event.raw;
}

function actionFor(event){
    if(event.phase==='A')return'setup';
    if(event.phase==='B')return'config';
    if(event.index>=(M.landmarks.success||Infinity))return'poll';
    if(event.index>=(M.landmarks.end||Infinity))return'complete';
    if(event.index>=(M.landmarks.begin||Infinity))return'consume';
    return'notify';
}

function clearMotion(){motionTimers.forEach(clearTimeout);motionTimers=[]}
function markNodes(names,observed){
    document.querySelectorAll('[data-node]').forEach(function(node){node.classList.remove('hot','observed-hot')});
    names.forEach(function(name){var node=document.querySelector('[data-node="'+name+'"]');if(node){node.classList.add('hot');if(observed)node.classList.add('observed-hot')}});
}

function setStageAction(action,event){
    $('protocol-stage').dataset.action=action;
    var ownershipOrder=['prepare','publish','notify','consume','complete','poll'],ownershipIndex=ownershipOrder.indexOf(action);
    $('ownership-track').querySelectorAll('button').forEach(function(button,index){button.classList.toggle('active',index===ownershipIndex)});
    $('ownership-track').querySelectorAll('i').forEach(function(edge,index){edge.classList.toggle('active',index<ownershipIndex)});
    var callout=$('ownership-callout'),guest=$('guest-action'),detail=$('guest-detail'),backend=$('backend-action');
    if(action==='setup'){
        markNodes(['guest','backend'],event.source==='ebpf');guest.textContent='virtio-mmio handshake';detail.textContent='identity · VERSION_1 · status';backend.textContent='read/write register semantics';callout.innerHTML='<em>CONTROL PLANE · OBSERVED</em><b>Modern virtio discovery and feature negotiation use MMIO exits.</b><span>The selected register boundary moves across guest, KVM, and VMM.</span>';
    }else if(action==='config'){
        markNodes(['guest','descriptor','avail','used','backend'],event.source==='ebpf');guest.textContent='configure queue 0';detail.textContent='publish three queue GPAs';backend.textContent='records fixed GPA layout';callout.innerHTML='<em>CONTROL PLANE · OBSERVED</em><b>The guest tells the device where the split ring lives.</b><span>QueueReady then DRIVER_OK makes the device operational.</span>';
    }else if(action==='prepare'){
        markNodes(['guest','descriptor'],false);guest.textContent='prepare desc[0]';detail.textContent='guest still owns request';backend.textContent='cannot consume yet';callout.innerHTML='<em>SOURCE-DERIVED · NO INDIVIDUAL TIMESTAMP</em><b>desc[0] is written in ordinary guest RAM.</b><span>addr=0x7000 · len=32 · WRITE; this replay is reconstructed from source and the QueueNotify snapshot.</span>';
    }else if(action==='publish'){
        markNodes(['descriptor','avail'],false);guest.textContent='publish avail.idx';detail.textContent='ownership → device';backend.textContent='new work is now available';callout.innerHTML='<em>SOURCE-DERIVED · NO INDIVIDUAL TIMESTAMP</em><b>avail.ring[0] names desc[0], then avail.idx changes 0 → 1.</b><span>The release barrier makes the descriptor visible before publication.</span>';
    }else if(action==='notify'){
        markNodes(['avail','notify','exit','backend'],true);guest.textContent='QueueNotify = 0';detail.textContent='doorbell only';backend.textContent='handle_mmio receives queue index';callout.innerHTML='<em>OBSERVED · MMIO EXIT</em><b>The doorbell contains queue index 0—not the request address or length.</b><span>The complete request is already visible in the captured shared-memory snapshot.</span>';
    }else if(action==='consume'){
        markNodes(['backend','descriptor','avail'],true);guest.textContent='guest yielded ownership';detail.textContent='device reads shared RAM';backend.textContent='reads avail → desc[0]';callout.innerHTML='<em>OBSERVED · eBPF ENTRY SNAPSHOT</em><b>process_queue() sees desc[0] and avail.idx=1 while used.idx=0.</b><span>descriptor.addr is a GPA; the VMM translates it to its guest-memory HVA.</span>';
    }else if(action==='complete'){
        markNodes(['backend','buffer','used'],true);guest.textContent='request outstanding';detail.textContent='waiting in shared RAM';backend.textContent='entropy + used publication';callout.innerHTML='<em>OBSERVED · eBPF RETURN SNAPSHOT</em><b>The backend writes random data and used.ring[0], then publishes used.idx 0 → 1.</b><span>The used ring is the authoritative completion state.</span>';
    }else{
        markNodes(['used','guest'],false);guest.textContent='poll used.idx';detail.textContent='observe completion in RAM';backend.textContent='request already complete';callout.innerHTML='<em>SOURCE-DERIVED · NOT INDIVIDUALLY TRAPPED</em><b>The guest observes used.idx=1 and validates id=0, len=32.</b><span>Polling is this teaching baseline, not a requirement of virtio.</span>';
    }
}

function renderMachine(event){
    clearMotion();
    var register=event.source==='ebpf'&&event.name==='virtio_mmio'?event.info.mmio.register:event.source==='tracefs'&&event.name==='kvm_mmio'?event.info.register:null;
    var value=event.source==='ebpf'&&event.name==='virtio_mmio'?event.info.mmio.value:event.source==='tracefs'&&event.name==='kvm_mmio'?event.info.value:null;
    $('control-register').textContent=register||('Phase '+event.phase+' execution boundary');$('control-value').textContent=register?(shown(value)+' · '+(event.info.mmio?event.info.mmio.direction:event.info.operation)):(event.lane+' · '+event.title);
    $('control-rail').classList.toggle('hot',event.phase!=='C'||Boolean(register));
    var action=actionFor(event);
    if(event.index===M.landmarks.notify){
        setStageAction('prepare',event);
        motionTimers.push(setTimeout(function(){setStageAction('publish',event)},520));
        motionTimers.push(setTimeout(function(){setStageAction('notify',event)},1040));
        $('machine-caption').textContent='Untimed source-derived prelude → observed QueueNotify boundary.';
    }else{
        setStageAction(action,event);
        $('machine-caption').textContent=event.state?'Actual state sampled at this selected boundary.':'Raw chronology boundary; queue fields are not sampled.';
    }
}

function executionStateBefore(index){
    var state='vmm';
    for(var i=0;i<index;i++){var event=M.events[i];if(event.name==='kvm_entry')state='guest';else if(event.name==='kvm_exit')state='kvm';else if(event.name==='kvm_userspace_exit')state='vmm'}
    return state;
}

function executionStateAfter(event,before){if(event.name==='kvm_entry')return'guest';if(event.name==='kvm_exit')return'kvm';if(event.name==='kvm_userspace_exit')return'vmm';return before}

function lifelineMarkup(event,before,after){
    var dom='<i class="life guest"></i><i class="life kvm"></i><i class="life vmm"></i><i class="residency top '+before+'"></i><i class="residency bottom '+after+'"></i>';
    if(event.name==='kvm_entry')dom+='<i class="boundary-arrow entry"></i><i class="life-point guest"></i><i class="life-point kvm"></i><span class="boundary-label guest-kvm">kvm_entry</span>';
    else if(event.name==='kvm_exit')dom+='<i class="boundary-arrow exit"></i><i class="life-point guest"></i><i class="life-point kvm"></i><span class="boundary-label guest-kvm">'+esc(event.info.reason||'VM exit')+'</span>';
    else if(event.name==='kvm_userspace_exit')dom+='<i class="boundary-arrow handoff"></i><i class="life-point kvm"></i><i class="life-point vmm"></i><span class="boundary-label kvm-vmm">'+esc((event.info.reason||'KVM_EXIT').replace('KVM_EXIT_',''))+'</span>';
    else if(event.source==='ebpf')dom+='<i class="life-hook vmm ebpf"></i><span class="boundary-label hook">'+esc(event.title)+'</span>';
    else dom+='<i class="life-hook kvm"></i><span class="boundary-label guest-kvm">'+esc(event.title)+'</span>';
    return dom;
}

function renderTimeline(){
    var filtered=M.events.filter(function(event){return event.phase===M.phase});
    $('timeline-scope').textContent='Phase '+M.phase+' · '+filtered.length+' real boundaries';
    $('timeline').style.setProperty('--rows',filtered.length);
    var state=filtered.length?executionStateBefore(filtered[0].index):'vmm';
    $('timeline').innerHTML=filtered.map(function(event){
        var previous=event.index>0?M.events[event.index-1]:null,delta=previous?((event.timeNs-previous.timeNs)/1000).toFixed(3):'0.000';
        var after=executionStateAfter(event,state),lifelines=lifelineMarkup(event,state,after);state=after;
        return'<button class="timeline-row '+(event.index===cursor?'active':'')+'" data-index="'+event.index+'"><span>+'+delta+'µs</span><span class="life-space">'+lifelines+'</span><span class="event-label">'+esc(event.title)+'</span></button>';
    }).join('');
    $('timeline').querySelectorAll('.timeline-row').forEach(function(row){row.addEventListener('click',function(){select(Number(row.dataset.index),false)})});
    var active=$('timeline').querySelector('.active');if(active)active.scrollIntoView({block:'nearest'});
}

function phaseSamples(phase){
    var events=M.events.filter(function(event){return event.phase===phase&&(event.source==='ebpf'||event.name==='kvm_exit')});
    if(events.length<=12)return events;
    var sampled=[];
    for(var i=0;i<12;i++)sampled.push(events[Math.round(i*(events.length-1)/11)]);
    return sampled;
}

function renderRoadmap(){
    var definitions={A:['VIRTIO BRING-UP','negotiate VERSION_1'],B:['QUEUE CONFIG','publish queue GPAs'],C:['SHARED-MEMORY I/O','desc → avail → notify → used']};
    $('roadmap').innerHTML=['A','B','C'].map(function(phase){
        var dots=phaseSamples(phase).map(function(event){return'<button class="phase-dot '+(event.index<cursor?'seen ':'')+(event.index===cursor?'current':'')+'" data-index="'+event.index+'" title="'+esc(event.title)+'"></button>'}).join('');
        return'<section class="phase-zone '+(phase===M.phase?'active':'')+'" data-phase="'+phase+'"><span class="phase-letter">'+phase+'</span><h2>'+definitions[phase][0]+'</h2><small>'+definitions[phase][1]+'</small><div class="phase-dots">'+dots+'</div></section>';
    }).join('');
    $('roadmap').querySelectorAll('.phase-zone').forEach(function(zone){zone.addEventListener('click',function(event){if(!event.target.classList.contains('phase-dot'))choosePhase(zone.dataset.phase)})});
    $('roadmap').querySelectorAll('.phase-dot').forEach(function(dot){dot.addEventListener('click',function(event){event.stopPropagation();select(Number(dot.dataset.index),true)})});
}

function select(index,changePhase){
    if(!M.events.length)return;
    cursor=Math.max(0,Math.min(M.events.length-1,index));
    var event=M.events[cursor];
    if(changePhase!==false)M.phase=event.phase;
    $('selected-time').textContent='t = '+event.timeUs.toFixed(3)+' µs';$('scrub').value=cursor;$('counter').textContent=(cursor+1)+' / '+M.events.length;
    renderRoadmap();renderQueue(event);renderMachine(event);renderInspector(event);renderTimeline();
}

function choosePhase(phase){M.phase=phase;var target=phase==='C'&&!missing(M.landmarks.notify)?M.landmarks.notify:M.landmarks['phase'+phase];select(target||0,false)}
function stopPlay(){if(!playTimer)return;clearInterval(playTimer);playTimer=null;$('play').textContent='▶';$('play').classList.remove('active')}
function togglePlay(){if(playTimer){stopPlay();return}$('play').textContent='Ⅱ';$('play').classList.add('active');playTimer=setInterval(function(){if(cursor>=M.events.length-1){stopPlay();return}select(cursor+1,true)},700)}

function wire(){
    $('ownership-track').querySelectorAll('button').forEach(function(button){button.addEventListener('click',function(){var target=button.dataset.target;if(!missing(M.landmarks[target])){select(M.landmarks[target],true);clearMotion();setStageAction(button.dataset.action,M.events[cursor])}})});
    $('prev').addEventListener('click',function(){stopPlay();select(cursor-1,true)});$('next').addEventListener('click',function(){stopPlay();select(cursor+1,true)});$('play').addEventListener('click',togglePlay);
    $('scrub').addEventListener('input',function(event){stopPlay();select(Number(event.target.value),true)});
    document.addEventListener('keydown',function(event){if(event.key==='ArrowLeft'){stopPlay();select(cursor-1,true)}if(event.key==='ArrowRight'){stopPlay();select(cursor+1,true)}if(event.key===' '){event.preventDefault();togglePlay()}});
}

Promise.all([fetch(BPF,{cache:'no-store'}).then(function(response){if(!response.ok)throw Error('eBPF HTTP '+response.status);return response.text()}),fetch(TRACE,{cache:'no-store'}).then(function(response){if(!response.ok)throw Error('trace HTTP '+response.status);return response.text()})]).then(function(parts){
    var ebpf=parseEbpf(parts[0]),trace=parseTrace(parts[1]);
    if(!M.meta||!ebpf.length||!trace.length)throw Error('capture is incomplete');
    buildModel(ebpf,trace);
    if(M.notifyMmio!==1||missing(M.landmarks.begin)||missing(M.landmarks.end))throw Error('required Phase-C observations are missing');
    $('notify-exits').textContent=M.notifyMmio+' exit';$('scrub').max=M.events.length-1;$('status').lastElementChild.textContent=M.events.length+' boundaries · one QueueNotify';
    wire();select(M.landmarks.notify,true);
}).catch(function(error){$('status').lastElementChild.textContent='para-I/O data error · '+error.message});
})();
