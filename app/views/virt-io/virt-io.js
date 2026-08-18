/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Virt-I/O viewer: interrupt virtualization and virtual DMA from one capture.
 *
 * One connected model:
 *   guest MMIO -> VM exit -> VMM device model -> virtual DMA -> KVM_IRQ_LINE
 *   (GSI) -> in-kernel IOAPIC -> in-kernel LAPIC -> guest ISR -> ACK/EOI.
 *
 * Sources: the eBPF canonical NDJSON (controller + DMA observations) and the
 * kvm trace (raw chronology: exit reasons, rip, ports).  There is no separate
 * phases file for virt-io, so the four phases are derived from the captured
 * accept/delivery/DMA boundaries instead of being invented.
 *
 * Machine-state explorer in the memory-view spirit: dense, technical, raw
 * values with decoded meaning, one selected observation drives the page.
 */
(function(){
'use strict';

var TS=Date.now(),
    BPF='../../shared/_captures/virt-io.eBPF.ndjson?v='+TS,
    TRC='../../shared/_captures/virt-io-Trace.txt?v='+TS;

var meta={},frames=[],trace=[],phases=[],selected=0;

function $(id){return document.getElementById(id)}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function short(x){x=String(x==null?'':x);return x.length>13?x.slice(0,10)+'…'+x.slice(-4):x}

/* ---- normalization -------------------------------------------------- */

function parseBpf(text){
    var out=[];
    text.split(/\r?\n/).forEach(function(line){
        if(!line.trim())return;
        var r;
        try{r=JSON.parse(line)}catch(ignore){return}
        if(r.kind==='meta'){meta=r;return}
        if(r.kind!=='snapshot')return;
        var st=r.state||{},ct=st.controller||{},d=st.dma||{};
        out.push({
            seq:Number(r.seq),
            time_ns:Number(r.time_ns),
            name:(r.event_info||{}).event_name,
            event:(r.event_info||{}).event,
            ctx:r.context||{},
            vcpu:st.vcpu,kvm:st.kvm,apic:st.apic,ioapic:st.ioapic,
            rte:ct.rte,irr:ct.irr,isr:ct.isr,
            dpresent:d.present,dgpa:d.gpa,ddir:d.dir
        });
    });
    return out.sort(function(a,b){return a.seq-b.seq});
}

function parseTrace(text){
    var out=[];
    text.split(/\r?\n/).forEach(function(raw){
        var m=raw.match(/^\s*(.+?)-(\d+)\s+\[(\d+)\]\s+(\S+)\s+([0-9]+\.[0-9]+):\s+([a-zA-Z0-9_]+):\s+(.+)$/);
        if(!m)return;
        var e={type:m[6],time:+m[5],body:m[7]};
        if(e.type==='kvm_exit'){
            var x=e.body.match(/vcpu\s+(\d+)\s+reason\s+([^\s]+)\s+rip\s+(0x[0-9a-f]+)/i);
            if(x){e.vcpu=x[1];e.reason=x[2];e.rip=x[3]}
        }else if(e.type==='kvm_entry'){
            var en=e.body.match(/vcpu\s+(\d+),\s+rip\s+(0x[0-9a-f]+)/i);
            if(en){e.vcpu=en[1];e.rip=en[2]}
        }else if(e.type==='kvm_userspace_exit'){
            var u=e.body.match(/reason\s+(.+?)\s*$/i);
            if(u)e.reason=u[1].replace(/ \(.*\)$/,'').trim();
        }else if(e.type==='kvm_ioapic_set_irq'){
            var io=e.body.match(/pin\s+(\d+)\s+dst\s+(\d+)\s+vec\s+(\d+)\s+\(([^)]+)\)/i);
            if(io){e.pin=io[1];e.dst=io[2];e.vec=io[3];e.mode=io[4].split('|')}
        }else if(e.type==='kvm_apic_accept_irq'){
            var ac=e.body.match(/apicid\s+(\d+)\s+vec\s+(\d+)\s+\(([^)]+)\)/i);
            if(ac){e.apicid=ac[1];e.vec=ac[2];e.mode=ac[3].split('|')}
        }else if(e.type==='kvm_apic'){
            var aw=e.body.match(/apic_(\w+)\s*=\s*(0x[0-9a-f]+)/i);
            if(aw){e.reg=aw[1];e.val=aw[2]}
        }
        out.push(e);
    });
    return out;
}

/* Attach the closest trace record of the same type to each eBPF frame.
   The eBPF snapshot is authoritative; the trace enriches it with exit
   reason/rip and the userspace-exit reason enum. */
function enrichFrames(){
    var produces={kvm_entry:1,kvm_exit:1,kvm_userspace_exit:1,kvm_ioapic_set_irq:1,kvm_apic_accept_irq:1,kvm_apic:1};
    frames.forEach(function(f){
        var best=null,bestD=1e18;
        trace.forEach(function(t){
            if(!produces[t.type]||t.type!==f.name)return;
            var d=Math.abs(t.time*1e9-f.time_ns);
            if(d<bestD){bestD=d;best=t}
        });
        if(best){f.tr=best;f.exitReason=best.reason;f.rip=best.rip;f.vec=best.vec}
    });
}

/* ---- phase derivation (from the events, not from a phases file) ----- */

function derivePhases(){
    var accepts=[],dmas=[];
    frames.forEach(function(f,i){
        if(f.name==='kvm_apic_accept_irq')accepts.push(i);
        if(f.name==='device_dma_transfer')dmas.push(i);
    });
    var B=accepts.length?accepts[0]:1,
        C=accepts.length>1?accepts[1]:B,
        E=dmas.length?dmas[0]:(frames.length-1),
        D=(accepts.length>2&&accepts[2]<E)?accepts[2]:E;
    phases=[
        {id:'A',label:'APIC READY',range:[0,B-1],note:'IDT · LAPIC · IOAPIC RTE(4) · marker 0x11'},
        {id:'B',label:'NORMAL IRQ',range:[B,C-1],note:'CMD_IRQ_ONLY · IOAPIC→LAPIC→ISR→EOI'},
        {id:'C',label:'IF=0 PENDING',range:[C,D-1],note:'IRQ raised while IF=0 · marker 0x12 · STI'}
    ];
    if(D<E){
        phases.push({id:'D',label:'IRQ BURST IF=0',range:[D,E-1],note:'CMD_IRQ_BURST · 3 same-vector GSI edges · one IRR bit · one ISR run · marker 0x13'});
        phases.push({id:'E',label:'VIRTUAL DMA',range:[E,frames.length-1],note:'DMA_TO_DEVICE & DMA_FROM_DEVICE'});
    }else{
        /* A pre-burst capture still renders the DMA phase as the last one. */
        phases.push({id:'D',label:'VIRTUAL DMA',range:[E,frames.length-1],note:'DMA_TO_DEVICE & DMA_FROM_DEVICE'});
    }
    phases.forEach(function(p){p.count=Math.max(0,p.range[1]-p.range[0]+1)});
}

function phaseOf(i){
    for(var k=0;k<phases.length;k++)
        if(i>=phases[k].range[0]&&i<=phases[k].range[1])return k;
    return phases.length-1;
}

/* ---- helpers --------------------------------------------------------- */

function rteDecode(raw){
    var v=Number(raw)||0;
    return{
        vector:v&0xff,
        delivery:(v>>8)&0x7,
        destid:(v>>11)&0xf,
        polarity:((v>>13)&1)?'high':'low',
        trigger:((v>>15)&1)?'level':'edge',
        mask:!!(v&(1<<16))
    };
}
function deliveryName(d){
    var names=['fixed','low priority','SMI','NMI','INIT','extINT','?(17)','?(18)'];
    return names[d]||('0x'+d.toString(16));
}
function fmtDelta(ns){
    if(ns==null)return'';
    var us=Math.round(ns/1000);
    if(us<100)return us+'µs';
    return (us/1000).toFixed(2)+'ms';
}

var LANE_T={vm:'GUEST',exit:'EXIT',user:'USER',ioapic:'IOAPIC',lapic:'LAPIC',dma:'DMA'};
function laneOf(name){
    if(name==='kvm_entry')return'vm';
    if(name==='kvm_exit')return'exit';
    if(name==='kvm_userspace_exit')return'user';
    if(name==='kvm_ioapic_set_irq')return'ioapic';
    if(name==='kvm_apic'||name==='kvm_apic_accept_irq')return'lapic';
    if(name==='device_dma_transfer')return'dma';
    return'vm';
}
function flowTitle(f){
    if(!f)return'';
    if(f.name==='kvm_entry')return'guest resumes · rip '+esc(f.rip||'?');
    if(f.name==='kvm_exit')return'vm exit · '+esc(f.exitReason||'reason');
    if(f.name==='kvm_userspace_exit')return esc((f.tr&&f.tr.reason)||'userspace exit');
    if(f.name==='kvm_ioapic_set_irq')return'IOAPIC pin '+((f.tr&&f.tr.pin)||meta.device_gsi)+' → vec '+(f.vec||'0x40');
    if(f.name==='kvm_apic_accept_irq')return'LAPIC accepts vec '+(f.vec||'0x40');
    if(f.name==='kvm_apic')return'APIC '+(f.tr&&f.tr.reg?('write '+f.tr.reg+'='+f.tr.val):'access');
    if(f.name==='device_dma_transfer')return f.dpresent
        ?'DMA '+(f.ddir==='to_device'?'guest→device':'device→guest')+' @ '+esc(f.dgpa)
        :'DMA (no transfer)';
    return esc(f.name);
}

var ALT=[
    {k:'guest',t:'GUEST',n:'runs before MMIO'},
    {k:'mmio',t:'DEVICE MMIO',n:'KVM_EXIT_MMIO'},
    {k:'vmm',t:'VMM MODEL',n:'device_execute'},
    {k:'irq',t:'IRQ LINE',n:'GSI '},
    {k:'ioapic',t:'IOAPIC',n:'RTE[4]'},
    {k:'lapic',t:'LAPIC',n:'IRR/ISR'},
    {k:'isr',t:'GUEST ISR',n:'vector 0x40'}
];
var HOPLABEL={mmio:'MMIO exit',vmm:'VMM handles',irq:'raises GSI',ioapic:'routes',lapic:'accepts',isr:'delivers'};

/* ---- rendering -------------------------------------------------------- */

function renderPath(f){
    if(!f){return'<div class="path-empty">no observation</div>'}
    /* reached = this hop has happened at or before the selected snapshot. */
    var reached={mmio:false,vmm:false,irq:false,ioapic:false,lapic:false,isr:false};
    var hot={guest:false,mmio:false,vmm:false,irq:false,ioapic:false,lapic:false,isr:false};
    frames.slice(0,selected+1).forEach(function(x){
        if(x.name==='kvm_userspace_exit')reached.mmio=true;
        if(x.name==='device_dma_transfer'){reached.vmm=true;reached.irq=true}
        if(x.name==='kvm_ioapic_set_irq')reached.ioapic=true;
        if(x.name==='kvm_apic_accept_irq')reached.lapic=true;
        if(x.irr||x.isr)reached.isr=true;
    });
    if(f.name==='kvm_entry'||f.name==='kvm_exit')hot.guest=true;
    if(f.name==='kvm_userspace_exit'){hot.mmio=true;hot.vmm=true}
    if(f.name==='device_dma_transfer')hot.vmm=true;
    if(f.name==='kvm_ioapic_set_irq')hot.ioapic=true;
    if(f.name==='kvm_apic'||f.name==='kvm_apic_accept_irq')hot.lapic=true;
    if(f.irr||f.isr)hot.isr=true;

    var html='';
    ALT.forEach(function(node,idx){
        if(idx>0){
            var from=ALT[idx-1],lit=reached[node.k];
            html+='<div class="hop'+(lit?' lit':'')+'"><i class="ar">'+(lit?'▶':'')+'</i>'+
                '<b>'+esc(lit?HOPLABEL[node.k]:'')+'</b></div>';
        }
        var val=stationVal(f,node.k,reached);
        html+='<div class="station'+(hot[node.k]?' hot':'')+(node.k==='vmm'&&f.dpresent?' dma':'')+'">'+
            '<div class="s-name">'+esc(node.t)+'</div>'+
            '<div class="s-note">'+esc(node.n)+(node.k==='irq'?esc(meta.device_gsi):'')+'</div>'+
            '<div class="s-val">'+val+'</div></div>';
    });
    html+='<div class="irq-state"><div class="irq-cell'+(f.irr?' on':'')+'"><small>IRR[0x40]</small><b>'+esc(f.irr?'set':'clear')+'</b></div>'+
        '<div class="irq-cell'+(f.isr?' on':'')+'"><small>ISR[0x40]</small><b>'+esc(f.isr?'active':'clear')+'</b></div>'+
        '<div class="irq-cell win"><small>delivery</small><b>'+esc(f.irr&&!f.isr?'pending (IF=0)':(f.isr?'in service':'idle'))+'</b></div></div>';
    return html;
}

function stationVal(f,k,reached){
    switch(k){
        case'guest':return esc(f.rip||'rip');
        case'mmio':return f.name==='kvm_userspace_exit'?'hand-off':(reached.mmio?'seen':'—');
        case'vmm':return f.dpresent
            ?(f.ddir==='to_device'?'memcpy ← '+esc(f.dgpa):'memcpy → '+esc(f.dgpa))
            :f.name==='device_dma_transfer'?'(no transfer)':'device model';
        case'irq':return reached.irq?'GSI '+meta.device_gsi+' seen':'—';
        case'ioapic':return f.rte?esc('0x'+Number(f.rte).toString(16)):'RTE 0x0';
        case'lapic':return 'IRR '+Number(!!f.irr)+' · ISR '+Number(!!f.isr);
        case'isr':return (f.irr||f.isr)?'vec '+meta.device_vector:'—';
    }
    return'—';
}

function renderRte(f){
    var avail=meta.ioapic_available;
    if(avail===false&&!f.rte){
        return'<div class="reg-panel"><header><strong>IOAPIC redirection entry</strong><span>GSI '+meta.device_gsi+'</span></header>'+
            '<div class="notsampled">RTE reader not available on this kernel · RTE bits ride only on kvm_ioapic_set_irq snapshots</div></div>';
    }
    var raw=f&&f.rte?f.rte:'0x0',dec=rteDecode(raw);
    return'<div class="reg-panel"><header><strong>IOAPIC redirection entry</strong><span>GSI '+meta.device_gsi+'</span></header>'+
        '<div class="rte-raw"><b>'+esc(short('0x'+Number(raw).toString(16)))+'</b><span>vector '+dec.vector+'</span></div>'+
        '<div class="reg-fields">'+
        '<span><small>vector</small><b>'+dec.vector+'</b></span>'+
        '<span><small>delivery</small><b>'+esc(deliveryName(dec.delivery))+'</b></span>'+
        '<span><small>trigger</small><b>'+esc(dec.trigger)+'</b></span>'+
        '<span><small>polarity</small><b>'+esc(dec.polarity)+'</b></span>'+
        '<span><small>mask</small><b>'+esc(dec.mask?'MASKED':'unmasked')+'</b></span>'+
        '</div></div>';
}

function renderIrqState(f){
    if(!f)return'<div class="matrix"></div>';
    var irr=!!f.irr,isr=!!f.isr,pending=irr&&!isr,
        ph=phases[phaseOf(selected)]||{},
        burst=ph.id==='D',
        foot=pending
            ?(burst?'several same-vector edges held ONE LAPIC IRR bit while IF=0 · STI releases a single delivery'
              :'IF=0 holds the vector in the LAPIC until STI releases delivery')
            :isr?'vector 0x40 in service until guest EOI'
            :(burst?'3 edges already latched into one pending bit · nothing serviced yet'
              :'no interrupt queued at this observation');
    return'<div class="matrix'+(pending?' pending':'')+'"><div class="m-head"><span>INTERRUPT STATE</span><small>vector '+meta.device_vector+(burst?' · phase D burst':'')+'</small></div>'+
        '<div class="m-row"><small>interrupt routed</small><b class="'+(f.name==='kvm_ioapic_set_irq'||f.rte?'lit':'')+'">'+esc(f.name==='kvm_ioapic_set_irq'||f.rte?'yes':'no')+'</b></div>'+
        '<div class="m-row"><small>LAPIC IRR pending</small><b class="'+(irr?'lit':'')+'">'+esc(irr?'yes':'no')+'</b></div>'+
        '<div class="m-row"><small>guest ISR running</small><b class="'+(isr?'lit':'')+'">'+esc(isr?'yes':'no')+'</b></div>'+
        '<div class="m-row"><small>state</small><b class="'+(pending?'warn':(isr?'lit':''))+'">'+esc(pending?'PENDING (IF=0)':(isr?'DELIVERED / in service':'idle'))+'</b></div>'+
        '<div class="m-foot">'+esc(foot)+'</div></div>';
}

function renderDma(f){
    var scans=[];
    frames.forEach(function(x){if(x.name==='device_dma_transfer')scans.push(x)});
    var html='<header><strong>Virtual DMA</strong><span>emulated · host memcpy through the registered KVM slot</span></header>';
    html+='<div class="dma-lanes">'+
        '<div class="dma-lane'+(f&&f.ddir==='to_device'?' on':'')+'"><div class="l-head"><span>DMA_TO_DEVICE</span><small>guest RAM 0x6000 → device buffer</small></div>'+
        '<div class="l-chain"><i>guest</i><i class="copy">memcpy</i><i>device</i></div>'+
        '<small class="l-note">bytes 0x00–0x3f read from the guest slot backing</small></div>'+
        '<div class="dma-lane'+(f&&f.ddir==='from_device'?' on':'')+'"><div class="l-head"><span>DMA_FROM_DEVICE</span><small>device buffer → guest RAM 0x7000</small></div>'+
        '<div class="l-chain"><i>device</i><i class="copy">memcpy</i><i>guest</i></div>'+
        '<small class="l-note">device pattern 0x40–0x7f written back · verified byte-for-byte</small></div>'+
        '</div>';
    if(f&&f.dpresent){
        html+='<div class="dma-now"><span>selected transfer</span><b>'+esc(f.ddir==='to_device'?'guest → device':'device → guest')+'</b><code>'+esc(short(f.dgpa))+'</code><small>len '+meta.dma_xfer_size+' B</small></div>';
    }else if(scans.length){
        var last=scans[scans.length-1];
        html+='<div class="dma-now muted"><span>last transfer</span><b>'+esc(last.ddir==='to_device'?'guest → device':'device → guest')+'</b><code>'+esc(short(last.dgpa))+'</code><small>len '+meta.dma_xfer_size+' B</small></div>';
    }
    return html;
}

function renderTimeline(){
    var ph=phases[phaseOf(selected)],out='';
    out+='<div class="tl-head"><span>PHASE '+ph.id+'</span><small>'+esc(ph.note)+'</small><b>'+ph.count+' events</b></div>';
    var prevTime=null;
    for(var i=ph.range[0];i<=ph.range[1];i++){
        var f=frames[i];
        if(!f)continue;
        var lane=laneOf(f.name),hot=i===selected;
        var delta=f.time_ns-prevTime;prevTime=f.time_ns;
        out+='<button type="button" class="tl-row '+lane+(hot?' hot':'')+(f.name==='kvm_exit'&&!f.irr&&!f.isr?' quiet':'')+'" data-idx="'+i+'">'+
            '<i class="lane-dot"></i><span class="lane">'+esc(LANE_T[lane])+'</span>'+
            '<strong>'+flowTitle(f)+'</strong>'+
            '<em>'+fmtDelta(delta)+'</em></button>';
    }
    return out;
}

function renderPhases(){
    var cur=phaseOf(selected);
    $('phases').innerHTML=phases.map(function(p,i){
        return'<button type="button" class="phase'+(i===cur?' active':'')+'" data-ph="'+i+'">'+
            '<b>'+p.id+'</b><span>'+esc(p.label)+'</span><small>'+p.count+'</small></button>';
    }).join('');
    $('phases').querySelectorAll('[data-ph]').forEach(function(b){
        b.onclick=function(){select(phases[+b.dataset.ph].range[0])};
    });
}

function renderInspector(f){
    if(!f){$('inspect-title').textContent='no observation';return}
    $('inspect-type').textContent='eBPF snapshot · '+f.name;
    $('inspect-title').textContent=flowTitle(f);
    var fields={
        'seq':f.seq,
        'time':(f.time_ns/1e9).toFixed(6)+' s',
        'event':f.event+' · '+f.name,
        'pid / tid':f.ctx.pid+' / '+f.ctx.tid,
        'cpu':f.ctx.cpu,
        'comm':f.ctx.comm,
        'vcpu':f.vcpu||'-',
        'kvm':f.kvm||'-',
        'apic':f.apic||'-',
        'ioapic':f.ioapic||'-'
    };
    if(f.rip)fields.rip=f.rip;
    if(f.exitReason)fields.exit_reason=f.exitReason;
    if(f.rte)fields.rte='0x'+Number(f.rte).toString(16);
    if(f.vec)fields.vector=f.vec;
    if(f.tr&&f.tr.reg){fields.apic_reg=f.tr.reg+'='+f.tr.val}
    if(f.irr)fields.irr='set';
    if(f.isr)fields.isr='active';
    if(f.dpresent){fields.dma=f.ddir+' @ '+f.dgpa}
    $('fields').innerHTML=Object.keys(fields).map(function(k){
        return'<dt>'+esc(k)+'</dt><dd title="'+esc(fields[k])+'">'+esc(fields[k])+'</dd>';
    }).join('');
}

function renderAll(){
    var f=frames[selected];
    $('meta-vec').innerHTML=
        '<span>GSI <b>'+meta.device_gsi+'</b></span><i>|</i>'+
        '<span>vector <b>'+meta.device_vector+'</b></span><i>|</i>'+
        '<span>RTE <b>'+(f&&f.rte?'0x'+Number(f.rte).toString(16):'0x0')+'</b></span><i>|</i>'+
        '<span>DMA <b>'+meta.dma_xfer_size+' B</b></span><i>|</i>'+
        '<span class="cap'+(meta.lapic_available?' ok':' off')+'">lapic reader '+(meta.lapic_available?'ok':'n/a')+'</span><i>|</i>'+
        '<span class="cap'+(meta.ioapic_available?' ok':' off')+'">ioapic reader '+(meta.ioapic_available?'ok':'n/a')+'</span>';
    $('phase-now').textContent='phase '+phases[phaseOf(selected)].id+' · '+phases[phaseOf(selected)].label;
    $('path').innerHTML=renderPath(f);
    $('rte').innerHTML=renderRte(f);
    $('irqmat').innerHTML=renderIrqState(f);
    $('dma').innerHTML=renderDma(f);
    $('timeline').innerHTML=renderTimeline();
    $('timeline').querySelectorAll('[data-idx]').forEach(function(b){
        b.onclick=function(){select(+b.dataset.idx)};
    });
    renderPhases();
    renderInspector(f);
    $('status').innerHTML='<i class="trace-dot"></i><span>'+frames.length+' snapshots · '+
        trace.length+' trace events · '+phases.length+' phases · vcpu '+ (f&&f.vcpu?short(f.vcpu):'—')+'</span>';
}

function select(i){
    if(!frames.length)return;
    selected=Math.max(0,Math.min(frames.length-1,i||0));
    renderAll();
}

/* ---- load ------------------------------------------------------------ */

Promise.all([
    fetch(BPF,{cache:'no-store'}).then(function(r){if(!r.ok)throw Error('bpf HTTP '+r.status);return r.text()}),
    fetch(TRC,{cache:'no-store'}).then(function(r){if(!r.ok)throw Error('trace HTTP '+r.status);return r.text()})
]).then(function(parts){
    frames=parseBpf(parts[0]);
    trace=parseTrace(parts[1]);
    if(!frames.length)throw Error('no eBPF snapshots parsed');
    derivePhases();
    enrichFrames();
    selected=0;
    renderAll();
}).catch(function(err){
    $('status').textContent='virt-io data error · '+err.message;
    $('inspect-title').textContent=err.message;
});
})();
