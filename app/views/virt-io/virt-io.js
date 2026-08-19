/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KVM virt-I/O state observer.
 *
 * Fuses two sources into one chronological event stream:
 *   - virt-io.eBPF.ndjson  canonical eBPF snapshots (interrupt/DMA state,
 *                          KVM object pointers, event kind).
 *   - virt-io-Trace.txt    raw tracefs kvm trace (exit reasons, rip, userspace
 *                          reason, flags, clock), joined line-by-line.
 *
 * Every captured value is kept: the raw trace line, sampled IRR/ISR/RTE, DMA
 * GPA and direction, timestamps and inter-event deltas, and the pointer to the
 * paired trace record.  Episodes are inferred groupings over that stream and
 * are labelled "inferred grouping" because they are derived, not invented.
 */
(function(){
'use strict';

var TS=Date.now(),
    BPF='../../shared/_captures/virt-io.eBPF.ndjson?v='+TS,
    TRC='../../shared/_captures/virt-io-Trace.txt?v='+TS;

var D=null, cursor=0, timer=null;

function $(id){return document.getElementById(id)}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function ev(){return D.events[cursor]}

/* ---- capture parsing ------------------------------------------------ */

/* Parse the canonical eBPF NDJSON into snapshots ordered by sequence number. */
function parseBpf(text){
    var out=[];
    text.split(/\r?\n/).forEach(function(line){
        if(!line.trim())return;
        var r;
        try{r=JSON.parse(line)}catch(ignore){return}
        if(r.kind==='meta'){D=D||{};D.meta=r;return}
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

/* Parse the raw kvm trace into records, keeping every prefix field and line number. */
function parseTrace(text){
    var out=[],ln=0;
    text.split(/\r?\n/).forEach(function(raw){
        ln++;
        var m=raw.match(/^\s*(.+?)-(\d+)\s+\[(\d+)\]\s+(\S+)\s+([0-9]+\.[0-9]+):\s+([a-zA-Z0-9_]+):\s+(.+)$/);
        if(!m)return;
        var e={
            line:ln,comm:m[1],pid:+m[2],tid:+m[2],cpu:+m[3],
            flags:m[4],time:+m[5],type:m[6],body:m[7],raw:raw.trim()
        };
        if(e.type==='kvm_exit'){
            var x=e.body.match(/vcpu\s+(\d+)\s+reason\s+([^\s]+)\s+rip\s+(0x[0-9a-f]+)/i);
            if(x){e.vcpu=x[1];e.reason=x[2];e.rip=x[3]}
            var ix=e.body.match(/info1\s+(0x[0-9a-f]+)/i);
            if(ix)e.info1=ix[1];
        }else if(e.type==='kvm_entry'){
            var en=e.body.match(/vcpu\s+(\d+),\s+rip\s+(0x[0-9a-f]+)/i);
            if(en){e.vcpu=en[1];e.rip=en[2]}
        }else if(e.type==='kvm_userspace_exit'){
            var u=e.body.match(/reason\s+(.+?)\s*$/i);
            if(u)e.userspace_reason=u[1].replace(/ \(.*\)$/,'').trim();
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

/* ---- event model ------------------------------------------------------ */

var KINDS={kvm_entry:'entry',kvm_exit:'exit',kvm_userspace_exit:'handoff',
    kvm_apic_accept_irq:'irq',kvm_ioapic_set_irq:'irq',kvm_apic:'apic',
    device_dma_transfer:'dma'};

/* Join each eBPF snapshot with its line-by-line trace record into one stream. */
function buildEvents(snaps,trs){
    var byType={};
    trs.forEach(function(t){(byType[t.type]=byType[t.type]||[]).push(t)});
    var used={};
    return snaps.map(function(f){
        var e={
            seq:f.seq,name:f.name,time_ns:f.time_ns,
            vcpu_ptr:f.vcpu,kvm_ptr:f.kvm,apic_ptr:f.apic,ioapic_ptr:f.ioapic,
            irr:f.irr,isr:f.isr,rte:f.rte,
            dma_present:f.dpresent,dma_gpa:f.dgpa,dma_dir:f.ddir,
            reason:'',info1:'',userspace_reason:'',rip:'',apic_text:'',irq_text:''
        };
        var list=byType[f.name],t=list?list[used[f.name]=(used[f.name]||0)]:null;
        if(t){
            used[f.name]++;
            e.trace_line=t.line;e.raw=t.raw;e.flags=t.flags;
            e.cpu=t.cpu;e.pid=t.pid;e.tid=t.tid;e.comm=t.comm;
            e.rip=t.rip||'';e.reason=t.reason||'';e.info1=t.info1||'';
            e.userspace_reason=t.userspace_reason||'';
            if(t.type==='kvm_apic')e.apic_text=t.body,e.apic_reg=t.reg,e.apic_val=t.val;
            if(t.type==='kvm_apic_accept_irq')e.irq_text=t.body,e.apicid=t.apicid,e.vec=t.vec;
            if(t.type==='kvm_ioapic_set_irq')e.irq_text=t.body,e.pin=t.pin,e.vec=t.vec;
        }else{
            e.trace_line=null;e.raw='eBPF-only device DMA observation';e.flags='';
            e.cpu=f.ctx.cpu;e.pid=f.ctx.pid;e.tid=f.ctx.tid;e.comm=f.ctx.comm;
        }
        e.kind=KINDS[f.name]||f.name;
        e.accent=e.kind==='entry'?'cyan':e.kind==='exit'?'orange':e.kind==='handoff'?'green':
            e.kind==='irq'?'yellow':e.kind==='dma'?'blue':e.kind==='apic'?'violet':e.kind;
        if(e.kind==='entry'){e.from='kvm';e.to='guest';e.label='VM entry'}
        else if(e.kind==='exit'){e.from='guest';e.to='kvm';e.label=e.reason||'VM exit'}
        else if(e.kind==='handoff'){e.from='kvm';e.to='vmm';e.label=(e.userspace_reason||'userspace exit').replace('KVM_EXIT_','')}
        else if(e.kind==='dma'){e.from=e.dma_dir==='to_device'?'memory':'device';e.to=e.dma_dir==='to_device'?'device':'memory';e.label=e.dma_dir==='to_device'?'DMA → device':'DMA ← device'}
        else if(e.name==='kvm_apic_accept_irq'){e.from='device';e.to='lapic';e.label='APIC accepts vec '+(e.vec||metaVec())}
        else if(e.name==='kvm_ioapic_set_irq'){e.from='gsi';e.to='lapic';e.label='IOAPIC pin '+(e.pin||metaGsi())+' → vec '+(e.vec||metaVec())}
        else if(e.name==='kvm_apic'){e.from='guest';e.to='lapic';e.label='APIC '+(e.apic_reg||'reg')+' write'}
        else{e.from='';e.to='';e.label=e.name}
        return e;
    });
}
function metaGsi(){return D&&D.meta?D.meta.device_gsi:''}
function metaVec(){return D&&D.meta?D.meta.device_vector:''}

/* Derive the shared timeline, cross-references, and hand-off pairing. */
function finalize(events){
    var base=events.length?events[0].time_ns:0;
    events.forEach(function(e){e.time_us=(e.time_ns-base)/1000});
    events.forEach(function(e,i){
        e.prev_seq=i>0?events[i-1].seq:null;
        e.next_seq=i<events.length-1?events[i+1].seq:null;
        e.dt_prev_us=i>0?+(e.time_us-events[i-1].time_us).toFixed(3):null;
        e.dt_next_us=i<events.length-1?+(events[i+1].time_us-e.time_us).toFixed(3):null;
        e.paired_handoff='';
        if(e.kind==='exit'&&i<events.length-1&&events[i+1].kind==='handoff'){
            e.paired_handoff=events[i+1].userspace_reason||'KVM_EXIT_?';
        }
    });
    return events;
}

/* ---- episode derivation ----------------------------------------------- */

/* Index of the first event matching pred, or -1. */
function findIdx(events,pred){
    for(var i=0;i<events.length;i++)if(pred(events[i],i))return i;
    return -1;
}
/* Strongest motif of a region, used to name and describe the episode. */
function regionName(evs,isLast){
    if(evs.some(function(e){return e.name==='device_dma_transfer'})){
        var d=evs.filter(function(e){return e.name==='device_dma_transfer'})[0];
        return 'DMA '+(d.dma_dir==='to_device'?'→':'←')+' device'+(isLast?' + tail':'');
    }
    var ac=evs.filter(function(e){return e.name==='kvm_apic_accept_irq'}).length;
    var mis=evs.filter(function(e){return e.name==='kvm_exit'&&e.reason==='EPT_MISCONFIG'&&e.rip==='0x108'}).length;
    if(mis>=6)return 'MMIO polling motif';
    if(ac>=3)return 'IRQ burst + service';
    if(ac>=1)return 'IRQ service';
    var em=evs.some(function(e){return e.kind==='handoff'})||
        evs.some(function(e){return e.name==='kvm_exit'&&e.reason==='EPT_MISCONFIG'});
    if(em)return 'first emulation';
    return 'bring-up';
}
function regionDesc(evs,startSeq,endSeq){
    var facts=[];
    var dm=evs.filter(function(e){return e.name==='device_dma_transfer'});
    if(dm.length)facts.push('DMA '+(dm[0].dma_dir==='to_device'?'→':'←')+' GPA '+dm[0].dma_gpa);
    var ac=evs.filter(function(e){return e.name==='kvm_apic_accept_irq'}).length;
    if(ac)facts.push(ac+' accepted vector-64 edge'+(ac>1?'s':''));
    var reas={};
    evs.forEach(function(e){if(e.name==='kvm_exit'&&e.reason)reas[e.reason]=(reas[e.reason]||0)+1});
    Object.keys(reas).forEach(function(k){
        if(k==='EPT_MISCONFIG')facts.push('EPT_MISCONFIG \u00d7'+reas[k]);
        else facts.push(k+(reas[k]>1?' \u00d7'+reas[k]:''));
    });
    var hc={};
    evs.forEach(function(e){if(e.kind==='handoff'){var k=(e.userspace_reason||'').replace('KVM_EXIT_','')||'?';hc[k]=(hc[k]||0)+1}});
    var hparts=Object.keys(hc).sort().map(function(k){return k+(hc[k]>1?' \u00d7'+hc[k]:'')});
    if(hparts.length)facts.push(hparts.join(' / ')+' handoffs');
    if(!facts.length)facts.push('guest bring-up: entry, exit, APIC wiring');
    return 'seq '+startSeq+'–'+endSeq+' · '+facts.join(' · ');
}
/* Guard markers the guest writes to port 0xe9 (PIO used only as a synchronization marker). */
var PHASE_LABEL={
    A:'APIC-ready baseline',
    B:'single IRQ_ONLY chain',
    C:'IRQ pending while IF=0',
    D:'same-vector IRQ burst while IF=0',
    E:'virtual DMA TO/FROM'
};
/* Segment the stream into the guest's A..E phases, anchored on the 0xe9 markers. */
function deriveEpisodes(events){
    var firstM=findIdx(events,function(e){return e.kind==='exit'&&e.reason==='EPT_MISCONFIG'});
    var dmas=[];
    events.forEach(function(e,i){if(e.name==='device_dma_transfer')dmas.push(i)});
    /* A..E: boundaries fall on the three 0xe9 markers and the first DMA transfer. */
    var markers=[];
    events.forEach(function(e,i){
        if(e.kind==='exit'&&e.reason==='IO_INSTRUCTION'&&/e900/.test(e.info1||''))markers.push(i);
    });
    var eps=[];
    if(markers.length>=3&&dmas.length){
        /* Boundaries as event indices: A=0..m1, B=m1+1..m2, C=m2+1..m3, D=m3+1..dma0-1, E=dma0..end. */
        var bd=[0,markers[0]+1,markers[1]+1,markers[2]+1,dmas[0],events.length];
        var letters=['A','B','C','D','E'];
        for(var s=0;s<5;s++){
            var a=bd[s],eb=bd[s+1]-1;
            var slice=events.slice(a,eb+1);
            eps.push({
                start:events[a].seq,end:events[eb].seq,count:eb-a+1,
                indices:(function(){var r=[];for(var k=a;k<=eb;k++)r.push(k);return r})(),
                name:'Phase '+letters[s]+' \u00b7 '+PHASE_LABEL[letters[s]],
                desc:regionDesc(slice,events[a].seq,events[eb].seq)
            });
        }
        return eps;
    }
    /* Fallback when no markers: strongest motifs (first emulation, IRQ bursts, DMA, polling run). */
    var accepts=[],starts=[0];
    events.forEach(function(e,i){if(e.name==='kvm_apic_accept_irq')accepts.push(i)});
    if(firstM>=0)starts.push(firstM);
    if(accepts.length)starts.push(accepts[0]);
    for(var b=0;b<accepts.length-1;b++){
        if(events[accepts[b+1]].time_us-events[accepts[b]].time_us<40){starts.push(accepts[b]);break}
    }
    dmas.forEach(function(i){starts.push(i)});
    var pollIdx=[];
    events.forEach(function(e,i){
        if(e.kind==='exit'&&e.reason==='EPT_MISCONFIG'&&e.rip==='0x108')pollIdx.push(i);
    });
    var pollStart=-1,best=-1,runStart=0;
    for(var p=1;p<=pollIdx.length;p++){
        var cont=p<pollIdx.length&&events[pollIdx[p]].time_us-events[pollIdx[p-1]].time_us<40;
        if(!cont){
            var len=p-runStart;
            if(len>=6&&len>best){best=len;pollStart=pollIdx[runStart]}
            runStart=p;
        }
    }
    if(pollStart>=0)starts.push(pollStart);
    starts=starts.filter(function(v,i){return starts.indexOf(v)===i}).sort(function(a,b){return a-b});
    for(var q=0;q<starts.length;q++){
        var sa=starts[q];
        if(sa>=events.length)break;
        var se=q+1<starts.length?starts[q+1]-1:events.length-1;
        var seg=events.slice(sa,se+1);
        eps.push({
            start:events[sa].seq,end:events[se].seq,count:se-sa+1,
            indices:(function(){var r=[];for(var k=sa;k<=se;k++)r.push(k);return r})(),
            name:regionName(seg,q===starts.length-1),desc:regionDesc(seg,events[sa].seq,events[se].seq)
        });
    }
    return eps;
}
function episodeFor(index){
    for(var i=0;i<D.episodes.length;i++){
        var ep=D.episodes[i];
        if(index>=ep.start-1&&index<=ep.end-1)return i;
    }
    return D.episodes.length-1;
}

/* Metrics for the sustained RIP 0x108 MMIO polling run. */
function pollMetrics(events){
    var run=[];
    events.forEach(function(e){
        if(e.kind==='exit'&&e.reason==='EPT_MISCONFIG'&&e.rip==='0x108')run.push(e);
    });
    var gaps=[];
    for(var i=1;i<run.length;i++)gaps.push(+(run[i].time_us-run[i-1].time_us).toFixed(3));
    var med=null;
    if(gaps.length){
        gaps.sort(function(a,b){return a-b});
        var m=Math.floor(gaps.length/2);
        med=gaps.length%2?gaps[m]:+( (gaps[m-1]+gaps[m])/2 ).toFixed(3);
    }
    return{poll_count:run.length,poll_median_us:med};
}

/* ---- presentation helpers ------------------------------------------- */

function prettyEvent(e){
    if(e.name==='kvm_entry')return'VM entry';
    if(e.name==='kvm_exit')return e.reason||'VM exit';
    if(e.name==='kvm_userspace_exit')return(e.userspace_reason||'userspace exit').replace('KVM_EXIT_','');
    if(e.name==='device_dma_transfer')return e.dma_dir==='to_device'?'DMA → device':'DMA ← device';
    if(e.name==='kvm_apic_accept_irq')return'APIC accepts vec 64';
    if(e.name==='kvm_ioapic_set_irq')return'IOAPIC set_irq';
    if(e.name==='kvm_apic')return'APIC SPIV write';
    return e.name;
}
function detailType(e){
    if(e.kind==='entry')return'domain transition · KVM → guest';
    if(e.kind==='exit')return'domain transition · guest → KVM';
    if(e.kind==='handoff')return'domain transition · KVM → userspace';
    if(e.kind==='dma')return'device state · DMA';
    if(e.kind==='irq')return'interrupt route';
    if(e.kind==='apic')return'guest APIC programming';
    return e.kind;
}
function explanation(e){
    if(e.name==='kvm_entry')return 'KVM is transferring execution into vCPU 0.  The snapshot is taken at the entry hook; RIP '+esc(e.rip||'—')+' is the guest instruction pointer reported by the trace.';
    if(e.name==='kvm_exit'){
        var extra=e.paired_handoff?'  The immediately following trace event is '+esc(e.paired_handoff)+', so this exit crosses onward into userspace emulation.':'';
        if(e.reason==='EPT_MISCONFIG')extra+='  Here the label is kept literal: this capture uses EPT_MISCONFIG repeatedly on the path that often hands off as KVM_EXIT_MMIO.';
        return 'Guest execution has stopped and control has returned to KVM with exit reason '+esc(e.reason||'—')+' at RIP '+esc(e.rip||'—')+'.'+extra;
    }
    if(e.name==='kvm_userspace_exit')return 'KVM_RUN returns to the userspace VMM with '+esc(e.userspace_reason||'—')+'.  This is the host-side emulation boundary visible in the flow trace.';
    if(e.name==='kvm_apic_accept_irq')return "KVM's LAPIC path records acceptance of vector 64 for APIC ID 0.  This event is part of the interrupt-delivery path, not itself proof that guest handler code has started.";
    if(e.name==='kvm_ioapic_set_irq')return 'The KVM IOAPIC tracepoint records pin '+(e.pin||D.meta.device_gsi)+' routed toward vector '+(e.vec||D.meta.device_vector)+'.  The eBPF metadata says the IOAPIC object was not directly available to the state sampler, so the route is learned from the tracepoint.';
    if(e.name==='kvm_apic')return 'The guest writes APIC_'+(e.apic_reg||'reg')+' = '+(e.apic_val||'?')+'.  This is guest APIC programming observed in the KVM trace before later vector-64 activity.';
    if(e.name==='device_dma_transfer')return 'An eBPF-only device event samples a '+D.meta.dma_xfer_size+'-byte '+(e.dma_dir==='to_device'?'guest-memory → device':'device → guest-memory')+' transfer at GPA '+esc(e.dma_gpa)+'.  It is inserted into the trace flow by monotonic time.';
    return 'Observed transition in the fused trace/eBPF sequence.';
}

/* ---- renderers -------------------------------------------------------- */

function renderRoadmap(){
    var active=episodeFor(cursor);
    $('roadmap').innerHTML=D.episodes.map(function(ep,ei){
        var dots=ep.indices.map(function(idx){
            var evt=D.events[idx];
            return '<button class="phase-dot '+(idx===cursor?'current':'')+'" data-index="'+idx+'" title="seq '+evt.seq+': '+esc(prettyEvent(evt))+' (raw: '+esc(evt.raw)+')"></button>';
        }).join('');
        return '<div class="zone '+(ei===active?'active':'')+'" data-ep="'+ei+'">'+
            '<div><div class="zone-label">'+esc(ep.name)+'</div><div class="zone-sub">seq '+ep.start+'–'+ep.end+' · '+ep.count+' events</div></div>'+
            '<div class="zone-dots">'+dots+'</div></div>';
    }).join('');
    $('roadmap').querySelectorAll('.phase-dot').forEach(function(b){
        b.addEventListener('click',function(x){x.stopPropagation();select(+b.dataset.index)});
    });
    $('roadmap').querySelectorAll('.zone').forEach(function(z){
        z.addEventListener('click',function(){select(D.episodes[+z.dataset.ep].start-1)});
    });
}
function domainState(e){
    var ds={vmm:false,kvm:false,guest:false};
    if(e.kind==='entry'){ds.kvm=true;ds.guest=true}
    else if(e.kind==='exit'){ds.guest=true;ds.kvm=true}
    else if(e.kind==='handoff'){ds.kvm=true;ds.vmm=true}
    else if(e.kind==='apic'){ds.guest=true;ds.kvm=true}
    else ds.kvm=true;
    return ds;
}
function renderExecution(e){
    var ds=domainState(e);
    document.querySelectorAll('.domain').forEach(function(n){n.classList.toggle('active',!!ds[n.dataset.domain])});
    $('rip-head').textContent=e.rip?'RIP '+e.rip:'RIP —';
    $('guest-state').textContent=e.rip?'RIP '+e.rip:'vCPU 0';
    $('guest-detail').textContent=e.kind==='exit'?('exit: '+e.reason):e.kind==='entry'?'entry point reported by KVM':'guest context preserved';
    $('kvm-state').textContent=e.kind==='exit'?(e.reason||'VM exit'):e.kind==='entry'?'KVM_RUN → guest':e.kind==='handoff'?'return to VMM':e.name.replace('kvm_','');
    $('kvm-detail').textContent=e.info1?('info1 '+e.info1):'kernel virtualization boundary';
    $('vmm-state').textContent=e.kind==='handoff'?(e.userspace_reason||'userspace exit'):'VMM run loop';
    $('vmm-detail').textContent=e.kind==='handoff'?'userspace emulation boundary':'outside guest while KVM_RUN active';

    var wrap=$('domains');
    wrap.querySelectorAll('.flow-arrow,.flow-tag').forEach(function(n){n.parentNode.removeChild(n)});
    var pos={vmm:16.5,kvm:50,guest:83.5};
    if(['entry','exit','handoff'].indexOf(e.kind)>=0){
        var a=pos[e.from],b=pos[e.to],left=Math.min(a,b),width=Math.abs(a-b);
        var ar=document.createElement('div');
        ar.className='flow-arrow'+(b<a?' reverse':'');
        ar.style.left=left+'%';ar.style.width=width+'%';
        var tag=document.createElement('div');
        tag.className='flow-tag';tag.style.left='calc('+((a+b)/2)+'% - 42px)';tag.textContent=prettyEvent(e);
        wrap.appendChild(ar);wrap.appendChild(tag);
    }
    $('flow-kind').textContent=e.kind;
    $('flow-caption').textContent=e.from+'\u00a0→\u00a0'+e.to;
}
function renderIRQ(e){
    var nodes=['irq-device','irq-ioapic','irq-lapic'],edges=['edge-gsi','edge-lapic'];
    nodes.forEach(function(id){$(id).classList.remove('hot')});
    edges.forEach(function(id){$(id).classList.remove('hot')});
    if(e.name==='kvm_apic_accept_irq'){nodes.forEach(function(id){$(id).classList.add('hot')});edges.forEach(function(id){$(id).classList.add('hot')})}
    if(e.name==='kvm_ioapic_set_irq'){$('irq-ioapic').classList.add('hot');$('edge-lapic').classList.add('hot');$('irq-lapic').classList.add('hot')}
    if(e.name==='kvm_apic')$('irq-lapic').classList.add('hot');

    var irr=$('irr-bit'),isr=$('isr-bit');
    irr.classList.toggle('on',!!e.irr);isr.classList.toggle('on',!!e.isr);
    irr.querySelector('strong').textContent=e.irr?'1':'0';isr.querySelector('strong').textContent=e.isr?'1':'0';
    $('irq-address').textContent='GSI '+D.meta.device_gsi+' → VEC '+D.meta.device_vector;
    $('rte-val').textContent=e.rte;
    $('ioapic-val').textContent=e.ioapic_ptr||'NULL';
    if(e.irr&&e.isr){$('irq-state').textContent='pending + in service';$('irq-caption').textContent='both sampled bits set'}
    else if(e.irr){$('irq-state').textContent='pending';$('irq-caption').textContent='IRR=1 / ISR=0 · vector held while IF=0'}
    else if(e.isr){$('irq-state').textContent='in service';$('irq-caption').textContent='IRR=0 / ISR=1 at this hook'}
    else{$('irq-state').textContent=e.kind==='irq'?'route activity':'idle';$('irq-caption').textContent=e.kind==='irq'?'trace route active; sampled IRR/ISR still zero':'no pending/in-service bit at this hook'}
}
function renderDMA(e){
    var edge=$('dma-edge'),buf=Array.prototype.slice.call($('buffer').children);
    edge.className='dma-edge';buf.forEach(function(x){x.classList.remove('hot')});
    $('gpa6000').classList.remove('hot');$('gpa7000').classList.remove('hot');
    if(e.dma_present){
        edge.classList.add('hot',e.dma_dir==='to_device'?'to':'from');
        buf[0].classList.add('hot');
        $('dma-gpa').textContent=e.dma_gpa;
        $('device-state').textContent=e.dma_dir==='to_device'?'receiving '+D.meta.dma_xfer_size+' B':'sending '+D.meta.dma_xfer_size+' B';
        $('device-detail').textContent=e.dma_dir.replace('_',' ')+'\u00a0· sampled eBPF event · verified byte-for-byte for this run';
        $(e.dma_gpa==='0x6000'?'gpa6000':'gpa7000').classList.add('hot');
        $('dma-state').textContent=e.dma_dir;
        $('dma-caption').textContent=D.meta.dma_xfer_size+' B at '+e.dma_gpa+' · '+e.dma_dir;
    }else{
        $('dma-gpa').textContent='no DMA now';
        $('device-state').textContent=D.meta.device_buffer_size+' B buffer';
        $('device-detail').textContent='no transfer sampled at current hook';
        $('dma-state').textContent='not present';
        $('dma-caption').textContent='DMA field is sampled only at the eBPF DMA event';
    }
}
function renderWindow(){
    var start=Math.max(0,Math.min(D.events.length-13,cursor-6)),
        end=Math.min(D.events.length,start+13);
    var slice=D.events.slice(start,end);
    $('flow-window').innerHTML=slice.map(function(e,i){
        var foot=e.rip?e.rip:e.irr?'IRR=1':e.isr?'ISR=1':e.rte!=='0x0'?'RTE '+e.rte:'';
        return '<button class="event-cell '+e.kind+' '+(start+i===cursor?'current':'')+'" data-index="'+(start+i)+'" title="seq '+e.seq+': '+esc(prettyEvent(e))+'\n'+esc(e.raw)+'">'+
            '<strong>'+esc(prettyEvent(e))+'</strong><span>seq '+e.seq+' · '+e.time_us.toFixed(3)+' µs</span><span>'+esc(foot)+'</span></button>';
    }).join('');
    $('flow-window').querySelectorAll('.event-cell').forEach(function(b){b.addEventListener('click',function(){select(+b.dataset.index)})});
}
function renderNotebook(e){
    $('source-badge').textContent=e.trace_line?'trace + eBPF':'eBPF-only';
    $('detail-type').textContent=detailType(e);
    $('detail-title').textContent=e.name;
    $('explain').textContent=explanation(e);
    var rows=[
        ['sequence',e.seq],
        ['time',e.time_us.toFixed(3)+' µs from capture start'],
        ['source',e.trace_line?'Trace.txt L'+e.trace_line+' (raw trace) + eBPF':'eBPF-only (no trace line)'],
        ['CPU / task',e.cpu+' / '+e.comm+'-'+e.pid+(e.tid?' (tid '+e.tid+')':'')],
        ['flags',e.flags||'—']
    ];
    if(e.rip)rows.push(['guest RIP',e.rip]);
    if(e.reason)rows.push(['VM-exit reason',e.reason]);
    if(e.userspace_reason)rows.push(['userspace reason',e.userspace_reason+' ('+e.userspace_reason.replace('KVM_EXIT_','')+' enum)']);
    if(e.info1)rows.push(['exit info1',e.info1]);
    if(e.accept_apicid!=null||e.apicid!=null)rows.push(['APIC id',e.apicid]);
    if(e.vec!=null)rows.push(['vector',e.vec]);
    if(e.apic_text)rows.push(['APIC write',e.apic_text]);
    if(e.irq_text)rows.push(['IRQ trace',e.irq_text]);
    if(e.paired_handoff)rows.push(['hand-off next',e.paired_handoff]);
    rows.push(['IRR / ISR',(e.irr?1:0)+' / '+(e.isr?1:0)],['RTE',e.rte],['vCPU *',e.vcpu_ptr],['KVM *',e.kvm_ptr],['LAPIC *',e.apic_ptr],['IOAPIC *',e.ioapic_ptr||'NULL']);
    if(e.dma_present)rows.push(['DMA',e.dma_dir+' · '+e.dma_gpa+' · '+D.meta.dma_xfer_size+' B']);
    if(e.dt_prev_us!=null)rows.push(['Δ previous',e.dt_prev_us+' µs']);
    if(e.dt_next_us!=null)rows.push(['Δ next',e.dt_next_us+' µs']);
    $('fields').innerHTML=rows.map(function(r){return '<dt>'+esc(r[0])+'</dt><dd title="'+esc(r[1])+'">'+esc(r[1])+'</dd>'}).join('');
    $('raw').textContent=e.raw;
}
function select(index){
    if(!D||!D.events.length)return;
    cursor=Math.max(0,Math.min(D.events.length-1,index||0));
    var e=ev(),epi=episodeFor(cursor),ep=D.episodes[epi];
    $('episode-name').textContent=ep.name;
    $('episode-name').title=ep.name+' — '+ep.desc;
    $('event-clock').textContent='t = '+e.time_us.toFixed(3)+' µs';
    $('scrub').value=cursor;
    $('counter').textContent=(cursor+1)+' / '+D.events.length;
    renderRoadmap();renderExecution(e);renderIRQ(e);renderDMA(e);renderWindow();renderNotebook(e);
}
function togglePlay(){
    if(timer){clearInterval(timer);timer=null;$('play').textContent='▶';$('play').classList.remove('active');return}
    $('play').textContent='Ⅱ';$('play').classList.add('active');
    timer=setInterval(function(){if(cursor>=D.events.length-1){togglePlay();return}select(cursor+1)},280);
}
function wireToolbar(){
    $('first').addEventListener('click',function(){select(0)});
    $('prev').addEventListener('click',function(){select(cursor-1)});
    $('play').addEventListener('click',togglePlay);
    $('scrub').addEventListener('input',function(e){select(+e.target.value)});
    document.addEventListener('keydown',function(e){
        if(e.key==='ArrowLeft')select(cursor-1);
        if(e.key==='ArrowRight')select(cursor+1);
        if(e.key===' '){e.preventDefault();togglePlay()}
    });
}

/* ---- load ------------------------------------------------------------- */

Promise.all([
    fetch(BPF,{cache:'no-store'}).then(function(r){if(!r.ok)throw Error('bpf HTTP '+r.status);return r.text()}),
    fetch(TRC,{cache:'no-store'}).then(function(r){if(!r.ok)throw Error('trace HTTP '+r.status);return r.text()})
]).then(function(parts){
    var snaps=parseBpf(parts[0]);
    if(!snaps.length)throw Error('no eBPF snapshots parsed');
    D.events=finalize(buildEvents(snaps,parseTrace(parts[1])));
    D.episodes=deriveEpisodes(D.events);
    var pm=pollMetrics(D.events);
    D.poll_count=pm.poll_count;D.poll_median_us=pm.poll_median_us;
    $('strip-host').textContent=D.events[0]?D.events[0].cpu:'—';
    $('strip-gsi').textContent=D.meta.device_gsi;
    $('strip-vector').textContent=D.meta.device_vector;
    $('strip-dma').textContent=D.meta.dma_xfer_size+' B';
    $('strip-buf').textContent=D.meta.device_buffer_size+' B';
    $('task').textContent=(D.events[0]?D.events[0].comm:'vmm')+'-'+(D.events[0]?D.events[0].pid:'?');
    $('status').lastElementChild.textContent=D.events.length+' observations aligned';
    wireToolbar();
    select(0);
}).catch(function(err){
    $('status').lastElementChild.textContent='virt-io data error · '+err.message;
});
})();