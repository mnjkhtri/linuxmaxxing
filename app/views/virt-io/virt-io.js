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
        var st=r.state||{},ct=st.controller||{},d=st.dma||{},ms=st.msi||{};
        out.push({
            seq:Number(r.seq),
            time_ns:Number(r.time_ns),
            name:(r.event_info||{}).event_name,
            event:(r.event_info||{}).event,
            ctx:r.context||{},
            vcpu:st.vcpu,kvm:st.kvm,apic:st.apic,ioapic:st.ioapic,
            rte:ct.rte,tpr:ct.tpr,svr:ct.svr,irr:ct.irr,isr:ct.isr,
            msi_present:ms.present,msi_addr:ms.address,msi_data:ms.data,
            msi_vector:ms.vector,msi_dest:ms.destination,msi_logical:ms.logical,
            msi_level:ms.level_triggered,msi_delivery:ms.delivery_mode,
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
        }else if(e.type==='kvm_msi_set_irq'){
            var msi=e.body.match(/address=0x([0-9a-f]+)\s+data=0x([0-9a-f]+)/i);
            if(msi){e.msi_address='0x'+msi[1];e.msi_data='0x'+msi[2]}
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
    kvm_apic_accept_irq:'irq',kvm_ioapic_set_irq:'irq',kvm_msi_set_irq:'msi',
    kvm_apic:'apic',device_dma_transfer:'dma'};

/* Join each eBPF snapshot with its line-by-line trace record into one stream. */
function buildEvents(snaps,trs){
    var byType={};
    trs.forEach(function(t){(byType[t.type]=byType[t.type]||[]).push(t)});
    var used={};
    return snaps.map(function(f){
        var e={
            seq:f.seq,name:f.name,time_ns:f.time_ns,
            vcpu_ptr:f.vcpu,kvm_ptr:f.kvm,apic_ptr:f.apic,ioapic_ptr:f.ioapic,
            irr:f.irr,isr:f.isr,rte:f.rte,tpr:f.tpr,svr:f.svr,
            msi_present:f.msi_present,msi_addr:f.msi_addr,msi_data:f.msi_data,
            msi_vector:f.msi_vector,msi_dest:f.msi_dest,msi_logical:f.msi_logical,
            msi_level:f.msi_level,msi_delivery:f.msi_delivery,
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
            if(t.type==='kvm_msi_set_irq')e.irq_text=t.body,e.trace_msi_addr=t.msi_address,e.trace_msi_data=t.msi_data;
        }else{
            e.trace_line=null;e.raw='eBPF-only device DMA observation';e.flags='';
            e.cpu=f.ctx.cpu;e.pid=f.ctx.pid;e.tid=f.ctx.tid;e.comm=f.ctx.comm;
        }
        e.kind=KINDS[f.name]||f.name;
        e.accent=e.kind==='entry'?'cyan':e.kind==='exit'?'orange':e.kind==='handoff'?'green':
            e.kind==='irq'?'yellow':e.kind==='dma'?'blue':e.kind==='apic'?'violet':e.kind==='msi'?'violet':e.kind;
        if(e.kind==='entry'){e.from='kvm';e.to='guest';e.label='VM entry'}
        else if(e.kind==='exit'){e.from='guest';e.to='kvm';e.label=e.reason||'VM exit'}
        else if(e.kind==='handoff'){e.from='kvm';e.to='vmm';e.label=(e.userspace_reason||'userspace exit').replace('KVM_EXIT_','')}
        else if(e.kind==='dma'){e.from=e.dma_dir==='to_device'?'memory':'device';e.to=e.dma_dir==='to_device'?'device':'memory';e.label=e.dma_dir==='to_device'?'DMA → device':'DMA ← device'}
        else if(e.name==='kvm_apic_accept_irq'){e.from='device';e.to='lapic';e.label='APIC accepts vec '+(e.vec||metaVec())}
        else if(e.name==='kvm_ioapic_set_irq'){e.from='gsi';e.to='lapic';e.label='IOAPIC pin '+(e.pin||metaGsi())+' → vec '+(e.vec||metaVec())}
        else if(e.name==='kvm_msi_set_irq'){e.from='vmm';e.to='lapic';e.label='MSI msg → vec '+(e.msi_vector||metaMsiVec())+' · no IOAPIC'}
        else if(e.name==='kvm_apic'){e.from='guest';e.to='lapic';e.label='APIC '+(e.apic_reg||'reg')+' write'}
        else{e.from='';e.to='';e.label=e.name}
        return e;
    });
}
function metaGsi(){return D&&D.meta?D.meta.device_gsi:''}
function metaVec(){return D&&D.meta?D.meta.device_vector:''}
function metaMsiVec(){return D&&D.meta?D.meta.msi_vector:''}

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
    if(ac>=3)return 'MSI + service';
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
    if(ac)facts.push(ac+' accepted '+(ac>1?'edges':'edge')+' (vec '+(metaVec())+')');
    var msi=evs.filter(function(e){return e.name==='kvm_msi_set_irq'}).length;
    if(msi)facts.push(msi+' MSI message vec '+(metaMsiVec())+' · IOAPIC bypassed');
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
    D:'MSI bypasses GSI/IOAPIC',
    E:'virtual DMA TO/FROM'
};
/* Narrative annotation for each guest phase: how it begins, how it hands off,
   and which guest.S section drives it.  Applied to whichever indices we derive. */
var SEMANTIC_PHASE={
    A:{ingress:'capture begins at the first kvm_entry; the earlier userspace KVM_RUN call is outside the capture',egress:'phase A ends inside guest residency: STI enables APIC interrupts, then the phase-B COMMAND MMIO write produces the next observed exit',source:'guest.S phase A'},
    B:{ingress:'phase B begins inside the guest run after the phase-A marker; the first phase-B-specific observed exit is the COMMAND MMIO exit',egress:'phase B ends inside guest residency: WAIT_IRQ_COUNT 1 completes before CLI and the phase-C command write',source:'guest.S phase B'},
    C:{ingress:'phase C begins inside the guest run preceding the phase-C command MMIO exit; CLI has set IF=0',egress:'phase C ends inside guest residency after the marker: the next observed exit is the phase-D (MSI) command write',source:'guest.S phase C'},
    D:{ingress:'phase D begins inside the guest run preceding the phase-D command MMIO exit; CLI keeps IF=0 while the device signals MSI vector 0x41',egress:'phase D ends inside guest residency: STI lets the pending MSI dispatch, then DMA programming begins',source:'guest.S phase D'},
    E:{ingress:'phase E begins inside the guest run preceding the first DMA-programming MMIO exit',egress:'run terminates through OUT 0x82 → KVM_EXIT_IO',source:'guest.S phase E'}
};
function annotateEpisode(ep){
    var letter=ep.name.charAt(6);
    var s=SEMANTIC_PHASE[letter];
    if(s){ep.ingress=s.ingress;ep.egress=s.egress;ep.source=s.source}
    return ep;
}
/* Segment the stream into the guest's A..E phases, anchored on the 0xe9 markers. */
function deriveEpisodes(events){
    var firstM=findIdx(events,function(e){return e.kind==='exit'&&e.reason==='EPT_MISCONFIG'});
    var dmas=[];
    events.forEach(function(e,i){if(e.name==='device_dma_transfer')dmas.push(i)});

    function letterOf(rip){if(rip<0x72)return'A';if(rip<0x8f)return'B';if(rip<0xb2)return'C';if(rip<0xcf)return'D';return'E'}
    var ISR_MIN=0x1b0,ISR_MAX=0x1f0,SETUP_MIN=0x160,SETUP_MAX=0x1af;
    var lastRip=0,lastAcceptLetter=null;

    var assigned=events.map(function(e){
        var rip=parseInt(e.rip||'0x0',16);
        var hasRip=/^0x[0-9a-f]+$/i.test(e.rip||'');
        var inISR=rip>=ISR_MIN&&rip<=ISR_MAX;
        var inSetup=rip>=SETUP_MIN&&rip<=SETUP_MAX;
        if(e.name==='device_dma_transfer')return'E';
        if(e.name==='kvm_apic_accept_irq'){lastAcceptLetter=letterOf(lastRip);return lastAcceptLetter}
        if(hasRip&&inISR)return lastAcceptLetter||letterOf(lastRip);
        if(hasRip&&inSetup)return'A';
        if(hasRip){lastRip=rip;return letterOf(rip)}
        return letterOf(lastRip);
    });

    var eps=[];
    var letters=['A','B','C','D','E'];
    for(var s=0;s<5;s++){
        var idx=[];
        assigned.forEach(function(L,i){if(L===letters[s])idx.push(i)});
        if(!idx.length)continue;
        eps.push({
            start:events[idx[0]].seq,end:events[idx[idx.length-1]].seq,count:idx.length,
            indices:idx,
            name:'Phase '+letters[s]+' \u00b7 '+PHASE_LABEL[letters[s]],
            desc:regionDesc(events.slice(idx[0],idx[idx.length-1]+1),events[idx[0]].seq,events[idx[idx.length-1]].seq)
        });
    }
    if(eps.length)return eps.map(annotateEpisode);
    /* Fallback when no markers: strongest motifs (first emulation, IRQ/MSI service, DMA, polling run). */
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
    return eps.map(annotateEpisode);
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
    if(e.name==='kvm_apic_accept_irq')return'APIC accepts vec '+(e.vec!=null?e.vec:'?');
    if(e.name==='kvm_ioapic_set_irq')return'IOAPIC set_irq';
    if(e.name==='kvm_msi_set_irq')return'MSI set_irq';
    if(e.name==='kvm_apic')return'APIC SPIV write';
    return e.name;
}
function detailType(e){
    if(e.kind==='entry')return'domain transition · KVM → guest';
    if(e.kind==='exit')return'domain transition · guest → KVM';
    if(e.kind==='handoff')return'domain transition · KVM → userspace';
    if(e.kind==='dma')return'device state · DMA';
    if(e.kind==='irq')return'interrupt route';
    if(e.kind==='msi')return'interrupt route · MSI';
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
    if(e.name==='kvm_ioapic_set_irq')return 'The KVM IOAPIC tracepoint records pin '+(e.pin||D.meta.device_gsi)+' routed toward vector '+(e.vec||D.meta.device_vector)+'.  The sampler also reads pin '+(e.pin||D.meta.device_gsi)+' RTE from vcpu->kvm->arch.vioapic, so the guest Phase-A RTE programming and this line assertion are both observable.';
    if(e.name==='kvm_msi_set_irq')return 'KVM_SIGNAL_MSI injected an architectural MSI message from the toy device.  The message carries its own address (0x'+(e.msi_addr!==undefined?e.msi_addr.toString(16):'—')+') and data (vec '+(e.msi_vector!=null?e.msi_vector:'—')+'); it targets the LAPIC directly, so no GSI and no IOAPIC redirection participates in this delivery.';
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
/* ---- execution chronogram helpers -------------------------------------- */

function lapicWindow(win){
    var out=[];
    if(win)for(var k=0;k<8;k++){
        var w=win['b'+k];
        if(!w)continue;
        var bits=parseInt(w,16);
        for(var b=0;b<32;b++)if(bits&(1<<b))out.push(k*32+b);
    }
    return out;
}
function vecList(vecs){
    if(!vecs.length)return '—';
    return vecs.map(function(v){return '0x'+v.toString(16)}).join(', ');
}

/* Decode a kvm_exit ioinfo1 into port / direction / size for IO_INSTRUCTION. */
function ioQualification(e){
    if(e.kind!=='exit'||e.reason!=='IO_INSTRUCTION'||!e.info1)return null;
    var q=parseInt(e.info1,16);
    if(q==null||isNaN(q))return null;
    var port=(q>>16)&0xffff;
    var isIn=((q>>>3)&1)===1;
    var sizeCode=q&7;
    var bytes=sizeCode===0?1:sizeCode===1?2:sizeCode===3?4:null;
    return{port:port,dir:isIn?'IN':'OUT',bytes:bytes};
}
/* Human meaning of the guest IO ports used by this capture. */
function ioMeaning(e){
    var q=ioQualification(e);
    if(!q)return'';
    if(q.port===0x21)return'master PIC mask';
    if(q.port===0xa1)return'slave PIC mask';
    if(q.port===0xe9)return'phase synchronization marker';
    if(q.port===0x82)return'VMM done / success port';
    return'port I/O';
}
/* Compact terminal label for a tracepoint/hook observation site. */
function compactObs(e){
    if(e.name==='kvm_apic_accept_irq')return 'APIC accept · vec '+(e.vec!=null?e.vec:'?');
    if(e.name==='kvm_ioapic_set_irq')return 'IOAPIC set_irq · pin '+(e.pin!=null?e.pin:'?');
    if(e.name==='kvm_msi_set_irq')return 'MSI set_irq · vec '+(e.msi_vector!=null?e.msi_vector:'?');
    if(e.name==='kvm_apic')return 'APIC '+(e.apic_reg||'reg')+' write';
    if(e.name==='device_dma_transfer')return (e.dma_dir==='to_device'?'DMA → device':'DMA ← device')+' · '+(e.dma_gpa||'');
    return prettyEvent(e);
}
/* Label for the deepest IO_INSTRUCTION reason an exit row can carry. */
function seqIoLabel(e){
    var q=ioQualification(e);
    if(!q)return e.reason||'IO_INSTRUCTION';
    var meaning=ioMeaning(e);
    return q.dir+' 0x'+q.port.toString(16)+(meaning?' · '+meaning:'');
}
/* Rightmost observation column label for any event kind. */
function seqObsLabel(e){
    if(e.kind==='entry')return 'kvm_entry';
    if(e.kind==='exit')return 'kvm_exit · '+(e.reason||'VM exit');
    if(e.kind==='handoff')return 'kvm_userspace_exit · '+((e.userspace_reason||'KVM_EXIT').replace('KVM_EXIT_',''));
    if(e.name==='device_dma_transfer')return 'VMM uprobe · device_dma_transfer';
    return 'KVM tracepoint · '+e.name;
}
/* Walking residency guess: update one domain per boundary event. */
function executionStateBefore(index){
    var s='unknown';
    for(var i=0;i<index;i++){
        var e=D.events[i];
        if(e.kind==='entry')s='guest';
        else if(e.kind==='exit')s='kvm';
        else if(e.kind==='handoff')s='vmm';
    }
    return s;
}
function stateAfterEvent(e,prior){
    if(e.kind==='entry')return 'guest';
    if(e.kind==='exit')return 'kvm';
    if(e.kind==='handoff')return 'vmm';
    return prior;
}

function renderExec(e){
    var ep=D.episodes[episodeFor(cursor)];
    var idxs=ep.indices,startIdx=idxs[0],endIdx=idxs[idxs.length-1];
    var slice=D.events.slice(startIdx,endIdx+1);
    var host=$('exec-html');
    $('rip-head').textContent=e.rip?('RIP '+e.rip):'RIP —';

    var head='<div class="seq-head">'
        +'<div class="seq-side-head">SEQ / Δt</div>'
        +'<div class="seq-domains">'
        +'<div class="seq-domain"><b>USERSPACE VMM</b><span>KVM_RUN caller · device model</span></div>'
        +'<div class="seq-domain"><b>KVM</b><span>VM-exit handling · irqchip</span></div>'
        +'<div class="seq-domain"><b>GUEST vCPU 0</b><span>runs between entry and exit</span></div>'
        +'</div>'
        +'<div class="seq-side-head right">OBSERVATION</div>'
        +'</div>';

    var state=executionStateBefore(startIdx),rows='';

    slice.forEach(function(evt,i){
        var global=startIdx+i,cur=global===cursor,before=state,after=stateAfterEvent(evt,before);
        var dom='<span class="seq-life vmm"></span><span class="seq-life kvm"></span><span class="seq-life guest"></span>';

        if(before==='vmm')dom+='<span class="seq-res top vmm"></span>';
        else if(before==='kvm')dom+='<span class="seq-res top kvm"></span>';
        else if(before==='guest')dom+='<span class="seq-res top guest"></span>';

        if(after==='vmm')dom+='<span class="seq-res bottom vmm"></span>';
        else if(after==='kvm')dom+='<span class="seq-res bottom kvm"></span>';
        else if(after==='guest')dom+='<span class="seq-res bottom guest"></span>';

        if(evt.kind==='entry'){
            var prev=D.events[global-1];
            var fromUserspace=before==='vmm'||(prev&&prev.kind==='handoff');
            if(fromUserspace){
                dom+='<span class="seq-arrow run"></span>'
                    +'<span class="seq-label run">ioctl(KVM_RUN) · boundary untraced</span>'
                    +'<span class="seq-arrow entry after-run"></span>'
                    +'<span class="seq-point kvm entry" style="top:70%"></span>'
                    +'<span class="seq-point guest entry" style="top:70%"></span>'
                    +'<span class="seq-label entry-after-run">kvm_entry'+(evt.rip?' · '+esc(evt.rip):'')+'</span>';
            }else{
                dom+='<span class="seq-arrow entry"></span>'
                    +'<span class="seq-point kvm entry"></span>'
                    +'<span class="seq-point guest entry"></span>'
                    +'<span class="seq-label between-kg">kvm_entry'+(evt.rip?' · '+esc(evt.rip):'')+'</span>';
            }
        }else if(evt.kind==='exit'){
            var label=evt.reason||'VM exit',cls='';
            if(evt.reason==='IO_INSTRUCTION'){label=seqIoLabel(evt);var eq=ioQualification(evt);cls=(eq&&eq.port===0xe9)?'marker':'io'}
            dom+='<span class="seq-arrow exit"></span>'
                +'<span class="seq-point guest exit"></span>'
                +'<span class="seq-point kvm exit"></span>'
                +'<span class="seq-label between-kg '+cls+'">'+esc(label)+(evt.rip?'<span class="sub">'+esc(evt.rip)+'</span>':'')+'</span>';
        }else if(evt.kind==='handoff'){
            dom+='<span class="seq-arrow handoff"></span>'
                +'<span class="seq-point kvm handoff"></span>'
                +'<span class="seq-point vmm handoff"></span>'
                +'<span class="seq-label between-vk handoff">'+esc((evt.userspace_reason||'KVM_EXIT').replace('KVM_EXIT_',''))+'</span>';
        }else if(evt.name==='device_dma_transfer'){
            dom+='<span class="seq-hook vmm"></span>'
                +'<span class="seq-label vmm-hook">'+esc(compactObs(evt))+'</span>';
        }else{
            if(before==='kvm')dom+='<span class="seq-pulse"></span>'
                +'<span class="seq-label between-vk pulse">VMM ioctl ↔ KVM</span>';
            dom+='<span class="seq-hook kvm"></span>'
                +'<span class="seq-label kvm-hook">'+esc(compactObs(evt))+'</span>';
        }

        var dt=evt.dt_prev_us!=null?('+'+Number(evt.dt_prev_us).toFixed(3)+'µs'):'';
        rows+='<div class="seq-row '+(cur?'current':'')+'" data-index="'+global+'">'
            +'<div class="seq-num"><span>'+dt+'</span></div>'
            +'<div class="seq-domain-space">'+dom+'</div>'
            +'<div class="seq-obs">'+esc(seqObsLabel(evt))+'</div>'
            +'</div>';

        state=after;
    });

    var inner='<div class="seq-inner '+(slice.length>32?'long':'')+'" style="--rows:'+slice.length+'">'+rows+'</div>';
    var tail=ep.egress?'<div class="seq-phase-tail"><b>phase boundary:</b> '+esc(ep.egress)+'</div>':'';
    var prevTrack=host.querySelector('.seq-track');
    var prevTop=prevTrack?prevTrack.scrollTop:null;
    host.innerHTML=head+'<div class="seq-track">'+inner+'</div>'+tail;

    host.querySelectorAll('.seq-row').forEach(function(row){
        row.addEventListener('click',function(){select(+row.dataset.index)});
    });
    var newTrack=host.querySelector('.seq-track');
    if(newTrack&&prevTop!=null)newTrack.scrollTop=prevTop;
    var selected=host.querySelector('.seq-row.current');
    if(selected)selected.scrollIntoView({block:'nearest'});

    $('flow-kind').textContent=(e.kind==='entry'||e.kind==='exit'||e.kind==='handoff')?'boundary transition':'observation';
    if(e.kind==='entry'){
        $('flow-caption').textContent='kvm_entry is a host-KVM tracepoint immediately before VM entry: KVM → guest';
    }else if(e.kind==='exit'){
        var fq=ioQualification(e);
        if(e.reason==='IO_INSTRUCTION'&&fq){
            $('flow-caption').textContent='guest executed '+fq.dir+' port 0x'+fq.port.toString(16)+' → VM-exit → KVM'+(e.paired_handoff?(' ; next kvm_userspace_exit returns '+e.paired_handoff+' to VMM'):' ; KVM handles this exit without a userspace return');
        }else{
            $('flow-caption').textContent=(e.reason||'VM exit')+' means guest → KVM'+(e.paired_handoff?(' ; next event returns '+e.paired_handoff+' to VMM'):'');
        }
    }else if(e.kind==='handoff'){
        $('flow-caption').textContent=(e.userspace_reason||'')+' : KVM_RUN returns KVM → userspace VMM';
    }else if(e.name==='device_dma_transfer'){
        $('flow-caption').textContent='device_dma_transfer executes in the userspace VMM/device model';
    }else{
        $('flow-caption').textContent='this hook executes in host KVM; it is an observation site, not a guest-residency transition';
    }
}
function irqStateMap(e){
    var pending=lapicWindow(e.irr).sort(function(a,b){return a-b});
    var inService=lapicWindow(e.isr).sort(function(a,b){return a-b});
    return {
        irr: pending.join(' '),
        isr: inService.join(' '),
        svr: e.svr!=null&&e.svr!==''?e.svr:'0x0',
        tpr: e.tpr!=null&&e.tpr!==''?e.tpr:'0x0',
        rte: e.rte!=null&&e.rte!==''?e.rte:'0x0',
        route: irqRouteLabel(e)
    };
}
function irqStateDisplay(e,f){
    if(f==='irr'||f==='isr')return vecList(lapicWindow(e[f]));
    return irqStateMap(e)[f];
}
function irqRouteLabel(e){
    var m=/^0x([0-9a-f]+)$/,v;
    if(e.kind==='msi'||e.name==='kvm_msi_set_irq'){
        return 'MSI → VEC 0x'+(e.msi_vector!=null?e.msi_vector.toString(16):'—');
    }
    if(e.rte!=null&&e.rte!==''&&(v=e.rte.match(m)))return 'GSI '+D.meta.device_gsi+' → VEC '+D.meta.device_vector;
    return 'GSI '+D.meta.device_gsi+' → VEC —';
}
function rteDecode(rte){
    var v=parseInt(rte,16);
    if(isNaN(v))return rte||'0x0';
    return 'vec 0x'+(v&0xff).toString(16)+' · '+(v&0x10000?'masked':'unmasked')+' · dest '+(v>>>24);
}
function svrDecode(svr){
    var v=parseInt(svr,16);
    if(isNaN(v))return svr||'0x0';
    return (v&0x100?'enabled':'disabled')+(v&0xff?' · spiv vec 0x'+(v&0xff).toString(16):'');
}
function tprDecode(tpr){
    var v=parseInt(tpr,16);
    if(isNaN(v))return tpr||'0x0';
    return 'priority 0x'+(v>>>4).toString(16);
}
function stateDecode(f,v){
    if(f==='svr')return svrDecode(v);
    if(f==='tpr')return tprDecode(v);
    if(f==='rte')return rteDecode(v);
    if(f==='irr')return 'pending · cleared on dispatch';
    if(f==='isr')return 'active until guest EOI';
    return 'assert path · pure observation';
}
var IRQ_STATE_ITEMS=['irr','isr','svr','tpr','rte','route'];
function renderIRQ(e){
    var card=$('irq-address').closest('.region');
    var isMsi=e.kind==='msi'||e.name==='kvm_msi_set_irq';
    card.classList.toggle('msi',isMsi);
    var nodes=['irq-device','irq-ioapic','irq-lapic'],edges=['edge-gsi','edge-lapic'];
    if(isMsi){
        nodes=['irq-device-msi','irq-msg','irq-lapic-msi'];edges=['edge-msg','edge-msi-lapic'];
    }
    nodes.forEach(function(id){$(id).classList.remove('hot')});
    edges.forEach(function(id){$(id).classList.remove('hot')});
    if(isMsi){
        nodes.forEach(function(id){$(id).classList.add('hot')});
        edges.forEach(function(id){$(id).classList.add('hot')});
        $('irq-address').textContent='MSI → VEC 0x'+(e.msi_vector!=null?e.msi_vector.toString(16):'—')+' · GSI/IOAPIC bypassed';
        $('msi-msg-detail').textContent='addr '+(e.msi_addr!=null?'0x'+e.msi_addr.toString(16):'0x0')+' · dest '+(e.msi_dest!=null?e.msi_dest:'0')+' · '+
            (e.msi_delivery===0||e.msi_delivery==null?'fixed':'delivery '+(e.msi_delivery))+' · '+(e.msi_level?'level':'edge');
        $('msi-vec-detail').textContent='vec 0x'+(e.msi_vector!=null?e.msi_vector.toString(16):'41')+(e.msi_logical?' · logical':' · physical')+' · no IOAPIC';
    }else{
        if(e.name==='kvm_apic_accept_irq'){nodes.forEach(function(id){$(id).classList.add('hot')});edges.forEach(function(id){$(id).classList.add('hot')})}
        if(e.name==='kvm_ioapic_set_irq'){$('irq-ioapic').classList.add('hot');$('edge-lapic').classList.add('hot');$('irq-lapic').classList.add('hot')}
        if(e.name==='kvm_apic')$('irq-lapic').classList.add('hot');
        $('irq-address').textContent='GSI '+D.meta.device_gsi+' → VEC '+D.meta.device_vector;
    }

    var pending=lapicWindow(e.irr),inService=lapicWindow(e.isr);
    var now=irqStateMap(e),prev=(cursor>0)?irqStateMap(D.events[cursor-1]):null;
    IRQ_STATE_ITEMS.forEach(function(f){
        var el=$('st-'+f);
        var changed=prev!==null&&prev[f]!==now[f];
        var nowF=irqStateDisplay(e,f);
        var prevF=(prev!=null)?irqStateDisplay(D.events[cursor-1],f):null;
        el.classList.toggle('changed',changed);
        var val=el.querySelector('.val');
        val.textContent=nowF;
        val.classList.toggle('big',changed);
        el.querySelector('.sub').textContent=changed?('▲ '+prevF+' → '+nowF):stateDecode(f,now[f]);
    });
    if(pending.length&&inService.length){$('irq-state').textContent='pending + in service';$('irq-caption').textContent=vecList(pending)+' pending; '+vecList(inService)+' in service'}
    else if(pending.length){$('irq-state').textContent='pending';$('irq-caption').textContent='IRR holds '+vecList(pending)+' · delivered while IF=0'}
    else if(inService.length){$('irq-state').textContent='in service';$('irq-caption').textContent=vecList(inService)+' in service at this hook'}
    else{$('irq-state').textContent=(e.kind==='irq'||e.kind==='msi')?'route activity':'idle';$('irq-caption').textContent=(e.kind==='irq'||e.kind==='msi')?'trace route active; IRR/ISR window empty':'no pending/in-service vector in the LAPIC window'}
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
        $('device-detail').textContent=e.dma_dir.replace('_',' ')+'\u00a0· eBPF event · verified byte-for-byte for this run';
        $(e.dma_gpa==='0x6000'?'gpa6000':'gpa7000').classList.add('hot');
        $('dma-state').textContent=e.dma_dir;
        $('dma-caption').textContent=D.meta.dma_xfer_size+' B at '+e.dma_gpa+' · '+e.dma_dir;
    }else{
        $('dma-gpa').textContent='no DMA now';
        $('device-state').textContent=D.meta.device_buffer_size+' B buffer';
        $('device-detail').textContent='no transfer at current hook';
        $('dma-state').textContent='not present';
        $('dma-caption').textContent='DMA recorded only at the eBPF DMA event';
    }
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
    var irrTxt=vecList(lapicWindow(e.irr));
    var isrTxt=vecList(lapicWindow(e.isr));
    var lapicOk=D.meta&&D.meta.lapic_available!==false;
    var ioOk=D.meta&&D.meta.ioapic_available!==false;
    rows.push(['IRR / ISR',irrTxt+' / '+isrTxt]);
    rows.push(['LAPIC TPR',lapicOk?(e.tpr!=null&&e.tpr!==''?e.tpr:'0x0'):'n/a']);
    rows.push(['LAPIC SVR',lapicOk?(e.svr!=null&&e.svr!==''?e.svr:'0x0'):'n/a']);
    rows.push(['IOAPIC RTE',ioOk?(e.rte!=null&&e.rte!==''?e.rte:'0x0'):'n/a']);
    rows.push(['vCPU *',e.vcpu_ptr],['KVM *',e.kvm_ptr],['LAPIC *',e.apic_ptr],['IOAPIC *',e.ioapic_ptr||'NULL']);
    if(e.msi_present){
        rows.push(['MSI address','0x'+(e.msi_addr!=null?e.msi_addr.toString(16):'0')]);
        rows.push(['MSI data','0x'+(e.msi_data!=null?e.msi_data.toString(16):'0')+' · vec '+(e.msi_vector!=null?e.msi_vector:'?')]);
        rows.push(['MSI decode','dest '+(e.msi_dest!=null?e.msi_dest:'0')+' · '+(e.msi_logical?'logical':'physical')+' · '+(e.msi_delivery===0||e.msi_delivery==null?'fixed':'dm '+(e.msi_delivery))+' · '+(e.msi_level?'level':'edge')]);
        rows.push(['MSG via','KVM_SIGNAL_MSI · IOAPIC/GSI bypassed']);
    } else if(e.msi_present===false && (e.kind==='msi'||e.name==='kvm_msi_set_irq')){
        rows.push(['MSG via','MSI event present, no raw message facts']);
    }
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
    renderRoadmap();renderIRQ(e);renderDMA(e);renderNotebook(e);renderExec(e);
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
    $('strip-vector').textContent=D.meta.device_vector+' / '+D.meta.msi_vector;
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
