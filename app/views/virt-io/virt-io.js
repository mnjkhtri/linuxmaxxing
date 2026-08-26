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
        var ei=r.event_info||{},st=r.state||{},ct=st.controller||{},d=st.dma||{},ms=st.msi||{},
            io=st.ioctl||{},di=st.disposition||{},mm=st.mmio||{},cmd=st.command||{};
        out.push({
            bpf_seq:Number(r.seq),time_ns:Number(r.time_ns),name:ei.event_name,event:ei.event,
            vmexit_id:Number(ei.vmexit_id||0),operation_id:Number(ei.operation_id||0),call_id:Number(ei.call_id||0),
            ctx:r.context||{},vcpu:st.vcpu,kvm:st.kvm,apic:st.apic,ioapic:st.ioapic,
            rte:ct.rte,tpr:ct.tpr,svr:ct.svr,irr:ct.irr,isr:ct.isr,
            msi_present:ms.present,msi_addr:ms.address,msi_data:ms.data,
            msi_vector:ms.vector,msi_dest:ms.destination,msi_logical:ms.logical,
            msi_level:ms.level_triggered,msi_delivery:ms.delivery_mode,
            dpresent:d.present,dcompleted:d.completed,dgpa:d.gpa,dhva:d.guest_hva,
            ddir:d.dir,dlen:d.len,dresult:d.result,dchecksum:d.checksum,dduration:d.duration_ns,
            ioctl_present:io.present,ioctl_completed:io.completed,ioctl_fd:io.fd,
            ioctl_request:io.request,ioctl_name:io.request_name,ioctl_arg:io.argument,
            ioctl_result:io.result,ioctl_duration:io.duration_ns,
            disposition_present:di.present,disposition_result:di.result,disposition_meaning:di.meaning,
            mmio_present:mm.present,mmio_offset:mm.offset,mmio_register:mm.register,mmio_value:mm.value,
            command_present:cmd.present,command_completed:cmd.completed,command:cmd.command,
            command_name:cmd.command_name,command_status:cmd.status,command_dma_gpa:cmd.dma_gpa,
            command_result:cmd.result,command_duration:cmd.duration_ns
        });
    });
    return out.sort(function(a,b){return a.bpf_seq-b.bpf_seq});
}

/* Parse tracefs independently; the render model correlates matching observations by monotonic time. */
function parseTrace(text){
    var out=[],ln=0;
    text.split(/\r?\n/).forEach(function(raw){
        ln++;
        var m=raw.match(/^\s*(.+?)-(\d+)\s+\[(\d+)\]\s+(\S+)\s+([0-9]+\.[0-9]+):\s+([a-zA-Z0-9_]+):\s+(.+)$/);
        if(!m)return;
        var e={line:ln,comm:m[1],pid:+m[2],tid:+m[2],cpu:+m[3],flags:m[4],
            time:+m[5],time_ns:Math.round(Number(m[5])*1e9),type:m[6],body:m[7],raw:raw.trim()};
        var x;
        if(e.type==='kvm_exit'){
            x=e.body.match(/vcpu\s+(\d+)\s+reason\s+([^\s]+)\s+rip\s+(0x[0-9a-f]+)/i);
            if(x){e.vcpu=x[1];e.reason=x[2];e.rip=x[3]}
            x=e.body.match(/info1\s+(0x[0-9a-f]+)/i);if(x)e.info1=x[1];
            x=e.body.match(/info2\s+(0x[0-9a-f]+)/i);if(x)e.info2=x[1];
            x=e.body.match(/intr_info\s+(0x[0-9a-f]+)/i);if(x)e.intr_info=x[1];
            x=e.body.match(/error_code\s+(0x[0-9a-f]+)/i);if(x)e.error_code=x[1];
        }else if(e.type==='kvm_entry'){
            x=e.body.match(/vcpu\s+(\d+),\s+rip\s+(0x[0-9a-f]+)/i);
            if(x){e.vcpu=x[1];e.rip=x[2]}
        }else if(e.type==='kvm_userspace_exit'){
            x=e.body.match(/reason\s+(.+?)\s*$/i);
            if(x)e.userspace_reason=x[1].replace(/ \(.*\)$/,'').trim();
        }else if(e.type==='kvm_page_fault'){
            x=e.body.match(/vcpu\s+(\d+)\s+rip\s+(0x[0-9a-f]+)\s+address\s+(0x[0-9a-f]+)\s+error_code\s+(0x[0-9a-f]+)/i);
            if(x){e.vcpu=x[1];e.rip=x[2];e.fault_gpa=x[3];e.fault_error=x[4]}
        }else if(e.type==='kvm_mmio'){
            x=e.body.match(/mmio\s+([^\s]+)\s+len\s+(\d+)\s+gpa\s+(0x[0-9a-f]+)\s+val\s+(0x[0-9a-f]+)/i);
            if(x){e.mmio_type=x[1];e.mmio_len=+x[2];e.mmio_gpa=x[3];e.mmio_val=x[4]}
        }else if(e.type==='kvm_fast_mmio'){
            x=e.body.match(/gpa\s+(0x[0-9a-f]+)/i);if(x)e.mmio_gpa=x[1];
        }else if(e.type==='kvm_pio'){
            x=e.body.match(/pio_(read|write)\s+at\s+(0x[0-9a-f]+)\s+size\s+(\d+)\s+count\s+(\d+)\s+val\s+(0x[0-9a-f]+)/i);
            if(x){e.pio_dir=x[1];e.pio_port=x[2];e.pio_size=+x[3];e.pio_count=+x[4];e.pio_val=x[5]}
        }else if(e.type==='kvm_set_irq'){
            x=e.body.match(/gsi\s+(\d+)\s+level\s+(-?\d+)\s+source\s+(-?\d+)/i);
            if(x){e.gsi=+x[1];e.level=+x[2];e.irq_source=+x[3]}
        }else if(e.type==='kvm_ack_irq'){
            x=e.body.match(/irqchip\s+(.+?)\s+pin\s+(\d+)/i);
            if(x){e.irqchip=x[1];e.pin=+x[2]}
        }else if(e.type==='kvm_ioapic_set_irq'){
            x=e.body.match(/pin\s+(\d+)\s+dst\s+([0-9a-f]+)\s+vec\s+(\d+)\s+\(([^)]+)\)/i);
            if(x){e.pin=+x[1];e.dst=x[2];e.vec=+x[3];e.mode=x[4].split('|')}
        }else if(e.type==='kvm_apic_accept_irq'){
            x=e.body.match(/apicid\s+([0-9a-f]+)\s+vec\s+(\d+)\s+\(([^)]+)\)/i);
            if(x){e.apicid=x[1];e.vec=+x[2];e.mode=x[3].split('|')}
        }else if(e.type==='kvm_msi_set_irq'){
            x=e.body.match(/dst\s+([0-9a-f]+)\s+vec\s+(\d+)/i);
            if(x){e.dst=x[1];e.vec=+x[2]}
        }else if(e.type==='kvm_apic'){
            x=e.body.match(/apic_(read|write)\s+(\S+)\s*=\s*(0x[0-9a-f]+)/i);
            if(x){e.apic_access=x[1];e.reg=x[2];e.val=x[3]}
        }else if(e.type==='kvm_inj_virq'||e.type==='kvm_eoi'){
            x=e.body.match(/(?:0x)?([0-9a-f]+)\b/i);if(x)e.vec=parseInt(x[1],16);
        }
        out.push(e);
    });
    return out;
}

/* ---- event model ------------------------------------------------------ */

var KINDS={
    kvm_entry:'entry',kvm_exit:'exit',kvm_userspace_exit:'handoff',
    kvm_apic_accept_irq:'irq',kvm_ioapic_set_irq:'irq',kvm_msi_set_irq:'msi',
    kvm_set_irq:'irq',kvm_ack_irq:'irq',kvm_inj_virq:'irq',kvm_eoi:'apic',
    kvm_apic:'apic',kvm_page_fault:'kvm_internal',kvm_mmio:'kvm_internal',
    kvm_fast_mmio:'kvm_internal',kvm_pio:'kvm_internal',kvm_emulate_insn:'kvm_internal',
    kvm_cr:'kvm_internal',device_dma_transfer:'dma',device_dma_transfer_return:'dma_return',
    sys_enter_ioctl:'ioctl_enter',sys_exit_ioctl:'ioctl_return',
    vmx_handle_exit_return:'disposition',device_mmio_write:'device_dispatch',
    device_execute_command:'command',device_execute_command_return:'command_return'
};

function applyTrace(e,t){
    if(!t)return e;
    e.trace_line=t.line;e.trace_time_ns=t.time_ns;e.raw=t.raw;e.flags=t.flags;
    e.cpu=t.cpu;e.pid=t.pid;e.tid=t.tid;e.comm=t.comm;e.source=e.source==='ebpf'?'trace + eBPF':'tracefs';
    ['rip','reason','info1','info2','intr_info','error_code','userspace_reason','fault_gpa','fault_error',
     'mmio_type','mmio_len','mmio_gpa','mmio_val','pio_dir','pio_port','pio_size','pio_count','pio_val',
     'gsi','level','irq_source','irqchip','pin','dst','vec','mode','apicid','apic_access','reg','val'].forEach(function(k){
        if(t[k]!=null)e[k]=t[k];
    });
    if(t.type==='kvm_apic')e.apic_text=t.body,e.apic_reg=t.reg,e.apic_val=t.val;
    if(t.type==='kvm_apic_accept_irq'||t.type==='kvm_ioapic_set_irq'||t.type==='kvm_msi_set_irq'||t.type==='kvm_set_irq'||t.type==='kvm_ack_irq')e.irq_text=t.body;
    if(t.type==='kvm_emulate_insn'||t.type==='kvm_cr')e.handler_text=t.body;
    return e;
}

function eventFromBpf(f){
    var e={
        bpf_seq:f.bpf_seq,name:f.name,time_ns:f.time_ns,source:'ebpf',state_sampled:!!f.vcpu,
        vmexit_id:f.vmexit_id,operation_id:f.operation_id,call_id:f.call_id,
        vcpu_ptr:f.vcpu,kvm_ptr:f.kvm,apic_ptr:f.apic,ioapic_ptr:f.ioapic,
        irr:f.irr,isr:f.isr,rte:f.rte,tpr:f.tpr,svr:f.svr,
        msi_present:f.msi_present,msi_addr:f.msi_addr,msi_data:f.msi_data,
        msi_vector:f.msi_vector,msi_dest:f.msi_dest,msi_logical:f.msi_logical,
        msi_level:f.msi_level,msi_delivery:f.msi_delivery,
        dma_present:f.dpresent,dma_completed:f.dcompleted,dma_gpa:f.dgpa,dma_hva:f.dhva,
        dma_dir:f.ddir,dma_len:f.dlen,dma_result:f.dresult,dma_checksum:f.dchecksum,dma_duration_ns:f.dduration,
        ioctl_present:f.ioctl_present,ioctl_completed:f.ioctl_completed,ioctl_fd:f.ioctl_fd,
        ioctl_request:f.ioctl_request,ioctl_name:f.ioctl_name,ioctl_arg:f.ioctl_arg,
        ioctl_result:f.ioctl_result,ioctl_duration_ns:f.ioctl_duration,
        disposition_present:f.disposition_present,disposition_result:f.disposition_result,
        disposition_meaning:f.disposition_meaning,mmio_present:f.mmio_present,
        mmio_offset:f.mmio_offset,mmio_register:f.mmio_register,mmio_value:f.mmio_value,
        command_present:f.command_present,command_completed:f.command_completed,command:f.command,
        command_name:f.command_name,command_status:f.command_status,command_dma_gpa:f.command_dma_gpa,
        command_result:f.command_result,command_duration_ns:f.command_duration,
        reason:'',info1:'',userspace_reason:'',rip:'',apic_text:'',irq_text:'',
        cpu:f.ctx.cpu,pid:f.ctx.pid,tid:f.ctx.tid,comm:f.ctx.comm,flags:''
    };
    e.raw='eBPF '+e.name;
    return e;
}

function eventFromTrace(t){
    var e={name:t.type,time_ns:t.time_ns,source:'tracefs',state_sampled:false,
        vmexit_id:0,operation_id:0,call_id:0,vcpu_ptr:null,kvm_ptr:null,apic_ptr:null,ioapic_ptr:null,
        msi_present:false,dma_present:false,reason:'',info1:'',userspace_reason:'',rip:'',
        apic_text:'',irq_text:'',cpu:t.cpu,pid:t.pid,tid:t.tid,comm:t.comm,flags:t.flags,raw:t.raw};
    return applyTrace(e,t);
}

/* Preserve both files independently, correlate duplicate observations, then order the render model by monotonic time. */
function buildEvents(snaps,trs){
    var byType={},used={},events=[];
    trs.forEach(function(t){(byType[t.type]=byType[t.type]||[]).push(t)});
    snaps.forEach(function(f){
        var e=eventFromBpf(f),list=byType[f.name],slot=used[f.name]||0,t=list&&list[slot];
        if(t){used[f.name]=slot+1;applyTrace(e,t)}
        events.push(e);
    });
    trs.forEach(function(t){
        var consumed=used[t.type]||0;
        if(consumed>0){used[t.type]=consumed-1;return}
        events.push(eventFromTrace(t));
    });
    events.sort(function(a,b){return a.time_ns-b.time_ns||(a.source==='tracefs'?-1:1)});
    events.forEach(function(e,index){
        e.seq=index+1;
        e.kind=KINDS[e.name]||'kvm_internal';
        if(e.kind==='entry'){e.from='kvm';e.to='guest';e.label='VM entry'}
        else if(e.kind==='exit'){e.from='guest';e.to='kvm';e.label=e.reason||'VM exit'}
        else if(e.kind==='handoff'){e.from='kvm';e.to='vmm';e.label=(e.userspace_reason||'userspace exit').replace('KVM_EXIT_','')}
        else if(e.kind==='dma'){e.from=e.dma_dir==='to_device'?'memory':'device';e.to=e.dma_dir==='to_device'?'device':'memory';e.label=e.dma_dir==='to_device'?'DMA → device':'DMA ← device'}
        else{e.from='';e.to='';e.label=e.name}
    });
    return events;
}
function metaGsi(){return D&&D.meta?D.meta.device_gsi:''}
function metaVec(){return D&&D.meta?D.meta.device_vector:''}
function metaMsiVec(){return D&&D.meta?D.meta.msi_vector:''}

/* Derive the shared timeline, cross-references, and hand-off pairing. */
function finalize(events){
    var base=events.length?events[0].time_ns:0,held={},activeVmexit=0;
    var heldFields=['vcpu_ptr','kvm_ptr','apic_ptr','ioapic_ptr','irr','isr','rte','tpr','svr'];
    events.forEach(function(e){e.time_us=(e.time_ns-base)/1000});
    events.forEach(function(e,index){
        if(e.name==='kvm_exit'&&e.vmexit_id)activeVmexit=e.vmexit_id;
        else if(!e.vmexit_id&&activeVmexit)e.vmexit_id=activeVmexit;
        heldFields.forEach(function(field){
            if(e.state_sampled&&e[field]!=null)held[field]=e[field];
            else if(e[field]==null&&held[field]!=null)e[field]=held[field];
        });
        e.prev_seq=index>0?events[index-1].seq:null;
        e.next_seq=index<events.length-1?events[index+1].seq:null;
        e.dt_prev_us=index>0?+(e.time_us-events[index-1].time_us).toFixed(3):null;
        e.dt_next_us=index<events.length-1?+(events[index+1].time_us-e.time_us).toFixed(3):null;
        e.paired_handoff='';
        if(e.kind==='exit'){
            for(var j=index+1;j<events.length&&events[j].kind!=='entry'&&events[j].kind!=='exit';j++){
                if(events[j].kind==='handoff'){e.paired_handoff=events[j].userspace_reason||'KVM_EXIT_?';break}
            }
        }
        if(e.kind==='entry')activeVmexit=0;
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
    var mis=evs.filter(function(e){return e.name==='kvm_exit'&&e.reason==='EPT_MISCONFIG'}).length;
    if(mis>=6)return 'MMIO-heavy region';
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
    A:'APIC ready',
    B:'legacy IRQ',
    C:'IRQ pending',
    D:'direct MSI',
    E:'virtual DMA'
};
/* Narrative annotation for each guest phase: how it begins, how it hands off,
   and which guest.S section drives it.  Applied to whichever indices we derive. */
var SEMANTIC_PHASE={
    A:{ingress:'the VMM configures KVM, creates vCPU 0, and enters it through KVM_RUN',egress:'phase A ends inside guest residency: STI enables APIC interrupts, then the phase-B COMMAND MMIO write produces the next observed exit',source:'guest.S phase A'},
    B:{ingress:'phase B begins inside the guest run after the phase-A marker; the first phase-B-specific observed exit is the COMMAND MMIO exit',egress:'phase B ends inside guest residency: WAIT_IRQ_COUNT 1 completes before CLI and the phase-C command write',source:'guest.S phase B'},
    C:{ingress:'phase C begins inside the guest run preceding the phase-C command MMIO exit; CLI has set IF=0',egress:'phase C ends inside guest residency after the marker: the next observed exit is the phase-D (MSI) command write',source:'guest.S phase C'},
    D:{ingress:'phase D begins after its PIO marker; the guest writes CMD_MSI_ONLY with interrupt delivery enabled',egress:'phase D ends inside guest residency after the MSI handler runs, then DMA programming begins',source:'guest.S phase D'},
    E:{ingress:'phase E begins inside the guest run preceding the first DMA-programming MMIO exit',egress:'run terminates through OUT 0x82 → KVM_EXIT_IO',source:'guest.S phase E'}
};
function annotateEpisode(ep){
    var letter=ep.name.charAt(6);
    var s=SEMANTIC_PHASE[letter];
    if(s){ep.ingress=s.ingress;ep.egress=s.egress;ep.source=s.source}
    return ep;
}
function deriveEpisodes(events){
    var accepts=[],dmas=[],markers=[];
    events.forEach(function(e,i){
        if(e.name==='kvm_apic_accept_irq')accepts.push(i);
        if(e.name==='device_dma_transfer')dmas.push(i);
        if(e.kind==='exit'&&e.reason==='IO_INSTRUCTION'){
            var info=parseInt(e.info1,16)||0;
            if(((info>>16)&0xffff)===0xe9)markers.push(i);
        }
    });

    var eps=[];
    if(accepts.length>=4){
        var seenCount={};
        for(var w=0;w+1<accepts.length;w++){
            var local={};
            for(var j=accepts[w]+1;j<accepts[w+1];j++){
                var e=events[j];
                if(e.kind==='exit'&&/^0x[0-9a-f]{2,}$/i.test(e.rip||''))local[parseInt(e.rip,16)]=1;
            }
            for(var r in local)seenCount[r]=(seenCount[r]||0)+1;
        }
        var recurring=[];
        for(var v in seenCount)if(seenCount[v]>=2)recurring.push(Number(v));
        function inISR(rip){return recurring.some(function(q){return Math.abs(q-rip)<=0x40})}
        function mmioExit(e){return e.kind==='exit'&&(e.reason==='EPT_MISCONFIG'||e.reason==='EPT_VIOLATION')}

        var openB=0;
        for(var k=markers.length?markers[0]+1:0;k<events.length;k++){
            if(events[k].name==='kvm_entry'){openB=k;break}
        }
        function openAfter(lo,hi){
            for(var i=lo+1;i<hi;i++){
                var e=events[i];
                if(e.kind!=='exit')continue;
                if(mmioExit(e)&&!inISR(parseInt(e.rip||'0',16)))return i;
            }
            return -1;
        }
        var opens=[0,openB];
        for(var i=1;i<=3;i++){
            if(i>=accepts.length)break;
            opens.push(openAfter(accepts[i-1],accepts[i]));
        }
        opens.push(events.length);
        if(opens.length===6&&opens.every(function(o){return o>=0})){
            var letters=['A','B','C','D','E'];
            for(var s=0;s<letters.length;s++){
                var lo=opens[s],hi=opens[s+1];
                if(hi<=lo)continue;
                var idx=[];
                for(var t=lo;t<hi;t++)idx.push(t);
                eps.push({
                    start:events[lo].seq,end:events[hi-1].seq,count:idx.length,indices:idx,
                    name:'Phase '+letters[s]+' \u00b7 '+PHASE_LABEL[letters[s]],
                    desc:regionDesc(events.slice(lo,hi),events[lo].seq,events[hi-1].seq)
                });
            }
            if(eps.length)return eps.map(annotateEpisode);
        }
    }

    var starts=[0];
    var firstM=findIdx(events,function(e){return e.kind==='exit'&&e.reason==='EPT_MISCONFIG'});
    if(firstM>=0)starts.push(firstM);
    if(accepts.length)starts.push(accepts[0]);
    for(var b=0;b<accepts.length-1;b++){
        if(events[accepts[b+1]].time_us-events[accepts[b]].time_us<40){starts.push(accepts[b]);break}
    }
    dmas.forEach(function(i){starts.push(i)});
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

/* ---- presentation helpers ------------------------------------------- */

function prettyEvent(e){
    if(e.name==='kvm_entry')return'VM entry';
    if(e.name==='kvm_exit')return e.reason||'VM exit';
    if(e.name==='kvm_userspace_exit')return(e.userspace_reason||'userspace exit').replace('KVM_EXIT_','');
    if(e.name==='vmx_handle_exit_return')return e.disposition_meaning||'exit disposition';
    if(e.name==='sys_enter_ioctl')return e.ioctl_name||'ioctl';
    if(e.name==='sys_exit_ioctl')return(e.ioctl_name||'ioctl')+' return';
    if(e.name==='device_mmio_write')return(e.mmio_register||'MMIO')+' write';
    if(e.name==='device_execute_command')return e.command_name||'execute command';
    if(e.name==='device_execute_command_return')return(e.command_name||'command')+' complete';
    if(e.name==='device_dma_transfer')return e.dma_dir==='to_device'?'DMA → device':'DMA ← device';
    if(e.name==='device_dma_transfer_return')return'DMA complete';
    if(e.name==='kvm_page_fault')return'EPT fault '+(e.fault_gpa||'');
    if(e.name==='kvm_mmio')return'KVM MMIO '+(e.mmio_type||'');
    if(e.name==='kvm_pio')return'KVM PIO '+(e.pio_dir||'');
    if(e.name==='kvm_emulate_insn')return'emulate instruction';
    if(e.name==='kvm_set_irq')return'set GSI '+(e.gsi!=null?e.gsi:'?')+'='+e.level;
    if(e.name==='kvm_ack_irq')return'ack IRQ pin '+(e.pin!=null?e.pin:'?');
    if(e.name==='kvm_apic_accept_irq')return'APIC accepts vec '+(e.vec!=null?e.vec:'?');
    if(e.name==='kvm_ioapic_set_irq')return'IOAPIC set_irq';
    if(e.name==='kvm_msi_set_irq')return'MSI set_irq';
    if(e.name==='kvm_apic')return'APIC '+(e.apic_reg||'register');
    return e.name;
}
function detailType(e){
    if(e.kind==='entry')return'domain transition · KVM → guest';
    if(e.kind==='exit')return'domain transition · guest → KVM';
    if(e.kind==='handoff')return'domain transition · KVM → userspace';
    if(e.kind==='disposition')return'KVM exit disposition';
    if(e.kind==='ioctl_enter'||e.kind==='ioctl_return')return'KVM userspace ABI';
    if(e.kind==='device_dispatch')return'VMM device dispatch';
    if(e.kind==='command'||e.kind==='command_return')return'device command';
    if(e.kind==='dma'||e.kind==='dma_return')return'device state · DMA';
    if(e.kind==='irq')return'interrupt route';
    if(e.kind==='msi')return'interrupt route · MSI';
    if(e.kind==='apic')return'guest APIC programming';
    return'KVM internal handling';
}
/* ---- renderers -------------------------------------------------------- */

function renderRoadmap(){
    var active=episodeFor(cursor);
    $('roadmap').innerHTML=D.episodes.map(function(ep,ei){
        return '<div class="zone '+(ei===active?'active':'')+'" data-ep="'+ei+'"><div class="zone-label">'+esc(ep.name.toUpperCase())+'</div></div>';
    }).join('');
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
    if(e.name==='kvm_apic_accept_irq')return'accept vec '+(e.vec!=null?vecHex(e.vec):'?');
    if(e.name==='kvm_ioapic_set_irq')return'route pin '+(e.pin!=null?e.pin:'?');
    if(e.name==='kvm_msi_set_irq')return'MSI vec '+(e.msi_vector!=null?vecHex(e.msi_vector):'?');
    if(e.name==='kvm_set_irq')return'GSI '+(e.gsi!=null?e.gsi:'?')+' = '+e.level;
    if(e.name==='kvm_ack_irq')return'ack pin '+(e.pin!=null?e.pin:'?');
    if(e.name==='kvm_apic')return(e.apic_reg||'APIC')+' '+(e.apic_access||'write');
    if(e.name==='kvm_page_fault')return'EPT fault · '+(e.fault_gpa||'?');
    if(e.name==='kvm_mmio')return'MMIO '+(e.mmio_type||'')+' · '+(e.mmio_gpa||'?')+' = '+(e.mmio_val||'?');
    if(e.name==='kvm_fast_mmio')return'fast MMIO · '+(e.mmio_gpa||'?');
    if(e.name==='kvm_pio')return'PIO '+(e.pio_dir||'')+' · '+(e.pio_port||'?')+' = '+(e.pio_val||'?');
    if(e.name==='kvm_emulate_insn')return'emulate · '+String(e.handler_text||e.raw).replace(/^.*kvm_emulate_insn:\s*/,'').slice(0,30);
    if(e.name==='kvm_cr')return String(e.handler_text||'CR access').slice(0,34);
    if(e.name==='device_dma_transfer')return(e.dma_dir==='to_device'?'DMA → device':'DMA ← device')+' · '+(e.dma_gpa||'');
    if(e.name==='device_dma_transfer_return')return'DMA ret '+e.dma_result+' · sum '+e.dma_checksum;
    if(e.name==='device_execute_command')return e.command_name||'execute command';
    if(e.name==='device_execute_command_return')return(e.command_name||'command')+' · status '+e.command_status;
    if(e.name==='device_mmio_write')return(e.mmio_register||'MMIO')+' = '+e.mmio_value;
    if(e.name==='vmx_handle_exit_return')return e.disposition_meaning||'exit disposition';
    if(e.name==='sys_enter_ioctl')return e.ioctl_name||'ioctl';
    if(e.name==='sys_exit_ioctl')return(e.ioctl_name||'ioctl')+' ret '+e.ioctl_result;
    return prettyEvent(e);
}
/* Label for the deepest IO_INSTRUCTION reason an exit row can carry. */
function seqIoLabel(e){
    var q=ioQualification(e);
    if(!q)return e.reason||'IO_INSTRUCTION';
    var meaning=ioMeaning(e);
    return q.dir+' 0x'+q.port.toString(16)+(meaning?' · '+meaning:'');
}
/* Component lifelines use the same actor/message model as the native I/O view. */
var COMPONENT_ACTORS=[
    {id:'vmm',role:'USERSPACE',name:'VMM'},
    {id:'kvm',role:'HOST KERNEL',name:'KVM'},
    {id:'guest',role:'GUEST',name:'vCPU 0'},
    {id:'lapic',role:'KVM IRQCHIP',name:'LAPIC'},
    {id:'ioapic',role:'KVM IRQCHIP',name:'IOAPIC'},
    {id:'device',role:'USERSPACE',name:'TOY DEVICE'},
    {id:'memory',role:'GUEST MEMORY',name:'RAM'}
];
function actorDetail(actor){
    if(actor.id==='vmm')return D.events[0].comm+'-'+D.events[0].pid;
    if(actor.id==='kvm')return'KVM_RUN + irqchip';
    if(actor.id==='guest')return'guest execution';
    if(actor.id==='lapic')return'vec '+vecHex(metaVec())+' / '+vecHex(metaMsiVec());
    if(actor.id==='ioapic')return'GSI '+metaGsi();
    if(actor.id==='device')return D.meta.device_buffer_size+' B buffer';
    var gpas=[];
    D.events.forEach(function(event){if(event.dma_present&&gpas.indexOf(event.dma_gpa)<0)gpas.push(event.dma_gpa)});
    return gpas.length?gpas.join(' / '):'DMA GPAs';
}
function actorIndex(id){
    for(var i=0;i<COMPONENT_ACTORS.length;i++)if(COMPONENT_ACTORS[i].id===id)return i;
    return 0;
}
function interruptTransport(index){
    for(var i=index-1;i>=0;i--){
        if(D.events[i].name==='kvm_msi_set_irq')return'msi';
        if(D.events[i].name==='kvm_ioapic_set_irq')return'ioapic';
        if(D.events[i].name==='kvm_apic_accept_irq')break;
    }
    return'ioapic';
}
function componentMessage(from,to,label,kind){
    return{from:from,to:to,label:label,kind:kind||'control'};
}
function componentFlow(event,index){
    var flow=[],vector=event.vec!=null?vecHex(event.vec):vecHex(metaVec()),request=event.ioctl_name||'ioctl';
    if(event.kind==='entry'){
        flow.push(componentMessage('kvm','guest','kvm_entry'+(event.rip?' · '+event.rip:''),'entry'));
    }else if(event.kind==='exit'){
        flow.push(componentMessage('guest','kvm',event.reason==='IO_INSTRUCTION'?seqIoLabel(event):(event.reason||'VM exit'),'exit'));
    }else if(event.kind==='handoff'){
        flow.push(componentMessage('kvm','vmm',(event.userspace_reason||'KVM_EXIT').replace('KVM_EXIT_',''),'handoff'));
    }else if(event.kind==='disposition'){
        flow.push(componentMessage('kvm','kvm',event.disposition_meaning+(event.disposition_result!=null?' · ret '+event.disposition_result:''),'local'));
    }else if(event.kind==='ioctl_enter'){
        var requester=(request==='KVM_IRQ_LINE'||request==='KVM_SIGNAL_MSI')?'device':'vmm';
        flow.push(componentMessage(requester,'kvm',request+' · fd '+event.ioctl_fd,'run'));
    }else if(event.kind==='ioctl_return'){
        var owner=(request==='KVM_IRQ_LINE'||request==='KVM_SIGNAL_MSI')?'device':'vmm';
        flow.push(componentMessage(owner,owner,request+' ret '+event.ioctl_result,'local'));
    }else if(event.name==='device_mmio_write'){
        flow.push(componentMessage('vmm','device',(event.mmio_register||'MMIO')+' = '+event.mmio_value,'handoff'));
    }else if(event.name==='device_execute_command'){
        flow.push(componentMessage('device','device','execute '+(event.command_name||'command'),'local'));
    }else if(event.name==='device_execute_command_return'){
        flow.push(componentMessage('device','device','complete · status '+event.command_status,'local'));
    }else if(event.name==='kvm_set_irq'){
        flow.push(componentMessage('kvm','ioapic','GSI '+(event.gsi!=null?event.gsi:metaGsi())+' = '+event.level,'interrupt'));
    }else if(event.name==='kvm_ioapic_set_irq'){
        flow.push(componentMessage('kvm','ioapic','route pin '+(event.pin!=null?event.pin:metaGsi()),'interrupt'));
    }else if(event.name==='kvm_msi_set_irq'){
        flow.push(componentMessage('kvm','lapic','MSI · vec '+vecHex(event.msi_vector!=null?event.msi_vector:metaMsiVec()),'interrupt'));
    }else if(event.name==='kvm_apic_accept_irq'){
        flow.push(componentMessage(interruptTransport(index)==='msi'?'kvm':'ioapic','lapic','accept '+vector,'interrupt'));
    }else if(event.name==='kvm_inj_virq'){
        flow.push(componentMessage('lapic','guest','inject '+vector,'interrupt'));
    }else if(event.name==='kvm_eoi'){
        flow.push(componentMessage('guest','lapic','EOI '+vector,'apic'));
    }else if(event.name==='kvm_apic'){
        flow.push(componentMessage('guest','lapic',(event.apic_reg||'APIC')+' '+(event.apic_access||'write'),'apic'));
    }else if(event.name==='kvm_ack_irq'){
        flow.push(componentMessage('ioapic','ioapic','ack pin '+(event.pin!=null?event.pin:'?'),'local'));
    }else if(event.name==='device_dma_transfer'){
        var access=event.dma_dir==='to_device'?'DMA read':'DMA write';
        flow.push(componentMessage('device','memory',access+' · '+event.dma_gpa+' · '+event.dma_len+' B','dma'));
    }else if(event.name==='device_dma_transfer_return'){
        flow.push(componentMessage('device','device','DMA ret '+event.dma_result+' · sum '+event.dma_checksum,'local'));
    }else{
        flow.push(componentMessage('kvm','kvm',compactObs(event),'local'));
    }
    return flow;
}
function renderExec(e){
    var ep=D.episodes[episodeFor(cursor)],host=$('exec-html'),interactions=[];
    ep.indices.forEach(function(global){
        componentFlow(D.events[global],global).forEach(function(flow){interactions.push({global:global,event:D.events[global],flow:flow})});
    });
    var currentFlows=componentFlow(e,cursor),active={};
    currentFlows.forEach(function(flow){active[flow.from]=true;active[flow.to]=true});
    $('rip-head').textContent=e.rip?('RIP '+e.rip):'RIP —';

    var head='<div class="component-head">'+COMPONENT_ACTORS.map(function(actor){
        return'<article class="component-actor '+(active[actor.id]?'active':'')+'"><small>'+esc(actor.role)+'</small><b>'+esc(actor.name)+'</b><em>'+esc(actorDetail(actor))+'</em></article>';
    }).join('')+'</div>';
    var laneLines='<div class="component-lifelines">'+COMPONENT_ACTORS.map(function(actor,index){
        return'<i class="'+(active[actor.id]?'active':'')+'" style="left:'+((index+.5)/COMPONENT_ACTORS.length*100)+'%"></i>';
    }).join('')+'</div>';
    var rows=interactions.map(function(item){
        var flow=item.flow,fromIndex=actorIndex(flow.from),toIndex=actorIndex(flow.to),selected=item.global===cursor?' current':'',kind=' '+flow.kind;
        var from=(fromIndex+.5)/COMPONENT_ACTORS.length*100,to=(toIndex+.5)/COMPONENT_ACTORS.length*100;
        var time='<span class="component-time">+'+Number(item.event.time_us).toFixed(3)+'µs</span>';
        if(fromIndex===toIndex){
            return'<button type="button" class="component-row local'+selected+'" data-index="'+item.global+'">'+time+'<i class="component-local '+flow.kind+'" style="left:'+from+'%"></i><code style="left:'+from+'%" title="'+esc(item.event.raw)+'">'+esc(flow.label)+'</code></button>';
        }
        var left=Math.min(from,to),width=Math.abs(to-from),direction=to>from?'forward':'reverse';
        return'<button type="button" class="component-row'+selected+'" data-index="'+item.global+'">'+time+'<i class="component-arrow '+direction+kind+'" style="left:'+left+'%;width:'+width+'%"></i><i class="component-point" style="left:'+from+'%"></i><i class="component-point" style="left:'+to+'%"></i><code style="left:'+((from+to)/2)+'%" title="'+esc(item.event.raw)+'">'+esc(flow.label)+'</code></button>';
    }).join('');
    var tail=ep.egress?'<div class="component-tail"><b>phase boundary:</b> '+esc(ep.egress)+'</div>':'';
    var previous=host.querySelector('.component-track'),previousTop=previous?previous.scrollTop:null;
    host.innerHTML=head+'<div class="component-track"><div class="component-body" style="--rows:'+Math.max(interactions.length,1)+'">'+laneLines+rows+'</div></div>'+tail;
    host.querySelectorAll('.component-row').forEach(function(row){row.addEventListener('click',function(){select(+row.dataset.index)})});
    var track=host.querySelector('.component-track');
    if(track&&previousTop!=null)track.scrollTop=previousTop;
    var selected=host.querySelector('.component-row.current');
    if(selected)selected.scrollIntoView({block:'nearest'});

    $('flow-kind').textContent=e.source==='trace + eBPF'?'trace + eBPF':e.source;
    if(e.kind==='entry'){
        $('flow-caption').textContent='kvm_entry transfers execution to the guest at '+(e.rip||'unknown RIP');
    }else if(e.kind==='exit'){
        $('flow-caption').textContent=(e.reason||'VM exit')+' transfers control from guest to KVM'+(e.rip?' at '+e.rip:'');
    }else if(e.kind==='handoff'){
        $('flow-caption').textContent=(e.userspace_reason||'KVM exit')+' returns KVM_RUN to the VMM';
    }else if(e.kind==='disposition'){
        $('flow-caption').textContent='vmx_handle_exit returned '+e.disposition_result+' · '+e.disposition_meaning;
    }else if(e.kind==='ioctl_enter'||e.kind==='ioctl_return'){
        $('flow-caption').textContent=(e.ioctl_name||'ioctl')+' · fd '+e.ioctl_fd+(e.ioctl_completed?' · ret '+e.ioctl_result+' · '+e.ioctl_duration_ns+' ns':'');
    }else if(e.name==='device_dma_transfer'||e.name==='device_dma_transfer_return'){
        $('flow-caption').textContent=e.dma_dir+' · GPA '+e.dma_gpa+' · '+e.dma_len+' B'+(e.dma_completed?' · ret '+e.dma_result+' · checksum '+e.dma_checksum:'');
    }else{
        $('flow-caption').textContent=compactObs(e);
    }
}
function vectorNumber(v){
    if(typeof v==='number')return v;
    var s=String(v==null?'':v).toLowerCase();
    return s.indexOf('0x')===0?parseInt(s,16):parseInt(s,10);
}
function commandNameFromEvent(e){
    if(e.command_name)return e.command_name;
    if(e.name!=='device_mmio_write'||e.mmio_register!=='REG_COMMAND')return'';
    var command=vectorNumber(e.mmio_value);
    return{1:'CMD_IRQ_ONLY',2:'CMD_DMA_TO_DEVICE',3:'CMD_DMA_FROM_DEVICE',4:'CMD_MSI_ONLY'}[command]||'';
}
function hasLapicVector(e,field,vector){return lapicWindow(e[field]).indexOf(vector)>=0}
function interruptCycle(index){
    var start=-1,anchor=null;
    for(var i=index;i>=0;i--){
        var candidate=D.events[i];
        if(candidate.name==='device_execute_command'||(candidate.name==='device_mmio_write'&&candidate.mmio_register==='REG_COMMAND')){
            start=i;anchor=candidate;break;
        }
    }
    if(start<0)return{start:-1,transport:'',vector:null,operationId:0,stages:{}};
    var command=commandNameFromEvent(anchor),transport=command==='CMD_MSI_ONLY'?'msi':'legacy';
    var vector=vectorNumber(transport==='msi'?metaMsiVec():metaVec());
    var cycle={start:start,transport:transport,vector:vector,operationId:anchor.operation_id||0,command:command,
        level:null,msiEvent:null,stages:{request:null,route:null,accept:null,pending:null,service:null,ack:null,cleared:null}};
    var sawService=false;
    for(i=start;i<=index;i++){
        var event=D.events[i],request=event.ioctl_name;
        if(event.kind==='ioctl_enter'&&((transport==='msi'&&request==='KVM_SIGNAL_MSI')||(transport==='legacy'&&request==='KVM_IRQ_LINE'))&&!cycle.stages.request)cycle.stages.request={index:i,event:event};
        if(transport==='legacy'&&event.name==='kvm_set_irq'){
            cycle.level=event.level;
            if(event.level===1&&!cycle.stages.route)cycle.stages.route={index:i,event:event};
        }
        if(transport==='legacy'&&event.name==='kvm_ioapic_set_irq'&&!cycle.stages.route)cycle.stages.route={index:i,event:event};
        if(transport==='msi'&&event.name==='kvm_msi_set_irq'){
            cycle.msiEvent=event;
            if(!cycle.stages.route)cycle.stages.route={index:i,event:event};
        }
        if(event.name==='kvm_apic_accept_irq'&&vectorNumber(event.vec)===vector&&!cycle.stages.accept)cycle.stages.accept={index:i,event:event};
        if(hasLapicVector(event,'irr',vector)&&!cycle.stages.pending)cycle.stages.pending={index:i,event:event};
        if(hasLapicVector(event,'isr',vector)){
            sawService=true;
            if(!cycle.stages.service)cycle.stages.service={index:i,event:event};
        }
        if(event.name==='device_mmio_write'&&event.mmio_register==='REG_IRQ_ACK'&&!cycle.stages.ack)cycle.stages.ack={index:i,event:event};
        if(sawService&&!hasLapicVector(event,'isr',vector)&&!cycle.stages.cleared&&cycle.stages.service.index<i)cycle.stages.cleared={index:i,event:event};
    }
    return cycle;
}
function irqRouteLabel(e,cycle){
    if((cycle&&cycle.transport==='msi')||e.kind==='msi'||e.name==='kvm_msi_set_irq'){
        var msi=cycle&&cycle.msiEvent?cycle.msiEvent:e;
        return 'MSI → VEC '+vecHex(msi.msi_vector!=null?msi.msi_vector:metaMsiVec());
    }
    if(e.rte!=null&&e.rte!=='')return 'GSI '+D.meta.device_gsi+' → VEC '+vecHex(metaVec());
    return 'GSI '+D.meta.device_gsi+' → VEC —';
}
function irqStateMap(e,cycle){
    var pending=lapicWindow(e.irr).sort(function(a,b){return a-b});
    var inService=lapicWindow(e.isr).sort(function(a,b){return a-b});
    return {
        irr:pending.join(' '),isr:inService.join(' '),
        svr:e.svr!=null&&e.svr!==''?e.svr:'0x0',tpr:e.tpr!=null&&e.tpr!==''?e.tpr:'0x0',
        rte:e.rte!=null&&e.rte!==''?e.rte:'0x0',route:irqRouteLabel(e,cycle)
    };
}
function irqStateDisplay(e,f,cycle){
    if(f==='irr'||f==='isr')return vecList(lapicWindow(e[f]));
    return irqStateMap(e,cycle)[f];
}
function vecHex(v){
    if(v==null)return'—';
    if(typeof v==='number')return'0x'+v.toString(16);
    var s=String(v).toLowerCase();
    if(/^0x[0-9a-f]+$/.test(s))return s;
    if(/^\d+$/.test(s))return'0x'+parseInt(s,10).toString(16);
    if(/^[0-9a-f]+$/.test(s))return'0x'+parseInt(s,16).toString(16);
    return'—';
}
function hexValue(v){
    if(v==null)return'0x0';
    if(typeof v==='number')return'0x'+v.toString(16);
    var s=String(v).toLowerCase();
    return s.indexOf('0x')===0?s:'0x'+s;
}
function rteDecode(rte){
    try{
        var v=BigInt(rte||0),delivery=['fixed','lowest','SMI','reserved','NMI','INIT','reserved','ExtINT'][Number((v>>8n)&7n)];
        return 'vec '+vecHex(Number(v&255n))+' · '+delivery+' · '+(v&2048n?'logical':'physical')+' · '+(v&32768n?'level':'edge')+'/'+(v&8192n?'low':'high')+' · '+(v&65536n?'masked':'unmasked')+' · dest '+Number((v>>56n)&255n);
    }catch(ignore){return rte||'0x0'}
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
    if(f==='irr')return 'vector presently pending';
    if(f==='isr')return 'vector presently in service';
    return String(v).indexOf('MSI')===0?'message route · IOAPIC bypassed':'IOAPIC redirection route';
}
function lifecycleActive(stage,e,cycle){
    var request=e.ioctl_name;
    if(stage==='request')return e.kind==='ioctl_enter'&&((cycle.transport==='msi'&&request==='KVM_SIGNAL_MSI')||(cycle.transport==='legacy'&&request==='KVM_IRQ_LINE'));
    if(stage==='route')return cycle.transport==='msi'?e.name==='kvm_msi_set_irq':(e.name==='kvm_set_irq'||e.name==='kvm_ioapic_set_irq');
    if(stage==='accept')return e.name==='kvm_apic_accept_irq'&&vectorNumber(e.vec)===cycle.vector;
    if(stage==='pending')return hasLapicVector(e,'irr',cycle.vector);
    if(stage==='service')return hasLapicVector(e,'isr',cycle.vector);
    if(stage==='ack')return e.name==='device_mmio_write'&&e.mmio_register==='REG_IRQ_ACK';
    return stage==='cleared'&&cycle.stages.cleared&&cycle.stages.cleared.index===cursor;
}
function renderInterruptLifecycle(e,cycle){
    var stages=['request','route','accept','pending','service','ack','cleared'];
    if(cycle.start<0){
        $('irq-life-mode').textContent='no delivery';$('irq-life-summary').textContent='waiting for an interrupt request';
        stages.forEach(function(stage){var node=$('irq-step-'+stage);node.className=stage==='cleared'?'derived':'';node.querySelector('small').textContent='—';node.removeAttribute('title')});
        return;
    }
    var msi=cycle.msiEvent,request=cycle.transport==='msi'?'KVM_SIGNAL_MSI':'KVM_IRQ_LINE';
    $('irq-life-mode').textContent=cycle.transport==='msi'?'MSI direct':'legacy line';
    if(cycle.transport==='msi'){
        $('irq-life-summary').textContent=(msi?'addr '+hexValue(msi.msi_addr)+' · data '+hexValue(msi.msi_data):'awaiting KVM_SIGNAL_MSI')+' · vec '+vecHex(cycle.vector)+(cycle.operationId?' · operation '+cycle.operationId:'');
    }else{
        $('irq-life-summary').textContent='GSI '+metaGsi()+(cycle.level==null?'':' = '+cycle.level)+' · vec '+vecHex(cycle.vector)+(cycle.operationId?' · operation '+cycle.operationId:'');
    }
    var requestEvent=cycle.stages.request&&cycle.stages.request.event;
    var facts={
        request:request+(requestEvent?' · fd '+requestEvent.ioctl_fd:''),
        route:cycle.transport==='msi'?(msi?'kvm_msi_set_irq · '+hexValue(msi.msi_data):'—'):'kvm_set_irq · GSI '+metaGsi()+(cycle.level==null?'':' = '+cycle.level),
        accept:'kvm_apic_accept_irq · '+vecHex(cycle.vector),
        pending:'LAPIC IRR · '+vecHex(cycle.vector),
        service:'LAPIC ISR · '+vecHex(cycle.vector),
        ack:'REG_IRQ_ACK · 0x1',
        cleared:'ISR '+vecHex(cycle.vector)+' → — · sampled'
    };
    stages.forEach(function(stage){
        var node=$('irq-step-'+stage),evidence=cycle.stages[stage],classes=[];
        if(evidence)classes.push('seen');
        if(lifecycleActive(stage,e,cycle))classes.push('active');
        if(stage==='cleared')classes.push('derived');
        node.className=classes.join(' ');node.querySelector('small').textContent=evidence?facts[stage]:'—';
        if(evidence)node.title=evidence.event.name+' · seq '+evidence.event.seq;else node.removeAttribute('title');
    });
}
var IRQ_STATE_ITEMS=['irr','isr','svr','tpr','rte','route'];
function renderIRQ(e){
    var cycle=interruptCycle(cursor),isMsi=cycle.transport==='msi'||e.kind==='msi'||e.name==='kvm_msi_set_irq';
    var pending=lapicWindow(e.irr),inService=lapicWindow(e.isr),msi=cycle.msiEvent||e;
    if(isMsi)$('irq-address').textContent='MSI → VEC '+vecHex(msi.msi_vector!=null?msi.msi_vector:metaMsiVec())+' · IOAPIC bypassed';
    else $('irq-address').textContent='GSI '+D.meta.device_gsi+' → VEC '+vecHex(metaVec());

    var previousCycle=cursor>0?interruptCycle(cursor-1):null;
    var now=irqStateMap(e,cycle),prev=(cursor>0)?irqStateMap(D.events[cursor-1],previousCycle):null;
    IRQ_STATE_ITEMS.forEach(function(f){
        var el=$('st-'+f),changed=prev!==null&&prev[f]!==now[f];
        var nowF=irqStateDisplay(e,f,cycle),prevF=prev!=null?irqStateDisplay(D.events[cursor-1],f,previousCycle):null;
        el.classList.toggle('changed',changed);
        var val=el.querySelector('.val'),sub=el.querySelector('.sub');
        val.textContent=nowF;val.classList.toggle('big',changed);
        sub.textContent=changed?('▲ '+prevF+' → '+nowF):stateDecode(f,now[f]);sub.title=sub.textContent;
    });
    renderInterruptLifecycle(e,cycle);
    if(pending.length&&inService.length){$('irq-state').textContent='pending + in service';$('irq-caption').textContent=vecList(pending)+' pending; '+vecList(inService)+' in service'}
    else if(pending.length){$('irq-state').textContent='pending';$('irq-caption').textContent='IRR holds '+vecList(pending)+' at this observation'}
    else if(inService.length){$('irq-state').textContent='in service';$('irq-caption').textContent=vecList(inService)+' in service at this observation'}
    else{$('irq-state').textContent=(e.kind==='irq'||e.kind==='msi')?'route activity':'idle';$('irq-caption').textContent=(e.kind==='irq'||e.kind==='msi')?'trace route active; IRR/ISR window empty':'no pending/in-service vector in the LAPIC window'}
}
function renderDMA(e){
    var to=$('dma-edge-to'),from=$('dma-edge-from');
    to.className=from.className='rt-edge';
    $('rt-src').classList.remove('hot');$('rt-dst').classList.remove('hot');
    if(e.dma_present){
        (e.dma_dir==='to_device'?to:from).classList.add('hot');
        $(e.dma_dir==='to_device'?'rt-src':'rt-dst').classList.add('hot');
        $('device-state').textContent=e.dma_dir==='to_device'?'receiving '+D.meta.dma_xfer_size+' B':'sending '+D.meta.dma_xfer_size+' B';
        $('device-detail').textContent=e.dma_dir==='to_device'?'storing the guest bytes for the return copy':'returning the stored bytes (echo)';
        $('dma-state').textContent=e.dma_dir.replace('_',' ');
        $('dma-caption').textContent=D.meta.dma_xfer_size+' B at '+e.dma_gpa+' · '+e.dma_dir;
    }else if(D.dmaFrom!=null&&cursor>=D.dmaFrom){
        from.className='rt-edge dim';
        $('rt-dst').classList.add('hot');
        $('device-state').textContent='round trip returned';
        $('device-detail').textContent='guest compares returned bytes to the source';
        $('dma-state').textContent='round-trip · verifying';
        $('dma-caption').textContent='one-shot round-trip verification runs after DMA_FROM';
    }else if(D.dmaTo!=null&&cursor>=D.dmaTo){
        to.className='rt-edge dim';
        $('rt-src').classList.add('hot');
        $('device-state').textContent='outbound copy complete';
        $('device-detail').textContent='awaiting the return copy · no DMA running';
        $('dma-state').textContent='staged · awaiting return';
        $('dma-caption').textContent='no DMA in progress between the two transfer hooks';
    }else{
        $('device-state').textContent=D.meta.device_buffer_size+' B buffer';
        $('device-detail').textContent='no transfer in this phase';
        $('dma-state').textContent='not present';
        $('dma-caption').textContent='two device_dma_transfer calls are observed at entry and return';
    }
}
function renderNotebook(e){
    $('source-badge').textContent=e.source;
    $('detail-type').textContent=detailType(e);
    $('detail-title').textContent=e.name;
    var source=e.source;
    if(e.trace_line)source+=' · Trace.txt L'+e.trace_line;
    if(e.bpf_seq)source+=' · eBPF seq '+e.bpf_seq;
    var rows=[
        ['sequence',e.seq],
        ['time',e.time_us.toFixed(3)+' µs from capture start'],
        ['source',source],
        ['CPU / task',e.cpu+' / '+e.comm+'-'+e.pid+(e.tid?' (tid '+e.tid+')':'')],
        ['flags',e.flags||'—']
    ];
    if(e.vmexit_id)rows.push(['VM-exit id',e.vmexit_id]);
    if(e.operation_id)rows.push(['device operation',e.operation_id]);
    if(e.call_id)rows.push(['ioctl call',e.call_id]);
    if(e.rip)rows.push(['guest RIP',e.rip]);
    if(e.reason)rows.push(['VM-exit reason',e.reason]);
    if(e.userspace_reason)rows.push(['userspace reason',e.userspace_reason]);
    if(e.info1)rows.push(['exit info1',e.info1]);
    if(e.info2)rows.push(['exit info2',e.info2]);
    if(e.intr_info)rows.push(['interrupt info',e.intr_info]);
    if(e.error_code)rows.push(['error code',e.error_code]);
    if(e.fault_gpa)rows.push(['fault GPA',e.fault_gpa],['fault access',e.fault_error]);
    if(e.mmio_gpa)rows.push(['KVM MMIO',(e.mmio_type||'')+' · '+e.mmio_gpa+' · '+e.mmio_len+' B · '+e.mmio_val]);
    if(e.pio_port)rows.push(['KVM PIO',(e.pio_dir||'')+' · '+e.pio_port+' · '+e.pio_size+' B · '+e.pio_val]);
    if(e.handler_text)rows.push(['KVM handler',e.handler_text]);
    if(e.disposition_present)rows.push(['disposition',e.disposition_meaning+' · ret '+e.disposition_result]);
    if(e.ioctl_present){
        rows.push(['request',e.ioctl_name+' · fd '+e.ioctl_fd]);
        if(e.ioctl_completed)rows.push(['ioctl result',e.ioctl_result+' · '+e.ioctl_duration_ns+' ns']);
    }
    if(e.mmio_present)rows.push(['device register',e.mmio_register+' +0x'+Number(e.mmio_offset).toString(16)+' · '+e.mmio_value]);
    if(e.command_present){
        rows.push(['command',e.command_name+' · GPA '+e.command_dma_gpa]);
        rows.push(['device state',e.command_status+' · result '+e.command_result+(e.command_completed?' · '+e.command_duration_ns+' ns':'')]);
    }
    if(e.apicid!=null)rows.push(['APIC id',e.apicid]);
    if(e.vec!=null)rows.push(['vector',vecHex(e.vec)]);
    if(e.apic_text)rows.push(['APIC access',e.apic_text]);
    if(e.irq_text)rows.push(['IRQ trace',e.irq_text]);
    if(e.paired_handoff)rows.push(['userspace handoff',e.paired_handoff]);
    var irrTxt=vecList(lapicWindow(e.irr)),isrTxt=vecList(lapicWindow(e.isr));
    var lapicOk=D.meta&&D.meta.lapic_available!==false,ioOk=D.meta&&D.meta.ioapic_available!==false;
    rows.push(['IRR / ISR',irrTxt+' / '+isrTxt]);
    rows.push(['LAPIC TPR',lapicOk?(e.tpr!=null&&e.tpr!==''?e.tpr:'0x0'):'n/a']);
    rows.push(['LAPIC SVR',lapicOk?(e.svr!=null&&e.svr!==''?e.svr:'0x0'):'n/a']);
    rows.push(['IOAPIC RTE',ioOk?(e.rte!=null&&e.rte!==''?e.rte:'0x0'):'n/a']);
    rows.push(['vCPU *',e.vcpu_ptr||'NULL'],['KVM *',e.kvm_ptr||'NULL'],['LAPIC *',e.apic_ptr||'NULL'],['IOAPIC *',e.ioapic_ptr||'NULL']);
    if(e.msi_present){
        rows.push(['MSI address',hexValue(e.msi_addr)]);
        rows.push(['MSI data',hexValue(e.msi_data)+' · vec '+vecHex(e.msi_vector)]);
        rows.push(['MSI decode','dest '+(e.msi_dest!=null?e.msi_dest:'0')+' · '+(e.msi_logical?'logical':'physical')+' · '+(e.msi_delivery===0||e.msi_delivery==null?'fixed':'dm '+e.msi_delivery)+' · '+(e.msi_level?'level':'edge')]);
    }
    if(e.dma_present){
        rows.push(['DMA',e.dma_dir+' · '+e.dma_gpa+' · '+e.dma_len+' B']);
        rows.push(['guest HVA',e.dma_hva||'NULL']);
        if(e.dma_completed)rows.push(['DMA result',e.dma_result+' · checksum '+e.dma_checksum+' · '+e.dma_duration_ns+' ns']);
    }
    if(e.dt_prev_us!=null)rows.push(['Δ previous',e.dt_prev_us+' µs']);
    if(e.dt_next_us!=null)rows.push(['Δ next',e.dt_next_us+' µs']);
    $('fields').innerHTML=rows.map(function(r){return '<dt>'+esc(r[0])+'</dt><dd title="'+esc(r[1])+'">'+esc(r[1])+'</dd>'}).join('');
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
    $('next').addEventListener('click',function(){select(cursor+1)});
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
    D.dmaTo=null;D.dmaFrom=null;
    D.events.forEach(function(x,i){
        if(x.name!=='device_dma_transfer')return;
        if(x.dma_dir==='to_device'&&D.dmaTo==null)D.dmaTo=i;
        if(x.dma_dir==='from_device'&&D.dmaFrom==null)D.dmaFrom=i;
    });
    $('strip-host').textContent=D.events[0]?D.events[0].cpu:'—';
    $('strip-gsi').textContent=D.meta.device_gsi;
    $('strip-vector').textContent=vecHex(D.meta.device_vector)+' / '+vecHex(D.meta.msi_vector);
    $('strip-dma').textContent=D.meta.dma_xfer_size+' B';
    $('strip-buf').textContent=D.meta.device_buffer_size+' B';
    $('dma-src-sub').textContent=(D.dmaTo!=null?'guest source · seq '+(D.dmaTo+1):'guest source');
    $('dma-dst-sub').textContent=(D.dmaFrom!=null?'guest receive · seq '+(D.dmaFrom+1)+' · echo':'guest receive');
    $('dma-xfer').textContent=D.meta.dma_xfer_size+' B / transfer';
    $('scrub').max=D.events.length-1;
    $('task').textContent=(D.events[0]?D.events[0].comm:'vmm')+'-'+(D.events[0]?D.events[0].pid:'?');
    $('status').lastElementChild.textContent=D.events.length+' observations aligned';
    wireToolbar();
    select(0);
}).catch(function(err){
    $('status').lastElementChild.textContent='virt-io data error · '+err.message;
});
})();
