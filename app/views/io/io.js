/* The UI reads the three experiment artifacts independently and correlates them only in browser memory. */
(function(){
'use strict';

var DATA={phases:'../../shared/_captures/io-Phases.ndjson',trace:'../../shared/_captures/io-Trace.txt',report:'../../shared/_captures/io-Report.txt'};
var records=[],tracepoints=[],markers=[],header=null,footer=null,parseStats={malformed:0,skippedTrace:0};
var operations=[],journeys={},navigation=[],selectedJourney=null,selectedStep=0,selectedNav=0,selectedEvent=null,selectedSequenceSeq=null;
var workloadPid=0,deviceResource=null,fileResource=null,dmaResource=null,barResource=null,localResource=null,irqResource=null,controllerResource=null;

function $(id){return document.getElementById(id)}
function esc(value){return String(value==null?'—':value).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function number(value,fallback){var parsed=Number(value);return Number.isFinite(parsed)?parsed:(fallback==null?0:fallback)}
function integer(value,fallback){var parsed=String(value).toLowerCase().indexOf('0x')===0?parseInt(value,16):parseInt(value,10);return Number.isFinite(parsed)?parsed:(fallback==null?0:fallback)}
function hex(value,width){var parsed=integer(value,0);return'0x'+parsed.toString(16).padStart(width||1,'0')}
function ns(record){return number(record&&record.time_ns)}
function bytes(value){value=number(value);if(value>=1048576)return(value/1048576).toFixed(1)+' MiB';if(value>=1024)return(value/1024).toFixed(value%1024?1:0)+' KiB';return value+' B'}
function duration(value){if(value<1000)return value+' ns';if(value<1000000)return(value/1000).toFixed(value<10000?2:1)+' µs';if(value<1000000000)return(value/1000000).toFixed(value<10000000?2:1)+' ms';return(value/1000000000).toFixed(2)+' s'}
function traceName(record){return(record.tracepoint||'').split(':')[1]||record.tracepoint||'event'}
function field(record,key,fallback){var value=record&&record.fields&&record.fields[key];return value==null?(fallback==null?'—':fallback):value}
function raw(record){return field(record,'raw_payload','')}
function isQedu(record){return(record.tracepoint||'').indexOf('qedu:')===0}
function resource(type){return(header&&header.resources||[]).find(function(item){return item.resource_type===type})||{fields:{}}}
function marker(name,edge){return markers.find(function(record){return record.marker===name&&record.edge===edge})}
function contextClass(record){return(record.context&&record.context.execution)||'process'}

function parseReport(text){
    var report={metadata:{},sysfs:{},debugfs:{},trace_stats:{}},section='';
    text.split(/\r?\n/).forEach(function(line){
        var heading=line.match(/^\[([a-z_]+)\]$/);if(heading){section=heading[1];return}
        if(!section||!line.trim())return;
        var delimiter=section==='debugfs'?line.indexOf(':'):line.indexOf('=');if(delimiter<0)return;
        report[section][line.slice(0,delimiter).trim()]=line.slice(delimiter+1).trim()
    });
    return report
}
function parsePhases(text){
    var output=[];parseStats.malformed=0;
    text.split(/\r?\n/).forEach(function(line){
        if(!line.trim())return;
        try{var source=JSON.parse(line),info=source.event_info||{},context=source.context||{};if(source.kind!=='phase')return;output.push({record:'workload_marker',source:'io-Phases.ndjson',source_seq:source.seq,time_ns:String(source.time_ns),marker:info.phase,edge:info.action,facts:Object.keys(info).reduce(function(result,key){if(!/^(phase|action|category)$/.test(key))result[key]=info[key];return result},{}),context:{pid:context.pid,comm:'qedu_workload',execution:'process'}})}catch(error){parseStats.malformed++}
    });
    return output
}
function traceTokens(body){
    var fields={},match,pattern=/([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|\S+)/g;
    while((match=pattern.exec(body))){var value=match[2];if(value[0]==='"')value=value.slice(1,-1);fields[match[1]]=value}
    return fields
}
function splitTrace(rendered){
    var syscall=rendered.match(/^sys_(openat|read|write|close)(\(|\s+->\s*)(.*)$/);
    if(syscall)return{system:'syscalls',event:'sys_'+(syscall[2].trim().indexOf('->')===0?'exit':'enter')+'_'+syscall[1],body:rendered.slice(('sys_'+syscall[1]).length).trim()};
    var normal=rendered.match(/^([^:]+):\s?(.*)$/);if(!normal)return null;
    var event=normal[1].trim(),systems={dma_alloc:'dma',irq_handler_entry:'irq',irq_handler_exit:'irq',workqueue_queue_work:'workqueue',workqueue_activate_work:'workqueue',workqueue_execute_start:'workqueue',workqueue_execute_end:'workqueue',sched_switch:'sched',sched_waking:'sched',sched_wakeup:'sched',vector_alloc:'irq_vectors',vector_config:'irq_vectors'};
    return{system:event.indexOf('qedu_')===0?'qedu':systems[event],event:event,body:normal[2]}
}
function syscallFields(event,body){
    var fields={raw_payload:body},pair,pattern=/([A-Za-z_][A-Za-z0-9_]*):\s*([^,)]+)/g;
    while((pair=pattern.exec(body)))fields[pair[1]]=pair[2].trim();
    if(event==='sys_enter_openat'){var path=body.match(/filename:\s+\d+\s+"([^"]+)"/),flags=body.match(/flags:\s+([A-Z0-9_|]+)/);if(path)fields.path=path[1];if(flags)fields.flags=flags[1]}
    if(event.indexOf('sys_exit_')===0){var result=body.match(/->\s+(-?(?:0x[0-9a-fA-F]+|[0-9]+))/);if(result)fields.return_value=integer(result[1],-1);if(event==='sys_exit_openat')fields.return_fd=fields.return_value}
    ['fd','count'].forEach(function(key){if(fields[key]!=null)fields[key]=integer(fields[key])});
    return fields
}
function parseTraceFields(system,event,body){
    var fields=system==='syscalls'?syscallFields(event,body):traceTokens(body);fields.raw_payload=body;
    if(system==='dma'){var allocation=body.match(/^(\S+)\s+dir=(\S+)\s+dma_addr=([0-9a-fA-F]+)\s+size=(\d+)\s+virt_addr=(\S+)\s+flags=(.*?)\s+attrs=(.*)$/);if(allocation){fields.device=allocation[1];fields.direction=allocation[2];fields.dma_address='0x'+allocation[3];fields.size_bytes=integer(allocation[4]);fields.cpu_pointer_token=allocation[5];fields.flags=allocation[6]||'none';fields.attributes=allocation[7]||'none';delete fields.dir;delete fields.dma_addr;delete fields.size;delete fields.virt_addr;delete fields.attrs}}
    ['io_id','leg','bytes','count','offset','requested','completed','irq','timeout_ms','wait_ret','event_bit','queued','pid','cpu','ret','input','result','prev_pid','next_pid'].forEach(function(key){if(fields[key]!=null&&/^-?(?:0x[0-9a-fA-F]+|[0-9]+)$/.test(fields[key]))fields[key]=integer(fields[key])});
    if(fields.queued!=null)fields.queued=!!fields.queued;
    if(event==='qedu_dma_submit'){var command=integer(fields.command);fields.command={raw:hex(command,16),start:!!(command&1),direction_from_device:!!(command&2),interrupt_enable:!!(command&4)};fields.source_address=hex(fields.src,16);fields.destination_address=hex(fields.dst,16);fields.source_space=fields.src_space;fields.destination_space=fields.dst_space;delete fields.src;delete fields.dst;delete fields.src_space;delete fields.dst_space}
    if(event==='qedu_irq_ack'){var status=integer(fields.status),ack=integer(fields.ack);fields.status={raw:hex(status,8),factorial:!!(status&1),dma:!!(status&0x100)};fields.ack=hex(ack,8)}
    if(event==='qedu_probe_stage'){
        var address=fields.address,size=fields.size,stage=fields.stage;
        delete fields.address;delete fields.size;
        if(stage==='PROBE_BEGIN'){fields.pci_dev=address;fields.object_size_bytes=integer(size)}
        else if(stage==='DEVICE_STATE_READY'){fields.qedu_dev=address;fields.object_size_bytes=integer(size)}
        else if(stage==='PCI_ENABLED')fields.pci_dev=address;
        else if(stage==='BAR_REGIONS_CLAIMED'){fields.bar0_bus_address=address;fields.bar0_length_bytes=integer(size)}
        else if(stage==='BAR0_MAPPED'){fields.bar0_kernel_virtual_address=address;fields.mapped_length_bytes=integer(size)}
        else if(stage==='IRQ_REGISTERED'){fields.linux_irq=integer(address);fields.irq_flags=hex(size)}
        else if(stage==='DMA_MASK_CONFIGURED'){fields.coherent_dma_mask=address;fields.dma_mask_bits=integer(size)}
        else if(stage==='BUS_MASTER_ENABLED')fields.bus_master_enabled=fields.result===0;
        else if(stage==='DMA_BUFFER_READY'){fields.dma_address=address;fields.size_bytes=integer(size)}
        else if(stage==='WORKQUEUE_READY')fields.workqueue_struct=address;
        else if(stage==='CHARDEV_PUBLISHED'||stage==='SYSFS_PUBLISHED')fields.misc_minor=integer(address);
        else if(stage==='DEBUGFS_PUBLISHED'){fields.dentry=address;fields.mode=integer(size).toString(8).padStart(4,'0')}
        else if(stage==='PROBE_READY'){fields.qedu_dev=address;fields.object_size_bytes=integer(size)}
    }
    if(event==='qedu_factorial_submit'&&fields.status_command!=null)fields.status_command=hex(fields.status_command,8);
    return fields
}
function parseTrace(text){
    var output=[];parseStats.skippedTrace=0;
    text.split(/\r?\n/).forEach(function(line,index){
        var match=line.match(/^\s*(.+)-(\d+)\s+\[(\d+)\]\s+(\S+)\s+(\d+\.\d+):\s+(.*)$/);if(!match)return;
        var split=splitTrace(match[6]);if(!split||!split.system){parseStats.skippedTrace++;return}
        var fields=parseTraceFields(split.system,split.event,split.body),device=fields.device,ioId=fields.io_id,correlation={};delete fields.device;delete fields.io_id;if(device)correlation.device=device;if(ioId)correlation.io_id=ioId;if(fields.leg!=null)correlation.dma_leg=fields.leg;
        var comm=match[1].trim(),flags=match[4],execution=flags.indexOf('h')>=0||split.event==='qedu_irq_ack'||split.event.indexOf('irq_handler_')===0?'hardirq':comm.indexOf('kworker')===0||split.event.indexOf('workqueue_')===0?'workqueue':'process';
        output.push({record:'tracepoint',source:'io-Trace.txt',source_index:index,time_ns:String(Math.round(Number(match[5])*1000000000)),tracepoint:split.system+':'+split.event,context:{cpu:Number(match[3]),pid:Number(match[2]),comm:comm,execution:execution,trace_flags:flags},correlation:correlation,fields:fields})
    });
    return output
}
function buildResources(report,devicePath){
    var debug=report.debugfs,meta=report.metadata,sysfs=report.sysfs,vector=tracepoints.find(function(record){return record.tracepoint==='irq_vectors:vector_config'}),device=debug.pci_device||'unknown';
    return[
        {resource_type:'pci_function',id:device,fields:{bdf:device,vendor_device:debug.vendor_device,driver:'qedu'}},
        {resource_type:'character_device',id:devicePath,fields:{path:devicePath,name:'qedu',minor:integer(debug.misc_minor),registration:'miscdevice'}},
        {resource_type:'bar_mapping',id:device+':bar0',fields:{bar:0,bus_start:debug.bar0_start,length:debug.bar0_length,kernel_virtual_address:debug.bar0_mapping,memory_type:'MMIO'}},
        {resource_type:'dma_allocation',id:device+':dma0',fields:{cpu_virtual_address:debug.cpu_address,dma_address:debug.device_address,size_bytes:integer(debug.buffer_size),coherent:true,dma_mask_bits:32}},
        {resource_type:'device_local_buffer',id:device+':edu-buffer',fields:{address_space:'EDU_LOCAL',offset:'0x0000000000040000',size_bytes:4096}},
        {resource_type:'irq_route',id:device+':irq',fields:{linux_irq:integer(debug.irq||meta.qedu_irq),delivery:'INTx',shared_handler:true}},
        {resource_type:'interrupt_controller',id:device+':controller-route',evidence:'configured_inferred',fields:{route:'IOAPIC → Local APIC',vector:field(vector,'vector'),target_cpu:field(vector,'cpu'),apic_destination:field(vector,'apicdest'),source_record:vector&&vector.tracepoint}},
        {resource_type:'final_driver_state',id:device+':final-state',fields:{tx_bytes:integer(sysfs.tx||debug.tx_bytes_to_user),rx_bytes:integer(sysfs.rx||debug.rx_bytes_from_user),result_size:integer(debug.result_size),timeout_ms:integer(sysfs.timeout_ms||debug.timeout_ms),completion_bits:debug.completed_events}}
    ]
}
function parseSources(source){
    var report=parseReport(source.report);markers=parsePhases(source.phases);tracepoints=parseTrace(source.trace);workloadPid=integer(report.metadata.workload_pid);
    records=markers.concat(tracepoints).sort(function(a,b){return ns(a)-ns(b)});records.forEach(function(record,index){record.seq=index+1});
    var run=markers.find(function(record){return record.marker==='run'&&record.edge==='begin'}),devicePath=run&&run.facts.device||'/dev/qedu',loss={};Object.keys(report.trace_stats).forEach(function(key){if(/_(overrun|dropped)$/.test(key))loss[key]=integer(report.trace_stats[key])});
    header={resources:buildResources(report,devicePath)};footer={tracepoint_records:tracepoints.length,trace_loss:loss};
    if(!markers.length||!tracepoints.length)throw Error('one or more independent capture logs are empty');
    deviceResource=resource('pci_function');fileResource=resource('character_device');dmaResource=resource('dma_allocation');barResource=resource('bar_mapping');localResource=resource('device_local_buffer');irqResource=resource('irq_route');controllerResource=resource('interrupt_controller');
    buildOperations();buildJourneys()
}

function buildOperations(){
	var ids={};
	tracepoints.forEach(function(record){var id=record.correlation&&record.correlation.io_id;if(id)ids[id]=true});
	operations=Object.keys(ids).map(Number).sort(function(a,b){return a-b}).map(function(id){
		var own=tracepoints.filter(function(record){return record.correlation&&record.correlation.io_id===id});
		var dma=own.some(function(record){return record.tracepoint==='qedu:qedu_dma_submit'});
		var phase=dma?'dma_echo':'factorial',begin=marker(phase,'begin'),end=marker(phase,'end');
		var operation={id:id,kind:dma?'dma':'factorial',label:dma?'Two-leg DMA echo':'Factorial through MMIO',start:ns(begin)||ns(own[0]),end:ns(end)||ns(own[own.length-1]),semantic:own};
		operation.events=operationEvents(operation);
		return operation
	})
}

function operationEvents(operation){
	var windowEvents=tracepoints.filter(function(record){return ns(record)>=operation.start&&ns(record)<=operation.end});
	var deviceSyscalls=[],deviceIrqRecords=[],deviceFd=null,pendingDeviceCall=null,activeQeduIrq={};
	windowEvents.forEach(function(record){
		var name=record.tracepoint||'';
		if(name==='irq:irq_handler_entry'&&number(field(record,'irq',-1))===number(irqResource.fields.linux_irq)&&field(record,'name')==='qedu'){
			deviceIrqRecords.push(record);activeQeduIrq[record.context.cpu]=(activeQeduIrq[record.context.cpu]||0)+1;return
		}
		if(name==='irq:irq_handler_exit'&&activeQeduIrq[record.context.cpu]){
			deviceIrqRecords.push(record);activeQeduIrq[record.context.cpu]--;return
		}
		if(record.context.pid!==workloadPid||name.indexOf('syscalls:')!==0)return;
		if(name==='syscalls:sys_enter_openat'&&field(record,'path')===fileResource.fields.path){deviceSyscalls.push(record);pendingDeviceCall='openat';return}
		if(name==='syscalls:sys_exit_openat'&&pendingDeviceCall==='openat'){deviceSyscalls.push(record);deviceFd=number(field(record,'return_fd'),-1);pendingDeviceCall=null;return}
		var enter=name.match(/^syscalls:sys_enter_(read|write|close)$/);
		if(enter&&number(field(record,'fd'),-1)===deviceFd){deviceSyscalls.push(record);pendingDeviceCall=enter[1];return}
		var exit=name.match(/^syscalls:sys_exit_(read|write|close)$/);
		if(exit&&pendingDeviceCall===exit[1]){deviceSyscalls.push(record);pendingDeviceCall=null}
	});
	var selected=windowEvents.filter(function(record){
		var name=record.tracepoint||'',correlation=record.correlation||{};
		if(isQedu(record))return (traceName(record)==='qedu_file_op'&&field(record,'operation')==='OPEN')||correlation.io_id===operation.id;
		if(name.indexOf('irq:')===0)return deviceIrqRecords.indexOf(record)>=0;
		if(name.indexOf('workqueue:')===0)return raw(record).indexOf('qedu_dma_')>=0;
		if(name.indexOf('syscalls:')===0)return deviceSyscalls.indexOf(record)>=0;
		return false
	});
	var waitBegin=operation.semantic.find(function(record){return record.tracepoint==='qedu:qedu_wait'&&field(record,'phase')==='BEGIN'});
	var completion=operation.semantic.find(function(record){return record.tracepoint==='qedu:qedu_completion_publish'});
	if(waitBegin){
		var sleep=windowEvents.find(function(record){return record.tracepoint==='sched:sched_switch'&&ns(record)>ns(waitBegin)&&number(field(record,'prev_pid',-1))===workloadPid});
		if(sleep)selected.push(sleep)
	}
	if(completion){
		var waking=windowEvents.find(function(record){return record.tracepoint==='sched:sched_waking'&&ns(record)>ns(completion)&&number(field(record,'pid',-1))===workloadPid});
		var running=windowEvents.find(function(record){return record.tracepoint==='sched:sched_switch'&&ns(record)>ns(completion)&&number(field(record,'next_pid',-1))===workloadPid});
		if(waking)selected.push(waking);
		if(running)selected.push(running)
	}
	return selected.filter(function(record,index,list){return list.indexOf(record)===index}).sort(function(a,b){return ns(a)-ns(b)})
}

function event(operation,name,test,index){
	var matches=operation.events.filter(function(record){return traceName(record)===name&&(!test||test(record))});
	return matches[index||0]||null
}
function range(operation,start,end){
	var from=typeof start==='number'?start:ns(start),to=end?(typeof end==='number'?end:ns(end)):operation.end+1;
	return operation.events.filter(function(record){return ns(record)>=from&&ns(record)<to})
}
function stage(shortTitle,anchor,stageRecords){
    return{shortTitle:shortTitle,anchor:anchor,records:stageRecords.filter(Boolean).sort(function(a,b){return ns(a)-ns(b)})}
}

function buildJourneys(){
    var setup=buildSetupJourney();
    var factorial=operations.find(function(operation){return operation.kind==='factorial'});
    var dma=operations.find(function(operation){return operation.kind==='dma'});
    journeys={};
    if(setup)journeys.setup=setup;
    if(factorial)journeys.factorial=buildFactorialJourney(factorial);
    if(dma)journeys.dma=buildDmaJourney(dma);
    navigation=[];
    ['setup','factorial','dma'].forEach(function(kind){var journey=journeys[kind];if(!journey)return;journey.steps.forEach(function(item,index){navigation.push({journey:journey,step:index,item:item})})})
}

function buildSetupJourney(){
    var setupEvents=tracepoints.filter(function(record){return record.tracepoint==='qedu:qedu_probe_stage'||(record.tracepoint==='dma:dma_alloc'&&record.correlation.device===deviceResource.fields.bdf)}).sort(function(a,b){return ns(a)-ns(b)});
    if(!setupEvents.length)return null;
    var operation={id:'probe',kind:'setup',label:'Driver initialization',start:ns(setupEvents[0]),end:ns(setupEvents[setupEvents.length-1]),semantic:setupEvents,events:setupEvents};
    function probeStages(names){return setupEvents.filter(function(record){return names.indexOf(field(record,'stage'))>=0})}
    function probeStage(name){return setupEvents.find(function(record){return field(record,'stage')===name})}
    var allocation=setupEvents.find(function(record){return record.tracepoint==='dma:dma_alloc'});
    return{
        kind:'setup',
        operation:operation,
        title:'Driver initialization',
        caption:'PCI binding acquires resources, registers execution machinery, allocates coherent RAM, and publishes user-facing interfaces.',
        steps:[
            stage('probe device state',probeStage('PROBE_BEGIN'),probeStages(['PROBE_BEGIN','DEVICE_STATE_READY'])),
            stage('map PCI BAR',probeStage('PCI_ENABLED'),probeStages(['PCI_ENABLED','BAR_REGIONS_CLAIMED','BAR0_MAPPED'])),
            stage('register INTx',probeStage('IRQ_REGISTERED'),probeStages(['IRQ_REGISTERED'])),
            stage('enable DMA',probeStage('DMA_MASK_CONFIGURED'),probeStages(['DMA_MASK_CONFIGURED','BUS_MASTER_ENABLED'])),
            stage('allocate DMA RAM',allocation||probeStage('DMA_BUFFER_READY'),[allocation,probeStage('DMA_BUFFER_READY')]),
            stage('create workqueue',probeStage('WORKQUEUE_READY'),probeStages(['WORKQUEUE_READY'])),
            stage('publish interfaces',probeStage('CHARDEV_PUBLISHED'),probeStages(['CHARDEV_PUBLISHED','SYSFS_PUBLISHED'])),
            stage('publish debugfs',probeStage('DEBUGFS_PUBLISHED'),probeStages(['DEBUGFS_PUBLISHED'])),
            stage('driver ready',probeStage('PROBE_READY'),probeStages(['PROBE_READY']))
        ].filter(function(item){return item.records.length})
    }
}

function buildFactorialJourney(operation){
    var submit=event(operation,'qedu_factorial_submit');
    var waitBegin=event(operation,'qedu_wait',function(record){return field(record,'engine')==='FACTORIAL'&&field(record,'phase')==='BEGIN'});
    var waitEnd=event(operation,'qedu_wait',function(record){return field(record,'engine')==='FACTORIAL'&&field(record,'phase')==='END'});
    var irqAck=event(operation,'qedu_irq_ack',function(record){return field(record,'engine')==='FACTORIAL'});
    var result=event(operation,'qedu_factorial_result');
    var copyOut=event(operation,'qedu_cpu_buffer_io',function(record){return field(record,'operation')==='COPY_TO_USER'});
    var openEnter=event(operation,'qedu_file_op',function(record){return field(record,'operation')==='OPEN'&&field(record,'phase')==='ENTER'});
    var writeOpEnter=event(operation,'qedu_file_op',function(record){return field(record,'operation')==='WRITE'&&field(record,'phase')==='ENTER'});
    var writeOpExit=event(operation,'qedu_file_op',function(record){return field(record,'operation')==='WRITE'&&field(record,'phase')==='EXIT'});
    var readOpEnter=event(operation,'qedu_file_op',function(record){return field(record,'operation')==='READ'&&field(record,'phase')==='ENTER'});
    var releaseEnter=event(operation,'qedu_file_op',function(record){return field(record,'operation')==='RELEASE'&&field(record,'phase')==='ENTER'});
    var writeEnter=event(operation,'sys_enter_write');
    var readEnter=event(operation,'sys_enter_read');
    var closeEnter=event(operation,'sys_enter_close');
    var interruptStart=event(operation,'irq_handler_entry')||irqAck;
    return{
        kind:'factorial',
        operation:operation,
        title:'Factorial through MMIO',
        caption:'One synchronous write, one MMIO command, one INTx completion, and a direct wakeup.',
        steps:[
            stage('open file',openEnter,range(operation,operation.start,writeEnter)),
            stage('write request',writeOpEnter||writeEnter,range(operation,writeEnter,submit)),
            stage('MMIO submit',submit,[submit]),
            stage('writer blocks',waitBegin,range(operation,waitBegin,interruptStart)),
            stage('IRQ completion',irqAck,range(operation,interruptStart,waitEnd)),
            stage('writer resumes',waitEnd,range(operation,waitEnd,result)),
            stage('read result',result,[result]),
            stage('finish write',writeOpExit,range(operation,writeOpExit,readEnter)),
            stage('read userspace',readOpEnter||copyOut,range(operation,readEnter,closeEnter)),
            stage('close file',releaseEnter,range(operation,closeEnter,operation.end+1))
        ].filter(function(item){return item.anchor&&item.records.length})
    }
}
function buildDmaJourney(operation){
    var copyIn=event(operation,'qedu_cpu_buffer_io',function(record){return field(record,'operation')==='COPY_FROM_USER'});
    var submits=operation.events.filter(function(record){return traceName(record)==='qedu_dma_submit'}).sort(function(a,b){return field(a,'leg')-field(b,'leg')});
    var submit0=submits[0],submit1=submits[1];
    var irqEntries=operation.events.filter(function(record){return traceName(record)==='irq_handler_entry'});
    var irqAcks=operation.events.filter(function(record){return traceName(record)==='qedu_irq_ack'&&field(record,'engine')==='DMA'});
    var advance=event(operation,'qedu_dma_stage',function(record){return field(record,'reason')==='ADVANCE_WORK'});
    var finish=event(operation,'qedu_dma_stage',function(record){return field(record,'reason')==='FINISH_WORK'});
    var waitBegin=event(operation,'qedu_wait',function(record){return field(record,'engine')==='DMA'&&field(record,'phase')==='BEGIN'});
    var waitEnd=event(operation,'qedu_wait',function(record){return field(record,'engine')==='DMA'&&field(record,'phase')==='END'});
    var copyOut=event(operation,'qedu_cpu_buffer_io',function(record){return field(record,'operation')==='COPY_TO_USER'});
    var openEnter=event(operation,'qedu_file_op',function(record){return field(record,'operation')==='OPEN'&&field(record,'phase')==='ENTER'});
    var writeOpEnter=event(operation,'qedu_file_op',function(record){return field(record,'operation')==='WRITE'&&field(record,'phase')==='ENTER'});
    var writeOpExit=event(operation,'qedu_file_op',function(record){return field(record,'operation')==='WRITE'&&field(record,'phase')==='EXIT'});
    var readOpEnter=event(operation,'qedu_file_op',function(record){return field(record,'operation')==='READ'&&field(record,'phase')==='ENTER'});
    var releaseEnter=event(operation,'qedu_file_op',function(record){return field(record,'operation')==='RELEASE'&&field(record,'phase')==='ENTER'});
    var writeEnter=event(operation,'sys_enter_write');
    var readEnter=event(operation,'sys_enter_read');
    var closeEnter=event(operation,'sys_enter_close');
    var entry0=irqEntries[0]||irqAcks[0],entry1=irqEntries[1]||irqAcks[1];
    return{
        kind:'dma',
        operation:operation,
        title:'Two-leg DMA echo',
        caption:'One write triggers two device transfers joined by two IRQ-to-workqueue handoffs.',
        steps:[
            stage('open file',openEnter,range(operation,operation.start,writeEnter)),
            stage('write request',writeOpEnter||copyIn,range(operation,writeEnter,submit0)),
            stage('outbound DMA',submit0,[submit0]),
            stage('writer blocks',waitBegin,range(operation,waitBegin,entry0)),
            stage('first IRQ',irqAcks[0],range(operation,entry0,advance)),
            stage('queue advance',advance,range(operation,advance,submit1)),
            stage('return DMA',submit1,[submit1]),
            stage('second IRQ',irqAcks[1],range(operation,entry1,finish)),
            stage('queue finish',finish,range(operation,finish,waitEnd)),
            stage('writer resumes',waitEnd,range(operation,waitEnd,writeOpExit)),
            stage('finish write',writeOpExit,range(operation,writeOpExit,readEnter)),
            stage('read userspace',readOpEnter||copyOut,range(operation,readEnter,closeEnter)),
            stage('close file',releaseEnter,range(operation,closeEnter,operation.end+1))
        ].filter(function(item){return item.anchor&&item.records.length})
    }
}
function eventTitle(record){
	var name=traceName(record),fields=record.fields||{};
	if(name==='qedu_probe_stage')return field(record,'api',fields.stage);
	if(name==='dma_alloc')return name+' · size='+fields.size_bytes+' · DMA='+fields.dma_address;
	if(name==='qedu_file_op')return fields.operation.toLowerCase()+' '+fields.phase.toLowerCase()+(fields.phase==='EXIT'?' · result='+fields.result:'');
	if(name==='qedu_cpu_buffer_io')return fields.operation+' · '+fields.completed+'/'+fields.requested+' B';
	if(name==='qedu_dma_stage')return fields.reason+' · '+fields.old+' → '+fields.new;
	if(name==='qedu_dma_submit')return fields.direction+' · leg '+fields.leg+' · '+fields.bytes+' B';
	if(name==='qedu_irq_ack')return'IRQ '+fields.irq+' · STATUS '+fields.status.raw+' · ACK '+fields.ack;
	if(name==='qedu_dma_work_queue')return fields.work_kind+' · queued='+fields.queued;
	if(name==='qedu_completion_publish')return'completed_events bit '+fields.event_bit+' · '+fields.bits_before+' → '+fields.bits_after;
	if(name==='qedu_wait')return fields.engine+' wait '+fields.phase+' · ret='+fields.wait_ret;
	if(name==='qedu_factorial_submit')return'input='+fields.input+' · status_command='+fields.status_command;
	if(name==='qedu_factorial_result')return'result='+fields.result;
	if(name==='irq_handler_entry')return record.tracepoint+' · irq='+field(record,'irq')+' · '+field(record,'name');
	if(name==='irq_handler_exit')return record.tracepoint+' · ret='+fields.ret;
	if(name==='workqueue_queue_work')return name+' · '+workFunction(record);
	if(name==='workqueue_activate_work')return name+' · '+workFunction(record);
	if(name==='workqueue_execute_start')return name+' · '+workFunction(record);
	if(name==='workqueue_execute_end')return name+' · '+workFunction(record);
	if(name==='sched_switch')return name+' · '+field(record,'prev_comm')+' → '+field(record,'next_comm');
	if(name==='sched_waking')return name+' · pid='+field(record,'pid')+' · CPU '+field(record,'target_cpu');
	if(/^sys_(enter|entry)_/.test(name))return name.replace(/^sys_(enter|entry)_/,'')+' enter';
	if(/^sys_exit_/.test(name))return name.replace(/^sys_exit_/,'')+' return='+field(record,'return_value');
	return name
}
function workFunction(record){var match=raw(record).match(/function[= ]([A-Za-z0-9_]+)/);return match?match[1]:'work item'}
function evidence(record){
	var name=traceName(record),operation=field(record,'operation');
	if(name==='qedu_probe_stage'){
		if(field(record,'stage')==='DMA_MASK_CONFIGURED')return field(record,'dma_mask_bits')+'-bit coherent DMA mask · result='+field(record,'result');
		return field(record,'resource')+' · result='+field(record,'result')
	}
	if(name==='dma_alloc')return field(record,'size_bytes')+' B coherent · DMA '+field(record,'dma_address')+' · CPU token '+field(record,'cpu_pointer_token');
	if(name==='qedu_file_op')return field(record,'operation')+' '+field(record,'phase')+' · count '+field(record,'count')+' · offset '+field(record,'offset')+(field(record,'phase')==='EXIT'?' · result '+field(record,'result'):'')+(field(record,'engine')!=='NONE'?' · '+field(record,'engine'):'');
	if(name==='qedu_cpu_buffer_io'&&operation==='COPY_FROM_USER')return'CPU copy · '+field(record,'completed')+' B · userspace → coherent RAM';
	if(name==='qedu_cpu_buffer_io'&&operation==='CLEAR_FOR_DMA_RETURN')return'Worker cleared coherent RAM.';
	if(name==='qedu_cpu_buffer_io'&&operation==='COPY_TO_USER')return'CPU copy · '+field(record,'completed')+' B · coherent RAM → userspace';
	if(name==='qedu_dma_stage')return'Driver state · '+field(record,'old')+' → '+field(record,'new');
	if(name==='qedu_dma_submit')return'Programmed SRC · DST · COUNT · CMD '+field(record,'command',{}).raw;
	if(name==='qedu_irq_ack')return'Hardirq · STATUS '+field(record,'status',{}).raw+' · ACK '+field(record,'ack');
	if(name==='qedu_dma_work_queue')return'Queue '+field(record,'work_kind')+' · queued='+field(record,'queued');
	if(name==='qedu_completion_publish')return'completed_events · '+field(record,'bits_before')+' → '+field(record,'bits_after');
	if(name==='qedu_wait')return field(record,'phase')+' · completion_bits '+field(record,'completion_bits')+' · wait_ret '+field(record,'wait_ret');
	if(name.indexOf('workqueue_')===0)return'Kernel workqueue lifecycle boundary.';
	if(name.indexOf('irq_handler_')===0)return'IRQ '+field(record,'irq')+' · handler '+(name.endsWith('entry')?'entry':'exit');
	if(name.indexOf('sched_')===0)return'Workload scheduling boundary.';
	if(name.indexOf('sys_')===0)return'Userspace ↔ kernel boundary.';
	if(name==='qedu_factorial_submit')return'MMIO · input '+field(record,'input')+' · IRQ enabled';
	if(name==='qedu_factorial_result')return'MMIO result read · '+field(record,'result');
	return'Captured tracepoint fields.'
}

function actorModel(journey){
    if(journey.kind==='setup')return[
        {id:'pci',type:'PCI SUBSYSTEM',name:deviceResource.fields.bdf,detail:deviceResource.fields.vendor_device+' · probe owner'},
        {id:'driver',type:'PCI DRIVER',name:'qedu_probe()',detail:'acquires and publishes device resources'},
        {id:'devres',type:'DEVICE-MANAGED ALLOCATOR',name:'devm_kzalloc()',detail:'owns struct qedu_dev until detach'},
        {id:'irq_core',type:'IRQ SUBSYSTEM',name:'request_irq()',detail:'Linux IRQ '+irqResource.fields.linux_irq+' · shared INTx'},
        {id:'dma_api',type:'DMA API / ALLOCATOR',name:'dma_alloc_coherent()',detail:'32-bit coherent DMA domain'},
        {id:'ram',type:'SYSTEM RAM',name:'coherent DMA buffer',detail:bytes(dmaResource.fields.size_bytes)+' · CPU + device views'},
        {id:'workqueue_core',type:'WORKQUEUE CORE',name:'alloc_ordered_workqueue()',detail:'qedu_dma · one ordered execution lane'},
        {id:'misc_core',type:'MISC CORE',name:'misc_register()',detail:fileResource.fields.path+' · minor '+fileResource.fields.minor},
        {id:'sysfs_core',type:'SYSFS',name:'/sys/class/misc/qedu',detail:'timeout + statistics attributes'},
        {id:'debugfs_core',type:'DEBUGFS',name:'/sys/kernel/debug/qedu/status',detail:'diagnostic state snapshot'}
    ];
    var operation=journey.operation;
    var processRecord=operation.events.find(function(record){return record.context&&record.context.pid===workloadPid});
    var irqRecord=operation.events.find(function(record){return contextClass(record)==='hardirq'});
    var workerRecord=operation.events.find(function(record){return contextClass(record)==='workqueue'});
    var openExit=operation.events.find(function(record){return record.tracepoint==='syscalls:sys_exit_openat'});
    var processName=processRecord&&processRecord.context.comm||'PID '+workloadPid;
    var irqName=irqRecord&&field(irqRecord,'name','IRQ '+irqResource.fields.linux_irq)||'IRQ '+irqResource.fields.linux_irq;
    var common=[
        {id:'user',type:'REQUESTER',name:processName,detail:'PID '+workloadPid},
        {id:'file',type:'VFS / OPEN FILE',name:fileResource.fields.path,detail:'fd '+field(openExit,'return_fd')+' · misc minor '+fileResource.fields.minor},
        {id:'driver',type:'FILE OPERATIONS / DRIVER',name:deviceResource.fields.driver,detail:deviceResource.fields.bdf},
        {id:'device',type:'PCI FUNCTION',name:deviceResource.fields.vendor_device,detail:deviceResource.fields.bdf},
        {id:'scheduler',type:'SCHEDULER',name:'sched core',detail:'captured switch / waking records'},
        {id:'state',type:'WAIT QUEUE + CONDITION',name:'job_wait',detail:'predicate: completed_events · io_id '+operation.id},
        {id:'irq',type:'HARDIRQ CONTEXT',name:irqName,detail:'Linux IRQ '+irqResource.fields.linux_irq},
        {id:'controller',type:'CONFIGURED / INFERRED',name:controllerResource.fields.route,detail:'vector '+controllerResource.fields.vector+' · CPU '+controllerResource.fields.target_cpu,inferred:true},
        {id:'irq_core',type:'GENERIC IRQ CORE',name:'irq_desc / action chain',detail:'invokes qedu on shared Linux IRQ '+irqResource.fields.linux_irq},
        {id:'ram',type:'SYSTEM RAM',name:'coherent DMA buffer',detail:bytes(dmaResource.fields.size_bytes)+' · DMA '+dmaResource.fields.dma_address+' · CPU VA '+dmaResource.fields.cpu_virtual_address}
    ];
    if(journey.kind==='dma')common.push({id:'worker',type:'WORKQUEUE / KWORKER',name:workerRecord&&workerRecord.context.comm||'qedu_dma worker',detail:workerRecord?'PID '+workerRecord.context.pid:'workqueue record unavailable'});
    return common
}
function recordFlow(record,journey){
    var name=traceName(record),operation=field(record,'operation'),execution=contextClass(record),edges=[],nodes=[];
    function connect(from,to,label,kind){edges.push({from:from,to:to,label:label||record.tracepoint,kind:kind||'control'})}
    function activate(id){if(nodes.indexOf(id)<0)nodes.push(id)}
    if(journey.kind==='setup'){
        if(name==='dma_alloc')connect('dma_api','ram','allocate '+bytes(field(record,'size_bytes'))+' coherent RAM','allocation');
        else if(name==='qedu_probe_stage'){
            var probeStage=field(record,'stage'),api=field(record,'api',probeStage),resourceName=field(record,'resource'),label=api+' · '+resourceName;
            if(probeStage==='PROBE_BEGIN')connect('pci','driver',label,'probe');
            else if(probeStage==='DEVICE_STATE_READY')connect('driver','devres',api+' · '+bytes(field(record,'object_size_bytes'))+' '+resourceName,'allocation');
            else if(probeStage==='PCI_ENABLED')connect('driver','pci',label,'resource');
            else if(probeStage==='BAR_REGIONS_CLAIMED')connect('driver','pci',api+' · BAR0 '+bytes(field(record,'bar0_length_bytes')),'resource');
            else if(probeStage==='BAR0_MAPPED')connect('driver','pci',api+' · '+bytes(field(record,'mapped_length_bytes')),'resource');
            else if(probeStage==='IRQ_REGISTERED')connect('driver','irq_core',api+' · IRQ '+field(record,'linux_irq'),'registration');
            else if(probeStage==='DMA_MASK_CONFIGURED')connect('driver','dma_api',api+' · '+field(record,'dma_mask_bits')+'-bit','configuration');
            else if(probeStage==='BUS_MASTER_ENABLED')connect('driver','pci',api+' · result='+field(record,'result'),'configuration');
            else if(probeStage==='DMA_BUFFER_READY')connect('driver','dma_api',api+' · '+bytes(field(record,'size_bytes'))+' · DMA '+field(record,'dma_address'),'allocation');
            else if(probeStage==='WORKQUEUE_READY')connect('driver','workqueue_core',label,'registration');
            else if(probeStage==='CHARDEV_PUBLISHED')connect('driver','misc_core',label,'publication');
            else if(probeStage==='SYSFS_PUBLISHED')connect('driver','sysfs_core',label,'publication');
            else if(probeStage==='DEBUGFS_PUBLISHED')connect('driver','debugfs_core',label+' · result='+field(record,'result'),'publication');
            else if(probeStage==='PROBE_READY')connect('driver','pci',api+' · return='+field(record,'result'),'probe')
        }
        edges.forEach(function(edge){activate(edge.from);activate(edge.to)});
        return{edges:edges,nodes:nodes,record:record}
    }
    if(/^sys_(enter|entry)_(openat|read|write|close)$/.test(name)){
        var syscallName=name.replace(/^sys_(enter|entry)_/,'');
        var syscallLabel=syscallName==='openat'?'openat("'+field(record,'path',fileResource.fields.path)+'")':syscallName==='close'?'close(fd='+field(record,'fd')+')':syscallName+'(fd='+field(record,'fd')+', count='+field(record,'count')+')';
        connect('user','file',syscallLabel,'syscall')
    }
    else if(/^sys_exit_(openat|read|write|close)$/.test(name))connect('file','user',name.replace(/^sys_exit_/,'')+' return='+field(record,'return_value'),'syscall');
    else if(name==='qedu_file_op'){
        var fileLabel=operation.toLowerCase()+' '+field(record,'phase').toLowerCase();
        if(field(record,'phase')==='ENTER')connect('file','driver',fileLabel+' · count='+field(record,'count')+' · offset='+field(record,'offset'),'dispatch');
        else connect('driver','file',fileLabel+' · result='+field(record,'result')+(field(record,'engine')!=='NONE'?' · '+field(record,'engine'):''),'dispatch')
    }
    else if(name==='qedu_cpu_buffer_io'&&operation==='COPY_FROM_USER'){
        connect('driver','user',operation+' · requested='+field(record,'requested')+' B','cpu-copy');
        connect('user','ram','completed='+field(record,'completed')+' B','cpu-copy')
    }
    else if(name==='qedu_cpu_buffer_io'&&operation==='COPY_TO_USER'){
        connect('driver','ram',operation+' · requested='+field(record,'requested')+' B','cpu-copy');
        connect('ram','user','completed='+field(record,'completed')+' B','cpu-copy')
    }
    else if(name==='qedu_cpu_buffer_io'&&operation==='CLEAR_FOR_DMA_RETURN')connect('worker','ram',operation+' · '+field(record,'completed')+' B','cpu-copy');
    else if(name==='qedu_factorial_submit')connect('driver','device','input='+field(record,'input')+' · status_command='+field(record,'status_command'),'mmio');
    else if(name==='qedu_factorial_result')connect('driver','device','read result register · value='+field(record,'result'),'mmio');
    else if(name==='qedu_dma_submit'){
        var executor=execution==='workqueue'?'worker':'driver',direction=field(record,'direction'),command=field(record,'command',{});
        connect(executor,'device','CMD '+command.raw+' · '+field(record,'bytes')+' B','mmio');
        connect('device','ram',(direction==='DMA_TO_DEVICE'?'DMA read submitted · RAM → EDU':'DMA write submitted · EDU → RAM')+' · '+field(record,'bytes')+' B','dma-submitted')
    }
    else if(name==='irq_handler_entry'){
        connect('device','controller','configured '+controllerResource.fields.route,'inferred-route');
        connect('controller','irq_core','vector '+controllerResource.fields.vector+' · CPU '+controllerResource.fields.target_cpu,'interrupt inferred-route');
        connect('irq_core','irq',record.tracepoint+' · irq='+field(record,'irq')+' · '+field(record,'name'),'interrupt')
    }
    else if(name==='irq_handler_exit')connect('irq','irq_core',record.tracepoint+' · ret='+field(record,'ret'),'interrupt');
    else if(name==='qedu_irq_ack')connect('irq','device','STATUS '+field(record,'status',{}).raw+' · ACK '+field(record,'ack'),'mmio');
    else if(name==='qedu_dma_work_queue')connect('irq','worker',field(record,'work_kind')+' · queued='+field(record,'queued'),'workqueue');
    else if(name==='workqueue_queue_work')connect('irq','worker',record.tracepoint+' · '+workFunction(record),'workqueue');
    else if(name==='qedu_completion_publish')connect(execution==='hardirq'?'irq':'worker','state','bit '+field(record,'event_bit')+' · '+field(record,'bits_before')+' → '+field(record,'bits_after'),'state');
    else if(name==='qedu_wait')connect(field(record,'phase')==='BEGIN'?'driver':'state',field(record,'phase')==='BEGIN'?'state':'driver',field(record,'engine')+' '+field(record,'phase')+' · ret='+field(record,'wait_ret'),'state');
    else if(name==='sched_waking'){var waker=execution==='hardirq'?'irq':execution==='workqueue'?'worker':'state';connect(waker,'scheduler',record.tracepoint+' · pid='+field(record,'pid'),'scheduler');connect('scheduler','user','runnable · CPU '+field(record,'target_cpu'),'scheduler')}
    else if(name==='sched_switch'){
        if(number(field(record,'prev_pid',-1))===workloadPid)connect('user','scheduler','prev_state='+field(record,'prev_state'),'scheduler');
        if(number(field(record,'next_pid',-1))===workloadPid)connect('scheduler','user','next_pid='+field(record,'next_pid')+' · CPU '+record.context.cpu,'scheduler');
        if(journey.kind==='dma'&&String(field(record,'prev_comm','')).indexOf('kworker')===0)connect('worker','scheduler','prev_state='+field(record,'prev_state'),'scheduler');
        if(journey.kind==='dma'&&String(field(record,'next_comm','')).indexOf('kworker')===0)connect('scheduler','worker','next_pid='+field(record,'next_pid')+' · CPU '+record.context.cpu,'scheduler')
    }
    else if(name.indexOf('workqueue_')===0||execution==='workqueue')activate('worker');
    else activate(execution==='hardirq'?'irq':'driver');
    edges.forEach(function(edge){activate(edge.from);activate(edge.to)});
    if(isQedu(record)){var executorActor=execution==='workqueue'?'worker':execution==='hardirq'?'irq':'driver';activate(executorActor)}
    return{edges:edges,nodes:nodes,record:record}
}
function stageActivity(item){
    var counts={};
    item.records.forEach(function(record){recordFlow(record,selectedJourney).nodes.forEach(function(id){counts[id]=(counts[id]||0)+1})});
    return counts
}
function renderActorGraph(){
    var item=selectedJourney.steps[selectedStep],activity=stageActivity(item),nodes=actorModel(selectedJourney);
    var order=selectedJourney.kind==='setup'?['pci','driver','devres','irq_core','dma_api','ram','workqueue_core','misc_core','sysfs_core','debugfs_core']:['user','file','driver','ram','device','controller','irq_core','irq','worker','state','scheduler'];
    nodes.sort(function(a,b){return order.indexOf(a.id)-order.indexOf(b.id)});
    var laneById={};nodes.forEach(function(node,index){laneById[node.id]=index});
    $('sequence-head').style.gridTemplateColumns='repeat('+nodes.length+',minmax(82px,1fr))';
    $('sequence-head').innerHTML=nodes.map(function(node){
        var count=activity[node.id]||0;
        return'<article data-actor="'+esc(node.id)+'" class="sequence-actor '+(count?'active ':'')+(node.inferred?'inferred':'')+'" title="'+esc(node.type+' · '+node.name+' · '+node.detail)+'"><small>'+esc(node.type)+'</small><b>'+esc(node.name)+'</b><em>'+count+' record'+(count===1?'':'s')+'</em></article>'
    }).join('');
    var interactions=[];
    item.records.forEach(function(record){
        var mapped=recordFlow(record,selectedJourney);
        if(mapped.edges.length)mapped.edges.forEach(function(flow){interactions.push({flow:flow,record:record})});
        else mapped.nodes.forEach(function(actorId){interactions.push({actor:actorId,record:record})})
    });
    $('sequence-body').style.setProperty('--rows',Math.max(interactions.length,1));
    var lifelines='<div class="sequence-lifelines">'+nodes.map(function(node,index){return'<i class="'+((activity[node.id]||0)?'active ':'')+(node.inferred?'inferred':'')+'" style="left:'+((index+.5)/nodes.length*100)+'%"></i>'}).join('')+'</div>';
    var rows=interactions.map(function(interaction){
        var record=interaction.record,label=interaction.flow?interaction.flow.label:eventTitle(record),selected=selectedSequenceSeq===record.seq?' selected':'';
        if(!interaction.flow){
            var local=(laneById[interaction.actor]+.5)/nodes.length*100;
            return'<button type="button" class="sequence-row local'+selected+'" data-sequence-event="'+record.seq+'"><span class="sequence-time">+'+esc(duration(ns(record)-selectedJourney.operation.start))+'</span><i class="sequence-local-mark" style="left:'+local+'%"></i><code style="left:'+local+'%" title="'+esc(record.tracepoint)+'">'+esc(label)+'</code></button>'
        }
        var from=(laneById[interaction.flow.from]+.5)/nodes.length*100,to=(laneById[interaction.flow.to]+.5)/nodes.length*100,left=Math.min(from,to),width=Math.abs(to-from),direction=to>from?'forward':'reverse';
        return'<button type="button" class="sequence-row'+selected+'" data-sequence-event="'+record.seq+'"><span class="sequence-time">+'+esc(duration(ns(record)-selectedJourney.operation.start))+'</span><i class="sequence-arrow '+direction+' '+esc(interaction.flow.kind)+'" data-from="'+esc(interaction.flow.from)+'" data-to="'+esc(interaction.flow.to)+'" title="'+esc(interaction.flow.from+' → '+interaction.flow.to+' · '+label)+'" style="left:'+left+'%;width:'+width+'%"></i><i class="sequence-point" style="left:'+from+'%"></i><i class="sequence-point" style="left:'+to+'%"></i><code style="left:'+((from+to)/2)+'%" title="'+esc(record.tracepoint)+'">'+esc(label.split(':').pop())+'</code></button>'
    }).join('');
    $('sequence-body').innerHTML=lifelines+(rows||'<p class="sequence-empty">No captured interaction in this stage.</p>');
    Array.prototype.forEach.call(document.querySelectorAll('[data-sequence-event]'),function(row){row.onclick=function(){selectRecord(selectedStep,number(row.dataset.sequenceEvent))}})
}
function renderHeader(){
    var loss=footer.trace_loss||{},lost=Object.keys(loss).reduce(function(sum,key){return sum+number(loss[key])},0),skipped=parseStats.malformed+parseStats.skippedTrace;
    $('capture-status').classList.toggle('complete',!lost&&!skipped);
    $('capture-status').innerHTML='<i></i><span>'+esc(deviceResource.fields.bdf)+' · '+esc(footer.tracepoint_records)+' events · '+lost+' lost'+(skipped?' · '+skipped+' unparsed':'')+'</span>'
}
function renderJourneyHeader(){
    $('journey-kicker').textContent=selectedJourney.kind==='setup'?'CAPTURED DRIVER LIFECYCLE':'CAPTURED I/O · io_id '+selectedJourney.operation.id;
    $('journey-title').textContent=selectedJourney.title;
    $('journey-caption').textContent=selectedJourney.caption
}
function renderRoadmap(){
    var kinds=['setup','factorial','dma'];
    $('step-roadmap').innerHTML=kinds.map(function(kind){
        var journey=journeys[kind];
        if(!journey)return'';
        var subtitle=kind==='setup'?'module insertion → ready':'io_id '+journey.operation.id;
        var steps=journey.steps.map(function(item,index){
            var navIndex=navigation.findIndex(function(entry){return entry.journey===journey&&entry.step===index});
            var state=navIndex===selectedNav?'active':'';
            return'<section class="flow-group '+state+'"><button type="button" class="flow-step" data-navigation="'+navIndex+'"><b>'+esc(item.shortTitle)+'</b></button></section>'
        }).join('');
        return'<section class="roadmap-section '+(journey===selectedJourney?'active':'')+'"><header><b>'+esc(journey.title)+'</b><small>'+esc(subtitle)+'</small></header>'+steps+'</section>'
    }).join('');
    Array.prototype.forEach.call(document.querySelectorAll('[data-navigation]'),function(button){button.onclick=function(){selectNavigation(number(button.dataset.navigation))}})
}
function renderStep(){
    var item=selectedJourney.steps[selectedStep],anchor=item.anchor||item.records[0];
    $('step-position').textContent=(selectedNav+1)+' of '+navigation.length;
    $('prev-stage').disabled=selectedNav===0;
    $('next-stage').disabled=selectedNav===navigation.length-1;
    if(!selectedEvent||item.records.indexOf(selectedEvent)<0)selectedEvent=anchor||item.records[0]||null;
    renderActorGraph();renderInspector()
}
function renderResources(){
    var rows;
    if(selectedJourney.kind==='setup')rows=[['PCI function',deviceResource.fields.bdf+' · '+deviceResource.fields.vendor_device],['BAR0',barResource.fields.bus_start+' · '+barResource.fields.length],['IRQ action','Linux '+irqResource.fields.linux_irq+' · shared INTx'],['coherent RAM',dmaResource.fields.cpu_virtual_address+' · '+bytes(dmaResource.fields.size_bytes)],['DMA address',dmaResource.fields.dma_address],['file + sysfs',fileResource.fields.path+' · /sys/class/misc/qedu'],['debugfs','/sys/kernel/debug/qedu/status']];
    else{
        var common=[['file interface',fileResource.fields.path+' · minor '+fileResource.fields.minor],['IRQ route','Linux '+irqResource.fields.linux_irq+' · '+irqResource.fields.delivery],['configured vector',controllerResource.fields.vector+' · CPU '+controllerResource.fields.target_cpu]];
        var specific=selectedJourney.kind==='dma'?[['CPU virtual',dmaResource.fields.cpu_virtual_address],['DMA address',dmaResource.fields.dma_address],['device-local',localResource.fields.offset]]:[['BAR0',barResource.fields.bus_start],['factorial reg','BAR0 + 0x08'],['completion','completed_events bit 0']];
        rows=common.concat(specific)
    }
    $('resource-facts').innerHTML=rows.map(function(row){return'<div class="resource-row"><small>'+esc(row[0])+'</small><code title="'+esc(row[1])+'">'+esc(row[1])+'</code></div>'}).join('')
}
function flatten(value,prefix,out){out=out||[];if(value&&typeof value==='object'&&!Array.isArray(value))Object.keys(value).forEach(function(key){flatten(value[key],prefix?prefix+'.'+key:key,out)});else out.push([prefix,value]);return out}
function renderInspector(){
    var record=selectedEvent;
    if(!record)return;
    var proof=evidence(record),context=record.context||{};
    $('inspect-index').textContent='record '+record.seq+' · +'+duration(ns(record)-selectedJourney.operation.start);
    $('inspect-title').textContent=eventTitle(record);
    $('inspect-tracepoint').textContent=record.tracepoint;
	$('inspect-proof').textContent=proof;
    $('inspect-evidence').textContent=isQedu(record)?'semantic trace':'kernel trace';
    var contextFields=[['context',context.execution],['CPU','CPU '+context.cpu],['task',context.comm],['PID',context.pid],['flags',context.trace_flags],['timestamp',record.time_ns+' ns']];
    $('inspect-context').innerHTML=contextFields.map(function(item){return'<div class="context-item"><small>'+esc(item[0])+'</small><b title="'+esc(item[1])+'">'+esc(item[1])+'</b></div>'}).join('');
    var fields={};Object.keys(record.fields||{}).forEach(function(key){if(key!=='raw_payload')fields[key]=record.fields[key]});
    var rows=flatten(fields,'',[]);
    $('inspect-fields').innerHTML=rows.length?rows.map(function(item){return'<dt>'+esc(item[0])+'</dt><dd>'+esc(item[1])+'</dd>'}).join(''):'<dt>payload</dt><dd>no structured fields</dd>';
}
function selectNavigation(index){
    selectedNav=Math.max(0,Math.min(navigation.length-1,index));
    var entry=navigation[selectedNav];
    selectedJourney=entry.journey;
    selectedStep=entry.step;
    selectedSequenceSeq=null;
    var item=entry.item;
    selectedEvent=item.anchor||item.records[0]||null;
    if(window.location.hash!=='#'+selectedJourney.kind)history.replaceState(null,'','#'+selectedJourney.kind);
    renderJourneyHeader();renderResources();renderRoadmap();renderStep()
}
function selectRecord(stepIndex,sequence){selectedStep=stepIndex;selectedSequenceSeq=sequence;selectedEvent=tracepoints.find(function(record){return record.seq===sequence})||null;renderRoadmap();renderStep()}
function bindControls(){
    $('prev-stage').onclick=function(){selectNavigation(selectedNav-1)};
    $('next-stage').onclick=function(){selectNavigation(selectedNav+1)};
    document.addEventListener('keydown',function(event){if(event.target&&/input|textarea|select/i.test(event.target.tagName))return;if(event.key==='ArrowLeft')selectNavigation(selectedNav-1);if(event.key==='ArrowRight')selectNavigation(selectedNav+1)})
}
function render(){
    var requested=window.location.hash.slice(1),initial=navigation.findIndex(function(entry){return entry.journey.kind===requested});
    if(initial<0)initial=0;
    renderHeader();bindControls();selectNavigation(initial)
}

Promise.all(Object.keys(DATA).map(function(key){return fetch(DATA[key]+'?v='+Date.now(),{cache:'no-store'}).then(function(response){if(!response.ok)throw Error(DATA[key]+' HTTP '+response.status);return response.text().then(function(text){return[key,text]})})})).then(function(entries){var source={};entries.forEach(function(entry){source[entry[0]]=entry[1]});parseSources(source);render()}).catch(function(error){$('capture-status').innerHTML='<span>capture error · '+esc(error.message)+'</span>';$('inspect-title').textContent=error.message})
})();
