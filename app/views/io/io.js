/*
 * QEDU PCI I/O flight recorder: MMIO · DMA · IRQ.
 *
 * io-Phases.ndjson is the authoritative structured source; each phase record
 * carries a monotonic time_ns and a sequence.  The private-instance trace is a
 * separate raw source correlated to phases by time, never by trace_marker.
 * parseIoPhases/parseIoTrace/parseIoReport feed buildIoModel(); rendering
 * reads only the normalized model.
 */
(function(){
'use strict';

var BASE='../../shared/_captures/';
var PATHS=['io-Phases.ndjson','io-Trace.txt','io-Report.txt'];
var events=[],phases=[],irqSpans=[],sleeps=[],workerPids={},meta={},debugState={},sysfsState={};
var selectedPhase=0,selectedEvent=null,runStart=0,runEnd=0,workloadPid=0,vectorEvent=null;
var CAT_LABEL={mmio:'MMIO',dma:'DMA',irq:'IRQ',syscall:'SYSCALL',sched:'SCHED',io:'IO'};
var NS='http://www.w3.org/2000/svg';

function $(id){return document.getElementById(id)}
function esc(value){return String(value==null?'—':value).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function number(value,fallback){var n=Number(value);return Number.isFinite(n)?n:(fallback||0)}
function duration(seconds){var ms=seconds*1000;if(ms<1000)return ms.toFixed(ms<10?2:ms<100?1:0)+' ms';return seconds.toFixed(2)+' s'}
function durNs(ns){return duration(ns/1e9)}
function short(value,max){value=String(value==null?'—':value);max=max||26;return value.length>max?value.slice(0,max-1)+'…':value}
function parseTokens(text){var out={},re=/([A-Za-z_]+)=("[^"]*"|\S+)/g,m;while((m=re.exec(text)))out[m[1]]=m[2].replace(/^"|"$/g,'');return out}

function parseIoPhases(text){
	var records=[];
	text.split(/\r?\n/).forEach(function(line){
		if(!line.trim())return;
		var record;
		try{record=JSON.parse(line)}catch(ignore){return}
		if(!record||record.kind!=='phase'||record.schema_version!==1)return;
		var info=record.event_info||{},context=record.context||{};
		records.push({seq:number(record.seq),time_ns:number(record.time_ns),phase:info.phase,category:info.category,action:info.action,facts:info,pid:number(context.pid)});
	});
	return records;
}

function parseIoTrace(text){
	var out=[];
	text.split(/\r?\n/).forEach(function(raw){
		var m=raw.match(/^\s*(.+)-(\d+)\s+\[(\d+)\]\s+(\S+)\s+([0-9]+\.[0-9]+):\s+(.*)$/);
		if(!m)return;
		var rendered=m[6],syscallMatch=rendered.match(/^(sys_(?:openat|read|write|close))(\(|\s+->\s*)(.*)$/),normalMatch=rendered.match(/^([^:]+):\s?(.*)$/);
		if(!syscallMatch&&!normalMatch)return;
		var type=syscallMatch?syscallMatch[1]:normalMatch[1].trim();
		var body=syscallMatch?(syscallMatch[2].charAt(0)==='('?syscallMatch[3].replace(/\)$/,''):'-> '+syscallMatch[3]):normalMatch[2]||'';
		var time=+m[5];
		var e={index:out.length,task:m[1].trim(),pid:+m[2],cpu:+m[3],flags:m[4],time:time,time_ns:Math.round(time*1e9),type:type,body:body,raw:raw};
		if(/^sys_(openat|read|write|close)$/.test(e.type)){e.syscall=e.type.slice(4);e.direction=/^\s*->/.test(e.body)?'exit':'entry'}
		if(e.type==='irq_handler_entry'){var im=e.body.match(/irq=(\d+)\s+name=(\S+)/);if(im){e.irq=+im[1];e.irqName=im[2]}}
		if(e.type==='irq_handler_exit'){var ix=e.body.match(/irq=(\d+)\s+ret=(\S+)/);if(ix){e.irq=+ix[1];e.ret=ix[2]}}
		if(e.type==='vector_alloc'||e.type==='vector_config')e.vector=parseTokens(e.body.replace(/\s+/g,' '));
		if(e.type.indexOf('workqueue_')===0)e.workqueue=/qedu_dma(?:_advance|_finish)?_work|workqueue=qedu_dma/.test(e.body);
		if(e.type==='page_fault_user')e.fault=parseTokens(e.body);
		if(e.type==='sched_switch'){
			var sm=e.body.match(/prev_comm=(.+?)\s+prev_pid=(\d+)\s+prev_prio=\d+\s+prev_state=(\S+)\s+==>\s+next_comm=(.+?)\s+next_pid=(\d+)/);
			if(sm)e.sched={prevComm:sm[1],prevPid:+sm[2],state:sm[3],nextComm:sm[4],nextPid:+sm[5]};
		}
		if(e.type==='sched_wakeup'||e.type==='sched_waking'){var wm=e.body.match(/comm=(.+?)\s+pid=(\d+)/);if(wm)e.wake={comm:wm[1],pid:+wm[2]}}
		out.push(e);
	});
	return out;
}

function parseSections(text){
	var out={},section='';
	text.split(/\r?\n/).forEach(function(line){
		var heading=line.match(/^\[([a-z]+)\]$/);
		if(heading){section=heading[1];out[section]='';return}
		if(section)out[section]+=line+'\n';
	});
	return out
}
function parsePairs(text,separator){
	var out={};text.split(/\r?\n/).forEach(function(line){var at=line.indexOf(separator);if(at>0)out[line.slice(0,at).trim()]=line.slice(at+1).trim()});return out
}
function parseDebug(text){
	var out={};text.split(/\r?\n/).forEach(function(line){var m=line.match(/^([a-zA-Z0-9_]+):\s*(.+)$/);if(m)out[m[1]]=m[2]});return out
}
function parseIoReport(text){
	var report=parseSections(text);
	return{metadata:parsePairs(report.metadata||'','='),sysfs:parsePairs(report.sysfs||'','='),debugfs:parseDebug(report.debugfs||'')};
}

function markDeviceSyscalls(){
	var deviceFds={},pendingOpen=null,pending={};
	events.forEach(function(e){
		if(e.pid!==workloadPid||!e.syscall)return;
		if(e.syscall==='openat'&&e.direction==='entry'){pendingOpen=e;if(e.body.indexOf('"/dev/qedu"')<0)pendingOpen=null;return}
		if(e.syscall==='openat'&&e.direction==='exit'&&pendingOpen){var opened=e.body.match(/->\s*(0x[0-9a-f]+|-?\d+)/i),fd=opened?Number(opened[1]): -1;pendingOpen.deviceSyscall=e.deviceSyscall=true;if(fd>=0)deviceFds[fd]=true;pendingOpen=null;return}
		if(e.direction==='entry'){
			var descriptor=e.body.match(/^fd:\s*(0x[0-9a-f]+|\d+)/i),fd=descriptor?Number(descriptor[1]):-1;if(fd>=0&&deviceFds[fd]){e.deviceSyscall=true;pending[e.syscall]=e;if(e.syscall==='close')delete deviceFds[fd]}
		}else if(pending[e.syscall]){e.deviceSyscall=true;pending[e.syscall]=null}
	});
}
function buildIrqs(){
	var open=null;irqSpans=[];
	events.forEach(function(e){if(e.type==='irq_handler_entry'&&e.irqName==='qedu')open=e;else if(e.type==='irq_handler_exit'&&open&&e.irq===open.irq){irqSpans.push({entry:open,exit:e,start:open.time_ns,end:e.time_ns});open=null}});
}
function buildSleeps(){
	var open=null;sleeps=[];
	events.forEach(function(e){
		if(!e.sched)return;
		if(e.sched.prevPid===workloadPid&&(e.sched.state.charAt(0)==='S'||e.sched.state.charAt(0)==='D'))open={start:e.time_ns,event:e,state:e.sched.state};
		if(open&&e.sched.nextPid===workloadPid){open.end=e.time_ns;open.wake=e;sleeps.push(open);open=null}
	});
}
function markWorkerSchedulerEvents(){
	var active={};workerPids={};
	events.forEach(function(e){
		if(e.workqueue&&e.type==='workqueue_execute_start'){active[e.pid]=true;workerPids[e.pid]=true}
		if(e.sched&&(active[e.sched.prevPid]||active[e.sched.nextPid]))e.workerSchedule=true;
		if(e.workqueue&&e.type==='workqueue_execute_end')delete active[e.pid];
	});
}
function isWorkloadEvent(e){
	var irq=number(meta.qedu_irq,number(debugState.irq,0));
	if(e.workqueue)return true;
	if(e.pid===workloadPid||e.irqName==='qedu')return true;
	if(e.type==='irq_handler_exit')return e.irq===irq;
	if(e.sched)return e.sched.prevPid===workloadPid||e.sched.nextPid===workloadPid;
	if(e.wake)return e.wake.pid===workloadPid;
	return false
}

var KIND={factorial:'factorial',dma_echo:'dma',sysfs:'sysfs',debugfs:'debugfs'};
function addPhase(kind,label,begin,end,data){
	if(!begin||!begin.time_ns||!end||!end.time_ns)return;
	phases.push({index:phases.length,kind:kind,label:label,start:begin.time_ns,end:end.time_ns,beginSeq:begin.seq,endSeq:end.seq,data:data||{}});
}
function buildPhases(records){
	var groups={};
	records.forEach(function(r){
		if(!KIND[r.phase])return;
		var g=groups[r.phase]||(groups[r.phase]={begin:null,end:null});
		if(r.action==='begin')g.begin=r;else g.end=r;
	});
	Object.keys(groups).forEach(function(name){
		var g=groups[name],b=g.begin,e=g.end,kind=KIND[name];
		if(name==='factorial')addPhase(kind,'MMIO · Factorial('+b.facts.input+') → '+e.facts.result,b,e,{kind:b.category,input:b.facts.input,result:e.facts.result,bytes:e.facts.bytes,summary:'Integer write enters qedu_write(), sleeps, and resumes after one factorial completion IRQ.'});
		if(name==='dma_echo')addPhase(kind,'DMA · echo · '+b.facts.bytes+' B',b,e,{kind:b.category,bytes:b.facts.bytes,reads:e.facts.read_calls,summary:'One synchronous write performs RAM → EDU and EDU → RAM, with one completion IRQ per direction.'});
		if(name==='sysfs')addPhase(kind,'SYSCALL · Sysfs · '+b.facts.attribute,b,e,{kind:b.category,summary:'Open, write, read, and close a stable device attribute from process context.'});
		if(name==='debugfs')addPhase(kind,'SYSCALL · Debugfs · '+b.facts.file,b,e,{kind:b.category,summary:'Open, read, and close the developer diagnostics state.'});
	});
	var order={sysfs:0,debugfs:1,factorial:2,dma:3};
	phases.sort(function(a,b){return order[a.kind]-order[b.kind]||a.start-b.start});phases.forEach(function(p,i){p.index=i});
}
function buildIoModel(records,report){
	events.sort(function(a,b){return a.time_ns-b.time_ns});
	var rb=records.find(function(r){return r.phase==='run'&&r.action==='begin'});
	var re=records.find(function(r){return r.phase==='run'&&r.action==='end'});
	runStart=rb?rb.time_ns:records[0]?records[0].time_ns:0;
	runEnd=re?re.time_ns:records.length?records[records.length-1].time_ns:0;
	workloadPid=number(meta.workload_pid,records.length?records[0].pid:0);
	markDeviceSyscalls();buildIrqs();buildSleeps();markWorkerSchedulerEvents();buildPhases(records);
}

function phaseOf(e){return phases.find(function(p){return e.time_ns>=p.start&&e.time_ns<=p.end})}
function eventCat(e,p){p=p||phaseOf(e);if(/^(irq_|vector_)/.test(e.type))return'irq';if(e.workqueue||e.workerSchedule)return'dma';return(p&&p.data&&p.data.kind)||'io'}
function catCounts(){var c={mmio:0,dma:0,irq:0,syscall:0,sched:0};events.forEach(function(e){if(e.time_ns<runStart||e.time_ns>runEnd)return;var k=eventCat(e);if(c[k]!=null)c[k]++});return c}
function phaseEvents(phase){
	return events.filter(function(e){return e.time_ns>=phase.start&&e.time_ns<=phase.end&&(isWorkloadEvent(e)||e.workerSchedule)});
}
function phaseSyscall(phase){
	var kind=(phase.data&&phase.data.kind)||'';
	return kind==='syscall';
}
function phaseIrqs(phase){return irqSpans.filter(function(i){return i.start>=phase.start&&i.start<=phase.end})}
function phaseSleeps(phase){return sleeps.filter(function(s){return s.start>=phase.start&&s.start<=phase.end&&s.state.charAt(0)==='S'})}
function runtimeEvents(type){return events.filter(function(e){return e.time_ns>=runStart&&e.time_ns<=runEnd&&(!type||e.type===type)})}
function entrySyscalls(){return runtimeEvents().filter(function(e){return e.deviceSyscall&&e.direction==='entry'})}
function renderMetrics(){
	var qeduIrq=number(meta.qedu_irq,number(debugState.irq,0));
	var irq=runtimeEvents('irq_handler_entry').filter(function(e){return e.irqName==='qedu'});
	var faults=runtimeEvents('page_fault_user').filter(function(e){return e.pid===workloadPid});
	var vector=events.find(function(e){return e.type==='vector_config'&&number(e.vector&&e.vector.irq,0)===qeduIrq})||events.find(function(e){return e.type==='vector_alloc'&&number(e.vector&&e.vector.irq,0)===qeduIrq});
	vectorEvent=vector||null;
	$('m-device').textContent=(debugState.vendor_device||'1234:11e8')+' · '+(debugState.pci_device||'PCI');
	$('m-device-sub').textContent='BAR0 '+(debugState.bar0_start||'—')+' · misc '+(debugState.misc_minor||'—');
	$('m-vector').textContent=vector&&vector.vector?'vector '+vector.vector.vector:'vector —';
	$('m-vector-sub').textContent=vector&&vector.vector?'CPU '+(vector.vector.cpu||vector.cpu)+' · APIC '+(vector.vector.apicdest||'—'):'no vector_config';
	$('m-irq').textContent=irq.length+' × IRQ '+(meta.qedu_irq||debugState.irq||'—');
	$('m-irq-sub').textContent='IRQF_SHARED · top half';
	$('m-syscalls').textContent=entrySyscalls().length+' entries';
	$('m-sleeps').textContent=sleeps.filter(function(s){return s.start>=runStart&&s.end<=runEnd&&s.state.charAt(0)==='S'}).length+' interruptible';
	$('m-faults').textContent=faults.length+' faults';
	var cc=catCounts();
	$('m-mmio').textContent=cc.mmio+' events';
	$('m-dma').textContent=cc.dma+' events';
	$('m-irqcat').textContent=cc.irq+' × IRQ';
	$('m-sys').textContent=cc.syscall+' entries';
	$('evidence-vector').textContent=vector&&vector.vector?'vector '+vector.vector.vector+' · CPU '+(vector.vector.cpu||vector.cpu):'vector —';
}
function svg(name,attrs,text){
	var node=document.createElementNS(NS,name);Object.keys(attrs||{}).forEach(function(k){node.setAttribute(k,attrs[k])});if(text!=null)node.textContent=text;return node
}
function localPhaseEvents(phase){
	return phaseEvents(phase).filter(function(e){return e.deviceSyscall||(phaseSyscall(phase)&&e.syscall)||e.type==='irq_handler_entry'||e.type==='irq_handler_exit'||(e.type==='sched_switch'&&((e.sched&&(e.sched.prevPid===workloadPid||e.sched.nextPid===workloadPid))||e.workerSchedule))||e.type==='sched_wakeup'||e.type==='page_fault_user'||e.workqueue})
}
function traceLane(event){
	if(event.syscall)return'syscall';
	if(event.type==='sched_switch'||event.type==='sched_wakeup'||event.type==='sched_waking')return'scheduler';
	if(event.type==='irq_handler_entry'||event.type==='irq_handler_exit')return'hardirq';
	if(event.workqueue)return'workqueue';
	return'exception'
}
function renderTimeline(){
	var root=$('timeline'),phase=phases[selectedPhase],records=localPhaseEvents(phase),visible=Math.max(240,root.parentElement.clientHeight-16),viewWidth=Math.max(900,Math.round(visible*root.parentElement.clientWidth/Math.max(1,root.parentElement.clientHeight))),side=96,laneGap=(viewWidth-side*2)/4,lanes=[
		{key:'syscall',x:side,title:'SYSCALL',note:'sys_enter / sys_exit'},
		{key:'scheduler',x:side+laneGap,title:'SCHED',note:'switch / wakeup'},
		{key:'hardirq',x:side+laneGap*2,title:'IRQ',note:'handler entry / exit'},
		{key:'workqueue',x:side+laneGap*3,title:'DMA WORK',note:'queue / execute · bottom half'},
		{key:'exception',x:side+laneGap*4,title:'EXCEPTION',note:'page fault'}
	],row=34,top=88,contentHeight=Math.max(20,(records.length-1)*row+20),needed=top+contentHeight+14,height=Math.max(visible,needed),bottom=height-14;
	root.setAttribute('viewBox','0 0 '+viewWidth+' '+height);
	root.style.height=height+'px';
	root.innerHTML='';
	var defs=svg('defs');var marker=svg('marker',{id:'activity-arrow',viewBox:'0 0 6 6',refX:5,refY:3,markerWidth:5,markerHeight:5,orient:'auto'});marker.appendChild(svg('path',{d:'M0,0 L6,3 L0,6 z',fill:'context-stroke'}));defs.appendChild(marker);root.appendChild(defs);
	lanes.forEach(function(lane){
		root.appendChild(svg('rect',{x:lane.x-74,y:13,width:148,height:50,rx:6,class:'activity-lane '+lane.key}));
		root.appendChild(svg('text',{x:lane.x,y:33,'text-anchor':'middle',class:'lane-text'},lane.title));
		root.appendChild(svg('text',{x:lane.x,y:49,'text-anchor':'middle',class:'lane-note'},lane.note));
		root.appendChild(svg('line',{x1:lane.x,y1:63,x2:lane.x,y2:bottom,class:'grid-line'}));
	});
	records.forEach(function(event,index){
		var lane=lanes.find(function(item){return item.key===traceLane(event)}),y=top+index*row,previous=index&&records[index-1],previousLane=previous&&lanes.find(function(item){return item.key===traceLane(previous)});
		if(previous){
			var py=top+(index-1)*row,path='M '+previousLane.x+' '+(py+8)+' L '+previousLane.x+' '+(y-8)+' L '+lane.x+' '+(y-8);
			root.appendChild(svg('path',{d:path,class:'activity-flow','marker-end':'url(#activity-arrow)'}));
		}
		var laneKey=traceLane(event),cpuClass='cpu-'+event.cpu,nodeClass='activity-node '+laneKey+' '+cpuClass+(selectedEvent&&selectedEvent.index===event.index?' selected':'');
		var activity=svg('g',{class:'activity-event','data-event':event.index});
		activity.appendChild(svg('rect',{x:lane.x-90,y:y-13,width:180,height:26,rx:5,class:'activity-hit'}));
		activity.appendChild(svg('rect',{x:lane.x-86,y:y-10,width:172,height:20,rx:4,class:nodeClass}));
		activity.appendChild(svg('text',{x:lane.x-6,y:y+2.5,'text-anchor':'middle',class:'activity-line'},short(event.type+' · '+event.body,33)));
		activity.appendChild(svg('rect',{x:lane.x+53,y:y-7,width:22,height:14,rx:3,class:'cpu-badge '+cpuClass}));
		activity.appendChild(svg('text',{x:lane.x+64,y:y+2.5,'text-anchor':'middle',class:'cpu-badge-text'},'C'+event.cpu));
		activity.appendChild(svg('text',{x:lane.x-94,y:y+2.5,'text-anchor':'end',class:'activity-time'},'+'+durNs(event.time_ns-phase.start)));
		root.appendChild(activity);
	});
	root.querySelectorAll('[data-event]').forEach(function(n){n.addEventListener('click',function(){selectEvent(+n.getAttribute('data-event'))})});
}
function renderFocus(){
	var phase=phases[selectedPhase],list=localPhaseEvents(phase);
	if(selectedEvent==null||selectedEvent.time_ns<phase.start||selectedEvent.time_ns>phase.end){var important=list.find(function(e){return e.type==='irq_handler_entry'})||list[0];if(important)selectedEvent=important}
	renderInspector();
}
function eventTitle(e){
	if(!e)return'No event';
	if(e.syscall)return e.syscall+' · '+e.direction;
	if(e.type==='irq_handler_entry')return'IRQ '+e.irq+' enters qedu';
	if(e.type==='irq_handler_exit')return'IRQ '+e.irq+' '+e.ret;
	if(e.workqueue)return e.type;
	if(e.workerSchedule&&e.sched){
		if(workerPids[e.sched.prevPid]&&(e.sched.state.charAt(0)==='S'||e.sched.state.charAt(0)==='D'))return e.sched.prevComm+' sleeps · state '+e.sched.state;
		if(workerPids[e.sched.nextPid])return e.sched.nextComm+' resumes';
		return e.sched.prevComm+' → '+e.sched.nextComm;
	}
	if(e.type==='sched_switch'&&e.sched)return e.sched.prevComm+' → '+e.sched.nextComm;
	if(e.type==='page_fault_user')return'user page fault';
	return e.type
}
function eventClass(e){if(!e)return'event';if(e.type.indexOf('irq_')===0)return'hardirq';if(e.workqueue)return'deferred work';if(e.syscall)return'syscall';if(e.type.indexOf('sched_')===0)return'scheduler';if(e.type==='page_fault_user')return'exception';return e.type}
function payloadRows(e){
	var rows={};
	if(e.syscall&&e.direction==='exit'){var rm=e.body.match(/->\s*(0x[0-9a-f]+|-?\d+)/);rows.ret=rm?rm[1]:e.body.trim();return rows}
	if(e.syscall){
		e.body.split(',').forEach(function(p){var kv=p.match(/^\s*([A-Za-z_]+):\s*([^,]*)$/);if(kv)rows[kv[1]]=kv[2].trim()});
		if(!Object.keys(rows).length)rows.payload=e.body;
		return rows
	}
	if(e.workqueue){var wm=e.body.match(/work struct ([0-9a-fA-F]+)/);if(wm)rows.work='0x'+wm[1];var fn=e.body.match(/function ([A-Za-z0-9_.]+)/);if(fn)rows.function=fn[1]}
	if(e.type==='sched_switch'){
		var sw=e.body.replace(/\s*==>\s*/,' next_comm=').match(/([A-Za-z_]+)=("[^"]*"|\S+)/g);
		if(sw)sw.forEach(function(t){var kv=t.match(/^([A-Za-z_]+)=(.*)$/);if(kv)rows[kv[1]]=kv[2]});
	}
	var tokens=e.body.replace(/\s*==>\s*/g,' ').match(/([A-Za-z_]+)=("[^"]*"|\S+)/g);
	if(tokens)tokens.forEach(function(t){var kv=t.match(/^([A-Za-z_]+)=(.*)$/);if(kv&&rows[kv[1]]==null)rows[kv[1]]=kv[2]});
	if(!Object.keys(rows).length)rows.payload=e.body;
	return rows
}
function renderInspector(){
	var e=selectedEvent;if(!e){$('inspect-title').textContent='No event';return}
	$('inspect-type').textContent='TRACEPOINT';$('inspect-title').textContent=e.type;
	var fields={timestamp:e.time.toFixed(6)+' s',relative:durNs(e.time_ns-runStart),cpu:'CPU '+e.cpu,context:e.flags,emitter:e.task+'['+e.pid+']'};
	if(e.irq!=null)fields.irq=e.irq;if(e.irqName)fields.handler=e.irqName;if(e.ret)fields.result=e.ret;if(e.syscall)fields.direction=e.direction;
	Object.keys(payloadRows(e)).forEach(function(k){if(fields[k]==null)fields[k]=payloadRows(e)[k]});
	$('fields').innerHTML=Object.keys(fields).map(function(k){return'<dt>'+esc(k)+'</dt><dd title="'+esc(fields[k])+'">'+esc(fields[k])+'</dd>'}).join('');
}
function renderPhaseList(){
	$('phase-list').innerHTML=phases.map(function(p){
		var irq=phaseIrqs(p).length,detail=durNs(p.end-p.start)+(irq?' · '+irq+' IRQ':' · no IRQ');
		return'<button type="button" class="phase-item '+p.kind+(p.index===selectedPhase?' active':'')+'" data-phase="'+p.index+'"><i></i><span><b>'+esc(p.label)+'</b><span>'+esc(detail)+'</span></span><em>'+String(p.index+1).padStart(2,'0')+'</em></button>'
	}).join('');
	$('phase-list').querySelectorAll('[data-phase]').forEach(function(button){button.onclick=function(){selectPhase(+button.dataset.phase)}});
	$('phase-summary').textContent=phases.length+' operations';
}
function renderState(){
	var completion=parseInt(debugState.completed_events||'0',16);
	var cells=[['IRQ',debugState.irq||meta.qedu_irq],['timeout',sysfsState.timeout_ms?sysfsState.timeout_ms+' ms':debugState.timeout_ms+' ms'],['TX',sysfsState.tx||debugState.tx_bytes_to_user],['RX',sysfsState.rx||debugState.rx_bytes_from_user],['DMA CPU',debugState.cpu_address],['DMA device',debugState.device_address]];
	$('state-grid').innerHTML=cells.map(function(c){return'<div class="state-cell"><small>'+esc(c[0])+'</small><b title="'+esc(c[1])+'">'+esc(c[1])+'</b></div>'}).join('');
	$('bit-factorial').classList.toggle('on',!!(completion&1));$('bit-dma').classList.toggle('on',!!(completion&2));
}
function selectEvent(index){selectedEvent=events[index]||null;renderFocus();renderTimeline()}
function selectPhase(index){
	selectedPhase=Math.max(0,Math.min(phases.length-1,index));selectedEvent=null;
	renderPhaseList();renderFocus();renderTimeline();
}
function load(parts){
	var report=parseIoReport(parts[2]);
	events=parseIoTrace(parts[1]);meta=report.metadata;debugState=report.debugfs;sysfsState=report.sysfs;
	if(!events.length)throw Error('no trace events captured');
	var records=parseIoPhases(parts[0]);
	if(!records.length)throw Error('no structured phases parsed');
	buildIoModel(records,report);
	if(!phases.length)throw Error('no workload operations derived from phases');
	if(!records.find(function(r){return r.phase==='run'&&r.action==='end'}))throw Error('workload did not finish');
	$('status').innerHTML='<i class="trace-dot"></i><span>'+events.length+' events · '+phases.length+' operations</span>';
	renderMetrics();renderState();
	selectedPhase=Math.max(0,phases.findIndex(function(p){return p.kind==='dma'}));selectPhase(selectedPhase)
}
Promise.all(PATHS.map(function(path){return fetch(BASE+path+'?v='+Date.now(),{cache:'no-store'}).then(function(response){if(!response.ok)throw Error(path+' HTTP '+response.status);return response.text()})})).then(load).catch(function(error){$('status').textContent='IO data error · '+error.message;$('inspect-title').textContent=error.message});
})();