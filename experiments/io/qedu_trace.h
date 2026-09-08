/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM qedu

#if !defined(_QEDU_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _QEDU_TRACE_H

#include <linux/tracepoint.h>
#include "qedu.h"

TRACE_DEFINE_ENUM(QEDU_ENGINE_NONE);
TRACE_DEFINE_ENUM(QEDU_ENGINE_FACTORIAL);
TRACE_DEFINE_ENUM(QEDU_ENGINE_DMA);
TRACE_DEFINE_ENUM(QEDU_BUFFER_COPY_FROM_USER);
TRACE_DEFINE_ENUM(QEDU_BUFFER_CLEAR_FOR_DMA_RETURN);
TRACE_DEFINE_ENUM(QEDU_BUFFER_COPY_TO_USER);
TRACE_DEFINE_ENUM(QEDU_FILE_OPEN);
TRACE_DEFINE_ENUM(QEDU_FILE_READ);
TRACE_DEFINE_ENUM(QEDU_FILE_WRITE);
TRACE_DEFINE_ENUM(QEDU_FILE_RELEASE);
TRACE_DEFINE_ENUM(QEDU_FILE_ENTER);
TRACE_DEFINE_ENUM(QEDU_FILE_EXIT);
TRACE_DEFINE_ENUM(QEDU_DMA_IDLE);
TRACE_DEFINE_ENUM(QEDU_DMA_TO_DEVICE);
TRACE_DEFINE_ENUM(QEDU_DMA_FROM_DEVICE);
TRACE_DEFINE_ENUM(QEDU_STAGE_SUBMIT);
TRACE_DEFINE_ENUM(QEDU_STAGE_ADVANCE_WORK);
TRACE_DEFINE_ENUM(QEDU_STAGE_FINISH_WORK);
TRACE_DEFINE_ENUM(QEDU_STAGE_SIGNAL);
TRACE_DEFINE_ENUM(QEDU_STAGE_TIMEOUT);
TRACE_DEFINE_ENUM(QEDU_DMA_DIR_TO_DEVICE);
TRACE_DEFINE_ENUM(QEDU_DMA_DIR_FROM_DEVICE);
TRACE_DEFINE_ENUM(QEDU_ADDR_DMA);
TRACE_DEFINE_ENUM(QEDU_ADDR_EDU_LOCAL);
TRACE_DEFINE_ENUM(QEDU_WORK_NONE);
TRACE_DEFINE_ENUM(QEDU_WORK_ADVANCE);
TRACE_DEFINE_ENUM(QEDU_WORK_FINISH);
TRACE_DEFINE_ENUM(QEDU_WAIT_BEGIN);
TRACE_DEFINE_ENUM(QEDU_WAIT_END);
TRACE_DEFINE_ENUM(QEDU_PROBE_BEGIN);
TRACE_DEFINE_ENUM(QEDU_DEVICE_STATE_READY);
TRACE_DEFINE_ENUM(QEDU_PCI_ENABLED);
TRACE_DEFINE_ENUM(QEDU_BAR_REGIONS_CLAIMED);
TRACE_DEFINE_ENUM(QEDU_BAR0_MAPPED);
TRACE_DEFINE_ENUM(QEDU_IRQ_REGISTERED);
TRACE_DEFINE_ENUM(QEDU_DMA_MASK_CONFIGURED);
TRACE_DEFINE_ENUM(QEDU_BUS_MASTER_ENABLED);
TRACE_DEFINE_ENUM(QEDU_DMA_BUFFER_READY);
TRACE_DEFINE_ENUM(QEDU_WORKQUEUE_READY);
TRACE_DEFINE_ENUM(QEDU_CHARDEV_PUBLISHED);
TRACE_DEFINE_ENUM(QEDU_SYSFS_PUBLISHED);
TRACE_DEFINE_ENUM(QEDU_DEBUGFS_PUBLISHED);
TRACE_DEFINE_ENUM(QEDU_PROBE_READY);

#define qedu_engine_name(engine) __print_symbolic(engine, {QEDU_ENGINE_NONE, "NONE"}, {QEDU_ENGINE_FACTORIAL, "FACTORIAL"}, {QEDU_ENGINE_DMA, "DMA"})

#define qedu_stage_name(stage) __print_symbolic(stage, {QEDU_DMA_IDLE, "IDLE"}, {QEDU_DMA_TO_DEVICE, "TO_DEVICE"}, {QEDU_DMA_FROM_DEVICE, "FROM_DEVICE"})

#define qedu_probe_stage_name(stage) __print_symbolic(stage, {QEDU_PROBE_BEGIN, "PROBE_BEGIN"}, {QEDU_DEVICE_STATE_READY, "DEVICE_STATE_READY"}, {QEDU_PCI_ENABLED, "PCI_ENABLED"}, {QEDU_BAR_REGIONS_CLAIMED, "BAR_REGIONS_CLAIMED"}, {QEDU_BAR0_MAPPED, "BAR0_MAPPED"}, {QEDU_IRQ_REGISTERED, "IRQ_REGISTERED"}, {QEDU_DMA_MASK_CONFIGURED, "DMA_MASK_CONFIGURED"}, {QEDU_BUS_MASTER_ENABLED, "BUS_MASTER_ENABLED"}, {QEDU_DMA_BUFFER_READY, "DMA_BUFFER_READY"}, {QEDU_WORKQUEUE_READY, "WORKQUEUE_READY"}, {QEDU_CHARDEV_PUBLISHED, "CHARDEV_PUBLISHED"}, {QEDU_SYSFS_PUBLISHED, "SYSFS_PUBLISHED"}, {QEDU_DEBUGFS_PUBLISHED, "DEBUGFS_PUBLISHED"}, {QEDU_PROBE_READY, "PROBE_READY"})

TRACE_EVENT(qedu_probe_stage,
			TP_PROTO(const char *device, u8 stage, const char *api, const char *resource, u64 address, u64 size, s32 result),
			TP_ARGS(device, stage, api, resource, address, size, result),
			TP_STRUCT__entry(
				__string(device, device)
					__field(u8, stage)
						__string(api, api)
							__string(resource, resource)
								__field(u64, address)
									__field(u64, size)
										__field(s32, result)),
			TP_fast_assign(
				__assign_str(device);
				__entry->stage = stage;
				__assign_str(api);
				__assign_str(resource);
				__entry->address = address;
				__entry->size = size;
				__entry->result = result;),
			TP_printk("device=%s stage=%s api=%s resource=%s address=0x%016llx size=%llu result=%d",
					  __get_str(device), qedu_probe_stage_name(__entry->stage),
						  __get_str(api), __get_str(resource), __entry->address,
						  __entry->size, __entry->result));

TRACE_EVENT(qedu_file_op,
	TP_PROTO(const char *device, u64 io_id, u8 operation, u8 phase, unsigned long file, u64 count, s64 offset, s64 result, u8 engine),
	TP_ARGS(device, io_id, operation, phase, file, count, offset, result, engine),
	TP_STRUCT__entry(
		__string(device, device)
		__field(u64, io_id)
		__field(u8, operation)
		__field(u8, phase)
		__field(unsigned long, file)
		__field(u64, count)
		__field(s64, offset)
		__field(s64, result)
		__field(u8, engine)
	),
	TP_fast_assign(
		__assign_str(device);
		__entry->io_id = io_id;
		__entry->operation = operation;
		__entry->phase = phase;
		__entry->file = file;
		__entry->count = count;
		__entry->offset = offset;
		__entry->result = result;
		__entry->engine = engine;
	),
	TP_printk("device=%s io_id=%llu operation=%s phase=%s file=%p count=%llu offset=%lld result=%lld engine=%s",
		__get_str(device), __entry->io_id,
		__print_symbolic(__entry->operation,
			{ QEDU_FILE_OPEN, "OPEN" },
			{ QEDU_FILE_READ, "READ" },
			{ QEDU_FILE_WRITE, "WRITE" },
			{ QEDU_FILE_RELEASE, "RELEASE" }),
		__print_symbolic(__entry->phase,
			{ QEDU_FILE_ENTER, "ENTER" },
			{ QEDU_FILE_EXIT, "EXIT" }),
		(void *)__entry->file, __entry->count, __entry->offset,
		__entry->result, qedu_engine_name(__entry->engine))
);

TRACE_EVENT(qedu_cpu_buffer_io,
			TP_PROTO(const char *device, u64 io_id, u8 operation, u64 offset,
					 u64 requested, s64 completed),
			TP_ARGS(device, io_id, operation, offset, requested, completed),
			TP_STRUCT__entry(
				__string(device, device)
					__field(u64, io_id)
						__field(u8, operation)
							__field(u64, offset)
								__field(u64, requested)
									__field(s64, completed)),
			TP_fast_assign(
				__assign_str(device);
				__entry->io_id = io_id;
				__entry->operation = operation;
				__entry->offset = offset;
				__entry->requested = requested;
				__entry->completed = completed;),
			TP_printk("device=%s io_id=%llu operation=%s offset=%llu requested=%llu completed=%lld",
					  __get_str(device), __entry->io_id,
					  __print_symbolic(__entry->operation,
									   {QEDU_BUFFER_COPY_FROM_USER, "COPY_FROM_USER"},
									   {QEDU_BUFFER_CLEAR_FOR_DMA_RETURN, "CLEAR_FOR_DMA_RETURN"},
									   {QEDU_BUFFER_COPY_TO_USER, "COPY_TO_USER"}),
					  __entry->offset, __entry->requested, __entry->completed));

TRACE_EVENT(qedu_dma_stage,
			TP_PROTO(const char *device, u64 io_id, u8 old_stage, u8 new_stage, u8 reason),
			TP_ARGS(device, io_id, old_stage, new_stage, reason),
			TP_STRUCT__entry(
				__string(device, device)
					__field(u64, io_id)
						__field(u8, old_stage)
							__field(u8, new_stage)
								__field(u8, reason)),
			TP_fast_assign(
				__assign_str(device);
				__entry->io_id = io_id;
				__entry->old_stage = old_stage;
				__entry->new_stage = new_stage;
				__entry->reason = reason;),
			TP_printk("device=%s io_id=%llu old=%s new=%s reason=%s",
					  __get_str(device), __entry->io_id,
					  qedu_stage_name(__entry->old_stage), qedu_stage_name(__entry->new_stage),
					  __print_symbolic(__entry->reason,
									   {QEDU_STAGE_SUBMIT, "SUBMIT"},
									   {QEDU_STAGE_ADVANCE_WORK, "ADVANCE_WORK"},
									   {QEDU_STAGE_FINISH_WORK, "FINISH_WORK"},
									   {QEDU_STAGE_SIGNAL, "SIGNAL"},
									   {QEDU_STAGE_TIMEOUT, "TIMEOUT"})));

TRACE_EVENT(qedu_dma_submit,
			TP_PROTO(const char *device, u64 io_id, u8 leg, u8 direction,
					 u8 source_space, u64 source_address, u8 destination_space,
					 u64 destination_address, u64 bytes, u64 command),
			TP_ARGS(device, io_id, leg, direction, source_space, source_address,
					destination_space, destination_address, bytes, command),
			TP_STRUCT__entry(
				__string(device, device)
					__field(u64, io_id)
						__field(u8, leg)
							__field(u8, direction)
								__field(u8, source_space)
									__field(u64, source_address)
										__field(u8, destination_space)
											__field(u64, destination_address)
												__field(u64, bytes)
													__field(u64, command)),
			TP_fast_assign(
				__assign_str(device);
				__entry->io_id = io_id;
				__entry->leg = leg;
				__entry->direction = direction;
				__entry->source_space = source_space;
				__entry->source_address = source_address;
				__entry->destination_space = destination_space;
				__entry->destination_address = destination_address;
				__entry->bytes = bytes;
				__entry->command = command;),
			TP_printk("device=%s io_id=%llu leg=%u direction=%s src_space=%s src=0x%016llx dst_space=%s dst=0x%016llx bytes=%llu command=0x%016llx",
					  __get_str(device), __entry->io_id, __entry->leg,
					  __print_symbolic(__entry->direction,
									   {QEDU_DMA_DIR_TO_DEVICE, "DMA_TO_DEVICE"},
									   {QEDU_DMA_DIR_FROM_DEVICE, "DMA_FROM_DEVICE"}),
					  __print_symbolic(__entry->source_space,
									   {QEDU_ADDR_DMA, "DMA_ADDRESS"},
									   {QEDU_ADDR_EDU_LOCAL, "EDU_LOCAL"}),
					  __entry->source_address,
					  __print_symbolic(__entry->destination_space,
									   {QEDU_ADDR_DMA, "DMA_ADDRESS"},
									   {QEDU_ADDR_EDU_LOCAL, "EDU_LOCAL"}),
					  __entry->destination_address, __entry->bytes, __entry->command));

TRACE_EVENT(qedu_irq_ack,
			TP_PROTO(const char *device, u64 io_id, u8 engine, int irq, u32 status,
					 u32 ack, u8 dma_stage),
			TP_ARGS(device, io_id, engine, irq, status, ack, dma_stage),
			TP_STRUCT__entry(
				__string(device, device)
					__field(u64, io_id)
						__field(u8, engine)
							__field(int, irq)
								__field(u32, status)
									__field(u32, ack)
										__field(u8, dma_stage)),
			TP_fast_assign(
				__assign_str(device);
				__entry->io_id = io_id;
				__entry->engine = engine;
				__entry->irq = irq;
				__entry->status = status;
				__entry->ack = ack;
				__entry->dma_stage = dma_stage;),
			TP_printk("device=%s io_id=%llu engine=%s irq=%d status=0x%08x ack=0x%08x dma_stage=%s",
					  __get_str(device), __entry->io_id, qedu_engine_name(__entry->engine),
					  __entry->irq, __entry->status, __entry->ack,
					  qedu_stage_name(__entry->dma_stage)));

TRACE_EVENT(qedu_dma_work_queue,
			TP_PROTO(const char *device, u64 io_id, u8 dma_stage, u8 work_kind,
					 unsigned long work, bool queued),
			TP_ARGS(device, io_id, dma_stage, work_kind, work, queued),
			TP_STRUCT__entry(
				__string(device, device)
					__field(u64, io_id)
						__field(u8, dma_stage)
							__field(u8, work_kind)
								__field(unsigned long, work)
									__field(bool, queued)),
			TP_fast_assign(
				__assign_str(device);
				__entry->io_id = io_id;
				__entry->dma_stage = dma_stage;
				__entry->work_kind = work_kind;
				__entry->work = work;
				__entry->queued = queued;),
			TP_printk("device=%s io_id=%llu dma_stage=%s work_kind=%s work=%p queued=%u",
					  __get_str(device), __entry->io_id, qedu_stage_name(__entry->dma_stage),
					  __print_symbolic(__entry->work_kind,
									   {QEDU_WORK_NONE, "NONE"},
									   {QEDU_WORK_ADVANCE, "ADVANCE"},
									   {QEDU_WORK_FINISH, "FINISH"}),
					  (void *)__entry->work, __entry->queued));

TRACE_EVENT(qedu_completion_publish,
			TP_PROTO(const char *device, u64 io_id, u8 engine, u8 event_bit,
					 unsigned long bits_before, unsigned long bits_after),
			TP_ARGS(device, io_id, engine, event_bit, bits_before, bits_after),
			TP_STRUCT__entry(
				__string(device, device)
					__field(u64, io_id)
						__field(u8, engine)
							__field(u8, event_bit)
								__field(unsigned long, bits_before)
									__field(unsigned long, bits_after)),
			TP_fast_assign(
				__assign_str(device);
				__entry->io_id = io_id;
				__entry->engine = engine;
				__entry->event_bit = event_bit;
				__entry->bits_before = bits_before;
				__entry->bits_after = bits_after;),
			TP_printk("device=%s io_id=%llu engine=%s event_bit=%u bits_before=0x%lx bits_after=0x%lx",
					  __get_str(device), __entry->io_id, qedu_engine_name(__entry->engine),
					  __entry->event_bit, __entry->bits_before, __entry->bits_after));

TRACE_EVENT(qedu_wait,
			TP_PROTO(const char *device, u64 io_id, u8 engine, u8 phase,
					 u32 timeout_ms, s64 wait_ret, unsigned long completion_bits),
			TP_ARGS(device, io_id, engine, phase, timeout_ms, wait_ret, completion_bits),
			TP_STRUCT__entry(
				__string(device, device)
					__field(u64, io_id)
						__field(u8, engine)
							__field(u8, phase)
								__field(u32, timeout_ms)
									__field(s64, wait_ret)
										__field(unsigned long, completion_bits)),
			TP_fast_assign(
				__assign_str(device);
				__entry->io_id = io_id;
				__entry->engine = engine;
				__entry->phase = phase;
				__entry->timeout_ms = timeout_ms;
				__entry->wait_ret = wait_ret;
				__entry->completion_bits = completion_bits;),
			TP_printk("device=%s io_id=%llu engine=%s phase=%s timeout_ms=%u wait_ret=%lld completion_bits=0x%lx",
					  __get_str(device), __entry->io_id, qedu_engine_name(__entry->engine),
					  __print_symbolic(__entry->phase,
									   {QEDU_WAIT_BEGIN, "BEGIN"},
									   {QEDU_WAIT_END, "END"}),
					  __entry->timeout_ms, __entry->wait_ret, __entry->completion_bits));

TRACE_EVENT(qedu_factorial_submit,
			TP_PROTO(const char *device, u64 io_id, u32 input, u32 status_command),
			TP_ARGS(device, io_id, input, status_command),
			TP_STRUCT__entry(
				__string(device, device)
					__field(u64, io_id)
						__field(u32, input)
							__field(u32, status_command)),
			TP_fast_assign(
				__assign_str(device);
				__entry->io_id = io_id;
				__entry->input = input;
				__entry->status_command = status_command;),
			TP_printk("device=%s io_id=%llu input=%u status_command=0x%08x",
					  __get_str(device), __entry->io_id, __entry->input, __entry->status_command));

TRACE_EVENT(qedu_factorial_result,
			TP_PROTO(const char *device, u64 io_id, u32 result),
			TP_ARGS(device, io_id, result),
			TP_STRUCT__entry(
				__string(device, device)
					__field(u64, io_id)
						__field(u32, result)),
			TP_fast_assign(
				__assign_str(device);
				__entry->io_id = io_id;
				__entry->result = result;),
			TP_printk("device=%s io_id=%llu result=%u",
					  __get_str(device), __entry->io_id, __entry->result));

#ifndef QEDU_TRACE_CALL_ALIASES
#define QEDU_TRACE_CALL_ALIASES

/* Capitalized aliases distinguish observation sites from functional driver calls. */
#define Trace_qedu_cpu_buffer_io(...) trace_qedu_cpu_buffer_io(__VA_ARGS__)
#define Trace_qedu_file_op(...) trace_qedu_file_op(__VA_ARGS__)
#define Trace_qedu_dma_stage(...) trace_qedu_dma_stage(__VA_ARGS__)
#define Trace_qedu_dma_submit(...) trace_qedu_dma_submit(__VA_ARGS__)
#define Trace_qedu_irq_ack(...) trace_qedu_irq_ack(__VA_ARGS__)
#define Trace_qedu_dma_work_queue(...) trace_qedu_dma_work_queue(__VA_ARGS__)
#define Trace_qedu_completion_publish(...) trace_qedu_completion_publish(__VA_ARGS__)
#define Trace_qedu_wait(...) trace_qedu_wait(__VA_ARGS__)
#define Trace_qedu_factorial_submit(...) trace_qedu_factorial_submit(__VA_ARGS__)
#define Trace_qedu_factorial_result(...) trace_qedu_factorial_result(__VA_ARGS__)
#define Trace_qedu_probe_stage(...) trace_qedu_probe_stage(__VA_ARGS__)

#endif /* QEDU_TRACE_CALL_ALIASES */

#endif /* _QEDU_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE qedu_trace

#include <trace/define_trace.h>
