// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>

#define CREATE_TRACE_POINTS
#include "qedu_trace.h"

EXPORT_TRACEPOINT_SYMBOL_GPL(qedu_probe_stage);
EXPORT_TRACEPOINT_SYMBOL_GPL(qedu_file_op);
EXPORT_TRACEPOINT_SYMBOL_GPL(qedu_cpu_buffer_io);
EXPORT_TRACEPOINT_SYMBOL_GPL(qedu_dma_stage);
EXPORT_TRACEPOINT_SYMBOL_GPL(qedu_dma_submit);
EXPORT_TRACEPOINT_SYMBOL_GPL(qedu_irq_ack);
EXPORT_TRACEPOINT_SYMBOL_GPL(qedu_dma_work_queue);
EXPORT_TRACEPOINT_SYMBOL_GPL(qedu_completion_publish);
EXPORT_TRACEPOINT_SYMBOL_GPL(qedu_wait);
EXPORT_TRACEPOINT_SYMBOL_GPL(qedu_factorial_submit);
EXPORT_TRACEPOINT_SYMBOL_GPL(qedu_factorial_result);

MODULE_DESCRIPTION("Tracepoint provider for the qedu educational PCI driver");
MODULE_LICENSE("GPL");
