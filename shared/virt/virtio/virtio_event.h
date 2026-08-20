/* SPDX-License-Identifier: GPL-2.0 */
/* This header is the binary ring-buffer ABI shared by virtio.bpf.c and virtio.c. */
#ifndef VIRTIO_EVENT_H
#define VIRTIO_EVENT_H

enum virtio_event_type
{
	VIRTIO_EVENT_MMIO = 0,
	VIRTIO_EVENT_QUEUE_BACKEND_BEGIN = 1,
	VIRTIO_EVENT_QUEUE_BACKEND_END = 2,
};

struct virtio_event_info
{
	unsigned int event;
	unsigned char mmio_present;
	unsigned char mmio_is_write;
	unsigned char mmio_value_present;
	unsigned char mmio_length;
	unsigned long long mmio_address;
	unsigned int mmio_offset;
	unsigned int mmio_value;
	unsigned char return_present;
	unsigned char reserved[3];
	int return_value;
};

struct virtio_context
{
	unsigned int pid;
	unsigned int tid;
	unsigned int cpu;
	char comm[16];
};

struct virtio_device_state
{
	unsigned char present; /* present distinguishes an unavailable sample from meaningful zero-valued state. */
	unsigned char reserved[3];
	unsigned int status;
	unsigned int device_features_sel;
	unsigned int driver_features_sel;
	unsigned int driver_features[2];
	unsigned int queue_sel;
};

struct virtio_queue_state
{
	unsigned char present;
	unsigned char reserved;
	unsigned short last_avail_idx;
	unsigned int size;
	unsigned int ready;
	unsigned long long desc_addr;
	unsigned long long driver_addr;
	unsigned long long device_addr;
};

struct virtio_descriptor_state
{
	unsigned char present;
	unsigned char reserved[7];
	unsigned long long addr;
	unsigned int len;
	unsigned short flags;
	unsigned short next;
};

struct virtio_avail_state
{
	unsigned char present;
	unsigned char reserved;
	unsigned short flags;
	unsigned short idx;
	unsigned short ring0;
};

struct virtio_used_state
{
	unsigned char present;
	unsigned char reserved;
	unsigned short flags;
	unsigned short idx;
	unsigned short reserved2;
	unsigned int ring0_id;
	unsigned int ring0_len;
};

#define VIRTIO_BUFFER_PREVIEW_BYTES 8

struct virtio_buffer_preview
{
	unsigned char present;
	unsigned char length;
	unsigned char bytes[VIRTIO_BUFFER_PREVIEW_BYTES];
};

struct virtio_state
{
	struct virtio_device_state device;
	struct virtio_queue_state queue;
	struct virtio_descriptor_state descriptor;
	struct virtio_avail_state avail;
	struct virtio_used_state used;
	struct virtio_buffer_preview buffer_preview;
};

struct virtio_event
{
	unsigned long long time_ns;
	struct virtio_event_info event_info;
	struct virtio_context context;
	struct virtio_state state;
};

#endif
