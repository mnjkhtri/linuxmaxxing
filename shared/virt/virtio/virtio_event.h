/* SPDX-License-Identifier: GPL-2.0 */
/* This header is the binary ring-buffer ABI shared by virtio.bpf.c and virtio.c. */
#ifndef VIRTIO_EVENT_H
#define VIRTIO_EVENT_H

#define VIRTIO_EVENT_QUEUE_SLOTS 8

enum virtio_event_type
{
	VIRTIO_EVENT_MMIO = 0,
	VIRTIO_EVENT_QUEUE_BACKEND_BEGIN = 1,
	VIRTIO_EVENT_QUEUE_BACKEND_END = 2,
	VIRTIO_EVENT_IOEVENTFD_KICK = 3,
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
	unsigned char ioeventfd_present;
	unsigned char reserved[2];
	int return_value;
	unsigned long long ioeventfd_count;
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

struct virtio_descriptor_entry
{
	unsigned long long addr;
	unsigned int len;
	unsigned short flags;
	unsigned short next;
};

struct virtio_descriptor_state
{
	unsigned char present; /* present says that every physical descriptor slot was sampled at this boundary. */
	unsigned char reserved[7];
	struct virtio_descriptor_entry entries[VIRTIO_EVENT_QUEUE_SLOTS];
};

struct virtio_avail_state
{
	unsigned char present; /* present distinguishes real zero-valued ring entries from unavailable data. */
	unsigned char reserved;
	unsigned short flags;
	unsigned short idx;
	unsigned short ring[VIRTIO_EVENT_QUEUE_SLOTS];
};

struct virtio_used_entry
{
	unsigned int id;
	unsigned int len;
};

struct virtio_used_state
{
	unsigned char present; /* present says that the complete used-ring snapshot is available. */
	unsigned char reserved;
	unsigned short flags;
	unsigned short idx;
	unsigned short reserved2;
	struct virtio_used_entry ring[VIRTIO_EVENT_QUEUE_SLOTS];
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
