#include <string>
#include <map>

#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_lcore.h>

#include "ConnectionOptions.h"
#include "ConnectionStats.h"
#include "Operation.h"
#include "DPDKConnection.h"
#include "binary_protocol.h"
#include "log.h"
#include "dpdktcp.h"

void DPDKConnection::pop_op(Operation *op)
{
	assert(op_queue.size() > 0);

	op_queue.pop();

	if (op_queue.size() > 0) {
		switch (op->type) {
		case Operation::GET:
			read_state = WAITING_FOR_GET;
			break;
		case Operation::SET:
			read_state = WAITING_FOR_SET;
			break;
		default:
			DIE("Not implemented.");
		}
	} else {
		read_state = IDLE;
	}
}

bool DPDKConnection::consume_tcp_binary_response(const char *data, size_t length)
{
	if (remaining)
		consume_rest(data, length);
	else
		consume_header(data, length);

	return remaining == 0;
}

void DPDKConnection::consume_header(const char *data, size_t length)
{
	assert(length >= 24);
	binary_header_t *h = (binary_header_t *) data;

	assert(h->magic == 0x81);
	assert(h->opcode == CMD_GET || h->opcode == CMD_SET);

	size_t targetLen = 24 + __builtin_bswap32(h->body_len);
	assert(length <= targetLen);

	// if something other than success, count it as a miss
	if (h->opcode == CMD_GET && h->status)
		stats.get_misses++;

	stats.rx_bytes += targetLen;

	remaining = targetLen - length;
}

void DPDKConnection::consume_rest(const char *data, size_t length)
{
	assert(length <= remaining);

	remaining -= length;
}

void DPDKConnection::read_callback(const char *data, size_t len)
{
	Operation *op;
	double now;

	if (!consume_tcp_binary_response(data, len))
		return;

	op = &op_queue.front();
	now = get_time();
	op->end_time = now;
	switch (op->type) {
	case Operation::GET:
		assert(read_state == WAITING_FOR_GET);
		stats.log_get(*op);
		break;
	case Operation::SET:
		assert(read_state == WAITING_FOR_SET);
		stats.log_set(*op);
		break;
	default:
		DIE("Not implemented.");
	}

	pop_op(op);

	drive_write_machine(now);
}

void DPDKConnection::timer_callback()
{
	drive_write_machine();
}

void timer_cb(struct rte_timer *tim, void *arg)
{
	DPDKConnection *conn = (DPDKConnection *) arg;
	conn->timer_callback();
}

void DPDKConnection::issue_get(string *key, double now)
{
	Operation op;

	if (now == 0.0)
		now = get_time();

	op.start_time = now;
	op.type = Operation::GET;
	op.key = *key;
	op_queue.push(op);

	uint16_t keylen = op.key.size();

	if (read_state == IDLE)
		read_state = WAITING_FOR_GET;

	struct {
		char header[24];
		char key[256];
	} data;

	binary_header_t *h = (binary_header_t *) data.header;
	h->magic = 0x80;
	h->opcode = CMD_GET;
	h->key_len = __builtin_bswap16(keylen);
	h->extra_len = 0x00;
	h->data_type = 0x00;
	h->vbucket = 0;
	h->body_len = __builtin_bswap32(keylen);
	assert(keylen < 256);
	memcpy(data.key, op.key.c_str(), keylen);

	tcp_send(pcb, &data, 24 + keylen);

	stats.tx_bytes += 24 + keylen;
}

void DPDKConnection::issue_set(string* key, const char* value, int length, double now)
{
	Operation op;
	uint16_t keylen = key->size();

	op.start_time = now;
	op.type = Operation::SET;
	op.key = *key;
	op_queue.push(op);

	if (read_state == IDLE)
		read_state = WAITING_FOR_SET;

	struct {
		char header[32];
		char keyvalue[32768];
	} data;

	binary_header_t *h = (binary_header_t *) data.header;
	h->magic = 0x80;
	h->opcode = CMD_SET;
	h->key_len = __builtin_bswap16(keylen);
	h->extra_len = 0x08;
	h->data_type = 0x00;
	h->vbucket = 0;
	h->body_len = __builtin_bswap32(keylen + 8 + length);
	assert(keylen + length < 32768);
	memcpy(data.keyvalue, op.key.c_str(), keylen);
	memcpy(data.keyvalue + keylen, value, length);

	tcp_send(pcb, &data, 32 + keylen + length);

	stats.tx_bytes += 32 + keylen + length;
}

void DPDKConnection::issue_something(double now)
{
	string key = keygen->generate(lrand48() % options.records);
	if (drand48() < options.update) {
		int index = lrand48() % (1024 * 1024);
		issue_set(&key, &random_char[index], valuesize->generate(), now);
	} else {
		issue_get(&key, now);
	}
}

void DPDKConnection::drive_write_machine(double now)
{
	if (now == 0.0)
		now = get_time();

	double delay;

	while (1) {
		switch (write_state) {
		case INIT_WRITE:
			delay = iagen->generate();
			next_time = now + delay;
			// TODO: cache rte_get_timer_hz
			rte_timer_reset(&timer, delay * rte_get_timer_hz(), SINGLE, rte_lcore_id(), timer_cb, this);
			write_state = WAITING_FOR_TIME;
			break;
		case ISSUING:
			if (op_queue.size() >= (size_t) options.depth) {
				write_state = WAITING_FOR_OPQ;
				break;
			} else if (now < next_time) {
				write_state = WAITING_FOR_TIME;
				break;
			}
			issue_something(now);
			stats.log_op(op_queue.size());
			delay = iagen->generate();
			next_time += delay;
			break;
		case WAITING_FOR_TIME:
			write_state = ISSUING;
			if (now < next_time) {
				if (!rte_timer_pending(&timer)) {
					delay = next_time - now;
					// TODO: cache rte_get_timer_hz
					rte_timer_reset(&timer, delay * rte_get_timer_hz(), SINGLE, rte_lcore_id(), timer_cb, this);
				}
				return;
			}
			write_state = ISSUING;
			break;
		case WAITING_FOR_OPQ:
			if (op_queue.size() >= (size_t) options.depth)
				return;
			write_state = ISSUING;
			break;
		default:
			DIE("Not implemented");
		}
	}
}

DPDKConnection::DPDKConnection(string hostname, int port, options_t options, bool sampling) :
	Connection(sampling), connected(false), options(options)
{
	pcb = tcp_create(this);

	struct ether_addr remote_mac;
	parse_mac(args.server_mac_arg, &remote_mac);

	tcp_connect(pcb, &remote_mac, parse_ip(hostname.c_str()), port);

	remaining = 0;
	read_state = IDLE;
	write_state = INIT_WRITE;
	iagen = createGenerator(options.ia);
	iagen->set_lambda(options.lambda);
	valuesize = createGenerator(options.valuesize);
	auto keysize = createGenerator(options.keysize);
	keygen = new KeyGenerator(keysize, options.records);
	rte_timer_init(&timer);
}

void on_tcp_connected(void *arg)
{
	DPDKConnection *conn = (DPDKConnection *) arg;
	conn->connected = true;
}

void on_tcp_recv(void *arg, char *data, size_t len)
{
	DPDKConnection *conn = (DPDKConnection *) arg;
	conn->read_callback(data, len);
}

void parse_mac(const char *str, struct ether_addr *res)
{
	int ret;
	ret = sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &res->addr_bytes[0], &res->addr_bytes[1], &res->addr_bytes[2], &res->addr_bytes[3], &res->addr_bytes[4], &res->addr_bytes[5]);
	assert(ret == 6);
}

uint32_t parse_ip(const char *str)
{
	int ret;
	uint8_t a, b, c, d;
	ret = sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d);
	assert(ret == 4);
	return IP4(a, b, c, d);
}
