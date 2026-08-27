#pragma once

#include <list>
#include <queue>

#include <rte_timer.h>

#include "Connection.h"
#include "ConnectionOptions.h"
#include "Generator.h"

class DPDKConnection : public Connection {
public:
	DPDKConnection(string hostname, int port, options_t options, bool sampling);
	void drive_write_machine(double now = 0.0);
	void retransmit(double now);
	void issue_something(double now);
	void issue_something(Operation &op);
	void issue_get(string *key, double now);
	void issue_set(string *key, const char* value, int length, double now);
	void issue_get(Operation &op);
	void timer_callback(void);
	void read_callback(const char *data, size_t len);
	void pop_op(Operation *op);
	bool consume_tcp_binary_response(const char *buf, size_t length);
	bool connected;
private:
	void consume_header(const char *data, size_t length);
	void consume_rest(const char *data, size_t length);

	struct pcb *pcb;
	KeyGenerator *keygen;
	double next_time;
	Generator *valuesize;
	Generator *iagen;
	options_t options;
	struct rte_timer timer;
	std::queue<Operation> op_queue;
	enum read_state_enum read_state;
	enum write_state_enum write_state;
	uint32_t remaining;
};

void parse_mac(const char *str, struct ether_addr *res);
uint32_t parse_ip(const char *str);
