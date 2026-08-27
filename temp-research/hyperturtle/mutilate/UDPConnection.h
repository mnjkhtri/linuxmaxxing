#pragma once

#include <list>
#include <queue>

#include "Connection.h"
#include "ConnectionOptions.h"
#include "Generator.h"

class OpQueue {
public:
	size_t size();
	void pop(Operation *op);
	void push(Operation op);
	Operation *find(uint16_t req_id);
	Operation *earliest_last_xmit(void);
	std::list<Operation>::iterator begin();
	std::list<Operation>::iterator end();
private:
	std::list<Operation> list;
};

class UDPConnection : public Connection {
public:
	UDPConnection(struct event_base* base, string hostname, int port, options_t options, bool sampling);
	void drive_write_machine(double now = 0.0);
	void retransmit(double now);
	void issue_something(double now);
	void issue_something(Operation &op);
	void issue_get(string *key, double now);
	void issue_get(Operation &op);
	void timer_callback(void);
	void read_callback(void);
	void pop_op(Operation *op);
	Operation *consume_udp_binary_response(char *buf, size_t length);
private:
	int fd;
	uint16_t req_id = 0;
	KeyGenerator *keygen;
	double next_time;
	Generator *iagen;
	options_t options;
	struct event *timer;
	OpQueue op_queue;
	enum read_state_enum read_state;
	enum write_state_enum write_state;
};
