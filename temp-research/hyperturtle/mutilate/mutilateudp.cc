#include <assert.h>
#include <event2/event.h>
#include <pthread.h>
#include <zmq.hpp>

#include <iostream>

#include "UDPConnection.h"
#include "common.h"
#include "log.h"
#include "mutilate.h"

/* Not used but must be defined */
struct scan_search_ctx scans_ctx;
struct scan_search_params_struct scan_search_params;
vector<zmq::socket_t*> agent_sockets;

gengetopt_args_info args;
pthread_barrier_t finish_barrier;
vector<Connection*> all_connections;
volatile bool received_stop;
zmq::context_t context(1);

static options_t options;
static pthread_barrier_t barrier;
static pthread_mutex_t all_connections_mutex;
static vector<string> servers;

static void assert_cmdline(void);

static void open_connections(struct event_base *base, vector<UDPConnection *> *connections)
{
	string server;
	int connections_count;
	bool sampling;

	if (args.agentmode_given) {
		server = servers[0];
		connections_count = options.connections;
		sampling = false;
	} else {
		server = args.server_arg[0];
		connections_count = args.measure_connections_arg;
		sampling = true;
	}

	int port = 11211;
	size_t pos = server.find(":");
	if (pos != string::npos) {
		port = stoi(server.substr(pos + 1));
		server = server.substr(0, pos);
	}

	for (int i = 0; i < connections_count; i++) {
		UDPConnection *conn = new UDPConnection(base, server, port, options, sampling);
		connections->push_back(conn);
	}
}

static void start_connections(vector<UDPConnection *> *connections)
{
	for (UDPConnection *conn: *connections)
		conn->drive_write_machine();
}

static void master(void)
{
	qps_function_init(&options);
	scan_search_init(&options);
	args_to_options(&options);

	connect_agent();

	// Synchronizes with init_agent
	prep_agent({ args.server_arg[0] }, options);

	struct event_base *base = event_base_new();
	assert(base);

	vector<UDPConnection *> connections;
	open_connections(base, &connections);

	// Synchronizes with sync_agent in agent
	sync_agent(NULL);

	start_connections(&connections);

	double start_time = get_time(), now;
	while (1) {
		event_base_loop(base, EVLOOP_ONCE | EVLOOP_NONBLOCK);
		now = get_time();
		if (now - start_time > options.time)
			break;
	}

	ConnectionStats stats;
	finish_agent(stats);

	for (UDPConnection *conn: connections)
		stats.accumulate(conn->stats);

	stats.start = start_time;
	stats.stop = now;

	print_stats(stats, 0, 0);

	for (auto s: agent_sockets)
		delete s;
}

static void *agent_thread(void *arg)
{
	struct event_base *base = event_base_new();
	assert(base);

	vector<UDPConnection *> connections;
	open_connections(base, &connections);

	pthread_mutex_lock(&all_connections_mutex);
	all_connections.insert(all_connections.end(), connections.begin(), connections.end());
	pthread_mutex_unlock(&all_connections_mutex);

	// Notify that all connections are open
	pthread_barrier_wait(&barrier);

	// Wait for synchronization with master
	pthread_barrier_wait(&barrier);

	start_connections(&connections);

	while (!received_stop)
		event_base_loop(base, EVLOOP_ONCE | EVLOOP_NONBLOCK);

	return NULL;
}

static void agent(void)
{
	zmq::socket_t socket(context, ZMQ_REP);
	string str_arg = string("tcp://*:") + args.agent_port_arg;
	char* chr_arg = const_cast<char*>(str_arg.c_str());
	socket.bind(chr_arg);

	while (1) {
		// Synchronizes with prep_agent
		init_agent(socket, options, servers);

		pthread_barrier_init(&barrier, NULL, options.threads + 1);
		pthread_barrier_init(&finish_barrier, NULL, 1);

		pthread_t pt[args.threads_arg];
		for (int i = 0; i < args.threads_arg; i++) {
			int ret = pthread_create(&pt[i], NULL, agent_thread, NULL);
			assert(!ret);
		}

		// Wait for opening all connections across all threads
		pthread_barrier_wait(&barrier);

		// Synchronizes with sync_agent in master
		sync_agent(&socket);

		// Release all threads after synchronization with master
		pthread_barrier_wait(&barrier);

		pthread_t stats_thread;
		struct agent_stats_thread_data data;
		data.socket = &socket;
		int ret = pthread_create(&stats_thread, NULL, agent_stats_thread, &data);
		assert(!ret);

		for (int i = 0; i < args.threads_arg; i++) {
			int ret = pthread_join(pt[i], NULL);
			assert(!ret);
		}

		ret = pthread_join(stats_thread, NULL);
		assert(!ret);
	}
}

int main(int argc, char **argv)
{
	if (cmdline_parser(argc, argv, &args) != 0)
		exit(-1);

	assert_cmdline();

	for (unsigned int i = 0; i < args.verbose_given; i++)
		log_level = (log_level_t) ((int) log_level - 1);

	if (args.quiet_given) log_level = QUIET;

	double boot_time = get_time();
	srand48(boot_time * 1000000);

	if (args.server_given) {
		assert(args.binary_given);
		assert(args.connections_given);
		assert(args.measure_connections_given);
		assert(args.noload_given);
		assert(args.server_given == 1);
		assert(args.threads_arg == 1);
		assert(args.update_arg == 0.0);
		master();
	} else if (args.agentmode_given) {
		agent();
	} else {
		DIE("--server or --agentmode must be specified.");
	}

	return 0;
}

static void assert_cmdline(void)
{
	assert(!args.affinity_given);
	assert(!args.blocking_given);
	assert(!args.getcount_given);
	assert(!args.lambda_mul_given);
	assert(!args.loadonly_given);
	assert(!args.moderate_given);
	assert(!args.no_nodelay_given);
	assert(!args.numreqperconn_given);
	assert(!args.password_given);
	assert(!args.qps_function_given);
	assert(!args.qps_warmup_given);
	assert(!args.quiet_given);
	assert(!args.report_stats_given);
	assert(!args.roundrobin_given);
	assert(!args.save_given);
	assert(!args.scan_given);
	assert(!args.scan_search_given);
	assert(!args.search_given);
	assert(!args.skip_given);
	assert(!args.src_port_given);
	assert(!args.stop_latency_given);
	assert(!args.username_given);
	assert(!args.wait_given);
	assert(!args.warmup_given);
}
