#include <assert.h>
#include <pthread.h>
#include <zmq.hpp>
#include <unistd.h>

#include <iostream>

#include <rte_config.h>
#include <rte_ether.h>

#include "DPDKConnection.h"
#include "common.h"
#include "log.h"
#include "mutilate.h"
#include "dpdktcp.h"

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
static vector<string> servers;

static void assert_cmdline(void);

static void open_connections(vector<DPDKConnection *> *connections)
{
	string server;
	int connections_count;
	bool sampling;

	server = args.server_arg[0];
	connections_count = args.measure_connections_arg;
	sampling = true;

	int port = 11211;
	size_t pos = server.find(":");
	if (pos != string::npos) {
		port = stoi(server.substr(pos + 1));
		server = server.substr(0, pos);
	}

	for (int i = 0; i < connections_count; i++) {
		DPDKConnection *conn = new DPDKConnection(server, port, options, sampling);
		connections->push_back(conn);
	}
}

static void start_connections(vector<DPDKConnection *> *connections)
{
	bool ok;
	double start_time = get_time();
	do {
		dpdk_loop();
		ok = true;
		for (DPDKConnection *conn: *connections) {
			if (!conn->connected) {
				ok = false;
				break;
			}
		}

	} while (!ok && get_time() - start_time < 5);

	assert(ok);

	for (DPDKConnection *conn: *connections)
		conn->drive_write_machine();
}

volatile int problem;

static void master(void)
{
	qps_function_init(&options);
	scan_search_init(&options);
	args_to_options(&options);

	connect_agent();

	// Synchronizes with init_agent
	prep_agent({ args.server_arg[0] }, options);

	vector<DPDKConnection *> connections;
	open_connections(&connections);

	// Synchronizes with sync_agent in agent
	sync_agent(NULL);

	start_connections(&connections);

	if (args.report_stats_given)
		report_stats_init();

	all_connections.insert(all_connections.end(), connections.begin(), connections.end());

	double start_time = get_time(), now;
	int idx = 0;
	while (1) {
		dpdk_loop();
		now = get_time();
		if (args.report_stats_given && report_stats_is_time(now)) {
			ConnectionStats stats = report_stats_get(now, -1);
			report_stats_print(now, idx++, stats);
		}
		if (now - start_time > options.time)
			break;
	}

	ConnectionStats stats;
	finish_agent(stats);

	for (DPDKConnection *conn: connections)
		stats.accumulate(conn->stats);

	stats.start = start_time;
	stats.stop = now;

	print_stats(stats, 0, 0);

	for (auto s: agent_sockets)
		delete s;
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
	setvbuf(stdout, NULL, _IOLBF, 0);
	init_random_stuff();

	struct ether_addr my_mac;
	parse_mac(args.my_mac_arg, &my_mac);

	dpdk_init(args.cpu_core_arg, &my_mac, parse_ip(args.my_ip_arg));
	tcp_init();

	// TODO: dpdk doesn't transmit the first packet
	sleep(2);

	master();

	return 0;
}

static void assert_cmdline(void)
{
	assert(!args.affinity_given);
	assert(!args.agentmode_given);
	assert(!args.blocking_given);
	assert(!args.getcount_given);
	assert(!args.lambda_mul_given);
	assert(!args.loadonly_given);
	assert(!args.moderate_given);
	assert(!args.no_nodelay_given);
	assert(!args.numreqperconn_given);
	assert(!args.password_given);
	assert(!args.qps_warmup_given);
	assert(!args.quiet_given);
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
	assert(args.binary_given);
	assert(args.connections_given);
	assert(args.measure_connections_given);
	assert(args.noload_given);
	assert(args.server_given == 1);
	assert(args.threads_arg == 1);
	assert(args.my_mac_given);
	assert(args.server_mac_given);
	assert(args.my_ip_given);
	assert(args.cpu_core_given);
}
