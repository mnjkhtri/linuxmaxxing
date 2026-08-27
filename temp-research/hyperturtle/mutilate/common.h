#pragma once

#include <zmq.hpp>

#include "Connection.h"
#include "ConnectionOptions.h"
#include "ConnectionStats.h"

extern zmq::context_t context;
extern vector<zmq::socket_t*> agent_sockets;

struct scan_search_params_struct {
  int n;
  int val;
  int start0;
  int step0;
  int stop0;
  int step1;
  int step2;
};

struct scan_search_ctx {
  int step;
  int qps;
  int region;
  int start2;
  double start_time1;
  double start_time2;
};

struct agent_stats_msg {
  enum type {
    STATS,
    STOP,
    SCAN_SEARCH_CTX,
  } type;
  union {
    struct scan_search_ctx scan_search_ctx;
  };
};

struct agent_stats_thread_data {
  zmq::socket_t *socket;
};

extern struct scan_search_params_struct scan_search_params;
extern volatile bool received_stop;
extern pthread_barrier_t finish_barrier;
extern struct scan_search_ctx scans_ctx;
extern vector<Connection*> all_connections;

std::string s_recv (zmq::socket_t &socket);
bool s_send (zmq::socket_t &socket, const std::string &string);
void init_agent(zmq::socket_t &socket, options_t &options, vector<string> &servers);
void prep_agent(const vector<string>& servers, options_t& options);
bool agent_stats_tx_stats(zmq::socket_t *s);
void finish_agent(ConnectionStats &stats);
void sync_agent(zmq::socket_t* socket);
int qps_function_calc(options_t *options, double t);
void qps_function_init(options_t *options);
void scan_search_init(options_t *options);
void connect_agent(void);
void print_stats(ConnectionStats &stats, double boot_time, double peak_qps);
void* agent_stats_thread(void *arg);
void args_to_options(options_t* options);
void report_stats_init(void);
bool report_stats_is_time(double now);
ConnectionStats report_stats_get(double now, int qps);
void report_stats_print(double now, int qps, ConnectionStats &report_stats);
void init_random_stuff();
