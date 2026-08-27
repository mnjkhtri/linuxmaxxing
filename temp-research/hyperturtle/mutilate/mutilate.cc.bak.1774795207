#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <queue>
#include <string>
#include <vector>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/util.h>

#include "config.h"

#ifdef HAVE_LIBZMQ
#include <zmq.hpp>
#endif

#include "AdaptiveSampler.h"
#include "AgentStats.h"
#ifndef HAVE_PTHREAD_BARRIER_INIT
#include "barrier.h"
#endif
#include "cmdline.h"
#include "common.h"
#include "TCPConnection.h"
#include "ConnectionOptions.h"
#include "log.h"
#include "mutilate.h"
#include "util.h"

#define MIN(a,b) ((a) < (b) ? (a) : (b))

using namespace std;

gengetopt_args_info args;

#ifdef HAVE_LIBZMQ
vector<zmq::socket_t*> agent_sockets;
zmq::context_t context(1);
#endif

struct thread_data {
  const vector<string> *servers;
  options_t *options;
  bool master;  // Thread #0, not to be confused with agent master.
#ifdef HAVE_LIBZMQ
  zmq::socket_t *socket;
#endif
  vector<int> src_ports;
};

// struct evdns_base *evdns;

pthread_barrier_t barrier;
pthread_barrier_t finish_barrier;

double boot_time;

pthread_mutex_t all_connections_mutex;
vector<Connection*> all_connections;

struct scan_search_params_struct scan_search_params;

struct scan_search_ctx scans_ctx;

void go(const vector<string> &servers, options_t &options,
        ConnectionStats &stats
#ifdef HAVE_LIBZMQ
, zmq::socket_t* socket = NULL
#endif
);

void do_mutilate(const vector<string> &servers, options_t &options,
                 ConnectionStats &stats, const vector<int>& src_ports, bool master = true
#ifdef HAVE_LIBZMQ
, zmq::socket_t* socket = NULL
#endif
);
void args_to_options(options_t* options);
void* thread_main(void *arg);

#ifdef HAVE_LIBZMQ
/*
 * Agent protocol
 *
 * PREPARATION PHASE
 *
 * 1. Master -> Agent: options_t
 *
 * options_t contains most of the information needed to drive the
 * client, including the aggregate QPS that has been requested.
 * However, neither the master nor the agent know at this point how
 * many total connections will be made to the memcached server.
 *
 * 2. Agent -> Master: int num = (--threads) * (--lambda_mul)
 *
 * The agent sends a number to the master indicating how many threads
 * this mutilate agent will spawn, and a mutiplier that weights how
 * many QPS this agent's connections will send relative to unweighted
 * connections (i.e. we can request that a purely load-generating
 * agent or an agent on a really fast network connection be more
 * aggressive than other agents or the master).
 *
 * 3. Master -> Agent: lambda_denom
 *
 * The master aggregates all of the numbers collected in (2) and
 * computes a global "lambda_denom".  Which is essentially a count of
 * the total number of Connections across all mutilate instances,
 * weighted by lambda_mul if necessary.  It broadcasts this number to
 * all agents.
 *
 * Each instance of mutilate at this point adjusts the lambda in
 * options_t sent in (1) to account for lambda_denom.  Note that
 * lambda_mul is specific to each instance of mutilate
 * (i.e. --lambda_mul X) and not sent as part of options_t.
 *
 *   lambda = qps / lambda_denom * args.lambda_mul;
 *
 * RUN PHASE
 *
 * After the PREP phase completes, everyone executes do_mutilate().
 * All clients spawn threads, open connections, load the DB, and wait
 * for all connections to become IDLE.  Following that, they
 * synchronize and finally do the heavy lifting.
 * 
 * [IF WARMUP] -1:  Master <-> Agent: Synchronize
 * [IF WARMUP]  0:  Everyone: RUN for options.warmup seconds.
 * 1. Master <-> Agent: Synchronize
 * 2. Everyone: RUN for options.time seconds.
 * 3. Master -> Agent: Dummy message
 * 4. Agent -> Master: Send AgentStats [w/ RX/TX bytes, # gets/sets]
 * 5. Master -> Agent: Stop message
 * 6. Agent -> Master: Dummy message
 *
 * The master then aggregates AgentStats across all agents with its
 * own ConnectionStats to compute overall statistics.
 */

void agent() {
  zmq::context_t context(1);

  zmq::socket_t socket(context, ZMQ_REP);
  socket.bind((string("tcp://*:")+string(args.agent_port_arg)).c_str());

  while (true) {
    options_t options;
    vector<string> servers;
    init_agent(socket, options, servers);

    //    if (options.threads > 1)
      pthread_barrier_init(&barrier, NULL, options.threads);
      pthread_barrier_init(&finish_barrier, NULL, options.threads + 1);

    ConnectionStats stats;
    all_connections.clear();

    go(servers, options, stats, &socket);
  }
}

static bool agent_stats_tx_scan_search_ctx(zmq::socket_t *s, struct scan_search_ctx *scan_search_ctx) {
  zmq::message_t zmsg(sizeof(struct agent_stats_msg));
  struct agent_stats_msg *msg = (struct agent_stats_msg *) zmsg.data();
  msg->type = msg->SCAN_SEARCH_CTX;
  msg->scan_search_ctx = *scan_search_ctx;
  return s->send(zmsg);
}
#endif

string name_to_ipaddr(string host) {
  char *s_copy = new char[host.length() + 1];
  strcpy(s_copy, host.c_str());

  char *saveptr = NULL;  // For reentrant strtok().

  char *h_ptr = strtok_r(s_copy, ":", &saveptr);
  char *p_ptr = strtok_r(NULL, ":", &saveptr);

  char ipaddr[16];

  if (h_ptr == NULL)
    DIE("strtok(.., \":\") failed to parse %s", host.c_str());

  string hostname = h_ptr;
  string port = "11211";
  if (p_ptr) port = p_ptr;

  struct evutil_addrinfo hints;
  struct evutil_addrinfo *answer = NULL;
  int err;

  /* Build the hints to tell getaddrinfo how to act. */
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC; /* v4 or v6 is fine. */
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP; /* We want a TCP socket */
  /* Only return addresses we can use. */
  hints.ai_flags = EVUTIL_AI_ADDRCONFIG;

  /* Look up the hostname. */
  err = evutil_getaddrinfo(h_ptr, NULL, &hints, &answer);
  if (err < 0) {
    DIE("Error while resolving '%s': %s",
        host.c_str(), evutil_gai_strerror(err));
  }

  if (answer == NULL) DIE("No DNS answer.");

  void *ptr = NULL;
  switch (answer->ai_family) {
  case AF_INET:
    ptr = &((struct sockaddr_in *) answer->ai_addr)->sin_addr;
    break;
  case AF_INET6:
    ptr = &((struct sockaddr_in6 *) answer->ai_addr)->sin6_addr;
    break;
  }

  inet_ntop (answer->ai_family, ptr, ipaddr, 16);

  D("Resolved %s to %s", h_ptr, (string(ipaddr) + ":" + string(port)).c_str());

  delete[] s_copy;

  return string(ipaddr) + ":" + string(port);
}

bool qps_function_enabled(options_t *options) {
  return options->qps_function.type != qps_function_type::NONE;
}

void qps_function_adjust(options_t *options, vector<TCPConnection*>& connections, int qps) {
  for (TCPConnection *conn: connections) {
    conn->options.lambda = (double) qps / (double) options->lambda_denom * args.lambda_mul_arg;
    conn->iagen->set_lambda(conn->options.lambda);
  }
}

static bool scan_search_enabled(options_t *options) {
  return options->scan_search_enabled;
}

static int scan_search_calc() {
  return scans_ctx.qps;
}

static void scan_search_tx_ctx() {
  for (auto s: agent_sockets) {
    agent_stats_tx_scan_search_ctx(s, &scans_ctx);
    assert(s_recv(*s) == "ok");
  }
}

static void scan_search_start() {
  scans_ctx.qps = scan_search_params.start0;
  scans_ctx.step = 1;
  scan_search_tx_ctx();
}

static void scan_search_wait() {
  while (scans_ctx.qps == 0)
    usleep(5000);
}

static bool scan_search_update(ConnectionStats *stats) {
  bool ret = true;

  if (stats->get_nth(scan_search_params.n) > scan_search_params.val) {
    switch (scans_ctx.region) {
    case 0:
      ret = false;
      break;
    case 1:
      scans_ctx.start2 = max(scan_search_params.stop0, (int) (stats->get_qps() - 2 * scan_search_params.step1));
      scans_ctx.qps = scans_ctx.start2;
      scans_ctx.region++;
      scans_ctx.step = 1;
      ret = true;
      break;
    case 2:
      ret = false;
      break;
    default:
      assert(false);
    }
  } else {
    switch (scans_ctx.region) {
    case 0:
      scans_ctx.qps = scan_search_params.start0 + scans_ctx.step * scan_search_params.step0;
      scans_ctx.step++;
      if (scans_ctx.qps >= scan_search_params.stop0) {
        scans_ctx.qps = scan_search_params.stop0;
        scans_ctx.region++;
        scans_ctx.step = 1;
      }
      break;
    case 1:
      scans_ctx.qps = scan_search_params.stop0 + scans_ctx.step * scan_search_params.step1;
      scans_ctx.step++;
      break;
    case 2:
      scans_ctx.qps = scans_ctx.start2 + scans_ctx.step * scan_search_params.step2;
      scans_ctx.step++;
      break;
    default:
      assert(false);
    }
  }

  if (ret)
    scan_search_tx_ctx();

  return ret;
}

int main(int argc, char **argv) {
  if (cmdline_parser(argc, argv, &args) != 0) exit(-1);

  for (unsigned int i = 0; i < args.verbose_given; i++)
    log_level = (log_level_t) ((int) log_level - 1);

  if (args.quiet_given) log_level = QUIET;

  if (args.depth_arg < 1) DIE("--depth must be >= 1");
  //  if (args.valuesize_arg < 1 || args.valuesize_arg > 1024*1024)
  //    DIE("--valuesize must be >= 1 and <= 1024*1024");
  if (args.qps_arg < 0) DIE("--qps must be >= 0");
  if (args.update_arg < 0.0 || args.update_arg > 1.0)
    DIE("--update must be >= 0.0 and <= 1.0");
  if (args.time_arg < 1) DIE("--time must be >= 1");
  //  if (args.keysize_arg < MINIMUM_KEY_LENGTH)
  //    DIE("--keysize must be >= %d", MINIMUM_KEY_LENGTH);
  if (args.connections_arg < 1 || args.connections_arg > MAXIMUM_CONNECTIONS)
    DIE("--connections must be between [1,%d]", MAXIMUM_CONNECTIONS);
  //  if (get_distribution(args.iadist_arg) == -1)
  //    DIE("--iadist invalid: %s", args.iadist_arg);
  if (!args.server_given && !args.agentmode_given)
    DIE("--server or --agentmode must be specified.");

  // TODO: Discover peers, share arguments.

  init_random_stuff();
  boot_time = get_time();
  srand48(boot_time * 1000000);
  setvbuf(stdout, NULL, _IONBF, 0);

  //  struct event_base *base;

  //  if ((base = event_base_new()) == NULL) DIE("event_base_new() fail");
  //  evthread_use_pthreads();

  //  if ((evdns = evdns_base_new(base, 1)) == 0) DIE("evdns");

#ifdef HAVE_LIBZMQ
  if (args.agentmode_given) {
    agent();
    return 0;
  } else if (args.agent_given) {
    connect_agent();
  }
#endif

  options_t options;
  qps_function_init(&options);
  scan_search_init(&options);
  args_to_options(&options);

  pthread_barrier_init(&barrier, NULL, options.threads);

  vector<string> servers;
  for (unsigned int s = 0; s < args.server_given; s++)
    servers.push_back(name_to_ipaddr(string(args.server_arg[s])));

  ConnectionStats stats;

  double peak_qps = 0.0;

  if (args.search_given) {
    char *n_ptr = strtok(args.search_arg, ":");
    char *x_ptr = strtok(NULL, ":");

    if (n_ptr == NULL || x_ptr == NULL) DIE("Invalid --search argument");

    int n = atoi(n_ptr);
    int x = atoi(x_ptr);

    I("Search-mode.  Find QPS @ %dus %dth percentile.", x, n);

    int high_qps = 2000000;
    int low_qps = 1; // 5000;
    double nth;
    int cur_qps;

    go(servers, options, stats);

    nth = stats.get_nth(n);
    peak_qps = stats.get_qps();
    high_qps = stats.get_qps();
    cur_qps = stats.get_qps();

    I("peak qps = %d, nth = %.1f", high_qps, nth);

    if (nth > x) {
      //    while ((high_qps > low_qps * 1.02) && cur_qps > 10000) {
    while ((high_qps > low_qps * 1.02) && cur_qps > (peak_qps * .1)) {
      cur_qps = (high_qps + low_qps) / 2;

      args_to_options(&options);

      options.qps = cur_qps;
      options.lambda = (double) options.qps / (double) options.lambda_denom * args.lambda_mul_arg;

      stats = ConnectionStats();

      go(servers, options, stats);

      nth = stats.get_nth(n);

      I("cur_qps = %d, get_qps = %f, nth = %f", cur_qps, stats.get_qps(), nth);

      if (nth > x /*|| cur_qps > stats.get_qps() * 1.05*/) high_qps = cur_qps;
      else low_qps = cur_qps;
    }

    //    while (nth > x && cur_qps > 10000) { // > low_qps) { // 10000) {
      //    while (nth > x && cur_qps > 10000 && cur_qps > (low_qps * 0.90)) {
    while (nth > x && cur_qps > (peak_qps * .1) && cur_qps > (low_qps * 0.90)) {
      cur_qps = cur_qps * 98 / 100;

      args_to_options(&options);

      options.qps = cur_qps;
      options.lambda = (double) options.qps / (double) options.lambda_denom * args.lambda_mul_arg;

      stats = ConnectionStats();

      go(servers, options, stats);

      nth = stats.get_nth(n);

      I("cur_qps = %d, get_qps = %f, nth = %f", cur_qps, stats.get_qps(), nth);
    }

    }
  } else if (args.scan_given) {
    char *min_ptr = strtok(args.scan_arg, ":");
    char *max_ptr = strtok(NULL, ":");
    char *step_ptr = strtok(NULL, ":");

    if (min_ptr == NULL || min_ptr == NULL || step_ptr == NULL)
      DIE("Invalid --scan argument");

    int min = atoi(min_ptr);
    int max = atoi(max_ptr);
    int step = atoi(step_ptr);

    printf("%-7s %7s %7s %7s %7s %7s %7s %7s %7s %7s %8s %8s\n",
           "#type", "avg", "min", "1st", "5th", "10th",
           "50th", "90th", "95th", "99th", "QPS", "target");

    for (int q = min; q <= max; q += step) {
      args_to_options(&options);

      options.qps = q;
      options.lambda = (double) options.qps / (double) options.lambda_denom * args.lambda_mul_arg;
      //      options.lambda = (double) options.qps / options.connections /
      //        args.server_given /
      //        (args.threads_arg < 1 ? 1 : args.threads_arg);

      stats = ConnectionStats();

      go(servers, options, stats);

      stats.print_stats("read", stats.get_sampler, false);
      printf(" %8.1f", stats.get_qps());
      printf(" %8d\n", q);
    }    
  } else {
    go(servers, options, stats);
  }

  if (!args.scan_given && !args.loadonly_given)
    print_stats(stats, boot_time, peak_qps);

  //  if (args.threads_arg > 1) 
    pthread_barrier_destroy(&barrier);

#ifdef HAVE_LIBZMQ
  if (args.agent_given) {
    for (auto i: agent_sockets) delete i;
  }
#endif

  // evdns_base_free(evdns, 0);
  // event_base_free(base);

  cmdline_parser_free(&args);
}

void populate_src_ports(vector<int>& src_ports, int offset, int count) {
  if (args.src_port_given == 0)
    return;

  for (int c = 0; c < count; c++) {
    int src_port = atoi(args.src_port_arg[offset + c]);
    assert(0 < src_port && src_port <= 0xffff);
    src_ports.push_back(src_port);
  }
}

void go(const vector<string>& servers, options_t& options,
        ConnectionStats &stats
#ifdef HAVE_LIBZMQ
, zmq::socket_t* socket
#endif
) {
#ifdef HAVE_LIBZMQ
  if (args.agent_given > 0) {
    prep_agent(servers, options);
  }
#endif

  if (options.threads > 1) {
    pthread_t pt[options.threads];
    struct thread_data td[options.threads];
#ifdef __clang__
    vector<string>* ts = static_cast<vector<string>*>(alloca(sizeof(vector<string>) * options.threads));
#else
    vector<string> ts[options.threads];
#endif

    int current_cpu = -1;

    int conns = args.measure_connections_given ? args.measure_connections_arg :
      options.connections;

    if (args.src_port_given && args.src_port_given < (unsigned) conns * options.threads)
      DIE("need at least %d source ports. %d were given.", conns * options.threads, args.src_port_given);

    for (int t = 0; t < options.threads; t++) {
      td[t].options = &options;
#ifdef HAVE_LIBZMQ
      td[t].socket = socket;
#endif
      if (t == 0) td[t].master = true;
      else td[t].master = false;

      if (options.roundrobin) {
        for (unsigned int i = (t % servers.size());
             i < servers.size(); i += options.threads)
          ts[t].push_back(servers[i % servers.size()]);

        td[t].servers = &ts[t];
      } else {
        td[t].servers = &servers;
      }

      populate_src_ports(td[t].src_ports, t * conns, conns);

      pthread_attr_t attr;
      pthread_attr_init(&attr);

      if (args.affinity_given) {
        int max_cpus = 8 * sizeof(cpu_set_t);
        cpu_set_t m;
        CPU_ZERO(&m);
        sched_getaffinity(0, sizeof(cpu_set_t), &m);

        for (int i = 0; i < max_cpus; i++) {
          int c = (current_cpu + i + 1) % max_cpus;
          if (CPU_ISSET(c, &m)) {
            CPU_ZERO(&m);
            CPU_SET(c, &m);
            int ret;
            if ((ret = pthread_attr_setaffinity_np(&attr,
                                                   sizeof(cpu_set_t), &m)))
              DIE("pthread_attr_setaffinity_np(%d) failed: %s",
                  c, strerror(ret));
            current_cpu = c;
            break;
          }
        }
      }

      if (pthread_create(&pt[t], &attr, thread_main, &td[t]))
        DIE("pthread_create() failed");
    }

    for (int t = 0; t < options.threads; t++) {
      ConnectionStats *cs;
      if (pthread_join(pt[t], (void**) &cs)) DIE("pthread_join() failed");
      stats.accumulate(*cs);
      delete cs;
    }
  } else if (options.threads == 1) {
    vector<int> src_ports;

    int conns = args.measure_connections_given ? args.measure_connections_arg :
      options.connections;

    if (args.src_port_given && args.src_port_given < (unsigned) conns * options.threads)
      DIE("need at least %d source ports. %d were given.", conns * options.threads, args.src_port_given);

    populate_src_ports(src_ports, 0, args.src_port_given);

    do_mutilate(servers, options, stats, src_ports, true
#ifdef HAVE_LIBZMQ
, socket
#endif
);
  } else {
#ifdef HAVE_LIBZMQ
    if (args.agent_given) {
      sync_agent(socket);
    }
#endif
  }

#ifdef HAVE_LIBZMQ
  if (args.agent_given > 0) {
    int total = stats.gets + stats.sets;

    V("Local QPS = %.1f (%d / %.1fs)",
      total / (stats.stop - stats.start),
      total, stats.stop - stats.start);    

    finish_agent(stats);
  }
#endif
}

void* thread_main(void *arg) {
  struct thread_data *td = (struct thread_data *) arg;

  ConnectionStats *cs = new ConnectionStats();

  do_mutilate(*td->servers, *td->options, *cs, td->src_ports, td->master
#ifdef HAVE_LIBZMQ
, td->socket
#endif
);

  return cs;
}

volatile bool received_stop;

void do_mutilate(const vector<string>& servers, options_t& options,
                 ConnectionStats& stats, const vector<int>& src_ports, bool master
#ifdef HAVE_LIBZMQ
, zmq::socket_t* socket
#endif
) {
  int loop_flag =
    (options.blocking || args.blocking_given) ? EVLOOP_ONCE : EVLOOP_ONCE | EVLOOP_NONBLOCK;

  char *saveptr = NULL;  // For reentrant strtok().

  struct event_base *base;
  struct evdns_base *evdns;
  struct event_config *config;

  if ((config = event_config_new()) == NULL) DIE("event_config_new() fail");

#ifdef HAVE_DECL_EVENT_BASE_FLAG_PRECISE_TIMER
  if (event_config_set_flag(config, EVENT_BASE_FLAG_PRECISE_TIMER))
    DIE("event_config_set_flag(EVENT_BASE_FLAG_PRECISE_TIMER) fail");
#endif

  if ((base = event_base_new_with_config(config)) == NULL)
    DIE("event_base_new() fail");

  //  evthread_use_pthreads();

  if ((evdns = evdns_base_new(base, 1)) == 0) DIE("evdns");

  //  event_base_priority_init(base, 2);

  // FIXME: May want to move this to after all connections established.
  double start = get_time();
  double now = start;

  vector<TCPConnection*> connections;
  vector<TCPConnection*> server_lead;

  for (auto s: servers) {
    // Split args.server_arg[s] into host:port using strtok().
    char *s_copy = new char[s.length() + 1];
    strcpy(s_copy, s.c_str());

    char *h_ptr = strtok_r(s_copy, ":", &saveptr);
    char *p_ptr = strtok_r(NULL, ":", &saveptr);

    if (h_ptr == NULL) DIE("strtok(.., \":\") failed to parse %s", s.c_str());

    string hostname = h_ptr;
    string port = "11211";
    if (p_ptr) port = p_ptr;

    delete[] s_copy;

    int conns = args.measure_connections_given ? args.measure_connections_arg :
      options.connections;

    if (args.src_port_given)
      assert((unsigned) conns <= src_ports.size());

    for (int c = 0; c < conns; c++) {
      int src_port = args.src_port_given ? src_ports[c] : 0;
      TCPConnection* conn = new TCPConnection(base, evdns, hostname, port, options,
                                        src_port, args.agentmode_given ? false :
                                        true);
      connections.push_back(conn);
      if (c == 0) server_lead.push_back(conn);
    }
  }

  pthread_mutex_lock(&all_connections_mutex);
  all_connections.insert(all_connections.end(), connections.begin(), connections.end());
  pthread_mutex_unlock(&all_connections_mutex);

  // Wait for all Connections to become IDLE.
  while (1) {
    // FIXME: If all connections become ready before event_base_loop
    // is called, this will deadlock.
    event_base_loop(base, EVLOOP_ONCE);

    bool restart = false;
    for (TCPConnection *conn: connections)
      if (conn->read_state != TCPConnection::IDLE)
        restart = true;

    if (restart) continue;
    else break;
  }

  // Load database on lead connection for each server.
  if (!options.noload) {
    V("Loading database.");

    for (auto c: server_lead) c->start_loading();

    // Wait for all Connections to become IDLE.
    while (1) {
      // FIXME: If all connections become ready before event_base_loop
      // is called, this will deadlock.
      event_base_loop(base, EVLOOP_ONCE);

      bool restart = false;
      for (TCPConnection *conn: connections)
        if (conn->read_state != TCPConnection::IDLE)
          restart = true;

      if (restart) continue;
      else break;
    }
  }

  if (options.loadonly) {
    evdns_base_free(evdns, 0);
    event_base_free(base);
    return;
  }

  // FIXME: Remove.  Not needed, testing only.
  //  // FIXME: Synchronize start_time here across threads/nodes.
  //  pthread_barrier_wait(&barrier);

  // Warmup connection.
  if (options.warmup > 0) {
    if (master) V("Warmup start.");

#ifdef HAVE_LIBZMQ
    if (args.agent_given || args.agentmode_given) {
      if (master) V("Synchronizing.");

      // 1. thread barrier: make sure our threads ready before syncing agents
      // 2. sync agents: all threads across all agents are now ready
      // 3. thread barrier: don't release our threads until all agents ready
      pthread_barrier_wait(&barrier);
      if (master) sync_agent(socket);
      pthread_barrier_wait(&barrier);

      if (master) V("Synchronized.");
    }
#endif

    int old_time = options.time;
    //    options.time = 1;

    start = get_time();
    for (TCPConnection *conn: connections) {
      conn->start_time = start;
      conn->options.time = options.warmup;
      conn->drive_write_machine(); // Kick the Connection into motion.
    }

    while (1) {
      event_base_loop(base, loop_flag);

      //#ifdef USE_CLOCK_GETTIME
      //      now = get_time();
      //#else
      struct timeval now_tv;
      event_base_gettimeofday_cached(base, &now_tv);
      now = tv_to_double(&now_tv);
      //#endif

      bool restart = false;
      for (TCPConnection *conn: connections)
        if (!conn->check_exit_condition(now))
          restart = true;

      if (restart) continue;
      else break;
    }

    bool restart = false;
    for (TCPConnection *conn: connections)
      if (conn->read_state != TCPConnection::IDLE)
        restart = true;

    if (restart) {

    // Wait for all Connections to become IDLE.
    while (1) {
      // FIXME: If there were to use EVLOOP_ONCE and all connections
      // become ready before event_base_loop is called, this will
      // deadlock.  We should check for IDLE before calling
      // event_base_loop.
      event_base_loop(base, EVLOOP_ONCE); // EVLOOP_NONBLOCK);

      bool restart = false;
      for (TCPConnection *conn: connections)
        if (conn->read_state != TCPConnection::IDLE)
          restart = true;

      if (restart) continue;
      else break;
    }
    }

    //    options.time = old_time;
    for (TCPConnection *conn: connections) {
      conn->reset();
      //      conn->stats = ConnectionStats();
      conn->options.time = old_time;
    }

    if (master) V("Warmup stop.");
  }


  // FIXME: Synchronize start_time here across threads/nodes.
  pthread_barrier_wait(&barrier);

  if (master && args.wait_given) {
    if (get_time() < boot_time + args.wait_arg) {
      double t = (boot_time + args.wait_arg)-get_time();
      V("Sleeping %.1fs for -W.", t);
      sleep_time(t);
    }
  }

#ifdef HAVE_LIBZMQ
  if (args.agent_given || args.agentmode_given) {
    if (master) V("Synchronizing.");

    pthread_barrier_wait(&barrier);
    if (master) sync_agent(socket);
    pthread_barrier_wait(&barrier);

    if (master) V("Synchronized.");
  }
#endif

  if (master && !args.scan_given && !args.search_given)
    V("started at %f", get_time());

  start = get_time();
  for (TCPConnection *conn: connections) {
    conn->start_time = start;
    conn->drive_write_machine(); // Kick the Connection into motion.
  }

  pthread_t stats_thread;
  struct agent_stats_thread_data data;

  if (args.agentmode_given && master) {
    data.socket = socket;
    if (pthread_create(&stats_thread, NULL, agent_stats_thread, &data))
      DIE("pthread_create() failed");
  }

  //  V("Start = %f", start);

  if (!args.agentmode_given && args.report_stats_given)
    report_stats_init();

  int stop_latency_n = 0, stop_latency_val = 0;
  if (args.stop_latency_given) {
    char *n_ptr = strtok(args.stop_latency_arg, ":");
    char *x_ptr = strtok(NULL, ":");

    if (n_ptr == NULL || x_ptr == NULL) DIE("Invalid --stop-latency argument");

    stop_latency_n = atoi(n_ptr);
    stop_latency_val = atoi(x_ptr);
  }

  if (scan_search_enabled(&options)) {
    if (!args.agentmode_given)
      scan_search_start();
    else
      scan_search_wait();
  }

  // Main event loop.
  while (1) {
    event_base_loop(base, loop_flag);

    //#if USE_CLOCK_GETTIME
    //    now = get_time();
    //#else
    struct timeval now_tv;
    event_base_gettimeofday_cached(base, &now_tv);
    now = tv_to_double(&now_tv);
    //#endif

    bool restart = false;
    for (TCPConnection *conn: connections)
      if (!conn->check_exit_condition(now))
        restart = true;

    int qps = 0;
    if (qps_function_enabled(&options)) {
      qps = qps_function_calc(&options, now - start);
      if (!args.measure_qps_given)
        qps_function_adjust(&options, connections, qps - options.measure_qps);
    } else if (scan_search_enabled(&options)) {
      qps = scan_search_calc();
      assert(qps != 0);
      if (!args.measure_qps_given)
        qps_function_adjust(&options, connections, qps - options.measure_qps);
    }

    if (!args.agentmode_given && args.report_stats_given && report_stats_is_time(now)) {
      if (!qps_function_enabled(&options) && !scan_search_enabled(&options)) {
        qps = options.qps;
        qps += args.measure_qps_given ? args.measure_qps_arg : 0;
      }
      ConnectionStats stats = report_stats_get(now, qps);
      report_stats_print(now, qps, stats);
      if (now - start > options.qps_function.warmup_time && stop_latency_n && stats.get_nth(stop_latency_n) > stop_latency_val)
        restart = false;
      else if (scan_search_enabled(&options))
        restart = scan_search_update(&stats);
    }

    if (args.agentmode_given)
      restart = !received_stop;

    if (restart) continue;
    else break;
  }

  if (master && !args.scan_given && !args.search_given)
    V("stopped at %f  options.time = %d", get_time(), options.time);

  // Tear-down and accumulate stats.
  for (TCPConnection *conn: connections) {
    stats.accumulate(conn->stats);
    delete conn;
  }

  stats.start = start;
  stats.stop = now;

  event_config_free(config);
  evdns_base_free(evdns, 0);
  event_base_free(base);

  if (args.agentmode_given && received_stop) {
    pthread_barrier_wait(&finish_barrier);
    received_stop = false;
  }

  if (args.agentmode_given && master)
    if (pthread_join(stats_thread, NULL))
      DIE("pthread_join() failed");
}
