#include <string.h>

#include "common.h"
#include "util.h"

void close_agent_sockets(void) {
  for (auto s: agent_sockets)
    s->close();
}

zmq::message_t s_recv_msg(zmq::socket_t &socket) {
  bool ret;
  zmq::message_t message;
  ret = socket.recv(&message);
  if (!ret) {
    char endpoint[64];
    size_t size = sizeof(endpoint);
    socket.getsockopt(ZMQ_LAST_ENDPOINT, endpoint, &size);
    CLOSE_AND_DIE("s_recv() timeout (%s)", endpoint);
  }

  return message;
}

std::string s_recv (zmq::socket_t &socket) {
  zmq::message_t message = s_recv_msg(socket);
  return std::string(static_cast<char*>(message.data()), message.size());
}

//  Convert string to 0MQ string and send to socket
bool s_send (zmq::socket_t &socket, const std::string &string) {
  zmq::message_t message(string.size());
  memcpy(message.data(), string.data(), string.size());

  return socket.send(message);
}

void init_agent(zmq::socket_t &socket, options_t &options, vector<string> &servers) {
  zmq::message_t request;

  socket.recv(&request);

  zmq::message_t num(sizeof(int));
  *((int *) num.data()) = args.threads_arg * args.lambda_mul_arg;
  socket.send(num);

  memcpy(&options, request.data(), sizeof(options));

  if (args.depth_given) {
    options.depth = args.depth_arg;
  }

  V("depth = %d\n", options.depth);

  for (int i = 0; i < options.server_given; i++) {
    servers.push_back(s_recv(socket));
    s_send(socket, "ACK");
  }

  for (auto i: servers) {
    V("Got server = %s", i.c_str());
  }

  options.threads = args.threads_arg;

  socket.recv(&request);
  options.lambda_denom = *((int *) request.data());
  s_send(socket, "THANKS");

  //    V("AGENT SLEEPS"); sleep(1);
  options.lambda = (double) options.qps / options.lambda_denom * args.lambda_mul_arg;

  V("lambda_denom = %d, lambda = %f, qps = %d",
    options.lambda_denom, options.lambda, options.qps);
}

void prep_agent(const vector<string>& servers, options_t& options) {
  int sum = options.lambda_denom;
  if (args.measure_connections_given)
    sum = args.measure_connections_arg * options.server_given * options.threads;

  int master_sum = sum;
  if (args.measure_qps_given) {
    sum = 0;
    if (options.qps) options.qps -= args.measure_qps_arg;
  }

  for (auto s: agent_sockets) {
    zmq::message_t message(sizeof(options_t));

    memcpy((void *) message.data(), &options, sizeof(options_t));
    s->send(message);

    zmq::message_t rep;
    rep = s_recv_msg(*s);
    unsigned int num = *((int *) rep.data());

    sum += options.connections * (options.roundrobin ?
            (servers.size() > num ? servers.size() : num) : 
            (servers.size() * num));

    for (auto i: servers) {
      s_send(*s, i);
      string rep = s_recv(*s);
    }
  }

  // Adjust options_t according to --measure_* arguments.
  options.lambda_denom = sum;
  options.lambda = (double) options.qps / options.lambda_denom *
    args.lambda_mul_arg;

  V("lambda_denom = %d", sum);

  if (args.measure_qps_given) {
    double master_lambda = (double) args.measure_qps_arg / master_sum;

    if (options.qps && master_lambda > options.lambda)
      V("warning: master_lambda (%f) > options.lambda (%f)",
        master_lambda, options.lambda);

    options.lambda = master_lambda;
  }

  if (args.measure_depth_given) options.depth = args.measure_depth_arg;

  for (auto s: agent_sockets) {
    zmq::message_t message(sizeof(sum));
    *((int *) message.data()) = sum;
    s->send(message);
    string rep = s_recv(*s);
  }

  // Master sleeps here to give agents a chance to connect to
  // memcached server before the master, so that the master is never
  // the very first set of connections.  Is this reasonable or
  // necessary?  Most probably not.
  V("MASTER SLEEPS"); sleep_time(1.5);
}

bool agent_stats_tx_stats(zmq::socket_t *s) {
  zmq::message_t zmsg(sizeof(struct agent_stats_msg));
  struct agent_stats_msg *msg = (struct agent_stats_msg *) zmsg.data();
  msg->type = msg->STATS;
  return s->send(zmsg);
}

static bool agent_stats_tx_stop(zmq::socket_t *s) {
  zmq::message_t zmsg(sizeof(struct agent_stats_msg));
  struct agent_stats_msg *msg = (struct agent_stats_msg *) zmsg.data();
  msg->type = msg->STOP;
  return s->send(zmsg);
}

void finish_agent(ConnectionStats &stats) {
  bool ret;
  for (auto s: agent_sockets) {
    agent_stats_tx_stats(s);

    AgentStats as;
    zmq::message_t message;

    ret = s->recv(&message);
    assert(ret == true);
    memcpy(&as, message.data(), sizeof(as));
    stats.accumulate(as);

    agent_stats_tx_stop(s);
    s_recv(*s);
  }
}

/*
 * This synchronization routine is ridiculous because the master only
 * has a ZMQ_REQ socket to the agents, but it needs to wait for a
 * message from each agent before it releases them.  In order to get
 * the ZMQ socket into a state where it'll allow the agent to send it
 * a message, it must first send a message ("sync_req").  In order to
 * not leave the socket dangling with an incomplete transaction, the
 * agent must send a reply ("ack").
 *
 * Without this stupid complication it would be:
 *
 * For each agent:
 *   Agent -> Master: sync
 * For each agent:
 *   Master -> Agent: proceed
 *
 * In this way, all agents must arrive at the barrier and the master
 * must receive a message from each of them before it continues.  It
 * then broadcasts the message to proceed, which reasonably limits
 * skew.
 */

void sync_agent(zmq::socket_t* socket) {
  //  V("agent: synchronizing");

  if (args.agent_given) {
    for (auto s: agent_sockets)
      s_send(*s, "sync_req");

    /* The real sync */
    for (auto s: agent_sockets)
      if (s_recv(*s).compare(string("sync")))
        CLOSE_AND_DIE("sync_agent[M]: out of sync [1]");
    for (auto s: agent_sockets)
      s_send(*s, "proceed");
    /* End sync */

    for (auto s: agent_sockets)
      if (s_recv(*s).compare(string("ack")))
        DIE("sync_agent[M]: out of sync [2]");
  } else if (args.agentmode_given) {
    if (s_recv(*socket).compare(string("sync_req")))
      DIE("sync_agent[A]: out of sync [1]");

    /* The real sync */
    s_send(*socket, "sync");
    if (s_recv(*socket).compare(string("proceed")))
      DIE("sync_agent[A]: out of sync [2]");
    /* End sync */

    s_send(*socket, "ack");
  }

  //  V("agent: synchronized");
}

static int triangle(struct qps_function_triangle *p, double t) {
  double t0 = fmod(t, p->period);
  double t1 = (p->period - p->max_hold) / 2;
  if (t0 < t1)
    return p->min + t0 * (p->max - p->min) / t1;
  else if (t0 < t1 + p->max_hold)
    return p->max;
  else
    return p->max - (t0 - t1 - p->max_hold) * (p->max - p->min) / t1;
}

static int qtriangle(struct qps_function_qtriangle *p, double t) {
  int value = triangle(&p->triangle, t);
  return (value - p->triangle.min) / p->step * p->step + p->triangle.min;
}

static int sin_noise(struct qps_function_sin_noise *p, double t) {
	static unsigned short xsubi[3];
	static double noise;
	static double prv_noise_timestamp;

	double offset = (double) (p->min + p->max) / 2;
	double amplitude = p->max - offset;
	double sin_value = amplitude * sin(t * 2 * M_PI / p->period) + offset;

	if (t - prv_noise_timestamp >= p->noise_update_interval) {
		noise = (erand48(xsubi) * 2 - 1) * p->noise_amplitude;
		prv_noise_timestamp = t;
	}
	return sin_value + noise;
}

int qps_function_calc(options_t *options, double t) {
  if (t <= options->qps_function.warmup_time && options->qps_function.warmup_rate)
    return options->qps_function.warmup_rate;

  t = max(0.0, t - options->qps_function.warmup_time);
  switch (options->qps_function.type) {
  case TRIANGLE:
    return triangle(&options->qps_function.params.triangle, t);
  case QTRIANGLE:
    return qtriangle(&options->qps_function.params.qtriangle, t);
  case SIN_NOISE:
    return sin_noise(&options->qps_function.params.sin_noise, t);
  case NONE:
    assert(false);
  }
  assert(false);
}

void qps_function_init(options_t *options) {
  char *type, *rest;
  int ret;

  if (!args.qps_function_given) {
    options->qps_function.type = qps_function_type::NONE;
    return;
  }

  options->qps_function.warmup_time = 0;
  options->qps_function.warmup_rate = 0;
  if (args.qps_warmup_given) {
    ret = sscanf(args.qps_warmup_arg, "%d:%d", &options->qps_function.warmup_time, &options->qps_function.warmup_rate);
    if (ret < 1)
      DIE("Invalid --qps-warmup argument");
  }

  type = strtok_r(args.qps_function_arg, ":", &rest);
  if (!strcasecmp(type, "triangle")) {
    struct qps_function_triangle *p = &options->qps_function.params.triangle;
    options->qps_function.type = qps_function_type::TRIANGLE;
    ret = sscanf(rest, "%d:%d:%lf:%lf", &p->min, &p->max, &p->period, &p->max_hold);
    if (ret != 4)
      DIE("Invalid --qps-function argument");
  } else if (!strcasecmp(type, "qtriangle")) {
    struct qps_function_qtriangle *p = &options->qps_function.params.qtriangle;
    options->qps_function.type = qps_function_type::QTRIANGLE;
    ret = sscanf(rest, "%d:%d:%lf:%d", &p->triangle.min, &p->triangle.max, &p->triangle.period, &p->step);
    if (ret != 4)
      DIE("Invalid --qps-function argument");
    p->triangle.max_hold = 0;
  } else if (!strcasecmp(type, "sin_noise")) {
    struct qps_function_sin_noise *p = &options->qps_function.params.sin_noise;
    options->qps_function.type = qps_function_type::SIN_NOISE;
    ret = sscanf(rest, "%d:%d:%lf:%d:%lf", &p->min, &p->max, &p->period, &p->noise_amplitude, &p->noise_update_interval);
    if (ret != 5)
      DIE("Invalid --qps-function argument");
  } else {
    DIE("Invalid --qps-function argument");
  }
  args.qps_given = true;
  args.qps_arg = qps_function_calc(options, 0);
}

static void scan_search_rx_ctx(struct agent_stats_msg *msg) {
  assert(msg->type == msg->SCAN_SEARCH_CTX);
  scans_ctx = msg->scan_search_ctx;
}

void scan_search_init(options_t *options) {
  options->scan_search_enabled = false;
  if (!args.scan_search_given)
    return;
  int ret = sscanf(args.scan_search_arg, "%d:%d,%d:%d:%d,%d:%d", &scan_search_params.n,
                   &scan_search_params.val, &scan_search_params.start0, &scan_search_params.step0,
                   &scan_search_params.stop0, &scan_search_params.step1, &scan_search_params.step2);
  if (ret != 7)
    DIE("Invalid --scan-search argument");
  options->scan_search_enabled = true;
  scan_search_params.start0 *= 1000;
  scan_search_params.step0 *= 1000;
  scan_search_params.stop0 *= 1000;
  scan_search_params.step1 *= 1000;
  scan_search_params.step2 *= 1000;
  args.qps_arg = scan_search_params.start0;
}

void connect_agent(void) {
  for (unsigned int i = 0; i < args.agent_given; i++) {
    zmq::socket_t *s = new zmq::socket_t(context, ZMQ_REQ);
    string host = string("tcp://") + string(args.agent_arg[i]) +
      string(":") + string(args.agent_port_arg);
    s->connect(host.c_str());
    int timeout = 10000;
    s->setsockopt(ZMQ_RCVTIMEO, &timeout, sizeof(timeout));

    agent_sockets.push_back(s);
  }
}

void print_stats(ConnectionStats &stats, double boot_time, double peak_qps) {
  stats.print_header();
  stats.print_stats("read",   stats.get_sampler);
  stats.print_stats("update", stats.set_sampler);
  stats.print_stats("op_q",   stats.op_sampler);

  int total = stats.gets + stats.sets;

  printf("\nTotal QPS = %.1f (%d / %.1fs)\n",
         total / (stats.stop - stats.start),
         total, stats.stop - stats.start);

  if (args.search_given && peak_qps > 0.0)
    printf("Peak QPS  = %.1f\n", peak_qps);

  printf("\n");

  printf("Misses = %" PRIu64 " (%.1f%%)\n", stats.get_misses,
         (double) stats.get_misses/stats.gets*100);

  printf("Retransmitted TXs = %" PRIu64 "\n", stats.retransmits);

  printf("Skipped TXs = %" PRIu64 " (%.1f%%)\n\n", stats.skips,
         (double) stats.skips / total * 100);

  printf("RX %10" PRIu64 " bytes : %6.1f MB/s\n",
         stats.rx_bytes,
         (double) stats.rx_bytes / 1024 / 1024 / (stats.stop - stats.start));
  printf("TX %10" PRIu64 " bytes : %6.1f MB/s\n",
         stats.tx_bytes,
         (double) stats.tx_bytes / 1024 / 1024 / (stats.stop - stats.start));

  if (args.save_given) {
    printf("Saving latency samples to %s.\n", args.save_arg);

    FILE *file;
    if ((file = fopen(args.save_arg, "w")) == NULL)
      DIE("--save: failed to open %s: %s", args.save_arg, strerror(errno));

#if PIGGY_BACK_STATS
    for (auto i: stats.get_sampler.samples) {
      fprintf(file, "%f %f cpu_nr= %d recv_timestamp= %ld before_syscall_latency= %d send_latency= %d recv_poll_iteration= %d send_poll_iteration_lag= %d\n", i.start_time - boot_time, i.time(), i.piggy_back_stats.cpu_nr, i.piggy_back_stats.recv_timestamp, i.piggy_back_stats.before_syscall_latency, i.piggy_back_stats.send_latency, i.piggy_back_stats.recv_poll_iteration, i.piggy_back_stats.send_poll_iteration_lag);
    }
#else
    for (auto i: stats.get_sampler.samples) {
      fprintf(file, "%d %f %f %s(%ld)\n", i.port, i.start_time - boot_time, i.time(), i.type == Operation::GET ? "GET" : (i.type == Operation::SET ? "SET" : "UNK"), i.key.size());
    }
    for (auto i: stats.set_sampler.samples) {
      fprintf(file, "%d %f %f %s(%ld)\n", i.port, i.start_time - boot_time, i.time(), i.type == Operation::GET ? "GET" : (i.type == Operation::SET ? "SET" : "UNK"), i.key.size());
    }
#endif
  }
}

void* agent_stats_thread(void *arg) {
  struct agent_stats_thread_data *data = (struct agent_stats_thread_data *) arg;
  zmq::message_t zmsg;
  struct agent_stats_msg *msg;

  while (1) {
    data->socket->recv(&zmsg);
    assert(zmsg.size() == sizeof(struct agent_stats_msg));
    msg = (struct agent_stats_msg *) zmsg.data();

    if (msg->type == msg->STOP) {
      received_stop = true;
      pthread_barrier_wait(&finish_barrier);
      s_send(*data->socket, "ok");
      break;
    }

    if (msg->type == msg->SCAN_SEARCH_CTX) {
      scan_search_rx_ctx(msg);
      s_send(*data->socket, "ok");
      continue;
    }

    assert(msg->type == msg->STATS);

    AgentStats as = {0};

    for (Connection *conn: all_connections) {
      as.rx_bytes += conn->stats.rx_bytes;
      as.tx_bytes += conn->stats.tx_bytes;
      as.gets += conn->stats.gets;
      as.sets += conn->stats.sets;
      as.get_misses += conn->stats.get_misses;
      as.skips += conn->stats.skips;
      as.retransmits += conn->stats.retransmits;
    }

    zmq::message_t reply(sizeof(as));
    memcpy(reply.data(), &as, sizeof(as));
    data->socket->send(reply);
  }

  return NULL;
}

void args_to_options(options_t* options) {
  //  bzero(options, sizeof(options_t));
  options->connections = args.connections_arg;
  options->blocking = args.blocking_given;
  options->qps = args.qps_arg;
  options->measure_qps = args.measure_qps_given ? args.measure_qps_arg : 0;
  options->threads = args.threads_arg;
  options->server_given = args.server_given;
  options->roundrobin = args.roundrobin_given;

  int connections = options->connections;
  if (options->roundrobin) {
    connections *= (options->server_given > options->threads ?
                    options->server_given : options->threads);
  } else {
    connections *= options->server_given * options->threads;
  }

  //  if (args.agent_given) connections *= (1 + args.agent_given);

  options->lambda_denom = connections > 1 ? connections : 1;
  if (args.lambda_mul_arg > 1) options->lambda_denom *= args.lambda_mul_arg;

  if (options->threads < 1) options->lambda_denom = 0;

  options->lambda = (double) options->qps / (double) options->lambda_denom * args.lambda_mul_arg;

  //  V("%d %d %d %f", options->qps, options->connections,
  //  connections, options->lambda);

  //  if (args.no_record_scale_given)
  //    options->records = args.records_arg;
  //  else
  options->records = args.records_arg / options->server_given;

  options->binary = args.binary_given;
  options->sasl = args.username_given;

  if (args.password_given)
    strcpy(options->password, args.password_arg);
  else
    strcpy(options->password, "");

  if (args.username_given)
    strcpy(options->username, args.username_arg);
  else
    strcpy(options->username, "");

  D("options->records = %d", options->records);

  if (!options->records) options->records = 1;
  strncpy(options->keysize, args.keysize_arg, sizeof(options->keysize));
  strncpy(options->valuesize, args.valuesize_arg, sizeof(options->valuesize));
  strncpy(options->getcount, args.getcount_arg, sizeof(options->getcount));
  strncpy(options->numreqperconn, args.numreqperconn_arg, sizeof(options->numreqperconn));
  strncpy(options->popularity, args.popularity_arg, sizeof(options->popularity));
  options->permutation_seed = lrand48();
  options->update = args.update_arg;
  options->time = args.time_arg;
  options->loadonly = args.loadonly_given;
  options->depth = args.depth_arg;
  options->no_nodelay = args.no_nodelay_given;
  options->noload = args.noload_given;
  options->iadist = get_distribution(args.iadist_arg);
  strcpy(options->ia, args.iadist_arg);
  options->warmup = args.warmup_given ? args.warmup_arg : 0;
  options->oob_thread = false;
  options->skip = args.skip_given;
  options->moderate = args.moderate_given;
}

static struct {
  double prv_time;
  double start_time;
  ConnectionStats prv_stats;
} report_stats_ctx;

void report_stats_init(void) {
  report_stats_ctx.prv_time = get_time();
  report_stats_ctx.start_time = report_stats_ctx.prv_time;
  printf("# start_time = %f\n", report_stats_ctx.start_time);
  printf("%-6s ", "#time");
  report_stats_ctx.prv_stats.print_header();
}

bool report_stats_is_time(double now) {
  return now - report_stats_ctx.prv_time >= args.report_stats_arg;
}

ConnectionStats report_stats_get(double now, int qps) {
  ConnectionStats stats;
  bool ret;
  for (Connection *conn: all_connections)
    stats.accumulate(conn->stats);

  for (auto s: agent_sockets) {
    agent_stats_tx_stats(s);

    AgentStats as;
    zmq::message_t message;

    ret = s->recv(&message);
    assert(ret == true);
    memcpy(&as, message.data(), sizeof(as));
    stats.accumulate(as);
  }

  stats.start = report_stats_ctx.prv_time;
  stats.stop = now;

  ConnectionStats report_stats = stats;
  report_stats.substract(report_stats_ctx.prv_stats);

  report_stats_ctx.prv_time = now;
  report_stats_ctx.prv_stats = stats;

  return report_stats;
}

void report_stats_print(double now, int qps, ConnectionStats &report_stats) {
  printf("%6.3f ", now - report_stats_ctx.start_time);
  report_stats.print_stats("read", report_stats.get_sampler, false);
  printf(" %8.1f", report_stats.get_qps());
  printf(" %8d\n", qps);
}

char random_char[2 * 1024 * 1024];  // Buffer used to generate random values.

void init_random_stuff() {
  static char lorem[] =
    R"(Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas
turpis dui, suscipit non vehicula non, malesuada id sem. Phasellus
suscipit nisl ut dui consectetur ultrices tincidunt eros
aliquet. Donec feugiat lectus sed nibh ultrices ultrices. Vestibulum
ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia
Curae; Mauris suscipit eros sed justo lobortis at ultrices lacus
molestie. Duis in diam mi. Cum sociis natoque penatibus et magnis dis
parturient montes, nascetur ridiculus mus. Ut cursus viverra
sagittis. Vivamus non facilisis tortor. Integer lectus arcu, sagittis
et eleifend rutrum, condimentum eget sem. Vestibulum tempus tellus non
risus semper semper. Morbi molestie rhoncus mi, in egestas dui
facilisis et.)";

  size_t cursor = 0;

  while (cursor < sizeof(random_char)) {
    size_t max = sizeof(lorem);
    if (sizeof(random_char) - cursor < max)
      max = sizeof(random_char) - cursor;

    memcpy(&random_char[cursor], lorem, max);
    cursor += max;
  }
}
