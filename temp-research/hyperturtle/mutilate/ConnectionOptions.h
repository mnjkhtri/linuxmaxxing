#ifndef CONNECTIONOPTIONS_H
#define CONNECTIONOPTIONS_H

#include "distributions.h"

enum qps_function_type {
  NONE,
  TRIANGLE,
  QTRIANGLE,
  SIN_NOISE,
};

struct qps_function_triangle {
  int min;
  int max;
  double period;
  double max_hold;
};

struct qps_function_qtriangle {
  struct qps_function_triangle triangle;
  int step;
};

struct qps_function_sin_noise {
  int min;
  int max;
  double period;
  int noise_amplitude;
  double noise_update_interval;
};

struct qps_function_info {
  enum qps_function_type type;
  int warmup_time;
  int warmup_rate;
  union {
    struct qps_function_triangle triangle;
    struct qps_function_qtriangle qtriangle;
    struct qps_function_sin_noise sin_noise;
  } params;
};

typedef struct {
  int connections;
  char numreqperconn[32];
  bool blocking;
  double lambda;
  int qps;
  int measure_qps;
  int records;

  bool binary;
  bool sasl;
  char username[32];
  char password[32];

  char keysize[32];
  char valuesize[32];
  char getcount[32];
  // int keysize;
  //  int valuesize;
  char ia[32];
  char popularity[32];
  long permutation_seed;

  // qps_per_connection
  // iadist

  double update;
  int time;
  bool loadonly;
  int depth;
  bool no_nodelay;
  bool noload;
  int threads;
  enum distribution_t iadist;
  int warmup;
  bool skip;

  bool roundrobin;
  int server_given;
  int lambda_denom;

  bool oob_thread;

  bool moderate;

  struct qps_function_info qps_function;
  bool scan_search_enabled;
} options_t;

#endif // CONNECTIONOPTIONS_H
