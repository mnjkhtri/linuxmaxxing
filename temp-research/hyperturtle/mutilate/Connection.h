#pragma once

#include "ConnectionStats.h"

class Connection {
public:
  Connection(bool sampling) : stats(sampling) { };
  ConnectionStats stats;

  enum read_state_enum {
    INIT_READ,
    LOADING,
    IDLE,
    WAITING_FOR_SASL,
    WAITING_FOR_GET,
    WAITING_FOR_GET_DATA,
    WAITING_FOR_END,
    WAITING_FOR_SET,
    MAX_READ_STATE,
  };

  enum write_state_enum {
    INIT_WRITE,
    ISSUING,
    WAITING_FOR_TIME,
    WAITING_FOR_OPQ,
    MAX_WRITE_STATE,
  };
};
