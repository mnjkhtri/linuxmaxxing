#!/bin/bash

set -e

trap 'ssh $REMOTEHOST pkill $REMOTEBIN' EXIT

scons -sj64

LOCALHOST=`hostname`
REMOTEHOST=icnals02
# RUNLOCAL=agent
RUNLOCAL=master
AGENT_CMDLINE='./mutilateudp -A --threads 4'
MASTER_CMDLINE='./mutilateudp --records=1000000 --time=1 --qps=10000
                --keysize=fb_key --valuesize=fb_value --iadist=fb_ia --update=0
                --server=10.90.44.200:11211 --noload --threads=1
                --connections=4 --measure_connections=32
                --measure_qps=2000 --agent=$AGENT --binary'

if [ $RUNLOCAL == agent ]; then
  AGENT=$LOCALHOST
  LOCALCMD=$AGENT_CMDLINE
  REMOTECMD=`eval echo $MASTER_CMDLINE`
elif [ $RUNLOCAL == master ]; then
  AGENT=$REMOTEHOST
  LOCALCMD=`eval echo $MASTER_CMDLINE`
  REMOTECMD=$AGENT_CMDLINE
fi
REMOTEBIN=${REMOTECMD/%\ */}
REMOTEBIN=${REMOTEBIN:2}

echo -e "\033[32m --- Run local: $LOCALCMD\033[0m"
echo -e "\033[32m --- Run remote: $REMOTECMD\033[0m"

scp -q $REMOTEBIN $REMOTEHOST:
ssh $REMOTEHOST "ulimit -c unlimited; stdbuf -oL $REMOTECMD" &

if [ x$1 == x -o x$1 == xrun ]; then
  $LOCALCMD
elif [ $1 == strace ]; then
  strace -e '!epoll_wait' -f $LOCALCMD
elif [ $1 == gdb ]; then
  gdb --args $LOCALCMD
fi
