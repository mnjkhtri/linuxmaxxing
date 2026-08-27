#!/usr/bin/env python

import getpass
import os
import select
import signal
import subprocess
import sys
import threading

class Runner:
  def __init__(self):
    self.exiting = False
    self.procs = {}
    self.unblockr, self.unblockw = os.pipe()
    t = threading.Thread(target = self.reader)
    t.start()

  def execute(self, id, cmdline):
    proc = subprocess.Popen(cmdline, shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE, preexec_fn = os.setsid)
    self.procs[id] = proc
    os.write(self.unblockw, 'x')

  def __enter__(self):
    return self

  def __exit__(self, type, value, traceback):
    self.exiting = True
    for id, proc in self.procs.items():
      os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
      proc.wait()
    else:
      os.write(self.unblockw, 'x')

  def reader(self):
    buf = {}

    while not self.exiting:
      for id in self.procs:
        if id + '/out' not in buf:
          buf[id + '/out'] = ''
          buf[id + '/err'] = ''
      rlist = [self.unblockr]
      rlist += [proc.stdout for proc in self.procs.itervalues()]
      rlist += [proc.stderr for proc in self.procs.itervalues()]
      rlist, _, _ = select.select(rlist, [], [])
      if self.unblockr in rlist:
        os.read(self.unblockr, 1)
      delete = []
      for id, proc in self.procs.iteritems():
        if proc.stdout in rlist:
          data = os.read(proc.stdout.fileno(), 4096)
          if len(data) == 0:
            delete.append(id)
          buf[id + '/out'] += data
        if proc.stderr in rlist:
          buf[id + '/err'] += os.read(proc.stderr.fileno(), 4096)
      for d in delete:
        status = self.procs[d].wait()
        print >>sys.stderr, '%s: exit status %s' % (d, status)
        del self.procs[d]
      for tag in buf:
        lines = buf[tag].split('\n')
        if not buf[tag].endswith('\n'):
          buf[tag] = lines[-1]
        else:
          buf[tag] = ''
        del lines[-1]
        for line in lines:
          print >>sys.stderr, '%s: %s' % (tag, line)

def getopt(args, short, long, has_value = True):
  for i in xrange(len(args)):
    if has_value and args[i].startswith('%s=' % long):
      return args[i].split('=')[1]
    elif args[i] == long or args[i] == short:
      if has_value and i+1 < len(args):
        return args[i+1]
      elif not has_value:
        return True
      else:
        assert 0
  if has_value:
    return None
  else:
    return False

def rmopt(args, short, long, has_value = True):
  for i in xrange(len(args)):
    if has_value and args[i].startswith('%s=' % long):
      del args[i]
      break
    elif args[i] == long or args[i] == short:
      if has_value and i+1 < len(args):
        del args[i:i+2]
      elif not has_value:
        del args[i]
      else:
        assert 0
      break
  return args

def main():
  agents = getopt(sys.argv, '-a', '--agent')
  master_agent = getopt(sys.argv, None, '--master-agent')
  src_ports_def = getopt(sys.argv, None, '--src-port')
  udp = getopt(sys.argv, None, '--udp', has_value = False)
  dpdk = getopt(sys.argv, None, '--dpdk', has_value = False)
  sys.argv = rmopt(sys.argv, None, '--master-agent')
  sys.argv = rmopt(sys.argv, None, '--src-port')
  sys.argv = rmopt(sys.argv, None, '--udp', has_value = False)
  sys.argv = rmopt(sys.argv, None, '--dpdk', has_value = False)

  assert master_agent is not None

  if agents is None:
    agents = []
  else:
    agents = agents.split(',')

  src_ports = None
  if src_ports_def is not None:
    src_ports = {}
    for x in src_ports_def.split(':'):
      if len(x) == 0:
        continue
      host, ports = x.split(',', 1)
      src_ports[host] = ports

  if udp:
    sudo = []
    binary_latency = 'mutilateudp'
    binary_throughput = 'mutilateudp'
  elif dpdk:
    sudo = ['sudo']
    binary_latency = 'mutilatedpdk'
    binary_throughput = 'mutilate'
  else:
    sudo = []
    binary_latency = 'mutilate'
    binary_throughput = 'mutilate'

  cwd = os.path.dirname(os.path.realpath(__file__))
  remotedir = '/tmp/' + getpass.getuser()

  for agent in [master_agent] + agents:
    subprocess.check_call(['ssh', agent, 'mkdir', '-p', remotedir])
    subprocess.call('ssh %s "pkill mutilate; pkill mutilateudp; sudo pkill mutilatedpdk"' % agent, shell = True)
    binary = binary_latency if agent == master_agent else binary_throughput
    subprocess.check_call('scp -q %s/%s %s:%s/%s' % (cwd, binary, agent, remotedir, binary), shell = True)

  with Runner() as runner:
    for agent in agents:
      params = '--agentmode --threads=16'
      if src_ports is not None:
        params += ' --src-port %s' % src_ports[agent]
      runner.execute(agent, 'ssh %s stdbuf -oL %s/%s %s < /dev/null' % (agent, remotedir, binary_throughput, params))
    params = sys.argv[1:]
    if src_ports is not None:
      params.append('--src-port')
      params.append(src_ports[master_agent])
    try:
      cmd = ['ssh', master_agent] + sudo + ['%s/%s' % (remotedir, binary_latency)] + params
      subprocess.call(cmd, stdin=open('/dev/null', 'r'))
    finally:
      cmd = ['ssh', master_agent] + sudo + ['pkill', binary_latency]
      subprocess.call(cmd)

if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    print
