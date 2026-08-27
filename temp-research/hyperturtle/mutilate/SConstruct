#!/usr/bin/python2
import os
import sys

env = Environment(ENV = os.environ)

env['HAVE_POSIX_BARRIER'] = True

env.Append(CPPPATH = ['/usr/local/include', '/opt/local/include'])
env.Append(LIBPATH = ['/opt/local/lib'])
env.Append(CCFLAGS = '-std=c++0x -D_GNU_SOURCE') # -D__STDC_FORMAT_MACROS')
if sys.platform == 'darwin':
    env['CC']  = 'clang'
    env['CXX'] = 'clang++'

conf = env.Configure(config_h = "config.h")
conf.Define("__STDC_FORMAT_MACROS")
if not conf.CheckCXX():
    print( "A compiler with C++11 support is required.")
    Exit(1)
print( "Checking for gengetopt...",)
if env.Execute("@which gengetopt &> /dev/null"):
    print( "not found (required)")
    Exit(1)
else: print( "found")
if not conf.CheckLibWithHeader("event", "event2/event.h", "C++"):
    print( "libevent required")
    Exit(1)
conf.CheckDeclaration("EVENT_BASE_FLAG_PRECISE_TIMER", '#include <event2/event.h>', "C++")
if not conf.CheckLibWithHeader("pthread", "pthread.h", "C++"):
    print( "pthread required")
    Exit(1)
conf.CheckLib("rt", "clock_gettime", language="C++")
conf.CheckLibWithHeader("zmq", ["algorithm", "zmq.hpp"], "C++")
# conf.CheckFunc('clock_gettime')
if not conf.CheckFunc('pthread_barrier_init'):
    conf.env['HAVE_POSIX_BARRIER'] = False

env = conf.Finish()

env.Append(CFLAGS = ' -O3 -Wall -g')
env.Append(CPPFLAGS = ' -O3 -Wall -g')
#env.Append(CPPFLAGS  = ' -D_GNU_SOURCE -D__STDC_FORMAT_MACROS')
#env.Append(CPPFLAGS = ' -DUSE_ADAPTIVE_SAMPLER')
#env.Append(CPPFLAGS = ' -DUSE_CUSTOM_PROTOCOL')

env.Command(['cmdline.cc', 'cmdline.h'], 'cmdline.ggo', 'gengetopt < $SOURCE')

src = Split("""mutilate.cc cmdline.cc log.cc distributions.cc util.cc
               TCPConnection.cc Generator.cc common.cc""")

if not env['HAVE_POSIX_BARRIER']: # USE_POSIX_BARRIER:
    src += ['barrier.cc']

env.Program(target='mutilate', source=src)
env.Program(target='gtest', source=['TestGenerator.cc', 'log.cc', 'util.cc',
                                    'Generator.cc'])
env.Program(target='mutilateudp', source=Split('''mutilateudp.cc cmdline.cc
  log.cc Generator.cc distributions.cc util.cc common.cc UDPConnection.cc'''))

if 'DPDK' in os.environ or env.GetOption('clean'):
    env_dpdk = Environment()
    env_dpdk['DPDK'] = os.environ.get('DPDK', '')
    env_dpdk['CPPFLAGS'] = '-I$DPDK/include -O2 -Wall -fno-strict-aliasing'
    env_dpdk['CXXFLAGS'] = '-std=c++0x'
    env_dpdk['LIBPATH'] = '$DPDK/lib'
    env_dpdk['LIBS'] = ['dpdk', 'zmq', 'pthread', 'dl']
    env_dpdk['_LIBFLAGS'] += ' -Wl,-whole-archive -lrte_pmd_ixgbe -Wl,-no-whole-archive'
    src = Split("""mutilatedpdk.cc DPDKConnection.cc dpdktcp.c""")
    obj = map(env.Object, Split('''cmdline.cc log.cc Generator.cc distributions.cc util.cc common.cc'''))
    env_dpdk.Program(target='mutilatedpdk', source=src+obj)
