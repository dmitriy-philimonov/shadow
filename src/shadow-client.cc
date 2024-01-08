#include "cpu_cycles.hpp"
#include "log.hpp"
#include "shadow.hpp"

#include <cstdlib>
#include <getopt.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <thread>

struct TClientOpts {
  TSecurityOpts sec;
  const char *rhost;
  const char *lhost;
  uint32_t ping;
  uint16_t rport;
  uint16_t lport;
  uint16_t robot;

  uint16_t mode;
  union {
    sockaddr_in6 _6;
    sockaddr_in _4;
  } raddr;
  union {
    sockaddr_in6 _6;
    sockaddr_in _4;
  } laddr;
};

TClientOpts ParseOptions(int argc, char *const *argv) {
  static struct option long_options[] = {
      {"ca", required_argument, nullptr, 0},    // 0
      {"crt", required_argument, nullptr, 0},   // 1
      {"key", required_argument, nullptr, 0},   // 2
      {"rhost", required_argument, nullptr, 0}, // 3
      {"lhost", required_argument, nullptr, 0}, // 4
      {"rport", required_argument, nullptr, 0}, // 5
      {"lport", required_argument, nullptr, 0}, // 6
      {"robot", required_argument, nullptr, 0}, // 7
      {"ping", required_argument, nullptr, 0},  // 8
      {"version", no_argument, nullptr, 0},     // 9

      {0, 0, 0, 0}};
  TClientOpts opts{};
  opts.ping = 1;

  int idx = 0, o = 0;
  uint32_t argnum = 0;
  while ((o = getopt_long(argc, argv, "", long_options, &idx)) != -1) {
    switch (idx) {
    case 0:
      opts.sec.ca = optarg;
      ++argnum;
      break;
    case 1:
      opts.sec.crt = optarg;
      ++argnum;
      break;
    case 2:
      opts.sec.key = optarg;
      ++argnum;
      break;
    case 3:
      opts.rhost = optarg;
      ++argnum;
      break;
    case 4:
      opts.lhost = optarg;
      ++argnum;
      break;
    case 5:
      opts.rport = strtoul(optarg, nullptr, 10);
      ++argnum;
      break;
    case 6:
      opts.lport = strtoul(optarg, nullptr, 10);
      ++argnum;
      break;
    case 7:
      opts.robot = strtoul(optarg, nullptr, 10);
      ++argnum;
      break;
    case 8:
      opts.ping = strtoul(optarg, nullptr, 10);
      break; /* not required parameter */
    case 9: {
      fprintf(stderr, "\nmTLS reverse proxy tunnel client, version %s\n\n",
              SHADOW_VERSION);
      exit(EXIT_SUCCESS);
    }
    }
  }
  if (argnum != 8) {
    ERR("Not all required arguments are set");
    exit(EXIT_FAILURE);
  }
  return opts;
}

bool IsIPv6Address(const char *addr) {
  while (*addr) {
    if (*addr == ':')
      return true;
    ++addr;
  }
  return false;
}

void ServeChannel(TSecuredSockProxy &&remote, TSockProxy &&local,
                  const TChannelRequest &req, const TClientOpts &opts) {
  if (!remote) {
    ERR("Can't connect to remote %s:%u", opts.rhost, opts.rport);
    return;
  }

  if (!local) {
    ERR("Can't connect to local %s:%u", opts.lhost, opts.lport);
    return;
  }

  INF("Register remotely robot %u channel %u", req.RobotId, req.ChannelId);
  if (!remote.WriteAll((const char *)&req, sizeof(req))) {
    ERR("Can't register channel in remote server, stop local channel");
    return;
  }

  auto remote2local = [&remote, &local]() {
    size_t nbytes = remote.TranferTo(local);
    INF("remote->local %lu bytes", nbytes);
    local.ForceStopCommunication();
    remote.ForceStopCommunication();
  };
  auto local2remote = [&remote, &local]() {
    size_t nbytes = local.TranferTo(remote);
    INF("local->remote %lu bytes", nbytes);
    local.ForceStopCommunication();
    remote.ForceStopCommunication();
  };

  std::thread s(remote2local);
  std::thread r(local2remote);
  s.join();
  r.join();

  INF("Channel service finished (robot %u, channel %u)", req.RobotId,
      req.ChannelId);
}

void ServeReq(const TChannelRequest req, const TClientOpts &opts) {
  /* no retries in the middle of negotiation */
  switch (opts.mode) {
  case 0x0: {
    INF("Start IPv6/6 Channel Request Service");
    TSecuredClientSocketV6 remoteSock(opts.sec);
    TClientSocketV6 localSock;
    return ServeChannel(remoteSock.ConnectNoRetry(opts.raddr._6),
                        localSock.ConnectNoRetry(opts.laddr._6), req, opts);
  }
  case 0x1: {
    INF("Start IPv6/4 Channel Request Service");
    TSecuredClientSocketV6 remoteSock(opts.sec);
    TClientSocketV4 localSock;
    return ServeChannel(remoteSock.ConnectNoRetry(opts.raddr._6),
                        localSock.ConnectNoRetry(opts.laddr._4), req, opts);
  }
  case 0x2: {
    INF("Start IPv4/6 Channel Request Service");
    TSecuredClientSocketV4 remoteSock(opts.sec);
    TClientSocketV6 localSock;
    return ServeChannel(remoteSock.ConnectNoRetry(opts.raddr._4),
                        localSock.ConnectNoRetry(opts.laddr._6), req, opts);
  }
  case 0x3: {
    INF("Start IPv4/4 Channel Request Service");
    TSecuredClientSocketV4 remoteSock(opts.sec);
    TClientSocketV4 localSock;
    return ServeChannel(remoteSock.ConnectNoRetry(opts.raddr._4),
                        localSock.ConnectNoRetry(opts.laddr._4), req, opts);
  }
  }
}

void RunPinger(TSecuredSockProxy &remoteScheduler, const TClientOpts &opts) {
  INF("Keep alive thread, ping %u", opts.ping);
  const TPingRequest pingReq;
  while (true) {
    sleep(opts.ping);
    DBG("Ping");
    if (!remoteScheduler.WriteAll((char *)&pingReq, sizeof(pingReq)))
      break;
  }

  ERR("Disconnected from server %s:%u", opts.rhost, opts.rport);
  remoteScheduler.ForceStopCommunication();
}

int RunClient(TSecuredSockProxy &&remoteScheduler, const TClientOpts &opts) {
  /* connect to server with infinite retries => must be success anyway */
  INF("Connected to server %s:%u", opts.rhost, opts.rport);

  const TRegisterMe me(opts.robot);
  /* any class can be aliased as a byte array */
  if (!remoteScheduler.WriteAll((const char *)&me, sizeof(me))) {
    ERR("Can't register on the server");
    return EXIT_FAILURE;
  }
  INF("Registered robot %u", opts.robot);

  std::thread(RunPinger, std::ref(remoteScheduler), std::cref(opts)).detach();

  while (true) {
    INF("Wait for channel request");

    /* a byte array can't be aliased as a class */
    char buf[sizeof(TChannelRequest)];
    size_t nread = remoteScheduler.ReadAll(buf, sizeof(buf));
    if (nread != sizeof(buf)) {
      ERR("Contract violation: sizeof(TChannelRequest)=%lu != %lu\n", nread,
          sizeof(TChannelRequest));
      exit(EXIT_FAILURE);
    }

    /* should be eliminated if a compiler optimization level is specified */
    TChannelRequest req;
    memcpy(&req, buf, sizeof(req));
    if (req.Hello != ECommand::CHANNEL || req.RobotId != me.RobotId) {
      ERR("Contract violation at robot register negotiation");
      exit(EXIT_FAILURE);
    }
    INF("Got channel creation request: robot %u channel %u", req.RobotId,
        req.ChannelId);

    std::thread(ServeReq, req, std::cref(opts)).detach();
  }
  return EXIT_SUCCESS;
}

SHADOW_TIMER_GLOBALS;
SHADOW_LOGGER_GLOBALS;

int main(int argc, char *const *argv) {
  TClientOpts opts = ParseOptions(argc, argv);
  Timer.Calibrate();
  signal(SIGPIPE, SIG_IGN);

  const bool ripv6 = IsIPv6Address(opts.rhost);
  const bool lipv6 = IsIPv6Address(opts.lhost);
  INF("IPv%u/%u mTLS tunnel robot %03u: sec=[ca='%s',crt='%s',key='%s'] %s:%u "
      "=> %s:%u",
      (ripv6 ? 6U : 4U), (lipv6 ? 6U : 4U), opts.robot, opts.sec.ca,
      opts.sec.crt, opts.sec.key, opts.rhost, opts.rport, opts.lhost,
      opts.lport);

  auto fillLocalEndpoint = [&opts, lipv6](const uint16_t mask) noexcept {
    if (lipv6) {
      opts.laddr._6 = CreateEndpointV6(opts.lhost, opts.lport);
      opts.mode = 0x0 | mask;
    } else {
      opts.laddr._4 = CreateEndpointV4(opts.lhost, opts.lport);
      opts.mode = 0x1 | mask;
    }
  };

  if (ripv6) {
    opts.raddr._6 = CreateEndpointV6(opts.rhost, opts.rport);
    fillLocalEndpoint(0x0);

    TSecuredClientSocketV6 scheduler(opts.sec);
    return RunClient(scheduler.Connect(opts.raddr._6), opts);
  } else {
    opts.raddr._4 = CreateEndpointV4(opts.rhost, opts.rport);
    fillLocalEndpoint(0x2);

    TSecuredClientSocketV4 scheduler(opts.sec);
    return RunClient(scheduler.Connect(opts.raddr._4), opts);
  }
}
