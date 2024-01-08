#include "cpu_cycles.hpp"
#include "epoll.hpp"
#include "io.hpp"
#include "log.hpp"
#include "shadow.hpp"

#include <arpa/inet.h>
#include <cstdlib>
#include <netinet/in.h>

#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

using TTunnelPoller = TPoller<16>;

struct TRobotChannel {
  uint64_t LastUpdatedCycles_;
  TSockProxy LocalTunnel_;
};

struct TRobot {
  uint64_t LastUpdatedCycles_;
  TSecuredSockProxy ControlTunnel_;
  TServerSocketUnix *USock;
  std::unordered_map<int, TRobotChannel> WaitingChannels_;
};

class TRobotManager {
private:
  TTunnelPoller Poll_;
  std::unordered_map<uint32_t, TRobot> Robots_;
  std::mutex Lock_;

public:
  int RegisterRobot(TSecuredSockProxy &&mainTunnel, uint32_t robotId,
                    TServerSocketUnix &usock) {
    int newfd = mainTunnel.NativeHandle();
    bool cleanOld = false;
    TRobot robot{Timer.GetTimestamp(), std::move(mainTunnel), &usock, {}};

    {
      std::lock_guard<std::mutex> lock(Lock_);
      auto it = Robots_.find(robotId);
      if (it == Robots_.end()) {
        /* since robot object is moved, must be sure no robot exists */
        Robots_.insert(std::make_pair(robotId, std::move(robot)));
      } else {
        std::swap(robot, it->second);
        cleanOld = true;
      }
    }
    /* asynchronous operations */
    if (cleanOld) {
      Poll_.Del(robot.ControlTunnel_
                    .NativeHandle()); // remove from tidyup polling list
      robot.ControlTunnel_.ForceStopCommunication(); // shutdown on tcp sock =>
                                                     // unlock old thread
      robot.USock->ForceStopCommunication(); // shutdown on unix sock => unlock
                                             // old thread
    }
    Poll_.Add(newfd, EPOLLIN); // add sock to tidyup polling list
    return newfd;
  }

  void RegisterRobotChannel(TSockProxy &&localTunnel, const uint32_t robotId) {
    int fd = localTunnel.NativeHandle();
    TRobotChannel robotChannel{Timer.GetTimestamp(), std::move(localTunnel)};

    std::lock_guard<std::mutex> lock(Lock_);
    auto it = Robots_.find(robotId);
    if (it == Robots_.end())
      return;
    it->second.WaitingChannels_.insert(
        std::make_pair(fd, std::move(robotChannel)));
  }

  TSockProxy UseRobotChannel(const uint32_t robotId, const uint32_t channelId) {
    std::lock_guard<std::mutex> lock(Lock_);

    auto rit = Robots_.find(robotId);
    if (rit == Robots_.end())
      return TSockProxy::Empty();

    TRobot &r = rit->second;
    auto chit = r.WaitingChannels_.find(channelId);
    if (chit == r.WaitingChannels_.end())
      TSockProxy::Empty();

    TSockProxy sock = std::move(chit->second.LocalTunnel_);
    r.WaitingChannels_.erase(chit);

    return sock;
  }

  std::unordered_map<uint32_t, uint32_t> TidyUpStep1() {
    std::unordered_map<uint32_t, uint32_t> toPoll;
    toPoll.reserve(Robots_.size());

    std::lock_guard<std::mutex> lock(Lock_);
    for (auto &p : Robots_) {
      /* cleanup dead waiting channels */
      std::vector<int> toErase;
      for (auto &ip : p.second.WaitingChannels_) {
        if (Timer.IsTimeout(ip.second.LastUpdatedCycles_, 10'000)) {
          toErase.push_back(ip.first);
        }
      }
      for (int key : toErase)
        p.second.WaitingChannels_.erase(key);

      /* collect robotId => control channel fd */
      toPoll.insert(
          std::make_pair(p.second.ControlTunnel_.NativeHandle(), p.first));
    }
    return toPoll;
  }

  void TidyUpStep2(std::vector<uint32_t> &good, std::vector<uint32_t> &bad) {
    std::lock_guard<std::mutex> lock(Lock_);

    auto currTs = Timer.GetTimestamp();
    for (const auto rId : good) {
      auto uit = Robots_.find(rId);
      if (uit == Robots_.end())
        continue;

      uit->second.LastUpdatedCycles_ = currTs;
    }

    for (auto &p : Robots_) {
      if (Timer.IsTimeout(p.second.LastUpdatedCycles_, currTs, 15'000)) {
        bad.push_back(p.first);
      }
    }

    for (const auto rId : bad) {
      auto eit = Robots_.find(rId);
      if (eit == Robots_.end())
        continue;
      if (eit->second.USock != nullptr) {
        eit->second.USock->ForceStopCommunication();
      }
      Poll_.Del(eit->second.ControlTunnel_.NativeHandle());
      Robots_.erase(eit);
    }
  }

  void TidyUp(const uint64_t startTs, const uint64_t deltaMs) {
    uint64_t currMs = deltaMs;

    /* robotId => fd */
    std::unordered_map<uint32_t, uint32_t> fd2robot = TidyUpStep1();
    if (fd2robot.empty())
      return;

    std::vector<uint32_t> good, bad;
    auto process = [&good, &bad, &fd2robot](int fd, const uint32_t event) {
      auto fit = fd2robot.find(fd);
      if (fit == fd2robot.end())
        return; /* impossible, however ... */

      uint32_t rId = fit->second;
      if ((event & EPOLLIN) == 0) {
        ERR("Interesting: unknown event 0x%x, robot %u fd %u", event, rId, fd);
        bad.push_back(rId);
        return;
      }

      /* (event & EPOLLIN) != 0 */

      char buf[64];
      uint32_t pings = 0;
      while (true) {
        size_t nbytes = TIO::ReadMany<sizeof(ECommand), sizeof(buf)>(fd, buf);
        for (size_t i = 0; i < nbytes; i += sizeof(ECommand)) {
          ECommand cmd;
          memcpy(&cmd, buf + i, sizeof(ECommand));
          if (cmd != ECommand::PING) {
            ERR("Got strange ping message 0x%x", static_cast<uint32_t>(cmd));
            continue;
          }
          ++pings;
        }
        if (nbytes < sizeof(buf))
          break;
      }

      DBG("robot %u ping %u", rId, pings);
      if (pings)
        good.push_back(rId);
    };

    currMs = Timer.HowMuchLeft(startTs, deltaMs);
    while (Poll_.Wait(process, currMs)) {
      currMs = Timer.HowMuchLeft(startTs, deltaMs);
    }

    /* update good, remove bad robots */
    TidyUpStep2(good, bad);
  }

} ActiveRobots;

struct TServerOpts {
  TSecurityOpts sec;
  const char *ldir;
  uint16_t lport;
  bool ipv6;
};

TServerOpts ParseOptions(int argc, char *const *argv) {
  static struct option long_options[] = {
      {"ca", required_argument, nullptr, 0},    // 0
      {"crt", required_argument, nullptr, 0},   // 1
      {"key", required_argument, nullptr, 0},   // 2
      {"ldir", required_argument, nullptr, 0},  // 3
      {"lport", required_argument, nullptr, 0}, // 4
      {"version", no_argument, nullptr, 0},     // 5
      {0, 0, 0, 0}};
  TServerOpts opts{};
  opts.ipv6 = true;

  int idx = 0, o = 0;
  uint32_t argnum = 0;
  while ((o = getopt_long(argc, argv, "46", long_options, &idx)) != -1) {
    if (o == '4') {
      opts.ipv6 = false;
      continue;
    }
    if (o == '6') {
      opts.ipv6 = true;
      continue;
    }
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
      opts.ldir = optarg;
      ++argnum;
      break;
    case 4:
      opts.lport = strtoul(optarg, nullptr, 10);
      ++argnum;
      break;
    case 5: {
      fprintf(stderr, "\nmTLS reverse proxy tunnel server, version %s\n\n",
              SHADOW_VERSION);
      exit(EXIT_SUCCESS);
    }
    }
  }
  if (argnum != 5) {
    ERR("Not all required arguments are set");
    exit(EXIT_FAILURE);
  }
  return opts;
}

void ServeRobot(TSecuredSockProxy &&robot, uint32_t rId, const char *ldir) {
  pid_t thread_id = gettid();
  INF("ServeRobot %u thread %u", rId, thread_id);

  static constexpr size_t MaxSockPath = sizeof(sockaddr_un::sun_path);

  char path[MaxSockPath];
  char *curr = path;
  size_t len = MaxSockPath - 1; /* '\0' at the string end */

  char *end = stpncpy(curr, ldir, len);
  size_t sz = (end - curr);
  len -= sz;
  curr += sz;

  sz = snprintf(curr, len, "/%03u.sock", rId);
  if (sz >= len) {
    ERR("Too long socket path, max is %lu", MaxSockPath);
    return;
  }

  TServerSocketUnix sunix(path);
  int tunnelfd = ActiveRobots.RegisterRobot(std::move(robot), rId, sunix);

  while (true) {
    INF("Wait unix connection robot %u", rId);
    sockaddr_un addr;
    TSockProxy from = sunix.Accept(addr);
    if (!from) {
      ERR_ERRNO("Stop servicing robot %u: sunix.Accept() failed", rId);
      break;
    }
    INF("Got unix connection robot %u", rId);

    int chId = from.NativeHandle();
    TChannelRequest channel(rId, chId);
    INF("Write channel request robot %u channel %u", rId, chId);
    if (!TIO::WriteAll(tunnelfd, (const char *)&channel, sizeof(channel))) {
      ERR_ERRNO("Stop servicing robot %u: robot.WriteAll() failed", rId);
      break;
    }

    INF("Register robot %u channel %u", rId, chId);
    ActiveRobots.RegisterRobotChannel(std::move(from), rId);
  }
  INF("ServeRobot %u thread %u finished", rId, thread_id);
}

void ServeChannel(TSecuredSockProxy &&remote, const uint32_t rId,
                  const uint32_t chId) {
  INF("Started thread %u for robot %u channel %u", gettid(), rId, chId);

  TSockProxy local = ActiveRobots.UseRobotChannel(rId, chId);
  if (!local) {
    fprintf(stderr, "ServeChannel(): ActiveRobots has empty cell");
    return;
  }
  if (!remote) {
    fprintf(stderr, "ServeChannel(): remote is empty");
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
  INF("ServeChannel finished for robot %u channel %u", rId, chId);
}

void DispatchSecuredConnection(TSecuredSockProxy &&robot,
                               const TServerOpts &opts) {
  /* a byte array can't be aliased as a class */
  ECommand cmd;
  char buf[std::max(sizeof(TRegisterMe), sizeof(TChannelRequest))];
  size_t nread = robot.ReadAll(buf, sizeof(cmd));
  if (nread != sizeof(cmd)) {
    ERR("Contract violation, can't read %lu bytes: %lu", sizeof(cmd), nread);
    return;
  }

  memcpy(&cmd, buf, sizeof(cmd));
  if (cmd == ECommand::REGISTER) {
    uint32_t robotId;
    nread = robot.ReadAll(buf, sizeof(robotId));
    if (nread != sizeof(robotId)) {
      ERR("Contract violation at reading TRegisterMe::robotId");
      return;
    }
    memcpy(&robotId, buf, sizeof(robotId));

    INF("Start register robot %u", robotId);

    std::thread(ServeRobot, std::move(robot), robotId, opts.ldir).detach();
    return;
  }

  if (cmd == ECommand::CHANNEL) {
    uint32_t robotId, channelId;
    const size_t toRead = sizeof(robotId) + sizeof(channelId);
    nread = robot.ReadAll(buf, toRead);
    if (nread != toRead) {
      ERR("Contract violation at reading TChannelRequest::robotId");
      return;
    }
    memcpy(&robotId, buf, sizeof(robotId));
    memcpy(&channelId, buf + sizeof(robotId), sizeof(channelId));

    INF("Start channel robot %u channel %u", robotId, channelId);
    std::thread(ServeChannel, std::move(robot), robotId, channelId).detach();
    return;
  }

  ERR("Unsupported cmd: 0x%x", static_cast<uint32_t>(cmd));
}

static inline int RunIPv6Server(const TServerOpts &opts) {
  INF("IPv6 mTLS server: sec=[ca='%s',crt='%s',key='%s'] :::%u <= "
      "'%s/$socket_name'",
      opts.sec.ca, opts.sec.crt, opts.sec.key, opts.lport, opts.ldir);

  TSecuredServerSocketV6 scheduler(opts.sec, opts.lport, 16);
  while (true) {
    sockaddr_in6 addr;
    TSecuredSockProxy robot = scheduler.Accept(addr);
    if (!robot)
      continue;
    PrintEndpointV6("Connection ", addr);
    DispatchSecuredConnection(std::move(robot), opts);
  }

  return EXIT_SUCCESS;
}

static inline int RunIPv4Server(const TServerOpts &opts) {
  fprintf(stderr,
          "IPv4 mTLS server: sec=[ca='%s',crt='%s',key='%s'] 0.0.0.0:%u <= "
          "'%s/$socket_name'",
          opts.sec.ca, opts.sec.crt, opts.sec.key, opts.lport, opts.ldir);

  TSecuredServerSocketV4 scheduler(opts.sec, opts.lport, 16);
  while (true) {
    sockaddr_in addr;
    TSecuredSockProxy robot = scheduler.Accept(addr);
    if (!robot) {
      fprintf(stderr, "mTLS problems, try again");
      continue;
    }
    PrintEndpointV4("Got tcp connection from ", addr);
    DispatchSecuredConnection(std::move(robot), opts);
  }

  return EXIT_SUCCESS;
}

static void RunPinger() {
  static constexpr uint64_t deltaMs = 1'000;

  while (true) {
    uint64_t startTs = Timer.GetTimestamp();

    ActiveRobots.TidyUp(startTs, deltaMs);

    uint64_t leftMs = Timer.HowMuchLeft(startTs, deltaMs);
    DBG("RunSoop(): leftMs %lu", leftMs);
    if (leftMs)
      usleep(leftMs * 1'000);
  }
}

SHADOW_TIMER_GLOBALS;
SHADOW_LOGGER_GLOBALS;

int main(int argc, char *const *argv) {
  TServerOpts opts = ParseOptions(argc, argv);
  Timer.Calibrate();
  signal(SIGPIPE, SIG_IGN);
  std::thread(RunPinger).detach();
  return opts.ipv6 ? RunIPv6Server(opts) : RunIPv4Server(opts);
}
