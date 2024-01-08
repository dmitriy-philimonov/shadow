#pragma once

#include "log.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>

#include <array>
#include <unordered_map>

template <size_t EventQueueSize = 16> class TPoller {
private:
  int Epollfd_;

public:
  TPoller() {
    Epollfd_ = epoll_create1(0);
    if (Epollfd_ == -1) {
      ERR_ERRNO("Can't create epoll kernel object");
      exit(EXIT_FAILURE); /* critical */
    }
  }

  ~TPoller() { close(Epollfd_); }

  bool Add(const int fd, const uint32_t events) const noexcept {
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(Epollfd_, EPOLL_CTL_ADD, fd, &ev) == -1) {
      ERR_ERRNO("EPOLL_CTL_ADD failed");
      return false;
    }
    INF("EPOLL_CTL_ADD %d 0x%x", fd, events);
    return true;
  }
  bool Mod(const int fd, const uint32_t events) const noexcept {
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(Epollfd_, EPOLL_CTL_MOD, fd, &ev) == -1) {
      ERR_ERRNO("EPOLL_CTL_ADD failed");
      return false;
    }
    INF("EPOLL_CTL_MOD %d 0x%x", fd, events);
    return true;
  }
  bool Del(const int fd) const noexcept {
    if (epoll_ctl(Epollfd_, EPOLL_CTL_DEL, fd, nullptr) == -1) {
      ERR_ERRNO("EPOLL_CTL_DEL failed");
      return false;
    }
    INF("EPOLL_CTL_DEL %d", fd);
    return true;
  }

  template <typename F> bool Wait(F &f, int timeoutMs) const noexcept {
    std::array<epoll_event, EventQueueSize> events;
    int nfds = epoll_wait(Epollfd_, events.data(), events.size(), timeoutMs);
    if (nfds == -1) {
      ERR_ERRNO("epoll_wait failed");
      return false;
    }
    for (int i = 0; i < nfds; ++i) {
      epoll_event ev = events[i];
      f(ev.data.fd, ev.events);
    }

    return size_t(nfds) == events.size();
  }
};
