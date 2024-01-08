#pragma once

#include "log.hpp"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

struct TIO {
  static bool WriteAll(int fd, const char *buf, size_t len) noexcept {
    while (len) {
      ssize_t nbytes = write(fd, buf, len);
      if (nbytes < 0) {
        if (errno == EINTR)
          continue;
        ERR_ERRNO("TIO::WriteAll() failed");
        return false;
      }

      buf += nbytes;
      len -= nbytes;
    }
    return true;
  }

  static size_t ReadSome(int fd, char *buf, size_t len) noexcept {
    while (len) {
      ssize_t nbytes = read(fd, buf, len);

      if (nbytes == 0)
        break;
      if (nbytes < 0) {
        if (errno == EINTR)
          continue;
        ERR_ERRNO("TIO::ReadSome() failed");
        break;
      }

      return nbytes;
    }
    return 0;
  }

  static size_t ReadAll(int fd, char *buf, size_t len) noexcept {
    size_t nread = 0;
    while (len) {
      ssize_t nbytes = read(fd, buf, len);

      if (nbytes == 0)
        break;
      if (nbytes < 0) {
        if (errno == EINTR)
          continue;
        ERR_ERRNO("TIO::ReadAll() failed");
        break;
      }

      buf += nbytes;
      len -= nbytes;
      nread += nbytes;
    }
    return nread; /* nread != len => unexpected EOF */
  }

  static size_t Tranfer(int dst_fd, int src_fd) noexcept {
    static constexpr size_t bufSize = 4096;
    char buf[bufSize];

    size_t transfered = 0;
    while (true) {
      size_t nbytes = ReadSome(src_fd, buf, bufSize);
      if (nbytes == 0)
        break;
      if (!WriteAll(dst_fd, buf, nbytes))
        break;
      transfered += nbytes;
    }
    return transfered;
  }

  template <size_t msglen, size_t buflen>
  static size_t ReadMany(int fd, char *buf) noexcept {
    static_assert(buflen % msglen == 0, "ReadMany is wrong used");

    size_t nbytes = ReadSome(fd, buf, buflen);
    size_t left = nbytes % msglen;
    if (left == 0)
      return nbytes;

    buf += nbytes;
    return nbytes + ReadAll(fd, buf, left);
  }
};
