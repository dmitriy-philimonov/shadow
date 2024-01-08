#pragma once

#include "cpu_cycles.hpp"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef __linux__
#error The code below supports Linux platform only
#endif

#ifndef __GNUC__
#error Tested only with GNU GCC
#endif

#define SHADOW_VERSION "1.0.0"
#define LOG_VERBOSE_LEVEL 2
#define MAX_LOG_LENGTH 256
#define LOGGER_IMPL TConsoleLogger

#define LOG_PRINTER(FORMAT, ...)                                               \
  do {                                                                         \
    char buf[22];                                                              \
    TimeFormatter.GenTime(buf);                                                \
    LOGGER_IMPL::Print("%s " FORMAT "\n", buf, ##__VA_ARGS__);                 \
  } while (0)

#define ERR(FORMAT, ...) LOG_PRINTER("ERR " FORMAT, ##__VA_ARGS__)

#if LOG_VERBOSE_LEVEL >= 1
#define WRN(FORMAT, ...) LOG_PRINTER("WRN " FORMAT, ##__VA_ARGS__)
#else
#define WRN(...)
#endif

#if LOG_VERBOSE_LEVEL >= 2
#define INF(FORMAT, ...) LOG_PRINTER("INF " FORMAT, ##__VA_ARGS__)
#else
#define INF(...)
#endif

#if LOG_VERBOSE_LEVEL >= 3
#define DBG(FORMAT, ...) LOG_PRINTER("DBG " FORMAT, ##__VA_ARGS__)
#else
#define DBG(...)
#endif

#define ERR_ERRNO_IMPL(ERRNO, FORMAT, ...)                                     \
  do {                                                                         \
    char buf[MAX_LOG_LENGTH];                                                  \
    const char *msg = strerror_r(ERRNO, buf, sizeof(buf));                     \
    LOG_PRINTER(FORMAT ": %s", ##__VA_ARGS__, msg);                            \
  } while (0)
#define ERR_ERRNO(FORMAT, ...) ERR_ERRNO_IMPL(errno, FORMAT, ##__VA_ARGS__)

#define SHADOW_LOGGER_GLOBALS TTimeFormatter TimeFormatter

class TTimeFormatter {
private:
  uint64_t StartTs_;
  uint64_t StartTimeMs_;

  void Sync() noexcept {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    StartTs_ = Timer.GetTimestamp();
    StartTimeMs_ = ts.tv_sec * 1'000 + ts.tv_nsec / 1'000'000;
  }

public:
  TTimeFormatter() { Sync(); }

  void GenTime(char (&buf)[22]) {
    uint64_t nowMs = Timer.Elapsed(StartTs_) + StartTimeMs_;
    time_t ms = nowMs % 1'000;
    time_t sec = nowMs / 1'000;

    struct tm tm;
    gmtime_r(&sec, &tm);

    size_t written = strftime(buf, sizeof(buf), "%Y%m%d %H:%M:%S", &tm);
    sprintf(buf + written, ".%03ld", ms);
  }
};

extern TTimeFormatter TimeFormatter;

struct TConsoleLogger {
  static void Print(const char *format, ...) noexcept {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
  }
};
