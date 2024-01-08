#pragma once

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <numeric>

static inline uint64_t CpuCycles() noexcept {
#if defined(__x86_64__)
  uint32_t lo, hi;
  asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
  uint64_t r;
  asm volatile("mrs %0, cntvct_el0" : "=r"(r));
  return r;
#else
#error "Unsupported hardware"
#endif
}

static inline uint64_t EstimateCpuCyclesInAMillisecond() noexcept {
  static constexpr uint64_t delta50ms = 50;
  static constexpr uint64_t delta50us = delta50ms * 1'000;
  std::array<uint64_t, 10 + 8> measures;

  fprintf(stderr, "Estimate CPU cycles in a millisecond ");
  for (size_t i = 0; i < measures.size(); ++i) {
    uint64_t cpu1 = CpuCycles();
    usleep(delta50us);
    uint64_t cpu2 = CpuCycles();
    measures[i] = cpu2 - cpu1;
    fprintf(stderr, ".");
  }

  std::nth_element(measures.begin(), measures.begin() + 5, measures.end());
  std::nth_element(measures.begin(), measures.end() - 6, measures.end());
  uint64_t middle =
      std::accumulate(measures.begin() + 5, measures.end() - 5, uint64_t(0));

  uint64_t avg = middle / ((measures.size() - 10) * delta50ms);
  fprintf(stderr, " %lu\n", avg);
  return avg;
}

struct TCpuCyclesRoughTimer {
  uint64_t CyclesPerMillisecond_ = 2'500'000ULL;

  inline void Calibrate() noexcept {
    CyclesPerMillisecond_ = EstimateCpuCyclesInAMillisecond();
  }

  inline uint64_t GetTimestamp() const noexcept { return CpuCycles(); }

  inline uint64_t Elapsed(const uint64_t oldTs) const noexcept {
    return (CpuCycles() - oldTs) / CyclesPerMillisecond_;
  }

  inline uint64_t HowMuchLeft(const uint64_t oldTs,
                              const uint64_t fullPeriod) const noexcept {
    uint64_t elapsed = Elapsed(oldTs);
    if (elapsed > fullPeriod)
      return 0;
    return fullPeriod - elapsed;
  }

  inline bool IsTimeout(const uint64_t oldTs,
                        const uint64_t ms) const noexcept {
    return (CpuCycles() - oldTs) / CyclesPerMillisecond_ > ms;
  }

  inline bool IsTimeout(const uint64_t oldTs, const uint64_t currTs,
                        const uint64_t ms) const noexcept {
    return (currTs - oldTs) / CyclesPerMillisecond_ > ms;
  }
};

extern TCpuCyclesRoughTimer Timer;

#define SHADOW_TIMER_GLOBALS TCpuCyclesRoughTimer Timer;
