#pragma once

#include <cstdint>

namespace TeslaBLE {

class SlidingWindow {
 public:
  static constexpr uint32_t WINDOW_SIZE = 64;

  SlidingWindow() = default;

  bool is_valid(uint32_t counter) const {
    if (!used_)
      return true;
    if (counter > highest_counter_)
      return true;
    if (highest_counter_ - counter >= WINDOW_SIZE)
      return false;
    return (window_ & (1ULL << (highest_counter_ - counter))) == 0;
  }

  bool add(uint32_t counter) {
    if (!used_) {
      highest_counter_ = counter;
      window_ = 1;
      used_ = true;
      return true;
    }

    if (counter > highest_counter_) {
      uint32_t shift = counter - highest_counter_;
      window_ = (shift >= WINDOW_SIZE) ? 1 : (window_ << shift) | 1;
      highest_counter_ = counter;
      return true;
    }

    if (highest_counter_ - counter >= WINDOW_SIZE)
      return false;

    uint64_t mask = 1ULL << (highest_counter_ - counter);
    if (window_ & mask)
      return false;

    window_ |= mask;
    return true;
  }

  uint32_t get_highest_counter() const { return highest_counter_; }
  bool is_initialized() const { return used_; }

  void reset() {
    window_ = 0;
    highest_counter_ = 0;
    used_ = false;
  }

  void force_set_counter(uint32_t counter) {
    highest_counter_ = counter;
    window_ = 1;
    used_ = true;
  }

 private:
  uint64_t window_ = 0;
  uint32_t highest_counter_ = 0;
  bool used_ = false;
};

}  // namespace TeslaBLE
