#pragma once

#include <cstdint>

namespace TeslaBLE {

/**
 * @brief Efficient anti-replay protection using a 64-bit sliding window
 *
 * This implementation is inspired by the Go vehicle-command library's approach.
 * It uses a 64-bit bitmask to track the last 64 message counters, allowing
 * for out-of-order message delivery within the window.
 *
 * Key features:
 * - O(1) time complexity for validation and addition
 * - Constant memory usage (just 12 bytes)
 * - Supports out-of-order messages within window
 * - Efficient bit operations
 */
class SlidingWindow {
 public:
  static constexpr uint32_t WINDOW_SIZE = 64;

  SlidingWindow() = default;

  /**
   * @brief Add a counter to the window (mark as seen)
   *
   * Call this after successfully processing a message with this counter.
   *
   * @param counter The counter value to add
   * @return true if successfully added, false if it was a replay
   */
  bool add(uint32_t counter) {
    // First counter - initialize
    if (!used_) {
      highest_counter_ = counter;
      window_ = 1;  // Mark position 0 as used
      used_ = true;
      return true;
    }

    // Counter is higher than highest seen
    if (counter > highest_counter_) {
      uint32_t shift = counter - highest_counter_;

      if (shift >= WINDOW_SIZE) {
        // New counter is far ahead - reset window
        window_ = 1;
      } else {
        // Shift window and set new bit
        window_ = (window_ << shift) | 1;
      }
      highest_counter_ = counter;
      return true;
    }

    // Counter too old - outside window
    if (highest_counter_ - counter >= WINDOW_SIZE) {
      return false;
    }

    // Counter within window - check if already used
    uint32_t offset = highest_counter_ - counter;
    uint64_t mask = 1ULL << offset;

    if (window_ & mask) {
      // Already seen - replay
      return false;
    }

    // Mark as seen
    window_ |= mask;
    return true;
  }

  /**
   * @brief Get the highest counter value seen
   */
  uint32_t get_highest_counter() const { return highest_counter_; }

  /**
   * @brief Reset the sliding window
   */
  void reset() {
    window_ = 0;
    highest_counter_ = 0;
    used_ = false;
  }

 private:
  uint64_t window_ = 0;           ///< 64-bit bitmask of seen counters
  uint32_t highest_counter_ = 0;  ///< Highest counter value seen
  bool used_ = false;             ///< Whether window has been initialized
};

}  // namespace TeslaBLE
