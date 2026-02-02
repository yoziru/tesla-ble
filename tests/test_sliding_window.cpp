

#include <gtest/gtest.h>
#include "sliding_window.h"

using namespace TeslaBLE;

class SlidingWindowTest : public ::testing::Test {
 protected:
  SlidingWindow window_;
};

/**
 * Test initial state allows any counter
 */
TEST_F(SlidingWindowTest, InitialStateAllowsAnyCounter) {
  EXPECT_FALSE(window_.is_initialized());
  EXPECT_TRUE(window_.is_valid(0));
  EXPECT_TRUE(window_.is_valid(100));
  EXPECT_TRUE(window_.is_valid(UINT32_MAX));
}

/**
 * Test adding first counter initializes window
 */
TEST_F(SlidingWindowTest, FirstCounterInitializesWindow) {
  EXPECT_TRUE(window_.add(100));
  EXPECT_TRUE(window_.is_initialized());
  EXPECT_EQ(window_.get_highest_counter(), 100);
}

/**
 * Test adding higher counter succeeds
 */
TEST_F(SlidingWindowTest, HigherCounterSucceeds) {
  EXPECT_TRUE(window_.add(100));
  EXPECT_TRUE(window_.add(101));
  EXPECT_EQ(window_.get_highest_counter(), 101);

  EXPECT_TRUE(window_.add(200));
  EXPECT_EQ(window_.get_highest_counter(), 200);
}

/**
 * Test duplicate counter is rejected
 */
TEST_F(SlidingWindowTest, DuplicateCounterRejected) {
  EXPECT_TRUE(window_.add(100));

  // First time at 100 succeeded, second time should fail
  EXPECT_FALSE(window_.add(100)) << "Duplicate counter should be rejected";
  EXPECT_FALSE(window_.is_valid(100)) << "Duplicate counter should be invalid";
}

/**
 * Test out-of-order within window succeeds
 */
TEST_F(SlidingWindowTest, OutOfOrderWithinWindow) {
  EXPECT_TRUE(window_.add(100));
  EXPECT_TRUE(window_.add(110));  // Jump ahead

  // Now add a message that arrived late but is within window (110 - 105 = 5 < 64)
  EXPECT_TRUE(window_.add(105)) << "Out-of-order within window should succeed";
  EXPECT_TRUE(window_.add(107));
  EXPECT_TRUE(window_.add(103));
}

/**
 * Test counter too old (outside window) is rejected
 */
TEST_F(SlidingWindowTest, CounterTooOldRejected) {
  EXPECT_TRUE(window_.add(100));

  // Highest is 100, counter 30 is 70 positions back (> 64 window size)
  EXPECT_FALSE(window_.add(30)) << "Counter too old should be rejected";
  EXPECT_FALSE(window_.is_valid(30));
}

/**
 * Test window boundary (exactly at window size)
 */
TEST_F(SlidingWindowTest, WindowBoundary) {
  EXPECT_TRUE(window_.add(100));

  // At boundary: 100 - 64 = 36, so 37 is just inside, 36 is just outside
  EXPECT_TRUE(window_.is_valid(37)) << "Counter at window edge should be valid";
  EXPECT_FALSE(window_.is_valid(36)) << "Counter just outside window should be invalid";
}

/**
 * Test large jump resets window
 */
TEST_F(SlidingWindowTest, LargeJumpResetsWindow) {
  EXPECT_TRUE(window_.add(100));
  EXPECT_TRUE(window_.add(105));

  // Jump far ahead (more than window size)
  EXPECT_TRUE(window_.add(300));
  EXPECT_EQ(window_.get_highest_counter(), 300);

  // Old counter 100 is now way outside window
  EXPECT_FALSE(window_.is_valid(100));

  // Counter just before 300 should work (within new window)
  EXPECT_TRUE(window_.add(250));
}

/**
 * Test sequential counters work correctly
 */
TEST_F(SlidingWindowTest, SequentialCounters) {
  for (uint32_t i = 0; i < 100; i++) {
    EXPECT_TRUE(window_.add(i)) << "Sequential counter " << i << " should succeed";
  }
  EXPECT_EQ(window_.get_highest_counter(), 99);

  // All previous counters should now be either outside window or already used
  EXPECT_FALSE(window_.is_valid(50));  // Used
  EXPECT_FALSE(window_.add(50));       // Replay
}

/**
 * Test reset clears all state
 */
TEST_F(SlidingWindowTest, ResetClearsState) {
  EXPECT_TRUE(window_.add(100));
  EXPECT_TRUE(window_.add(150));
  EXPECT_TRUE(window_.is_initialized());

  window_.reset();

  EXPECT_FALSE(window_.is_initialized());
  EXPECT_EQ(window_.get_highest_counter(), 0);

  // After reset, any counter is valid again
  EXPECT_TRUE(window_.is_valid(50));
  EXPECT_TRUE(window_.add(50));
}

/**
 * Test forceSetCounter
 */
TEST_F(SlidingWindowTest, ForceSetCounter) {
  EXPECT_TRUE(window_.add(100));
  EXPECT_TRUE(window_.add(110));

  // Force set to a new counter (session recovery scenario)
  window_.force_set_counter(200);

  EXPECT_TRUE(window_.is_initialized());
  EXPECT_EQ(window_.get_highest_counter(), 200);

  // 200 itself should now be marked as used
  EXPECT_FALSE(window_.add(200));

  // But counters near it should work
  EXPECT_TRUE(window_.add(195));
  EXPECT_TRUE(window_.add(201));
}

/**
 * Test zero counter
 */
TEST_F(SlidingWindowTest, ZeroCounter) {
  EXPECT_TRUE(window_.add(0));
  EXPECT_TRUE(window_.is_initialized());
  EXPECT_EQ(window_.get_highest_counter(), 0);

  // Cannot add 0 again
  EXPECT_FALSE(window_.add(0));

  // Can add higher counters
  EXPECT_TRUE(window_.add(1));
}

/**
 * Test maximum counter value
 */
TEST_F(SlidingWindowTest, MaxCounterValue) {
  EXPECT_TRUE(window_.add(UINT32_MAX - 10));
  EXPECT_TRUE(window_.add(UINT32_MAX));
  EXPECT_EQ(window_.get_highest_counter(), UINT32_MAX);

  // Counters near max should work
  EXPECT_TRUE(window_.add(UINT32_MAX - 5));
}

/**
 * Test isValid doesn't modify state
 */
TEST_F(SlidingWindowTest, IsValidDoesNotModifyState) {
  EXPECT_TRUE(window_.add(100));

  // Check if 101 is valid (it should be)
  EXPECT_TRUE(window_.is_valid(101));

  // isValid shouldn't have added it, so add should still succeed
  EXPECT_TRUE(window_.add(101));

  // Now it's been added, so both should fail
  EXPECT_FALSE(window_.is_valid(101));
  EXPECT_FALSE(window_.add(101));
}

/**
 * Stress test with many counters
 */
TEST_F(SlidingWindowTest, StressTestManyCounters) {
  // Add 10000 sequential counters
  for (uint32_t i = 0; i < 10000; i++) {
    EXPECT_TRUE(window_.add(i));
  }
  EXPECT_EQ(window_.get_highest_counter(), 9999);

  // All previous 10000 counters should be rejected as replays
  for (uint32_t i = 0; i < 10000; i++) {
    EXPECT_FALSE(window_.add(i)) << "Counter " << i << " should be rejected as replay";
  }

  // Next counter should work
  EXPECT_TRUE(window_.add(10000));
}
