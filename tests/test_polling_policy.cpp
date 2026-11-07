#include <gtest/gtest.h>

#include "polling_policy.h"

using TeslaBLE::InfotainmentPollDecision;
using TeslaBLE::InfotainmentPollPolicy;
using TeslaBLE::WakePolicy;

namespace {
void configure(InfotainmentPollPolicy &p) {
  p.set_awake_interval_ms(30000);
  p.set_active_interval_ms(10000);
  p.set_sleep_timeout_ms(660000);
}
}  // namespace

TEST(PollingPolicyTest, DefaultIntervals) {
  InfotainmentPollPolicy p;
  EXPECT_EQ(p.update(1000, false, false, false).interval_ms, 30000U);
  EXPECT_EQ(p.update(1000, false, true, false).interval_ms, 10000U);
  EXPECT_EQ(p.update(1000, true, false, false).interval_ms, 660000U);
}

TEST(PollingPolicyTest, IdlePollingBacksOffAfterTimeout) {
  InfotainmentPollPolicy p;
  configure(p);

  InfotainmentPollDecision d = p.update(1000, false, false, false);
  EXPECT_EQ(d.wake_policy, WakePolicy::WAKE_IF_NEEDED);
  EXPECT_EQ(d.interval_ms, 30000U);

  d = p.update(1000 + 600000, false, false, false);
  EXPECT_EQ(d.wake_policy, WakePolicy::WAKE_IF_NEEDED);

  d = p.update(1000 + 660000, false, false, false);
  EXPECT_EQ(d.wake_policy, WakePolicy::NO_WAKE_SKIP);
  EXPECT_EQ(d.interval_ms, 660000U);
}

TEST(PollingPolicyTest, ObservedAsleepSkipsWakePolling) {
  InfotainmentPollPolicy p;
  configure(p);

  InfotainmentPollDecision d = p.update(1000, true, false, false);
  EXPECT_EQ(d.wake_policy, WakePolicy::NO_WAKE_SKIP);
  EXPECT_EQ(d.interval_ms, 660000U);
}

TEST(PollingPolicyTest, ChargingKeepsVehicleAwake) {
  InfotainmentPollPolicy p;
  configure(p);

  InfotainmentPollDecision d = p.update(1000, false, true, false);
  EXPECT_EQ(d.wake_policy, WakePolicy::WAKE_IF_NEEDED);
  EXPECT_EQ(d.interval_ms, 10000U);

  d = p.update(1000 + 7200000, false, true, false);
  EXPECT_EQ(d.wake_policy, WakePolicy::WAKE_IF_NEEDED);
  EXPECT_EQ(d.interval_ms, 10000U);
}

TEST(PollingPolicyTest, SentryModeKeepsVehicleAwake) {
  InfotainmentPollPolicy p;
  configure(p);

  InfotainmentPollDecision d = p.update(1000, false, false, true);
  EXPECT_EQ(d.wake_policy, WakePolicy::WAKE_IF_NEEDED);
  EXPECT_EQ(d.interval_ms, 10000U);

  d = p.update(1000 + 7200000, false, false, true);
  EXPECT_EQ(d.wake_policy, WakePolicy::WAKE_IF_NEEDED);
  EXPECT_EQ(d.interval_ms, 10000U);
}

TEST(PollingPolicyTest, AwakeBlipDoesNotResumeWakePolling) {
  InfotainmentPollPolicy p;
  configure(p);

  p.update(1000, false, false, false);
  EXPECT_EQ(p.update(1000 + 660000, false, false, false).wake_policy, WakePolicy::NO_WAKE_SKIP);

  EXPECT_EQ(p.update(1000 + 700000, false, false, false).wake_policy, WakePolicy::NO_WAKE_SKIP);
  EXPECT_EQ(p.update(1000 + 730000, true, false, false).wake_policy, WakePolicy::NO_WAKE_SKIP);
}

TEST(PollingPolicyTest, ActivityAfterSleepResumesFastPolling) {
  InfotainmentPollPolicy p;
  configure(p);

  p.update(1000, false, false, false);
  EXPECT_EQ(p.update(1000 + 660000, false, false, false).wake_policy, WakePolicy::NO_WAKE_SKIP);

  InfotainmentPollDecision d = p.update(1000 + 700000, false, true, false);
  EXPECT_EQ(d.wake_policy, WakePolicy::WAKE_IF_NEEDED);
  EXPECT_EQ(d.interval_ms, 10000U);
}

TEST(PollingPolicyTest, ResetStartsFreshIdleWindow) {
  InfotainmentPollPolicy p;
  configure(p);

  p.update(1000, false, false, false);
  p.reset();
  InfotainmentPollDecision d = p.update(1000000, false, false, false);
  EXPECT_EQ(d.wake_policy, WakePolicy::WAKE_IF_NEEDED);
  EXPECT_EQ(d.interval_ms, 30000U);
}

TEST(PollingPolicyTest, IdleTimeoutCountsFromChargingStop) {
  InfotainmentPollPolicy p;
  configure(p);

  p.update(1000, false, true, false);
  p.update(1000 + 7200000, false, true, false);
  p.update(1000 + 7200000 + 1, false, false, false);

  InfotainmentPollDecision d = p.update(1000 + 7200000 + 100000, false, false, false);
  EXPECT_EQ(d.wake_policy, WakePolicy::WAKE_IF_NEEDED);
  EXPECT_EQ(d.interval_ms, 30000U);

  d = p.update(1000 + 7200000 + 660000, false, false, false);
  EXPECT_EQ(d.wake_policy, WakePolicy::NO_WAKE_SKIP);
}

TEST(PollingPolicyTest, IdleTimeoutCountsFromSentryOff) {
  InfotainmentPollPolicy p;
  configure(p);

  p.update(1000, false, false, true);
  p.update(1000 + 28800000, false, false, true);
  p.update(1000 + 28800000 + 1, false, false, false);

  InfotainmentPollDecision d = p.update(1000 + 28800000 + 100000, false, false, false);
  EXPECT_EQ(d.wake_policy, WakePolicy::WAKE_IF_NEEDED);

  d = p.update(1000 + 28800000 + 660000, false, false, false);
  EXPECT_EQ(d.wake_policy, WakePolicy::NO_WAKE_SKIP);
}

TEST(PollingPolicyTest, ChargingAndSentryTogetherStayAwake) {
  InfotainmentPollPolicy p;
  configure(p);

  InfotainmentPollDecision d = p.update(1000, false, true, true);
  EXPECT_EQ(d.wake_policy, WakePolicy::WAKE_IF_NEEDED);
  EXPECT_EQ(d.interval_ms, 10000U);
}

TEST(PollingPolicyTest, PollDueWhenNoPollFiredYet) {
  InfotainmentPollPolicy p;
  configure(p);
  EXPECT_TRUE(p.should_poll(50000, 30000));
  p.on_poll(50000);
  EXPECT_FALSE(p.should_poll(50000 + 10000, 30000));
}

TEST(PollingPolicyTest, PollDueAfterInterval) {
  InfotainmentPollPolicy p;
  configure(p);
  p.on_poll(1000);
  EXPECT_FALSE(p.should_poll(1000 + 29999, 30000));
  EXPECT_TRUE(p.should_poll(1000 + 30000, 30000));
}

TEST(PollingPolicyTest, PollTracksFireTime) {
  InfotainmentPollPolicy p;
  configure(p);
  p.on_poll(1000);
  EXPECT_TRUE(p.should_poll(1000 + 30000, 30000));
  p.on_poll(1000 + 30000);
  EXPECT_FALSE(p.should_poll(1000 + 30000 + 1000, 30000));
}

TEST(PollingPolicyTest, ForceUpdateThrottledToActiveInterval) {
  InfotainmentPollPolicy p;
  configure(p);
  p.on_poll(1000);
  EXPECT_FALSE(p.should_poll(1000 + 5000, p.active_interval_ms()));
  EXPECT_TRUE(p.should_poll(1000 + 10000, p.active_interval_ms()));
}

TEST(PollingPolicyTest, PollStaysCorrectAcrossMillisWraparound) {
  InfotainmentPollPolicy p;
  configure(p);
  const uint32_t last_poll = 0xFFFFFFFFu - 10000u;
  p.on_poll(last_poll);
  EXPECT_FALSE(p.should_poll(5000, 30000));
  EXPECT_TRUE(p.should_poll(30000, 30000));
}

TEST(PollingPolicyTest, FullTickCadenceWhileCharging) {
  InfotainmentPollPolicy p;
  configure(p);

  InfotainmentPollDecision d = p.update(20000, false, true, false);
  EXPECT_EQ(d.interval_ms, 10000U);
  EXPECT_TRUE(p.should_poll(20000, d.interval_ms));
  p.on_poll(20000);

  d = p.update(20000 + 5000, false, true, false);
  EXPECT_EQ(d.interval_ms, 10000U);
  EXPECT_FALSE(p.should_poll(20000 + 5000, d.interval_ms));

  d = p.update(20000 + 10000, false, true, false);
  EXPECT_TRUE(p.should_poll(20000 + 10000, d.interval_ms));
}

TEST(PollingPolicyTest, ProbeOverridesIdleBackoffWithoutResettingIdleOrCadence) {
  InfotainmentPollPolicy p;
  p.update(1000, false, false, false);
  EXPECT_FALSE(p.probe_window_active(1000));
  p.on_poll(640000);
  p.begin_probe_window(650000, 180000);
  EXPECT_FALSE(p.should_poll(650000, p.awake_interval_ms()));
  EXPECT_TRUE(p.should_poll(670000, p.awake_interval_ms()));
  EXPECT_EQ(p.update(650000, false, false, false).wake_policy, WakePolicy::WAKE_IF_NEEDED);
  p.on_poll(650000);

  for (uint32_t now : {661000U, 679999U, 680000U, 829999U}) {
    auto d = p.update(now, false, false, false);
    EXPECT_TRUE(p.probe_window_active(now));
    EXPECT_EQ(d.interval_ms, 30000U);
    EXPECT_EQ(d.wake_policy, WakePolicy::NO_WAKE_SKIP);
    EXPECT_EQ(p.should_poll(now, d.interval_ms), now >= 680000U);
  }

  auto d = p.update(830000, false, false, false);
  EXPECT_FALSE(p.probe_window_active(830000));
  EXPECT_EQ(d.interval_ms, 660000U);
  EXPECT_EQ(d.wake_policy, WakePolicy::NO_WAKE_SKIP);
}

TEST(PollingPolicyTest, ProbeIsSuppressedByObservedSleepEvenWithActiveState) {
  for (bool active : {false, true}) {
    InfotainmentPollPolicy p;
    p.begin_probe_window(1000, 180000);
    auto d = p.update(1000, true, active, active);
    EXPECT_EQ(d.interval_ms, 660000U);
    EXPECT_EQ(d.wake_policy, WakePolicy::NO_WAKE_SKIP);
    EXPECT_TRUE(p.probe_window_active(1000));
  }
}

TEST(PollingPolicyTest, ProbeRestartsAndCancelsButPollsAndAwakeReportsDoNotExtendIt) {
  InfotainmentPollPolicy p;
  p.begin_probe_window(1000, 180000);
  p.begin_probe_window(100000, 180000);
  EXPECT_TRUE(p.probe_window_active(181000));
  p.on_poll(279999);
  p.update(279999, false, false, false);
  EXPECT_TRUE(p.probe_window_active(279999));
  EXPECT_FALSE(p.probe_window_active(280000));

  p.begin_probe_window(280000, 180000);
  p.begin_probe_window(280001, 0);
  EXPECT_FALSE(p.probe_window_active(280001));
  EXPECT_EQ(p.update(1000000, false, false, false).interval_ms, 660000U);
}

TEST(PollingPolicyTest, ProbeExpiryAcrossMillisWraparoundAndStartAtZero) {
  for (uint32_t start : {0U, 0xFFFFFFFFU - 10000U}) {
    InfotainmentPollPolicy p;
    p.begin_probe_window(start, 30000);
    EXPECT_TRUE(p.probe_window_active(start));
    EXPECT_TRUE(p.probe_window_active(start + 29999U));
    EXPECT_FALSE(p.probe_window_active(start + 30000U));
  }
}

TEST(PollingPolicyTest, ProbeHandsOverToChargingOrSentryWithoutSlowingPolling) {
  for (bool charging : {false, true}) {
    InfotainmentPollPolicy p;
    p.update(1000, false, false, false);
    p.begin_probe_window(700000, 180000);
    EXPECT_EQ(p.update(700000, false, false, false).interval_ms, 30000U);
    auto d = p.update(730000, false, charging, !charging);
    EXPECT_EQ(d.interval_ms, 10000U);
    EXPECT_EQ(d.wake_policy, WakePolicy::WAKE_IF_NEEDED);
    d = p.update(880000, false, charging, !charging);
    EXPECT_FALSE(p.probe_window_active(880000));
    EXPECT_EQ(d.interval_ms, 10000U);
    EXPECT_EQ(d.wake_policy, WakePolicy::WAKE_IF_NEEDED);
  }
}
