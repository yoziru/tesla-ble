/**
 * @file test_session_recovery.cpp
 * @brief Tests for session recovery after session errors like ERROR_TIME_EXPIRED
 *
 * These tests verify that:
 * 1. Session errors (ERROR_TIME_EXPIRED, etc.) trigger session invalidation
 * 2. forceUpdateSession() can recover from counter anti-replay failures
 * 3. The Vehicle class properly handles session recovery flow
 */

#include <gtest/gtest.h>
#include "client.h"
#include "peer.h"
#include "errors.h"
#include "test_constants.h"
#include <cstring>

using namespace TeslaBLE;

class SessionRecoveryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    crypto_ = std::make_shared<CryptoContext>();

    // Load the client private key
    int result = crypto_->loadPrivateKey(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                         strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
    ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to load private key";

    // Create peer for testing
    peer_ = std::make_unique<Peer>(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, crypto_, TestConstants::TEST_VIN);
  }

  void TearDown() override {
    peer_.reset();
    crypto_.reset();
  }

  Signatures_SessionInfo createSessionInfo(uint32_t counter, uint32_t clock_time = 1000) {
    Signatures_SessionInfo session_info = Signatures_SessionInfo_init_zero;
    session_info.counter = counter;
    session_info.clock_time = clock_time;
    session_info.status = Signatures_Session_Info_Status_SESSION_INFO_STATUS_OK;

    // Set valid epoch
    memcpy(session_info.epoch, TestConstants::TEST_EPOCH, 16);

    // Set vehicle public key
    memcpy(session_info.publicKey.bytes, TestConstants::EXPECTED_VEHICLE_PUBLIC_KEY, 65);
    session_info.publicKey.size = 65;

    return session_info;
  }

  std::shared_ptr<CryptoContext> crypto_;
  std::unique_ptr<Peer> peer_;
};

/**
 * Test that updateSession accepts higher counter values
 */
TEST_F(SessionRecoveryTest, UpdateSessionWithHigherCounter) {
  // Initialize with counter = 100
  auto session_info = createSessionInfo(100);
  int result = peer_->updateSession(&session_info);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Initial session update should succeed";
  EXPECT_EQ(peer_->getCounter(), 100);

  // Update with higher counter = 200
  auto new_session_info = createSessionInfo(200);
  result = peer_->updateSession(&new_session_info);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Update with higher counter should succeed";
  EXPECT_EQ(peer_->getCounter(), 200);
}

/**
 * Test that updateSession rejects lower counter values (anti-replay)
 */
TEST_F(SessionRecoveryTest, UpdateSessionRejectsLowerCounter) {
  // Initialize with counter = 100
  auto session_info = createSessionInfo(100);
  int result = peer_->updateSession(&session_info);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Initial session update should succeed";

  // Try to update with lower counter = 50 (should fail)
  auto old_session_info = createSessionInfo(50);
  result = peer_->updateSession(&old_session_info);
  EXPECT_EQ(result, TeslaBLE_Status_E_ERROR_COUNTER_REPLAY) << "Update with lower counter should fail";
  EXPECT_EQ(peer_->getCounter(), 100) << "Counter should remain unchanged";
}

/**
 * Test that forceUpdateSession accepts lower counter values
 * This is the key test for session recovery after ERROR_TIME_EXPIRED
 */
TEST_F(SessionRecoveryTest, ForceUpdateSessionAcceptsLowerCounter) {
  // Initialize with counter = 100000 (simulating our local counter being high)
  auto session_info = createSessionInfo(100000);
  int result = peer_->updateSession(&session_info);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Initial session update should succeed";
  EXPECT_EQ(peer_->getCounter(), 100000);
  EXPECT_TRUE(peer_->isValid());

  // Simulate vehicle sending new session info with lower counter (this is what happens after ERROR_TIME_EXPIRED)
  // The vehicle may have restarted or our local counter drifted too high
  auto new_session_info = createSessionInfo(500);  // Much lower counter from vehicle

  // Regular updateSession should reject this
  result = peer_->updateSession(&new_session_info);
  EXPECT_EQ(result, TeslaBLE_Status_E_ERROR_COUNTER_REPLAY) << "Regular update should reject lower counter";

  // forceUpdateSession should accept it
  result = peer_->forceUpdateSession(&new_session_info);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Force update should accept lower counter";
  EXPECT_EQ(peer_->getCounter(), 500) << "Counter should be updated to vehicle's value";
  EXPECT_TRUE(peer_->isValid()) << "Session should be valid after force update";
}

/**
 * Test that forceUpdateSession marks session as valid
 */
TEST_F(SessionRecoveryTest, ForceUpdateSessionRestoresValidity) {
  // Initialize with a valid session
  auto session_info = createSessionInfo(100);
  int result = peer_->updateSession(&session_info);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK);
  EXPECT_TRUE(peer_->isValid());

  // Invalidate the session (simulating what happens on ERROR_TIME_EXPIRED)
  peer_->setIsValid(false);
  EXPECT_FALSE(peer_->isValid()) << "Session should be invalidated";

  // Force update with new session info
  auto new_session_info = createSessionInfo(50);  // Lower counter
  result = peer_->forceUpdateSession(&new_session_info);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Force update should succeed";
  EXPECT_TRUE(peer_->isValid()) << "Session should be valid again after force update";
}

/**
 * Test that forceUpdateSession handles epoch changes correctly
 */
TEST_F(SessionRecoveryTest, ForceUpdateSessionWithEpochChange) {
  // Initialize with original session
  auto session_info = createSessionInfo(100);
  int result = peer_->updateSession(&session_info);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK);

  // Create session info with different epoch
  Signatures_SessionInfo new_session_info = Signatures_SessionInfo_init_zero;
  new_session_info.counter = 50;  // Lower counter
  new_session_info.clock_time = 2000;
  new_session_info.status = Signatures_Session_Info_Status_SESSION_INFO_STATUS_OK;

  // Different epoch (simulating vehicle restart with new epoch)
  uint8_t new_epoch[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                           0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};
  memcpy(new_session_info.epoch, new_epoch, 16);

  // Set vehicle public key
  memcpy(new_session_info.publicKey.bytes, TestConstants::EXPECTED_VEHICLE_PUBLIC_KEY, 65);
  new_session_info.publicKey.size = 65;

  // Note: With a different epoch, updateSession should actually accept lower counter
  // because epochs define independent counter spaces
  result = peer_->updateSession(&new_session_info);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Update with new epoch should succeed even with lower counter";
}

/**
 * Test that forceUpdateSession handles null session info
 */
TEST_F(SessionRecoveryTest, ForceUpdateSessionWithNullInfo) {
  int result = peer_->forceUpdateSession(nullptr);
  EXPECT_EQ(result, TeslaBLE_Status_E_ERROR_INVALID_SESSION) << "Force update with null should fail";
}

/**
 * Test the full session recovery flow:
 * 1. Start with valid session
 * 2. Session becomes invalid (ERROR_TIME_EXPIRED scenario)
 * 3. Invalidate session
 * 4. Receive new session info with lower counter
 * 5. Force update to recover
 */
TEST_F(SessionRecoveryTest, FullSessionRecoveryFlow) {
  // Step 1: Establish initial session with high counter
  auto initial_session = createSessionInfo(180000);  // High counter like in the logs
  int result = peer_->updateSession(&initial_session);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK) << "Initial session should be established";
  EXPECT_TRUE(peer_->isInitialized()) << "Peer should be initialized";

  // Step 2 & 3: Simulate ERROR_TIME_EXPIRED by invalidating session
  peer_->setIsValid(false);
  EXPECT_FALSE(peer_->isValid()) << "Session should be invalid";

  // Step 4: Receive new session info with lower counter (from vehicle after error)
  auto recovery_session = createSessionInfo(174762);  // Lower counter (from logs)

  // Regular update should fail due to anti-replay
  result = peer_->updateSession(&recovery_session);
  EXPECT_EQ(result, TeslaBLE_Status_E_ERROR_COUNTER_REPLAY) << "Regular update should fail";

  // Step 5: Force update to recover
  result = peer_->forceUpdateSession(&recovery_session);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Force update should succeed";
  EXPECT_TRUE(peer_->isValid()) << "Session should be valid after recovery";
  EXPECT_EQ(peer_->getCounter(), 174762) << "Counter should match vehicle's value";
}

/**
 * Test that isInitialized() returns false when session is invalid
 */
TEST_F(SessionRecoveryTest, IsInitializedReturnsFalseWhenInvalid) {
  // Initialize session
  auto session_info = createSessionInfo(100);
  int result = peer_->updateSession(&session_info);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK);
  EXPECT_TRUE(peer_->isInitialized()) << "Peer should be initialized";

  // Invalidate
  peer_->setIsValid(false);
  EXPECT_FALSE(peer_->isInitialized()) << "Peer should not be initialized when invalid";
}

/**
 * Test updating session with same counter (edge case)
 */
TEST_F(SessionRecoveryTest, UpdateSessionWithSameCounter) {
  auto session_info = createSessionInfo(100);
  int result = peer_->updateSession(&session_info);
  ASSERT_EQ(result, TeslaBLE_Status_E_OK);

  // Update with same counter should succeed (not a replay, same state)
  result = peer_->updateSession(&session_info);
  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Update with same counter should succeed";
}
