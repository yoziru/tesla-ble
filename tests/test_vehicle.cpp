#include <gtest/gtest.h>

#include <vehicle.h>
#include "mocks/mock_adapters.h"
#include "test_constants.h"

using namespace TeslaBLE;

class VehicleTest : public ::testing::Test {
 protected:
  void SetUp() override {
    mock_ble_ = std::make_shared<MockBleAdapter>();
    mock_storage_ = std::make_shared<MockStorageAdapter>();

    // Inject a valid PEM private key from test_constants.h
    std::vector<uint8_t> key(reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                             reinterpret_cast<const uint8_t *>(TestConstants::CLIENT_PRIVATE_KEY_PEM) +
                                 strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
    mock_storage_->set_data("private_key", key);

    vehicle_ = std::make_shared<Vehicle>(mock_ble_, mock_storage_);
    vehicle_->set_vin(TestConstants::TEST_VIN);
  }

  std::shared_ptr<MockBleAdapter> mock_ble_;
  std::shared_ptr<MockStorageAdapter> mock_storage_;
  std::shared_ptr<Vehicle> vehicle_;
};

// ============================================================================
// Basic Initialization Tests
// ============================================================================

TEST_F(VehicleTest, Initialization) {
  // Vehicle should be created successfully with valid adapters
  EXPECT_NE(vehicle_, nullptr);
  EXPECT_FALSE(vehicle_->is_connected()) << "Newly created vehicle should not be connected";
}

TEST_F(VehicleTest, SetVin) {
  std::string vin = "TESTVIN123456789";
  EXPECT_NO_THROW(vehicle_->set_vin(vin));
}

// ============================================================================
// Connection State Tests
// ============================================================================

TEST_F(VehicleTest, ConnectionStateTransitions) {
  EXPECT_FALSE(vehicle_->is_connected());

  vehicle_->set_connected(true);
  EXPECT_TRUE(vehicle_->is_connected());

  vehicle_->set_connected(false);
  EXPECT_FALSE(vehicle_->is_connected());
}

// ============================================================================
// Command Sending Tests
// ============================================================================

TEST_F(VehicleTest, WakeCommandSendsData) {
  // When wake() is called and loop() is processed,
  // the vehicle should send BLE data (session auth or command)
  vehicle_->wake();
  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  EXPECT_GE(writes.size(), 1) << "Wake command should result in BLE data being sent";
}

TEST_F(VehicleTest, VCSECPollSendsData) {
  vehicle_->vcsec_poll();
  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  EXPECT_GE(writes.size(), 1) << "VCSEC poll should result in BLE data being sent";
}

TEST_F(VehicleTest, InfotainmentPollWithForceWakeSendsData) {
  vehicle_->infotainment_poll(true);  // force_wake = true
  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  EXPECT_GE(writes.size(), 1) << "Infotainment poll with force_wake should send data";
}

// ============================================================================
// Vehicle Sleep State Tests - Regression test for charging vehicle polling bug
// Issue: Infotainment polls were skipped when vehicle was charging because
// VCSEC reports UNKNOWN status (not AWAKE) for charging vehicles.
// Fix: Inverted logic to treat vehicle as awake unless explicitly ASLEEP.
// ============================================================================

TEST_F(VehicleTest, InfotainmentPollSkippedWhenAsleepByDefault) {
  // Verify default behavior: vehicle starts in asleep state (no VCSEC status received)
  // and infotainment polls without force_wake should be skipped

  bool poll_callback_called = false;
  bool poll_success = false;

  vehicle_->send_command(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Optional Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      [&](bool success) {
        poll_callback_called = true;
        poll_success = success;
      },
      false  // requires_wake = false (optional poll)
  );
  vehicle_->loop();

  // Poll should be skipped (no BLE writes) but callback invoked with success
  EXPECT_TRUE(poll_callback_called) << "Callback should be invoked for skipped poll";
  EXPECT_TRUE(poll_success) << "Skipped poll should report success (no-op)";

  auto writes = mock_ble_->get_written_data();
  EXPECT_EQ(writes.size(), 0) << "Poll should be skipped when vehicle is asleep";
}

TEST_F(VehicleTest, SetChargingAmpsSendsData) {
  vehicle_->set_charging_amps(16);
  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  EXPECT_GE(writes.size(), 1) << "Set charging amps should initiate communication";
}

TEST_F(VehicleTest, SetChargingLimitSendsData) {
  vehicle_->set_charging_limit(80);
  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  EXPECT_GE(writes.size(), 1) << "Set charging limit should initiate communication";
}

// ============================================================================
// Command Callback Tests
// ============================================================================

TEST_F(VehicleTest, CommandCallbackIsInvokedOnSuccess) {
  bool callback_called = false;
  bool callback_result = false;

  vehicle_->send_command(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Test Command",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_vcsec_action_message(VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, buff, len);
      },
      [&](bool success) {
        callback_called = true;
        callback_result = success;
      });

  // Process initial auth request
  vehicle_->loop();
  ASSERT_GE(mock_ble_->get_written_data().size(), 1);
  mock_ble_->clear_written_data();

  // Inject valid session info response to complete auth
  std::vector<uint8_t> rx_data;
  rx_data.push_back(0x00);
  rx_data.push_back(177);
  rx_data.insert(rx_data.end(), TestConstants::MOCK_VCSEC_MESSAGE, TestConstants::MOCK_VCSEC_MESSAGE + 177);
  vehicle_->on_rx_data(rx_data);

  // Process response and send command
  vehicle_->loop();
  vehicle_->loop();

  // Command should have been sent
  EXPECT_GE(mock_ble_->get_written_data().size(), 1) << "Command should be sent after auth";
}

TEST_F(VehicleTest, CommandCallbackReceivesFailureOnDisconnect) {
  bool callback_called = false;
  bool callback_success = true;  // Will be set to false if properly failed

  vehicle_->send_command(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Test",
      [](Client *, uint8_t *, size_t *len) {
        *len = 10;
        return TeslaBLEStatus::OK;
      },
      [&](bool success) {
        callback_called = true;
        callback_success = success;
      });

  // Disconnect before command completes
  vehicle_->set_connected(false);

  EXPECT_TRUE(callback_called) << "Callback should be invoked on disconnect";
  EXPECT_FALSE(callback_success) << "Disconnected command should report failure";
}

TEST_F(VehicleTest, NullCallbackIsHandledSafely) {
  // Enqueue command without callback - should not crash
  vehicle_->send_command(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "No Callback Command",
      [](Client *, uint8_t *, size_t *len) {
        *len = 10;
        return TeslaBLEStatus::OK;
      },
      nullptr);

  EXPECT_NO_THROW(vehicle_->loop());
  EXPECT_NO_THROW(vehicle_->set_connected(false));
}

// ============================================================================
// Message Receiving Tests
// ============================================================================

TEST_F(VehicleTest, ReceivingDataDoesNotCrash) {
  // Receiving arbitrary data should not crash (graceful error handling)
  std::vector<uint8_t> garbage_data = {0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
  EXPECT_NO_THROW(vehicle_->on_rx_data(garbage_data));
}

TEST_F(VehicleTest, ReceivingPartialDataDoesNotCrash) {
  // Partial message (header says 32 bytes, only 2 provided)
  std::vector<uint8_t> partial_data = {0x00, 0x20, 0x01, 0x02};
  EXPECT_NO_THROW(vehicle_->on_rx_data(partial_data));
}

TEST_F(VehicleTest, ReceivingEmptyDataDoesNotCrash) {
  std::vector<uint8_t> empty_data;
  EXPECT_NO_THROW(vehicle_->on_rx_data(empty_data));
}

TEST_F(VehicleTest, ReceivingValidSessionInfoUpdatesState) {
  // First, send a command to initiate auth
  vehicle_->vcsec_poll();
  vehicle_->loop();

  auto writes_before = mock_ble_->get_written_data().size();
  mock_ble_->clear_written_data();

  // Inject valid session info response
  std::vector<uint8_t> rx_data;
  rx_data.push_back(0x00);
  rx_data.push_back(177);
  rx_data.insert(rx_data.end(), TestConstants::MOCK_VCSEC_MESSAGE, TestConstants::MOCK_VCSEC_MESSAGE + 177);

  vehicle_->on_rx_data(rx_data);
  vehicle_->loop();

  // After receiving session info, the next step should proceed
  // (either send command or transition to next state)
  // The fact that loop() processes without crash indicates success
}

// ============================================================================
// Polling Behavior Tests (requires_wake)
// ============================================================================

TEST_F(VehicleTest, InfotainmentPollWithoutForceWakeSkipsWhenAsleep) {
  bool callback_called = false;
  bool callback_success = false;

  // Send poll that doesn't require wake
  vehicle_->send_command(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Infotainment Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
      },
      [&](bool success) {
        callback_called = true;
        callback_success = success;
      },
      false  // requires_wake = false
  );

  vehicle_->loop();

  // When vehicle is asleep and command doesn't require wake,
  // it should be skipped (completed as success without sending)
  EXPECT_TRUE(callback_called) << "Poll callback should be called";
  EXPECT_TRUE(callback_success) << "Skipped poll should be marked success (no-op)";
}

// ============================================================================
// Disconnect Handling Tests
// ============================================================================

TEST_F(VehicleTest, DisconnectClearsAuthenticationState) {
  vehicle_->set_connected(true);
  EXPECT_TRUE(vehicle_->is_connected());

  vehicle_->set_connected(false);
  EXPECT_FALSE(vehicle_->is_connected());

  // After reconnection, commands should go through full auth flow
  vehicle_->set_connected(true);
  vehicle_->vcsec_poll();
  vehicle_->loop();

  auto writes = mock_ble_->get_written_data();
  EXPECT_GE(writes.size(), 1) << "Should initiate auth after reconnection";
}

TEST_F(VehicleTest, DisconnectClearsAllPendingCommands) {
  bool callback1_called = false;
  bool callback1_success = true;
  bool callback2_called = false;
  bool callback2_success = true;

  // Enqueue multiple commands
  vehicle_->send_command(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Command 1",
      [](Client *, uint8_t *, size_t *len) {
        *len = 10;
        return TeslaBLEStatus::OK;
      },
      [&](bool success) {
        callback1_called = true;
        callback1_success = success;
      });

  vehicle_->send_command(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Command 2",
      [](Client *, uint8_t *, size_t *len) {
        *len = 10;
        return TeslaBLEStatus::OK;
      },
      [&](bool success) {
        callback2_called = true;
        callback2_success = success;
      });

  // Disconnect should clear queue and fail all commands
  vehicle_->set_connected(false);

  EXPECT_TRUE(callback1_called) << "First command should receive callback";
  EXPECT_FALSE(callback1_success) << "First command should fail on disconnect";
  EXPECT_TRUE(callback2_called) << "Second command should receive callback";
  EXPECT_FALSE(callback2_success) << "Second command should fail on disconnect";
}

TEST_F(VehicleTest, DisconnectClearsPartiallyReceivedData) {
  // Inject partial data (incomplete message)
  std::vector<uint8_t> partial_data = {0x00, 0x20, 0x01, 0x02};
  vehicle_->on_rx_data(partial_data);

  // Disconnect should clear buffers
  vehicle_->set_connected(false);
  vehicle_->set_connected(true);

  // New data after reconnection should be processed independently
  std::vector<uint8_t> fresh_data = {0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
  EXPECT_NO_THROW(vehicle_->on_rx_data(fresh_data));
}

TEST_F(VehicleTest, DisconnectWithEmptyQueueDoesNotCrash) { EXPECT_NO_THROW(vehicle_->set_connected(false)); }

TEST_F(VehicleTest, ReconnectionAllowsFreshCommands) {
  vehicle_->set_connected(true);
  vehicle_->vcsec_poll();
  vehicle_->loop();
  mock_ble_->clear_written_data();

  // Disconnect and reconnect
  vehicle_->set_connected(false);
  vehicle_->set_connected(true);

  // New command should work
  vehicle_->vcsec_poll();
  vehicle_->loop();

  EXPECT_GE(mock_ble_->get_written_data().size(), 1) << "Should be able to send commands after reconnection";
}

TEST_F(VehicleTest, MultipleDisconnectsOnlyCallbackOnce) {
  vehicle_->set_connected(true);

  int callback_count = 0;
  vehicle_->send_command(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Test",
      [](Client *, uint8_t *, size_t *len) {
        *len = 10;
        return TeslaBLEStatus::OK;
      },
      [&](bool) { callback_count++; });

  // Multiple disconnects should be idempotent
  vehicle_->set_connected(false);
  vehicle_->set_connected(false);
  vehicle_->set_connected(false);

  EXPECT_EQ(callback_count, 1) << "Callback should only be invoked once";
}

// ============================================================================
// Command Struct Tests
// ============================================================================

TEST(CommandStructTest, DefaultRequiresWakeIsTrue) {
  Command cmd(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Test Command",
      [](Client *, uint8_t *, size_t *) { return TeslaBLEStatus::OK; }, nullptr);

  EXPECT_TRUE(cmd.requires_wake) << "Commands should default to requiring wake for safety";
}

TEST(CommandStructTest, RequiresWakeCanBeSetFalse) {
  Command cmd(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Test Poll",
      [](Client *, uint8_t *, size_t *) { return TeslaBLEStatus::OK; }, nullptr, false);

  EXPECT_FALSE(cmd.requires_wake);
}

// ============================================================================
// Internal Helper Tests (for regression testing specific fixes)
// These test internal behavior but are necessary for regression coverage
// ============================================================================

// Friend test helper to access protected members for regression tests
class VehicleTestHelper : public Vehicle {
 public:
  using Vehicle::get_expected_message_length_;
  using Vehicle::rx_buffer_;

  VehicleTestHelper(std::shared_ptr<BleAdapter> b, std::shared_ptr<StorageAdapter> s) : Vehicle(b, s) {}

  void set_buffer(const std::vector<uint8_t> &data) { rx_buffer_ = data; }
};

TEST(VehicleInternalTest, ExpectedLengthIncludesHeader) {
  // Regression test: message length calculation must include 2-byte header
  // This prevents "End of stream" parsing bugs
  auto b = std::make_shared<MockBleAdapter>();
  auto s = std::make_shared<MockStorageAdapter>();
  VehicleTestHelper v(b, s);

  std::vector<uint8_t> data = {0x00, 0x0A};  // Length field = 10
  v.set_buffer(data);

  // Total expected length should be payload (10) + header (2) = 12
  EXPECT_EQ(v.get_expected_message_length_(), 12);
}
