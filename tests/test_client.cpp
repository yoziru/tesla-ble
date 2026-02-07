#include <gtest/gtest.h>
#include <client.h>
#include <cstdint>
#include <cstring>
#include "test_constants.h"

using namespace TeslaBLE;

class ClientTest : public ::testing::Test {
 protected:
  void SetUp() override {
    client_ = TestConstants::TestUtils::create_test_client();
    ASSERT_NE(client_, nullptr) << "Failed to create test client with loaded key";
  }

  void TearDown() override { client_.reset(); }

  std::unique_ptr<Client> client_;
};

TEST_F(ClientTest, GetPeerForBothDomains) {
  auto *vcsec_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  EXPECT_NE(vcsec_peer, nullptr) << "VCSEC peer should be available";

  auto *infotainment_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
  EXPECT_NE(infotainment_peer, nullptr) << "Infotainment peer should be available";
}

TEST_F(ClientTest, SetConnectionID) { EXPECT_NO_THROW(client_->set_connection_id(TestConstants::TEST_CONNECTION_ID)); }

TEST_F(ClientTest, BuildWhiteListMessage) {
  unsigned char whitelist_message_buffer[VCSEC_ToVCSECMessage_size];
  size_t whitelist_message_length;

  auto result =
      client_->build_white_list_message(Keys_Role_ROLE_CHARGING_MANAGER, VCSEC_KeyFormFactor_KEY_FORM_FACTOR_CLOUD_KEY,
                                        whitelist_message_buffer, &whitelist_message_length);

  EXPECT_EQ(result, TeslaBLE_Status_E_OK) << "Failed to build whitelist message";
  EXPECT_GT(whitelist_message_length, 0) << "Whitelist message should have content";
  EXPECT_LE(whitelist_message_length, sizeof(whitelist_message_buffer)) << "Message should fit in buffer";
}

TEST_F(ClientTest, BuildWhiteListMessageInvalidRole) {
  unsigned char whitelist_message_buffer[VCSEC_ToVCSECMessage_size];
  size_t whitelist_message_length;

  // Test with invalid role (using a high number that's likely not defined)
  auto role_seed = static_cast<int>(reinterpret_cast<uintptr_t>(client_.get()) & 0x1);
  int invalid_role_value = static_cast<int>(Keys_Role_ROLE_GUEST) + 1 + role_seed;
  auto invalid_role = static_cast<Keys_Role>(invalid_role_value);
  auto result = client_->build_white_list_message(invalid_role, VCSEC_KeyFormFactor_KEY_FORM_FACTOR_CLOUD_KEY,
                                                  whitelist_message_buffer, &whitelist_message_length);

  EXPECT_NE(result, TeslaBLE_Status_E_OK) << "Building whitelist message with invalid role should fail";
}
