#include <gtest/gtest.h>
#include <client.h>
#include <cstring>
#include "test_constants.h"

using namespace TeslaBLE;

class ClientTest : public ::testing::Test {
 protected:
  void SetUp() override {
    client = TestConstants::TestUtils::createTestClient();
    ASSERT_NE(client, nullptr) << "Failed to create test client with loaded key";
  }

  void TearDown() override { client.reset(); }

  std::unique_ptr<Client> client;
};

TEST_F(ClientTest, GetPeerForBothDomains) {
  auto vcsec_peer = client->get_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  EXPECT_NE(vcsec_peer, nullptr) << "VCSEC peer should be available";

  auto infotainment_peer = client->get_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
  EXPECT_NE(infotainment_peer, nullptr) << "Infotainment peer should be available";
}

TEST_F(ClientTest, SetConnectionID) { EXPECT_NO_THROW(client->set_connection_id(TestConstants::TEST_CONNECTION_ID)); }

TEST_F(ClientTest, BuildWhiteListMessage) {
  unsigned char whitelist_message_buffer[VCSEC_ToVCSECMessage_size];
  size_t whitelist_message_length;

  auto result =
      client->build_white_list_message(Keys_Role_ROLE_CHARGING_MANAGER, VCSEC_KeyFormFactor_KEY_FORM_FACTOR_CLOUD_KEY,
                                       whitelist_message_buffer, &whitelist_message_length);

  EXPECT_EQ(result, TeslaBLEStatus::OK) << "Failed to build whitelist message";
  EXPECT_GT(whitelist_message_length, 0) << "Whitelist message should have content";
  EXPECT_LE(whitelist_message_length, sizeof(whitelist_message_buffer)) << "Message should fit in buffer";
}

TEST_F(ClientTest, BuildWhiteListMessageInvalidRole) {
  unsigned char whitelist_message_buffer[VCSEC_ToVCSECMessage_size];
  size_t whitelist_message_length;

  // Test with invalid role (using a high number that's likely not defined)
  auto result =
      client->build_white_list_message(static_cast<Keys_Role>(999), VCSEC_KeyFormFactor_KEY_FORM_FACTOR_CLOUD_KEY,
                                       whitelist_message_buffer, &whitelist_message_length);

  EXPECT_NE(result, TeslaBLEStatus::OK) << "Building whitelist message with invalid role should fail";
}
