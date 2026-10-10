#include <gtest/gtest.h>
#include <client.h>
#include <peer.h>
#include <universal_message.pb.h>
#include <signatures.pb.h>
#include <cstring>
#include "test_constants.h"

using namespace TeslaBLE;

class SessionManagementTest : public ::testing::Test {
 protected:
  void SetUp() override {
    client_ = std::make_unique<Client>();
    client_->set_vin(TestConstants::TEST_VIN);

    // Load private key for testing
    auto status =
        client_->load_private_key(reinterpret_cast<const unsigned char *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                  strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
    ASSERT_EQ(status, TeslaBLE_Status_E_OK) << "Failed to load private key for testing";
  }

  void TearDown() override { client_.reset(); }

  std::unique_ptr<Client> client_;
};

TEST_F(SessionManagementTest, GetVCSECPeer) {
  auto *vcsec_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);

  EXPECT_NE(vcsec_peer, nullptr) << "VCSEC peer should not be null";
  EXPECT_FALSE(vcsec_peer->is_initialized()) << "VCSEC peer should not be initialized initially";
}

TEST_F(SessionManagementTest, GetInfotainmentPeer) {
  auto *infotainment_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);

  EXPECT_NE(infotainment_peer, nullptr) << "Infotainment peer should not be null";
  EXPECT_FALSE(infotainment_peer->is_initialized()) << "Infotainment peer should not be initialized initially";
}

TEST_F(SessionManagementTest, InitializeVCSECSession) {
  // Parse the VCSEC message
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
  auto parse_result = client_->parse_universal_message(const_cast<pb_byte_t *>(TestConstants::MOCK_VCSEC_MESSAGE),
                                                       sizeof(TestConstants::MOCK_VCSEC_MESSAGE), &received_message);
  ASSERT_EQ(parse_result, TeslaBLE_Status_E_OK) << "Failed to parse VCSEC message";

  // Parse session info
  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  auto session_parse_result =
      client_->parse_payload_session_info(&received_message.payload.session_info, &session_info);
  ASSERT_EQ(session_parse_result, TeslaBLE_Status_E_OK) << "Failed to parse session info";

  // Get peer and update session
  auto *vcsec_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  ASSERT_NE(vcsec_peer, nullptr) << "VCSEC peer should not be null";

  auto update_result = vcsec_peer->update_session(&session_info);
  EXPECT_EQ(update_result, TeslaBLE_Status_E_OK) << "Updating VCSEC session should succeed";
  EXPECT_TRUE(vcsec_peer->is_initialized()) << "VCSEC peer should be initialized after update";
}

TEST_F(SessionManagementTest, InitializeInfotainmentSession) {
  // Parse the Infotainment message
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
  auto parse_result =
      client_->parse_universal_message(const_cast<pb_byte_t *>(TestConstants::MOCK_INFOTAINMENT_MESSAGE),
                                       sizeof(TestConstants::MOCK_INFOTAINMENT_MESSAGE), &received_message);
  ASSERT_EQ(parse_result, TeslaBLE_Status_E_OK) << "Failed to parse Infotainment message";

  // Parse session info
  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  auto session_parse_result =
      client_->parse_payload_session_info(&received_message.payload.session_info, &session_info);
  ASSERT_EQ(session_parse_result, TeslaBLE_Status_E_OK) << "Failed to parse session info";

  // Get peer and update session
  auto *infotainment_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
  ASSERT_NE(infotainment_peer, nullptr) << "Infotainment peer should not be null";

  auto update_result = infotainment_peer->update_session(&session_info);
  EXPECT_EQ(update_result, TeslaBLE_Status_E_OK) << "Updating Infotainment session should succeed";
  EXPECT_TRUE(infotainment_peer->is_initialized()) << "Infotainment peer should be initialized after update";
}

TEST_F(SessionManagementTest, UpdateSessionWithNullSessionInfo) {
  auto *vcsec_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  ASSERT_NE(vcsec_peer, nullptr) << "VCSEC peer should not be null";

  auto update_result = vcsec_peer->update_session(nullptr);
  EXPECT_NE(update_result, TeslaBLE_Status_E_OK) << "Updating session with null session info should fail";
  EXPECT_FALSE(vcsec_peer->is_initialized()) << "Peer should not be initialized after failed update";
}

TEST_F(SessionManagementTest, MultipleSessionUpdates) {
  // Initialize VCSEC session
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
  client_->parse_universal_message(const_cast<pb_byte_t *>(TestConstants::MOCK_VCSEC_MESSAGE),
                                   sizeof(TestConstants::MOCK_VCSEC_MESSAGE), &received_message);

  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  client_->parse_payload_session_info(&received_message.payload.session_info, &session_info);

  auto *vcsec_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);

  // First update
  auto first_update = vcsec_peer->update_session(&session_info);
  EXPECT_EQ(first_update, TeslaBLE_Status_E_OK) << "First session update should succeed";
  EXPECT_TRUE(vcsec_peer->is_initialized()) << "Peer should be initialized after first update";

  // Second update with same session info should also work
  auto second_update = vcsec_peer->update_session(&session_info);
  EXPECT_EQ(second_update, TeslaBLE_Status_E_OK) << "Second session update should succeed";
  EXPECT_TRUE(vcsec_peer->is_initialized()) << "Peer should remain initialized after second update";
}
