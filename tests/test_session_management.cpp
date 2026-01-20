#include <gtest/gtest.h>
#include <client.h>
#include <peer.h>
#include <universal_message.pb.h>
#include <signatures.pb.h>
#include <cstring>
#include "test_constants.h"

using namespace TeslaBLE;

// Mock received message from VCSEC (from main.cpp)
static pb_byte_t MOCK_VCSEC_MESSAGE[177] = {
    0x32, 0x12, 0x12, 0x10, 0x2f, 0xdd, 0xc1, 0x45, 0xca, 0xcc, 0xca, 0x43, 0x05, 0x66, 0x37, 0x0d, 0xf1, 0x49,
    0x85, 0x5d, 0x3a, 0x02, 0x08, 0x02, 0x7a, 0x5e, 0x08, 0x01, 0x12, 0x41, 0x04, 0xc7, 0xa1, 0xf4, 0x71, 0x38,
    0x48, 0x6a, 0xa4, 0x72, 0x99, 0x71, 0x49, 0x48, 0x78, 0xd3, 0x3b, 0x1a, 0x24, 0xe3, 0x95, 0x71, 0xf7, 0x48,
    0xa6, 0xe1, 0x6c, 0x59, 0x55, 0xb3, 0xd8, 0x77, 0xd3, 0xa6, 0xaa, 0xa0, 0xe9, 0x55, 0x16, 0x64, 0x74, 0xaf,
    0x5d, 0x32, 0xc4, 0x10, 0xf4, 0x39, 0xa2, 0x23, 0x41, 0x37, 0xad, 0x1b, 0xb0, 0x85, 0xfd, 0x4e, 0x88, 0x13,
    0xc9, 0x58, 0xf1, 0x1d, 0x97, 0x1a, 0x10, 0x4c, 0x46, 0x3f, 0x9c, 0xc0, 0xd3, 0xd2, 0x69, 0x06, 0xe9, 0x82,
    0xed, 0x22, 0x4a, 0xdd, 0xe6, 0x25, 0x85, 0x4a, 0x00, 0x00, 0x30, 0x06, 0x6a, 0x24, 0x32, 0x22, 0x0a, 0x20,
    0x5a, 0x0d, 0x3c, 0x7c, 0xb0, 0x2c, 0x04, 0xd9, 0x12, 0xa3, 0x58, 0x8b, 0xc2, 0xa6, 0xfd, 0x8c, 0x00, 0xf2,
    0x44, 0x09, 0x1b, 0xdd, 0x9d, 0xfe, 0x46, 0xfc, 0xdc, 0x47, 0x06, 0x41, 0x5b, 0x26, 0x92, 0x03, 0x10, 0x3c,
    0xcc, 0xe3, 0xd5, 0x1a, 0x6f, 0x3c, 0x2a, 0xee, 0xa8, 0x91, 0x36, 0x44, 0xa7, 0x05, 0x84};

// Mock received message from INFOTAINMENT (from main.cpp)
static pb_byte_t MOCK_INFOTAINMENT_MESSAGE[177] = {
    0x32, 0x12, 0x12, 0x10, 0x8f, 0x3d, 0x24, 0x4b, 0x50, 0xb0, 0x7a, 0x98, 0x42, 0xca, 0xc1, 0x08, 0xc9, 0x28,
    0xb5, 0xe7, 0x3a, 0x02, 0x08, 0x03, 0x7a, 0x5e, 0x08, 0x01, 0x12, 0x41, 0x04, 0xc7, 0xa1, 0xf4, 0x71, 0x38,
    0x48, 0x6a, 0xa4, 0x72, 0x99, 0x71, 0x49, 0x48, 0x78, 0xd3, 0x3b, 0x1a, 0x24, 0xe3, 0x95, 0x71, 0xf7, 0x48,
    0xa6, 0xe1, 0x6c, 0x59, 0x55, 0xb3, 0xd8, 0x77, 0xd3, 0xa6, 0xaa, 0xa0, 0xe9, 0x55, 0x16, 0x64, 0x74, 0xaf,
    0x5d, 0x32, 0xc4, 0x10, 0xf4, 0x39, 0xa2, 0x23, 0x41, 0x37, 0xad, 0x1b, 0xb0, 0x85, 0xfd, 0x4e, 0x88, 0x13,
    0xc9, 0x58, 0xf1, 0x1d, 0x97, 0x1a, 0x10, 0x4c, 0x46, 0x3f, 0x9c, 0xc0, 0xd3, 0xd2, 0x69, 0x06, 0xe9, 0x82,
    0xed, 0x22, 0x4a, 0xdd, 0xe6, 0x25, 0x5f, 0x0a, 0x00, 0x00, 0x30, 0x07, 0x6a, 0x24, 0x32, 0x22, 0x0a, 0x20,
    0x8e, 0x8d, 0xcd, 0x16, 0x4e, 0xf3, 0x61, 0xfd, 0x12, 0x3c, 0x46, 0xc2, 0xb2, 0xbd, 0xfd, 0x1f, 0xc9, 0x30,
    0x56, 0xf4, 0xef, 0x32, 0xc9, 0x31, 0x1a, 0x27, 0x5d, 0xb9, 0x08, 0xd4, 0xd2, 0x3f, 0x92, 0x03, 0x10, 0x0a,
    0x40, 0x4e, 0xc0, 0xfc, 0x9a, 0xa8, 0x63, 0xae, 0xc3, 0xe5, 0x01, 0x96, 0xfb, 0xf3, 0x0b};

class SessionManagementTest : public ::testing::Test {
 protected:
  void SetUp() override {
    client = std::make_unique<TeslaBLE::Client>();
    client->setVIN(TestConstants::TEST_VIN);

    // Load private key for testing
    int status = client->loadPrivateKey(reinterpret_cast<const unsigned char *>(TestConstants::CLIENT_PRIVATE_KEY_PEM),
                                        strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1);
    ASSERT_EQ(status, 0) << "Failed to load private key for testing";
  }

  void TearDown() override { client.reset(); }

  std::unique_ptr<TeslaBLE::Client> client;
};

TEST_F(SessionManagementTest, GetVCSECPeer) {
  auto vcsec_peer = client->getPeer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);

  EXPECT_NE(vcsec_peer, nullptr) << "VCSEC peer should not be null";
  EXPECT_FALSE(vcsec_peer->isInitialized()) << "VCSEC peer should not be initialized initially";
}

TEST_F(SessionManagementTest, GetInfotainmentPeer) {
  auto infotainment_peer = client->getPeer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);

  EXPECT_NE(infotainment_peer, nullptr) << "Infotainment peer should not be null";
  EXPECT_FALSE(infotainment_peer->isInitialized()) << "Infotainment peer should not be initialized initially";
}

TEST_F(SessionManagementTest, GetMultiplePeersReturnsSameInstance) {
  auto vcsec_peer1 = client->getPeer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  auto vcsec_peer2 = client->getPeer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);

  EXPECT_EQ(vcsec_peer1, vcsec_peer2) << "Multiple calls to getPeer should return same instance";
}

TEST_F(SessionManagementTest, InitializeVCSECSession) {
  // Parse the VCSEC message
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
  int parse_result = client->parseUniversalMessage(MOCK_VCSEC_MESSAGE, sizeof(MOCK_VCSEC_MESSAGE), &received_message);
  ASSERT_EQ(parse_result, 0) << "Failed to parse VCSEC message";

  // Parse session info
  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  int session_parse_result = client->parsePayloadSessionInfo(&received_message.payload.session_info, &session_info);
  ASSERT_EQ(session_parse_result, 0) << "Failed to parse session info";

  // Get peer and update session
  auto vcsec_peer = client->getPeer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  ASSERT_NE(vcsec_peer, nullptr) << "VCSEC peer should not be null";

  int update_result = vcsec_peer->updateSession(&session_info);
  EXPECT_EQ(update_result, 0) << "Updating VCSEC session should succeed";
  EXPECT_TRUE(vcsec_peer->isInitialized()) << "VCSEC peer should be initialized after update";
}

TEST_F(SessionManagementTest, InitializeInfotainmentSession) {
  // Parse the Infotainment message
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
  int parse_result =
      client->parseUniversalMessage(MOCK_INFOTAINMENT_MESSAGE, sizeof(MOCK_INFOTAINMENT_MESSAGE), &received_message);
  ASSERT_EQ(parse_result, 0) << "Failed to parse Infotainment message";

  // Parse session info
  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  int session_parse_result = client->parsePayloadSessionInfo(&received_message.payload.session_info, &session_info);
  ASSERT_EQ(session_parse_result, 0) << "Failed to parse session info";

  // Get peer and update session
  auto infotainment_peer = client->getPeer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
  ASSERT_NE(infotainment_peer, nullptr) << "Infotainment peer should not be null";

  int update_result = infotainment_peer->updateSession(&session_info);
  EXPECT_EQ(update_result, 0) << "Updating Infotainment session should succeed";
  EXPECT_TRUE(infotainment_peer->isInitialized()) << "Infotainment peer should be initialized after update";
}

TEST_F(SessionManagementTest, SessionCounterHandling) {
  // Initialize VCSEC session first
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
  client->parseUniversalMessage(MOCK_VCSEC_MESSAGE, sizeof(MOCK_VCSEC_MESSAGE), &received_message);

  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  client->parsePayloadSessionInfo(&received_message.payload.session_info, &session_info);

  auto vcsec_peer = client->getPeer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  vcsec_peer->updateSession(&session_info);

  ASSERT_TRUE(vcsec_peer->isInitialized()) << "VCSEC peer should be initialized";

  // Test counter retrieval
  uint32_t counter = vcsec_peer->getCounter();
  EXPECT_GE(counter, 0) << "Counter should be non-negative";
}

TEST_F(SessionManagementTest, SessionEpochHandling) {
  // Initialize VCSEC session first
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
  client->parseUniversalMessage(MOCK_VCSEC_MESSAGE, sizeof(MOCK_VCSEC_MESSAGE), &received_message);

  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  client->parsePayloadSessionInfo(&received_message.payload.session_info, &session_info);

  auto vcsec_peer = client->getPeer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  vcsec_peer->updateSession(&session_info);

  ASSERT_TRUE(vcsec_peer->isInitialized()) << "VCSEC peer should be initialized";

  // Test epoch retrieval
  const unsigned char *epoch = vcsec_peer->getEpoch();
  EXPECT_NE(epoch, nullptr) << "Epoch should not be null";
}

TEST_F(SessionManagementTest, UpdateSessionWithNullSessionInfo) {
  auto vcsec_peer = client->getPeer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  ASSERT_NE(vcsec_peer, nullptr) << "VCSEC peer should not be null";

  int update_result = vcsec_peer->updateSession(nullptr);
  EXPECT_NE(update_result, 0) << "Updating session with null session info should fail";
  EXPECT_FALSE(vcsec_peer->isInitialized()) << "Peer should not be initialized after failed update";
}

TEST_F(SessionManagementTest, MultipleSessionUpdates) {
  // Initialize VCSEC session
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
  client->parseUniversalMessage(MOCK_VCSEC_MESSAGE, sizeof(MOCK_VCSEC_MESSAGE), &received_message);

  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  client->parsePayloadSessionInfo(&received_message.payload.session_info, &session_info);

  auto vcsec_peer = client->getPeer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);

  // First update
  int first_update = vcsec_peer->updateSession(&session_info);
  EXPECT_EQ(first_update, 0) << "First session update should succeed";
  EXPECT_TRUE(vcsec_peer->isInitialized()) << "Peer should be initialized after first update";

  // Second update with same session info should also work
  int second_update = vcsec_peer->updateSession(&session_info);
  EXPECT_EQ(second_update, 0) << "Second session update should succeed";
  EXPECT_TRUE(vcsec_peer->isInitialized()) << "Peer should remain initialized after second update";
}
