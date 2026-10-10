/**
 * @file test_encrypted_responses.cpp
 * @brief End-to-end coverage for AES-GCM encrypted response handling.
 *
 * The Vehicle always requests encrypted responses (FLAG_ENCRYPT_RESPONSE), so
 * response decryption is the primary real-vehicle path. These tests drive a
 * full command round trip with encrypted responses for both domains, and pin
 * the per-domain request hash used as AD metadata.
 */

#include <gtest/gtest.h>

#include <client.h>
#include <peer.h>
#include <tb_utils.h>
#include <vehicle.h>

#include "mocks/mock_adapters.h"
#include "test_constants.h"

#include <car_server.pb.h>
#include <signatures.pb.h>
#include <vcsec.pb.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <memory>
#include <optional>
#include <vector>

using TeslaBLE::Client;
using TeslaBLE::MockBleAdapter;
using TeslaBLE::MockStorageAdapter;
using TeslaBLE::OperationOutcome;
using TeslaBLE::TeslaBLE_Status_E_OK;
using TeslaBLE::Vehicle;
using TeslaBLE::TestConstants::CLIENT_PRIVATE_KEY_PEM;
using TeslaBLE::TestConstants::EXPECTED_VEHICLE_PUBLIC_KEY;
using TeslaBLE::TestConstants::TEST_EPOCH;
using TeslaBLE::TestConstants::TEST_VIN;

namespace {

std::vector<uint8_t> frame_universal_message(const UniversalMessage_RoutableMessage &message) {
  size_t encoded_length = UniversalMessage_RoutableMessage_size;
  std::vector<pb_byte_t> encoded(UniversalMessage_RoutableMessage_size);
  auto status =
      TeslaBLE::pb_encode_fields(encoded.data(), &encoded_length, UniversalMessage_RoutableMessage_fields, &message);
  if (status != TeslaBLE_Status_E_OK) {
    return {};
  }

  std::vector<uint8_t> framed(encoded_length + 2);
  framed[0] = static_cast<uint8_t>((encoded_length >> 8) & 0xFF);
  framed[1] = static_cast<uint8_t>(encoded_length & 0xFF);
  std::copy_n(encoded.begin(), encoded_length, framed.begin() + 2);
  return framed;
}

Signatures_SessionInfo make_session_info(uint32_t counter) {
  Signatures_SessionInfo info = Signatures_SessionInfo_init_default;
  info.counter = counter;
  info.clock_time = static_cast<uint32_t>(
      std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
  info.status = Signatures_Session_Info_Status_SESSION_INFO_STATUS_OK;
  std::copy_n(TEST_EPOCH, sizeof(TEST_EPOCH), info.epoch);
  std::copy_n(EXPECTED_VEHICLE_PUBLIC_KEY, sizeof(EXPECTED_VEHICLE_PUBLIC_KEY), info.publicKey.bytes);
  info.publicKey.size = sizeof(EXPECTED_VEHICLE_PUBLIC_KEY);
  return info;
}

// Preload storage with a fresh valid session, as Vehicle::load_session_from_storage_ expects.
void preload_session(const std::shared_ptr<MockStorageAdapter> &storage, const char *key, uint32_t counter) {
  Signatures_SessionInfo info = make_session_info(counter);
  pb_byte_t blob[256];
  size_t blob_length = sizeof(blob);
  if (TeslaBLE::pb_encode_fields(blob, &blob_length, Signatures_SessionInfo_fields, &info) == TeslaBLE_Status_E_OK) {
    storage->set_data(key, std::vector<uint8_t>(blob, blob + blob_length));
  }
}

std::shared_ptr<Client> make_helper_client() {
  auto client = std::make_shared<Client>();
  client->set_vin(TEST_VIN);
  if (client->load_private_key(reinterpret_cast<const uint8_t *>(CLIENT_PRIVATE_KEY_PEM),
                               strlen(CLIENT_PRIVATE_KEY_PEM) + 1) != TeslaBLE_Status_E_OK) {
    return nullptr;
  }

  for (auto domain : {UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, UniversalMessage_Domain_DOMAIN_INFOTAINMENT}) {
    Signatures_SessionInfo info = make_session_info(100);
    auto *peer = client->get_peer(domain);
    if (peer == nullptr || peer->update_session(&info) != TeslaBLE_Status_E_OK) {
      return nullptr;
    }
  }
  return client;
}

// Request hash derived from a built encrypted request frame: 1 auth bytes + tag.
std::array<pb_byte_t, 17> request_hash_from_frame(Client &parser, const std::vector<uint8_t> &frame) {
  std::array<pb_byte_t, 17> hash{};
  if (frame.size() <= 2) {
    return hash;
  }

  UniversalMessage_RoutableMessage request = UniversalMessage_RoutableMessage_init_default;
  if (parser.parse_universal_message(const_cast<pb_byte_t *>(frame.data()) + 2, frame.size() - 2, &request) !=
      TeslaBLE_Status_E_OK) {
    return hash;
  }

  hash[0] = static_cast<pb_byte_t>(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED);
  std::copy_n(request.sub_sigData.signature_data.sig_type.AES_GCM_Personalized_data.tag, 16, hash.begin() + 1);
  return hash;
}

// Encrypt a payload the way the vehicle does for a response to request_frame:
// response AD (request hash, flags, fault, response counter) + AES-GCM with the session key.
std::vector<uint8_t> make_encrypted_response(Client &helper, UniversalMessage_Domain domain, uint32_t counter,
                                             const std::vector<uint8_t> &request_frame, const pb_byte_t *payload,
                                             size_t payload_length, std::optional<uint32_t> ad_counter_override = {}) {
  if (request_frame.size() <= 2) {
    return {};
  }

  UniversalMessage_RoutableMessage request = UniversalMessage_RoutableMessage_init_default;
  if (helper.parse_universal_message(const_cast<pb_byte_t *>(request_frame.data()) + 2, request_frame.size() - 2,
                                     &request) != TeslaBLE_Status_E_OK) {
    return {};
  }

  const auto request_hash = request_hash_from_frame(helper, request_frame);

  auto *peer = helper.get_peer(domain);
  if (peer == nullptr) {
    return {};
  }

  const uint32_t flags = 1u << UniversalMessage_Flags_FLAG_ENCRYPT_RESPONSE;
  std::array<pb_byte_t, 80> ad{};
  size_t ad_length = 0;
  // The response is authenticated with the counter reported in
  // AES_GCM_ResponseData; ad_counter_override lets tests sign with a
  // different counter than the one the message reports.
  if (peer->construct_ad_buffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_RESPONSE, TEST_VIN, 0, ad.data(),
                                &ad_length, flags, request_hash.data(), request_hash.size(), 0,
                                ad_counter_override.value_or(counter)) != TeslaBLE_Status_E_OK) {
    return {};
  }

  std::vector<pb_byte_t> ciphertext(payload_length);
  size_t ciphertext_length = 0;
  std::array<pb_byte_t, 16> response_tag{};
  std::array<pb_byte_t, 12> nonce{};
  if (peer->encrypt(const_cast<pb_byte_t *>(payload), payload_length, ciphertext.data(), ciphertext.size(),
                    &ciphertext_length, response_tag.data(), ad.data(), ad_length,
                    nonce.data()) != TeslaBLE_Status_E_OK) {
    return {};
  }

  UniversalMessage_RoutableMessage response = UniversalMessage_RoutableMessage_init_default;
  response.has_from_destination = true;
  response.from_destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
  response.from_destination.sub_destination.domain = domain;
  response.which_payload = UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag;
  response.payload.protobuf_message_as_bytes.size = static_cast<pb_size_t>(ciphertext_length);
  std::copy_n(ciphertext.begin(), ciphertext_length, response.payload.protobuf_message_as_bytes.bytes);
  response.flags = flags;
  response.request_uuid.size = request.uuid.size;
  std::copy_n(request.uuid.bytes, request.uuid.size, response.request_uuid.bytes);

  response.which_sub_sigData = UniversalMessage_RoutableMessage_signature_data_tag;
  auto &signature_data = response.sub_sigData.signature_data;
  signature_data.which_sig_type = Signatures_SignatureData_AES_GCM_Response_data_tag;
  signature_data.sig_type.AES_GCM_Response_data.counter = counter;
  std::copy_n(nonce.begin(), nonce.size(), signature_data.sig_type.AES_GCM_Response_data.nonce);
  std::copy_n(response_tag.begin(), response_tag.size(), signature_data.sig_type.AES_GCM_Response_data.tag);

  return frame_universal_message(response);
}

}  // namespace

class EncryptedResponseTest : public ::testing::Test {
 protected:
  void SetUp() override {
    mock_ble_ = std::make_shared<MockBleAdapter>();
    mock_storage_ = std::make_shared<MockStorageAdapter>();

    size_t key_length = 0;
    while (CLIENT_PRIVATE_KEY_PEM[key_length] != '\0') {
      ++key_length;
    }
    std::vector<uint8_t> key(reinterpret_cast<const uint8_t *>(CLIENT_PRIVATE_KEY_PEM),
                             reinterpret_cast<const uint8_t *>(CLIENT_PRIVATE_KEY_PEM) + key_length + 1);
    mock_storage_->set_data("private_key", key);
    preload_session(mock_storage_, "session_vcsec", 100);
    preload_session(mock_storage_, "session_infotainment", 200);

    vehicle_ = std::make_shared<Vehicle>(mock_ble_, mock_storage_);
    vehicle_->set_vin(TEST_VIN);
    vehicle_->set_connected(true);
    vehicle_->set_awake(true);

    helper_ = make_helper_client();
    ASSERT_NE(helper_, nullptr) << "Helper client with both sessions should be usable";
  }

  std::shared_ptr<MockBleAdapter> mock_ble_;
  std::shared_ptr<MockStorageAdapter> mock_storage_;
  std::shared_ptr<Vehicle> vehicle_;
  std::shared_ptr<Client> helper_;

  // Sends the standard "Climate On" command with the preloaded session and
  // returns the encrypted request frame that was written.
  std::vector<uint8_t> send_climate_command(OperationOutcome *outcome) {
    vehicle_->send_command_result(
        UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Climate On",
        [](Client *client, uint8_t *buff, size_t *len) {
          bool enabled = true;
          return client->build_car_server_vehicle_action_message(buff, len, CarServer_VehicleAction_hvacAutoAction_tag,
                                                                 &enabled);
        },
        [outcome](TeslaBLE::OperationResult result) { *outcome = result.outcome(); });
    vehicle_->loop();
    vehicle_->loop();

    const auto &writes = mock_ble_->get_written_data();
    if (writes.size() != 1U) {
      return {};
    }
    return writes.front();
  }

  // A CarServer OK response encrypted for request_frame.
  std::vector<uint8_t> make_ok_infotainment_response(const std::vector<uint8_t> &request_frame, uint32_t counter,
                                                     std::optional<uint32_t> ad_counter_override = {}) {
    CarServer_Response content = CarServer_Response_init_default;
    content.has_actionStatus = true;
    content.actionStatus.result = CarServer_OperationStatus_E_OPERATIONSTATUS_OK;
    pb_byte_t payload[256];
    size_t payload_length = sizeof(payload);
    if (TeslaBLE::pb_encode_fields(payload, &payload_length, CarServer_Response_fields, &content) !=
        TeslaBLE_Status_E_OK) {
      return {};
    }

    return make_encrypted_response(*helper_, UniversalMessage_Domain_DOMAIN_INFOTAINMENT, counter, request_frame,
                                   payload, payload_length, ad_counter_override);
  }
};

TEST_F(EncryptedResponseTest, InfotainmentCommandCompletesWithEncryptedResponse) {
  OperationOutcome outcome = OperationOutcome::FAILED;
  auto request = send_climate_command(&outcome);
  ASSERT_FALSE(request.empty()) << "Preloaded sessions should send the encrypted command directly";

  auto response = make_ok_infotainment_response(request, 201);
  ASSERT_FALSE(response.empty()) << "Encrypted response should be built";

  vehicle_->on_rx_data(response);
  vehicle_->loop();

  EXPECT_EQ(outcome, OperationOutcome::SUCCESS) << "Encrypted response should complete the command";
}

TEST_F(EncryptedResponseTest, TamperedResponseTagIsRejected) {
  OperationOutcome outcome = OperationOutcome::FAILED;
  auto request = send_climate_command(&outcome);
  ASSERT_FALSE(request.empty());

  auto response = make_ok_infotainment_response(request, 201);
  ASSERT_FALSE(response.empty());

  // Corrupt one byte of the response tag.
  TeslaBLE::Client parser;
  UniversalMessage_RoutableMessage parsed = UniversalMessage_RoutableMessage_init_default;
  ASSERT_EQ(parser.parse_universal_message(const_cast<pb_byte_t *>(response.data() + 2), response.size() - 2, &parsed),
            TeslaBLE_Status_E_OK);
  parsed.sub_sigData.signature_data.sig_type.AES_GCM_Response_data.tag[0] ^= 0xFF;
  auto tampered = frame_universal_message(parsed);
  ASSERT_FALSE(tampered.empty());

  vehicle_->on_rx_data(tampered);
  vehicle_->loop();

  EXPECT_EQ(outcome, OperationOutcome::FAILED) << "Tampered response must not complete the command";
}

TEST_F(EncryptedResponseTest, ResponseWithMismatchedCounterIsRejected) {
  OperationOutcome outcome = OperationOutcome::FAILED;
  auto request = send_climate_command(&outcome);
  ASSERT_FALSE(request.empty());

  // Sign with a different counter than the one reported in AES_GCM_ResponseData.
  auto response = make_ok_infotainment_response(request, 201, /*ad_counter_override=*/202);
  ASSERT_FALSE(response.empty());

  vehicle_->on_rx_data(response);
  vehicle_->loop();

  EXPECT_EQ(outcome, OperationOutcome::FAILED) << "Response authenticated with a different counter must be rejected";
}

TEST_F(EncryptedResponseTest, VcsecCommandCompletesWithEncryptedResponse) {
  bool completed = false;
  bool success = false;
  vehicle_->send_command_bool(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Lock",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_vcsec_action_message(VCSEC_RKEAction_E_RKE_ACTION_LOCK, buff, len);
      },
      [&](bool ok) {
        completed = true;
        success = ok;
      });

  vehicle_->loop();
  vehicle_->loop();

  const auto &writes = mock_ble_->get_written_data();
  ASSERT_EQ(writes.size(), 1U) << "Preloaded sessions should send the encrypted command directly";

  VCSEC_FromVCSECMessage content = VCSEC_FromVCSECMessage_init_default;
  content.which_sub_message = VCSEC_FromVCSECMessage_commandStatus_tag;
  content.sub_message.commandStatus.operationStatus = VCSEC_OperationStatus_E_OPERATIONSTATUS_OK;
  pb_byte_t payload[256];
  size_t payload_length = sizeof(payload);
  ASSERT_EQ(TeslaBLE::pb_encode_fields(payload, &payload_length, VCSEC_FromVCSECMessage_fields, &content),
            TeslaBLE_Status_E_OK);

  auto response = make_encrypted_response(*helper_, UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, 101,
                                          writes.front(), payload, payload_length);
  ASSERT_FALSE(response.empty()) << "Encrypted response should be built";

  vehicle_->on_rx_data(response);
  vehicle_->loop();

  EXPECT_TRUE(completed) << "Encrypted VCSEC response should complete the command";
  EXPECT_TRUE(success);
}

TEST_F(EncryptedResponseTest, ClientKeepsRequestHashPerDomain) {
  std::vector<pb_byte_t> vcsec_frame(UniversalMessage_RoutableMessage_size + 2);
  size_t vcsec_length = vcsec_frame.size();
  ASSERT_EQ(helper_->build_vcsec_action_message(VCSEC_RKEAction_E_RKE_ACTION_LOCK, vcsec_frame.data(), &vcsec_length),
            TeslaBLE_Status_E_OK);
  vcsec_frame.resize(vcsec_length);

  // Building an encrypted Infotainment request must not clobber the VCSEC slot.
  std::vector<pb_byte_t> info_frame(UniversalMessage_RoutableMessage_size + 2);
  size_t info_length = info_frame.size();
  bool enabled = true;
  ASSERT_EQ(helper_->build_car_server_vehicle_action_message(info_frame.data(), &info_length,
                                                             CarServer_VehicleAction_hvacAutoAction_tag, &enabled),
            TeslaBLE_Status_E_OK);
  info_frame.resize(info_length);

  size_t vcsec_hash_length = 0;
  size_t info_hash_length = 0;
  const pb_byte_t *vcsec_hash =
      helper_->get_last_request_hash(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, &vcsec_hash_length);
  const pb_byte_t *info_hash =
      helper_->get_last_request_hash(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, &info_hash_length);

  ASSERT_NE(vcsec_hash, nullptr);
  ASSERT_NE(info_hash, nullptr);
  EXPECT_EQ(vcsec_hash_length, 17U);
  EXPECT_EQ(info_hash_length, 17U);

  const auto expected_vcsec_hash = request_hash_from_frame(*helper_, vcsec_frame);
  const auto expected_info_hash = request_hash_from_frame(*helper_, info_frame);
  EXPECT_TRUE(std::equal(vcsec_hash, vcsec_hash + vcsec_hash_length, expected_vcsec_hash.begin()))
      << "VCSEC request hash must survive a later Infotainment request";
  EXPECT_TRUE(std::equal(info_hash, info_hash + info_hash_length, expected_info_hash.begin()))
      << "Infotainment request hash must match its request";
}
