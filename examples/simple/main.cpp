#include <client.h>
#include <cstdio>
#include <cinttypes>
#include <pb_decode.h>
#include <pb_encode.h>
#include <signatures.pb.h>
#include <cstring>
#include <universal_message.pb.h>
#include <vcsec.pb.h>
#include <sstream>
#include <iomanip>

#include "defs.h"
#include "errors.h"
#include "log.h"

// mock data from PROTOCOL.md examples
static constexpr char MOCK_VIN[] = "5YJ30123456789ABC";
static const unsigned char MOCK_PRIVATE_KEY[227] =
    "-----BEGIN EC PRIVATE "
    "KEY-----\nMHcCAQEEILRjIS9VEyG+0K71a2T/"
    "lKVF5MllmYu78y14UzHgPQb5oAoGCCqGSM49\nAwEHoUQDQgAEUxC4mUu1EemeRNJFvgU3RHptxzxR1kCc+"
    "fVIwxNg4Pxa2AzDDAbZ\njh4MR49c2FBOLVVzYlUnt1F35HFWGjaXsg==\n-----END EC PRIVATE KEY-----";

std::string bytes_to_hex_string(const pb_byte_t *bytes, size_t length) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < length; i++) {
    ss << std::setw(2) << static_cast<unsigned>(bytes[i]);
  }
  return ss.str();
}

int main() {
  TeslaBLE::Client client = TeslaBLE::Client{};
  client.set_vin(MOCK_VIN);
  /*
   * this loads an existing private key and generates the public key
   */
  LOG_INFO("Loading private key");
  int status = client.load_private_key(MOCK_PRIVATE_KEY, sizeof MOCK_PRIVATE_KEY);
  // int status = client.create_private_key();
  if (status != 0) {
    LOG_ERROR("Failed create private key");
  }

  unsigned char private_key_buffer[sizeof MOCK_PRIVATE_KEY + 1];
  size_t private_key_length;
  status = client.get_private_key(private_key_buffer, sizeof(private_key_buffer), &private_key_length);
  if (status != 0) {
    LOG_ERROR("Failed to get private key");
  }
  LOG_DEBUG("Private key length: %d", private_key_length);
  LOG_VERBOSE("Private key: %s", bytes_to_hex_string(private_key_buffer, private_key_length).c_str());

  unsigned char whitelist_message_buffer[VCSEC_ToVCSECMessage_size];
  size_t whitelist_message_length;
  // support for wake command added to CHARGING_MANAGER_ROLE in 2024.20.x (not sure?)
  // https://github.com/teslamotors/vehicle-command/issues/232#issuecomment-2181503570
  LOG_INFO("Building whitelist message for CHARGING MANAGER");
  int return_code =
      client.build_white_list_message(Keys_Role_ROLE_CHARGING_MANAGER, VCSEC_KeyFormFactor_KEY_FORM_FACTOR_CLOUD_KEY,
                                      whitelist_message_buffer, &whitelist_message_length);

  if (return_code != 0) {
    auto status = static_cast<TeslaBLE::TeslaBLE_Status_E>(return_code);
    LOG_ERROR("Failed to build whitelist message: %s", TeslaBLE::teslable_status_to_string(status));
    return -1;
  }
  LOG_DEBUG("Whitelist message length: %d", whitelist_message_length);
  LOG_DEBUG("Whitelist message hex: %s",
            bytes_to_hex_string(whitelist_message_buffer, whitelist_message_length).c_str());

  // mock received_message from VSSEC
  // 321212102fddc145caccca430566370df149855d3a0208027a5e0801124104c7a1f47138486aa4729971494878d33b1a24e39571f748a6e16c5955b3d877d3a6aaa0e955166474af5d32c410f439a2234137ad1bb085fd4e8813c958f11d971a104c463f9cc0d3d26906e982ed224adde625854a000030066a2432220a205a0d3c7cb02c04d912a3588bc2a6fd8c00f244091bdd9dfe46fcdc4706415b269203103ccce3d51a6f3c2aeea8913644a70584
  pb_byte_t received_bytes_vcsec[177] = {
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

  // parse received universal message
  UniversalMessage_RoutableMessage received_message_vcsec = UniversalMessage_RoutableMessage_init_default;
  return_code =
      client.parse_universal_message(received_bytes_vcsec, sizeof(received_bytes_vcsec), &received_message_vcsec);
  if (return_code != 0) {
    auto status = static_cast<TeslaBLE::TeslaBLE_Status_E>(return_code);
    LOG_ERROR("Failed to parse received message VSSE: %s", TeslaBLE::teslable_status_to_string(status));
    return -1;
  }
  log_routable_message(&received_message_vcsec);

  Signatures_SessionInfo session_info_vcsec = Signatures_SessionInfo_init_default;
  return_code = client.parse_payload_session_info(&received_message_vcsec.payload.session_info, &session_info_vcsec);
  if (return_code != 0) {
    LOG_ERROR("Failed to parse session info VSSEC");
    return -1;
  }
  log_session_info(&session_info_vcsec);

  UniversalMessage_Domain domain = UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY;
  auto *session = client.get_peer(domain);

  return_code = session->update_session(&session_info_vcsec);
  if (return_code != 0) {
    LOG_ERROR("Failed to update session VSSEC");
    return -1;
  }

  LOG_INFO("Session initialized: %s", session->is_initialized() ? "true" : "false");
  if (!session->is_initialized()) {
    LOG_ERROR("Session not initialized");
    return 1;
  }

  LOG_DEBUG("VCSEC Public key: %s",
            bytes_to_hex_string(session_info_vcsec.publicKey.bytes, session_info_vcsec.publicKey.size).c_str());

  LOG_DEBUG("Parsed VCSEC session info response");
  LOG_DEBUG("Received new counter from the car: %" PRIu32, session->get_counter());
  LOG_INFO("Epoch: %s", bytes_to_hex_string(session->get_epoch(), 16).c_str());

  // build wake command
  LOG_INFO("Building wake command");
  unsigned char action_message_buffer[UniversalMessage_RoutableMessage_size];
  size_t action_message_buffer_length = 0;
  return_code = client.build_vcsec_action_message(VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, action_message_buffer,
                                                  &action_message_buffer_length);
  if (return_code != 0) {
    LOG_ERROR("Failed to build action message ");
    return -1;
  }
  LOG_DEBUG("Action message length: %d", action_message_buffer_length);
  LOG_INFO("Action message hex: %s", bytes_to_hex_string(action_message_buffer, action_message_buffer_length).c_str());

  // build information request status
  LOG_INFO("Building information request status");
  pb_byte_t info_request_status_buffer[UniversalMessage_RoutableMessage_size];
  size_t info_request_status_length = 0;
  return_code =
      client.build_vcsec_information_request_message(VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS,
                                                     info_request_status_buffer, &info_request_status_length);
  if (return_code != 0) {
    LOG_ERROR("Failed to build action message ");
    return -1;
  }
  LOG_DEBUG("VCSEC InfoRequest status length: %d", info_request_status_length);
  LOG_INFO("VCSEC InfoRequest status hex: %s",
           bytes_to_hex_string(info_request_status_buffer, info_request_status_length).c_str());

  // mock received message from INFOTAINMENT
  // 321212108f3d244b50b07a9842cac108c928b5e73a0208037a5e0801124104c7a1f47138486aa4729971494878d33b1a24e39571f748a6e16c5955b3d877d3a6aaa0e955166474af5d32c410f439a2234137ad1bb085fd4e8813c958f11d971a104c463f9cc0d3d26906e982ed224adde6255f0a000030076a2432220a208e8dcd164ef361fd123c46c2b2bdfd1fc93056f4ef32c9311a275db908d4d23f9203100a404ec0fc9aa863aec3e50196fbf30b
  pb_byte_t received_bytes_infotainment[177] = {
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

  // parse received universal message
  LOG_INFO("Parsing received message INFOTAINMENT");
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
  return_code = client.parse_universal_message(received_bytes_infotainment, sizeof(received_bytes_infotainment),
                                               &received_message);
  if (return_code != 0) {
    LOG_ERROR("Failed to parse received message INFOTAINMENT");
    return -1;
  }
  log_routable_message(&received_message);

  LOG_INFO("Parsing session info INFOTAINMENT");
  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  return_code = client.parse_payload_session_info(&received_message.payload.session_info, &session_info);
  if (return_code != 0) {
    LOG_ERROR("Failed to parse session info INFOTAINMENT");
    return -1;
  }
  log_session_info(&session_info);

  session = client.get_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
  return_code = session->update_session(&session_info);
  if (return_code != 0) {
    LOG_ERROR("Failed to update session INFOTAINMENT");
    return -1;
  }

  LOG_INFO("Session initialized: %s", session->is_initialized() ? "true" : "false");
  if (!session->is_initialized()) {
    LOG_ERROR("Session not initialized");
    return 1;
  }

  LOG_DEBUG("Parsed INFOTAINMENT session info response");
  LOG_DEBUG("Received new counter from the car: %" PRIu32, session_info.counter);
  LOG_DEBUG("Received new clock time from the car: %" PRIu32, session_info.clock_time);
  LOG_DEBUG("Epoch: %s", bytes_to_hex_string(session->get_epoch(), 16).c_str());

  // 8f3d244b50b07a9842cac108c928b5e7
  // pb_byte_t connection_id[16] = {0x8f, 0x3d, 0x24, 0x4b, 0x50, 0xb0, 0x7a, 0x98, 0x42, 0xca, 0xc1, 0x08, 0xc9, 0x28,
  // 0xb5, 0xe7}; 934f10691deda826a7982e92c4fce83f
  pb_byte_t connection_id[16] = {0x93, 0x4f, 0x10, 0x69, 0x1d, 0xed, 0xa8, 0x26,
                                 0xa7, 0x98, 0x2e, 0x92, 0xc4, 0xfc, 0xe8, 0x3f};
  client.set_connection_id(connection_id);

  LOG_INFO("Building charging amps message");
  pb_byte_t charging_amps_message_buffer[UniversalMessage_RoutableMessage_size];
  size_t charging_amps_message_length;
  CarServer_SetChargingAmpsAction charging_amps_action = CarServer_SetChargingAmpsAction_init_default;
  charging_amps_action.charging_amps = 12;
  return_code = client.build_car_server_vehicle_action_message(
      charging_amps_message_buffer, &charging_amps_message_length, CarServer_VehicleAction_setChargingAmpsAction_tag,
      &charging_amps_action);
  if (return_code != 0) {
    LOG_ERROR("Failed to build charging amps message");
    return -1;
  }
  LOG_DEBUG("ChargingAmpsMessage length: %d", charging_amps_message_length);
  LOG_INFO("ChargingAmpsMessage hex: %s",
           bytes_to_hex_string(charging_amps_message_buffer, charging_amps_message_length).c_str());

  LOG_INFO("Set charging limit message");
  pb_byte_t charging_limit_message_buffer[UniversalMessage_RoutableMessage_size];
  size_t charging_limit_message_length;
  CarServer_ChargingSetLimitAction charging_limit_action = CarServer_ChargingSetLimitAction_init_default;
  charging_limit_action.percent = 95;
  return_code = client.build_car_server_vehicle_action_message(
      charging_limit_message_buffer, &charging_limit_message_length, CarServer_VehicleAction_chargingSetLimitAction_tag,
      &charging_limit_action);
  if (return_code != 0) {
    LOG_ERROR("Failed to build charging limit message");
    return -1;
  }
  LOG_DEBUG("ChargingSetLimitMessage length: %d", charging_limit_message_length);
  LOG_INFO("ChargingSetLimitMessage hex: %s",
           bytes_to_hex_string(charging_limit_message_buffer, charging_limit_message_length).c_str());

  LOG_INFO("Turn on HVAC limit message");
  pb_byte_t hvac_on_message_buffer[UniversalMessage_RoutableMessage_size];
  size_t hvac_on_message_length;
  CarServer_HvacAutoAction hvac_action = CarServer_HvacAutoAction_init_default;
  hvac_action.power_on = true;
  hvac_action.manual_override = false;
  return_code = client.build_car_server_vehicle_action_message(
      hvac_on_message_buffer, &hvac_on_message_length, CarServer_VehicleAction_hvacAutoAction_tag, &hvac_action);
  if (return_code != 0) {
    LOG_ERROR("Failed to build HVAC message");
    return -1;
  }
  LOG_DEBUG("HVAC length: %d", hvac_on_message_length);
  LOG_INFO("HVAC hex: %s", bytes_to_hex_string(hvac_on_message_buffer, hvac_on_message_length).c_str());

  LOG_INFO("Get charge data message");
  pb_byte_t get_data_message_buffer[UniversalMessage_RoutableMessage_size];
  size_t get_data_message_length;
  return_code = client.build_car_server_get_vehicle_data_message(get_data_message_buffer, &get_data_message_length,
                                                                 CarServer_GetVehicleData_getChargeState_tag);
  if (return_code != 0) {
    LOG_ERROR("Failed to build_car_server_get_vehicle_data_message");
    return -1;
  }
  LOG_DEBUG("HVAC length: %d", get_data_message_length);
  LOG_INFO("HVAC hex: %s", bytes_to_hex_string(get_data_message_buffer, get_data_message_length).c_str());
}
