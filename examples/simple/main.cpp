#include <client.h>
#include <cstdio>
#include <inttypes.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <signatures.pb.h>
#include <string.h>
#include <universal_message.pb.h>
#include <vcsec.pb.h>

#include "log.cpp"

// mock data from PROTOCOL.md examples
static const char *MOCK_VIN = "5YJ30123456789ABC";
static const unsigned char MOCK_PRIVATE_KEY[227] = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEILRjIS9VEyG+0K71a2T/lKVF5MllmYu78y14UzHgPQb5oAoGCCqGSM49\nAwEHoUQDQgAEUxC4mUu1EemeRNJFvgU3RHptxzxR1kCc+fVIwxNg4Pxa2AzDDAbZ\njh4MR49c2FBOLVVzYlUnt1F35HFWGjaXsg==\n-----END EC PRIVATE KEY-----";

int main()
{
  TeslaBLE::Client client = TeslaBLE::Client{};
  client.setVIN(MOCK_VIN);
  /*
   * this loads an existing private key and generates the public key
   */
  printf("Loading private key\n");
  int status = client.loadPrivateKey(MOCK_PRIVATE_KEY, sizeof MOCK_PRIVATE_KEY);
  // int status = client.createPrivateKey();
  if (status != 0)
  {
    printf("Failed create private key\n");
  }

  unsigned char private_key_buffer[sizeof MOCK_PRIVATE_KEY + 1];
  size_t private_key_length;
  status = client.getPrivateKey(private_key_buffer, sizeof(private_key_buffer),
                                &private_key_length);
  if (status != 0)
  {
    printf("Failed to get private key\n");
  }
  printf("Private key length: %d\n", private_key_length);
  printf("Private key: ");
  for (int i = 0; i < private_key_length; i++)
  {
    printf("%02X", private_key_buffer[i]);
  }
  printf("\n");
  printf("Private key as char: %s\n", private_key_buffer);

  unsigned char whitelist_message_buffer[client.MAX_BLE_MESSAGE_SIZE];
  size_t whitelist_message_length;
  // support for wake command added to CHARGING_MANAGER_ROLE in 2024.20.x (not sure?)
  // https://github.com/teslamotors/vehicle-command/issues/232#issuecomment-2181503570
  printf("Building whitelist message for CHARGING MANAGER\n");
  int return_code = client.buildWhiteListMessage(Keys_Role_ROLE_CHARGING_MANAGER, VCSEC_KeyFormFactor_KEY_FORM_FACTOR_CLOUD_KEY, whitelist_message_buffer, &whitelist_message_length);

  if (return_code != 0)
  {
    printf("Failed to build whitelist message\n");
    return -1;
  }
  printf("Whitelist message length: %d\n", whitelist_message_length);
  printf("Whitelist message hex: ");
  for (int i = 0; i < whitelist_message_length; i++)
  {
    printf("%02X", whitelist_message_buffer[i]);
  }
  printf("\n");
  // mock received_message from VSSEC
  // 321212102fddc145caccca430566370df149855d3a0208027a5e0801124104c7a1f47138486aa4729971494878d33b1a24e39571f748a6e16c5955b3d877d3a6aaa0e955166474af5d32c410f439a2234137ad1bb085fd4e8813c958f11d971a104c463f9cc0d3d26906e982ed224adde625854a000030066a2432220a205a0d3c7cb02c04d912a3588bc2a6fd8c00f244091bdd9dfe46fcdc4706415b269203103ccce3d51a6f3c2aeea8913644a70584
  pb_byte_t received_bytes_vcsec[177] = {0x32, 0x12, 0x12, 0x10, 0x2f, 0xdd, 0xc1, 0x45, 0xca, 0xcc, 0xca, 0x43, 0x05, 0x66, 0x37, 0x0d, 0xf1, 0x49, 0x85, 0x5d, 0x3a, 0x02, 0x08, 0x02, 0x7a, 0x5e, 0x08, 0x01, 0x12, 0x41, 0x04, 0xc7, 0xa1, 0xf4, 0x71, 0x38, 0x48, 0x6a, 0xa4, 0x72, 0x99, 0x71, 0x49, 0x48, 0x78, 0xd3, 0x3b, 0x1a, 0x24, 0xe3, 0x95, 0x71, 0xf7, 0x48, 0xa6, 0xe1, 0x6c, 0x59, 0x55, 0xb3, 0xd8, 0x77, 0xd3, 0xa6, 0xaa, 0xa0, 0xe9, 0x55, 0x16, 0x64, 0x74, 0xaf, 0x5d, 0x32, 0xc4, 0x10, 0xf4, 0x39, 0xa2, 0x23, 0x41, 0x37, 0xad, 0x1b, 0xb0, 0x85, 0xfd, 0x4e, 0x88, 0x13, 0xc9, 0x58, 0xf1, 0x1d, 0x97, 0x1a, 0x10, 0x4c, 0x46, 0x3f, 0x9c, 0xc0, 0xd3, 0xd2, 0x69, 0x06, 0xe9, 0x82, 0xed, 0x22, 0x4a, 0xdd, 0xe6, 0x25, 0x85, 0x4a, 0x00, 0x00, 0x30, 0x06, 0x6a, 0x24, 0x32, 0x22, 0x0a, 0x20, 0x5a, 0x0d, 0x3c, 0x7c, 0xb0, 0x2c, 0x04, 0xd9, 0x12, 0xa3, 0x58, 0x8b, 0xc2, 0xa6, 0xfd, 0x8c, 0x00, 0xf2, 0x44, 0x09, 0x1b, 0xdd, 0x9d, 0xfe, 0x46, 0xfc, 0xdc, 0x47, 0x06, 0x41, 0x5b, 0x26, 0x92, 0x03, 0x10, 0x3c, 0xcc, 0xe3, 0xd5, 0x1a, 0x6f, 0x3c, 0x2a, 0xee, 0xa8, 0x91, 0x36, 0x44, 0xa7, 0x05, 0x84};

  // parse received universal message
  UniversalMessage_RoutableMessage received_message_vcsec = UniversalMessage_RoutableMessage_init_default;
  return_code = client.parseUniversalMessage(received_bytes_vcsec, sizeof(received_bytes_vcsec), &received_message_vcsec);
  if (return_code != 0)
  {
    printf("Failed to parse received message VSSEC\n");
    return -1;
  }
  log_routable_message(&received_message_vcsec);

  Signatures_SessionInfo session_info_vcsec = Signatures_SessionInfo_init_default;
  return_code = client.parsePayloadSessionInfo(&received_message_vcsec.payload.session_info, &session_info_vcsec);
  if (return_code != 0)
  {
    printf("Failed to parse session info VSSEC\n");
    return -1;
  }
  log_session_info(&session_info_vcsec);

  uint32_t generated_at_vcsec = std::time(nullptr);
  uint32_t time_zero_vcsec = generated_at_vcsec - session_info_vcsec.clock_time;
  client.session_vcsec_.setCounter(&session_info_vcsec.counter);
  client.session_vcsec_.setExpiresAt(&session_info_vcsec.clock_time);
  client.session_vcsec_.setEpoch(session_info_vcsec.epoch);
  client.session_vcsec_.setTimeZero(&time_zero_vcsec);
  client.session_vcsec_.setIsAuthenticated(true);
  printf("Session authenticated: %s\n", client.session_vcsec_.isAuthenticated ? "true" : "false");
  return_code = client.loadTeslaKey(false, session_info_vcsec.publicKey.bytes, session_info_vcsec.publicKey.size);
  if (return_code != 0)
  {
    printf("Failed load vssec tesla key\n");
    return 1;
  }
  printf("Loaded VCSEC Tesla key\n");
  printf("VCSEC Public key: ");
  for (int i = 0; i < session_info_vcsec.publicKey.size; i++)
  {
    printf("%02X", session_info_vcsec.publicKey.bytes[i]);
  }
  printf("\n");

  printf("Parsed VCSEC session info response\n");
  printf("Received new counter from the car: %" PRIu32, client.session_vcsec_.counter_);
  printf("\n");
  printf("Received new expires at from the car: %" PRIu32, client.session_vcsec_.expires_at_);
  printf("\n");
  printf("Epoch: ");
  for (int i = 0; i < sizeof(client.session_vcsec_.epoch_); i++)
  {
    printf("%02X", client.session_vcsec_.epoch_[i]);
  }
  printf("\n");

  // build wake command
  printf("Building wake command\n");
  unsigned char action_message_buffer[client.MAX_BLE_MESSAGE_SIZE];
  size_t action_message_buffer_length = 0;
  return_code = client.buildVCSECActionMessage(VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, action_message_buffer, &action_message_buffer_length);
  if (return_code != 0)
  {
    printf("Failed to build action message \n");
    return -1;
  }
  printf("Action message length: %d\n", action_message_buffer_length);
  printf("Action message hex: ");
  for (int i = 0; i < action_message_buffer_length; i++)
  {
    printf("%02X", action_message_buffer[i]);
  }
  printf("\n");

  // build information request status
  printf("Building information request status\n");
  pb_byte_t info_request_status_buffer[client.MAX_BLE_MESSAGE_SIZE];
  size_t info_request_status_length = 0;
  return_code = client.buildVCSECInformationRequestMessage(VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS, info_request_status_buffer, &info_request_status_length);
  if (return_code != 0)
  {
    printf("Failed to build action message \n");
    return -1;
  }
  printf("VCSEC InfoRequest status length: %d\n", info_request_status_length);
  printf("VCSEC InfoRequest status hex: ");
  for (int i = 0; i < info_request_status_length; i++)
  {
    printf("%02X", info_request_status_buffer[i]);
  }
  printf("\n");

  // mock received message from INFOTAINMENT
  // 321212108f3d244b50b07a9842cac108c928b5e73a0208037a5e0801124104c7a1f47138486aa4729971494878d33b1a24e39571f748a6e16c5955b3d877d3a6aaa0e955166474af5d32c410f439a2234137ad1bb085fd4e8813c958f11d971a104c463f9cc0d3d26906e982ed224adde6255f0a000030076a2432220a208e8dcd164ef361fd123c46c2b2bdfd1fc93056f4ef32c9311a275db908d4d23f9203100a404ec0fc9aa863aec3e50196fbf30b
  pb_byte_t received_bytes_infotainment[177] = {0x32, 0x12, 0x12, 0x10, 0x8f, 0x3d, 0x24, 0x4b, 0x50, 0xb0, 0x7a, 0x98, 0x42, 0xca, 0xc1, 0x08, 0xc9, 0x28, 0xb5, 0xe7, 0x3a, 0x02, 0x08, 0x03, 0x7a, 0x5e, 0x08, 0x01, 0x12, 0x41, 0x04, 0xc7, 0xa1, 0xf4, 0x71, 0x38, 0x48, 0x6a, 0xa4, 0x72, 0x99, 0x71, 0x49, 0x48, 0x78, 0xd3, 0x3b, 0x1a, 0x24, 0xe3, 0x95, 0x71, 0xf7, 0x48, 0xa6, 0xe1, 0x6c, 0x59, 0x55, 0xb3, 0xd8, 0x77, 0xd3, 0xa6, 0xaa, 0xa0, 0xe9, 0x55, 0x16, 0x64, 0x74, 0xaf, 0x5d, 0x32, 0xc4, 0x10, 0xf4, 0x39, 0xa2, 0x23, 0x41, 0x37, 0xad, 0x1b, 0xb0, 0x85, 0xfd, 0x4e, 0x88, 0x13, 0xc9, 0x58, 0xf1, 0x1d, 0x97, 0x1a, 0x10, 0x4c, 0x46, 0x3f, 0x9c, 0xc0, 0xd3, 0xd2, 0x69, 0x06, 0xe9, 0x82, 0xed, 0x22, 0x4a, 0xdd, 0xe6, 0x25, 0x5f, 0x0a, 0x00, 0x00, 0x30, 0x07, 0x6a, 0x24, 0x32, 0x22, 0x0a, 0x20, 0x8e, 0x8d, 0xcd, 0x16, 0x4e, 0xf3, 0x61, 0xfd, 0x12, 0x3c, 0x46, 0xc2, 0xb2, 0xbd, 0xfd, 0x1f, 0xc9, 0x30, 0x56, 0xf4, 0xef, 0x32, 0xc9, 0x31, 0x1a, 0x27, 0x5d, 0xb9, 0x08, 0xd4, 0xd2, 0x3f, 0x92, 0x03, 0x10, 0x0a, 0x40, 0x4e, 0xc0, 0xfc, 0x9a, 0xa8, 0x63, 0xae, 0xc3, 0xe5, 0x01, 0x96, 0xfb, 0xf3, 0x0b};

  // parse received universal message
  UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
  return_code = client.parseUniversalMessage(received_bytes_infotainment, sizeof(received_bytes_infotainment), &received_message);
  if (return_code != 0)
  {
    printf("Failed to parse received message INFOTAINMENT\n");
    return -1;
  }
  log_routable_message(&received_message);

  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  return_code = client.parsePayloadSessionInfo(&received_message.payload.session_info, &session_info);
  if (return_code != 0)
  {
    printf("Failed to parse session info INFOTAINMENT\n");
    return -1;
  }
  log_session_info(&session_info);

  uint32_t generated_at = std::time(nullptr);
  uint32_t time_zero = generated_at - session_info.clock_time;
  client.session_infotainment_.setCounter(&session_info.counter);
  client.session_infotainment_.setExpiresAt(&session_info.clock_time);
  client.session_infotainment_.setEpoch(session_info.epoch);
  client.session_infotainment_.setTimeZero(&time_zero);
  client.session_infotainment_.setIsAuthenticated(true);
  printf("Session authenticated: %s\n", client.session_infotainment_.isAuthenticated ? "true" : "false");
  client.loadTeslaKey(true, session_info.publicKey.bytes, session_info.publicKey.size);

  printf("Parsed INFOTAINMENT session info response\n");
  printf("Received new counter from the car: %" PRIu32, client.session_infotainment_.counter_);
  printf("\n");
  printf("Received new counter from the car (hex): ");
  for (int i = 0; i < sizeof(session_info.counter); i++)
  {
    printf("%02X", ((uint8_t *)&session_info.counter)[i]);
  }
  printf("\n");

  printf("Received new clock time from the car (hex): ");
  for (int i = 0; i < sizeof(session_info.clock_time); i++)
  {
    printf("%02X", ((uint8_t *)&session_info.clock_time)[i]);
  }
  printf("\n");

  printf("Received new expires at from the car: %" PRIu32, client.session_infotainment_.expires_at_);
  printf("\n");
  printf("Epoch: ");
  for (int i = 0; i < sizeof(client.session_infotainment_.epoch_); i++)
  {
    printf("%02X", client.session_infotainment_.epoch_[i]);
  }
  printf("\n");

  printf("Loading public key from car\n");
  // convert pb Failed to parse incoming message
  int result_code = client.loadTeslaKey(true, session_info.publicKey.bytes, session_info.publicKey.size);
  if (result_code != 0)
  {
    printf("Failed load tesla key\n");
    return 1;
  }

  // 8f3d244b50b07a9842cac108c928b5e7
  // pb_byte_t connection_id[16] = {0x8f, 0x3d, 0x24, 0x4b, 0x50, 0xb0, 0x7a, 0x98, 0x42, 0xca, 0xc1, 0x08, 0xc9, 0x28, 0xb5, 0xe7};
  // 934f10691deda826a7982e92c4fce83f
  pb_byte_t connection_id[16] = {0x93, 0x4f, 0x10, 0x69, 0x1d, 0xed, 0xa8, 0x26, 0xa7, 0x98, 0x2e, 0x92, 0xc4, 0xfc, 0xe8, 0x3f};
  client.setConnectionID(connection_id);

  printf("Building charging amps message\n");
  pb_byte_t charging_amps_message_buffer[client.MAX_BLE_MESSAGE_SIZE];
  size_t charging_amps_message_length;
  client.buildChargingAmpsMessage(12, charging_amps_message_buffer, &charging_amps_message_length);
  printf("ChargingAmpsMessage length: %d\n", charging_amps_message_length);
  printf("ChargingAmpsMessage hex: ");
  for (int i = 0; i < charging_amps_message_length; i++)
  {
    printf("%02X", charging_amps_message_buffer[i]);
  }
  printf("\n");

  printf("Set charging limit message\n");
  pb_byte_t charging_limit_message_buffer[client.MAX_BLE_MESSAGE_SIZE];
  size_t charging_limit_message_length;
  client.buildChargingSetLimitMessage(95, charging_limit_message_buffer, &charging_limit_message_length);
  printf("ChargingSetLimitMessage length: %d\n", charging_limit_message_length);
  printf("ChargingSetLimitMessage hex: ");
  for (int i = 0; i < charging_limit_message_length; i++)
  {
    printf("%02X", charging_limit_message_buffer[i]);
  }
  printf("\n");

  printf("Turn on HVAC limit message\n");
  pb_byte_t hvac_on_message_buffer[client.MAX_BLE_MESSAGE_SIZE];
  size_t hvac_on_message_length;
  client.buildHVACMessage(true, hvac_on_message_buffer, &hvac_on_message_length);
  printf("HVAC length: %d\n", hvac_on_message_length);
  printf("HVAC hex: ");
  for (int i = 0; i < hvac_on_message_length; i++)
  {
    printf("%02X", hvac_on_message_buffer[i]);
  }
  printf("\n");
}
