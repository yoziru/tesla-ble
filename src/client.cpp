// https://github.com/platformio/platform-espressif32/issues/957
// specifically set when compiling with ESP-IDF
#ifdef ESP_PLATFORM
#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#endif

#ifndef TESLA_LOG_TAG
#define TESLA_LOG_TAG "TeslaBLE::Client"
#endif

#include "client.h"

#include "crypto_context.h"
#include "defs.h"
#include "errors.h"
#include "message_builders.h"
#include "tb_utils.h"

#include "car_server.pb.h"
#include "keys.pb.h"
#include "universal_message.pb.h"
#include "vcsec.pb.h"
#include "vehicle.pb.h"

#include <pb_decode.h>
#include <pb_encode.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>

namespace TeslaBLE {
Client::Client() { initialize_peers(); }

void Client::initialize_peers() {
  auto crypto_context_shared = std::shared_ptr<CryptoContext>(&crypto_context_, [](CryptoContext *) {});

  session_vcsec_ = std::make_unique<Peer>(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, crypto_context_shared, vin_);

  session_infotainment_ =
      std::make_unique<Peer>(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, crypto_context_shared, vin_);
}

void Client::set_vin(const std::string &vin) {
  if (!ParameterValidator::is_valid_vin(vin.c_str())) {
    LOG_WARNING("Invalid VIN format: %s", vin.c_str());
  }

  vin_ = vin;

  // Update peers with new VIN
  if (session_vcsec_) {
    session_vcsec_->set_vin(vin);
  }
  if (session_infotainment_) {
    session_infotainment_->set_vin(vin);
  }
}

void Client::set_connection_id(const pb_byte_t *connection_id) {
  if (!ParameterValidator::is_valid_connection_id(connection_id)) {
    LOG_ERROR("Invalid connection ID");
    return;
  }

  std::memcpy(connection_id_.data(), connection_id, connection_id_.size());
}

/*
 * Create a new private key, public key and key ID
 *
 * @return Error code (0 for success)
 */
int Client::create_private_key() {
  int result = crypto_context_.create_private_key();
  if (result != TeslaBLE_Status_E_OK) {
    return result;
  }

  result = generate_public_key_data();
  if (result != TeslaBLE_Status_E_OK) {
    return result;
  }

  return TeslaBLE_Status_E_OK;
}

int Client::load_private_key(const uint8_t *private_key_buffer, size_t private_key_length) {
  int result = crypto_context_.load_private_key(private_key_buffer, private_key_length);
  if (result != TeslaBLE_Status_E_OK) {
    return result;
  }

  result = generate_public_key_data();
  if (result != TeslaBLE_Status_E_OK) {
    return result;
  }

  return TeslaBLE_Status_E_OK;
}

int Client::get_private_key(pb_byte_t *output_buffer, size_t output_buffer_length, size_t *output_length) {
  return crypto_context_.get_private_key(output_buffer, output_buffer_length, output_length);
}

int Client::get_public_key(pb_byte_t *output_buffer, size_t *output_buffer_length) {
  if (output_buffer == nullptr || output_buffer_length == nullptr) {
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  if (public_key_size_ == 0) {
    LOG_ERROR("Public key not generated");
    return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
  }

  std::memcpy(output_buffer, public_key_.data(), public_key_size_);
  *output_buffer_length = public_key_size_;
  return TeslaBLE_Status_E_OK;
}

int Client::generate_public_key_data() {
  // Set the buffer size to maximum capacity before calling generate_public_key
  public_key_size_ = public_key_.size();

  int result = crypto_context_.generate_public_key(public_key_.data(), &public_key_size_);
  if (result != TeslaBLE_Status_E_OK) {
    return result;
  }

  return generate_key_id();
}

int Client::generate_key_id() {
  return crypto_context_.generate_key_id(public_key_.data(), public_key_size_, public_key_id_.data());
}

Peer *Client::get_peer(UniversalMessage_Domain domain) {
  switch (domain) {
    case UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY:
      return session_vcsec_.get();
    case UniversalMessage_Domain_DOMAIN_INFOTAINMENT:
      return session_infotainment_.get();
    default:
      LOG_ERROR("Invalid domain: %d", domain);
      return nullptr;
  }
}

const Peer *Client::get_peer(UniversalMessage_Domain domain) const {
  switch (domain) {
    case UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY:
      return session_vcsec_.get();
    case UniversalMessage_Domain_DOMAIN_INFOTAINMENT:
      return session_infotainment_.get();
    default:
      LOG_ERROR("Invalid domain: %d", domain);
      return nullptr;
  }
}
/*
 * This prepends the size of the message to the
 * front of the message
 *
 * @param input_buffer Pointer to the input buffer
 * @param input_buffer_length Size of the input buffer
 * @param output_buffer Pointer to the output buffer
 * @param output_length Pointer to size_t that will store the written length
 */
void Client::prepend_length(const pb_byte_t *input_buffer, size_t input_buffer_length, pb_byte_t *output_buffer,
                            size_t *output_buffer_length) {
  uint8_t higher_byte = input_buffer_length >> 8;
  uint8_t lower_byte = input_buffer_length & 0xFF;

  uint8_t temp_buffer[2];
  temp_buffer[0] = higher_byte;
  temp_buffer[1] = lower_byte;

  memcpy(output_buffer, temp_buffer, sizeof(temp_buffer));
  memcpy(output_buffer + 2, input_buffer, input_buffer_length);
  *output_buffer_length = input_buffer_length + 2;
}

/*
 * This will build the message need to whitelist
 * the public key in the car.
 * Beware that the car does not show any signs of that
 * interaction before you tab your keyboard on the reader
 *
 * @param input_buffer Pointer to the input buffer
 * @param input_buffer_length Size of the input buffer
 * @param output_buffer Pointer to the output buffer
 * @param output_length Pointer to size_t that will store the written length
 * @return int result code 0 for successful
 */
int Client::build_white_list_message(Keys_Role role, VCSEC_KeyFormFactor form_factor, pb_byte_t *output_buffer,
                                     size_t *output_length) {
  // printf("Building whitelist message\n");
  if (!crypto_context_.is_private_key_initialized()) {
    LOG_ERROR("[build_white_list_message] Private key is not initialized");
    return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
  }

  // Validate role parameter - Tesla protocol requires specific role values
  if (role < _Keys_Role_MIN || role > _Keys_Role_MAX) {
    LOG_ERROR("[build_white_list_message] Invalid role value: %d (valid range: %d-%d)", role, _Keys_Role_MIN,
              _Keys_Role_MAX);
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  VCSEC_PermissionChange permissions_action = VCSEC_PermissionChange_init_default;
  permissions_action.has_key = true;
  memcpy(permissions_action.key.PublicKeyRaw.bytes, public_key_.data(), this->public_key_size_);
  permissions_action.key.PublicKeyRaw.size = this->public_key_size_;
  permissions_action.keyRole = role;
  // permissions_action.secondsToBeActive = 0;

  VCSEC_WhitelistOperation whitelist = VCSEC_WhitelistOperation_init_default;
  whitelist.has_metadataForKey = true;
  whitelist.metadataForKey.keyFormFactor = form_factor;

  whitelist.which_sub_message = VCSEC_WhitelistOperation_addKeyToWhitelistAndAddPermissions_tag;
  whitelist.sub_message.addKeyToWhitelistAndAddPermissions = permissions_action;

  VCSEC_UnsignedMessage payload = VCSEC_UnsignedMessage_init_default;
  payload.which_sub_message = VCSEC_UnsignedMessage_WhitelistOperation_tag;
  payload.sub_message.WhitelistOperation = whitelist;

  // printf("Encoding whitelist message\n");
  pb_byte_t payload_buffer[VCSEC_UnsignedMessage_size];
  size_t payload_length;
  int return_code = pb_encode_fields(payload_buffer, &payload_length, VCSEC_UnsignedMessage_fields, &payload);
  if (return_code != 0) {
    LOG_ERROR("Failed to encode whitelist message");
    return TeslaBLE_Status_E_ERROR_PB_ENCODING;
  }

  // printf("Building VCSEC to VCSEC message\n");
  VCSEC_ToVCSECMessage vcsec_message = VCSEC_ToVCSECMessage_init_default;
  VCSEC_SignedMessage signed_message = VCSEC_SignedMessage_init_default;
  vcsec_message.has_signedMessage = true;

  signed_message.signatureType = VCSEC_SignatureType_SIGNATURE_TYPE_PRESENT_KEY;
  memcpy(signed_message.protobufMessageAsBytes.bytes, &payload_buffer, payload_length);
  signed_message.protobufMessageAsBytes.size = payload_length;
  vcsec_message.signedMessage = signed_message;

  // printf("Encoding VCSEC to VCSEC message\n");
  pb_byte_t vcsec_encode_buffer[VCSEC_ToVCSECMessage_size];
  size_t vcsec_encode_buffer_size;
  return_code =
      pb_encode_fields(vcsec_encode_buffer, &vcsec_encode_buffer_size, VCSEC_ToVCSECMessage_fields, &vcsec_message);
  if (return_code != 0) {
    LOG_ERROR("[build_white_list_message] Failed to encode VCSEC to VCSEC message");
    return TeslaBLE_Status_E_ERROR_PB_ENCODING;
  }

  // printf("Prepending length\n");
  TeslaBLE::Client::prepend_length(vcsec_encode_buffer, vcsec_encode_buffer_size, output_buffer, output_length);
  return TeslaBLE_Status_E_OK;
}

/*
 * This will parse the incoming message
 *
 * @param input_buffer Pointer to the input buffer
 * @param input_buffer_length Size of the input buffer
 * @param output_message Pointer to the output message
 * @return int result code 0 for successful
 */
int Client::parse_from_vcsec_message(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                     VCSEC_FromVCSECMessage *output_message) {
  pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
  bool status = pb_decode(&stream, VCSEC_FromVCSECMessage_fields, output_message);
  if (!status) {
    LOG_ERROR("[parse_from_vcsec_message] Decoding failed: %s", PB_GET_ERROR(&stream));
    return TeslaBLE_Status_E_ERROR_PB_DECODING;
  }

  return TeslaBLE_Status_E_OK;
}

int Client::parse_vcsec_information_request(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                            VCSEC_InformationRequest *output) {
  pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
  bool status = pb_decode(&stream, VCSEC_InformationRequest_fields, output);
  if (!status) {
    LOG_ERROR("[parse_vcsec_information_request] Decoding failed: %s", PB_GET_ERROR(&stream));
    return TeslaBLE_Status_E_ERROR_PB_DECODING;
  }

  return TeslaBLE_Status_E_OK;
}

/*
 * This will parse the incoming message
 *
 * @param input_buffer Pointer to the input buffer
 * @param input_buffer_length Size of the input buffer
 * @param output_message Pointer to the output message
 * @return int result code 0 for successful
 */

int Client::parse_universal_message(pb_byte_t *input_buffer, size_t input_size,
                                    UniversalMessage_RoutableMessage *output) {
  // Validate input parameters
  if (input_buffer == nullptr || output == nullptr || input_size == 0) {
    LOG_ERROR("Invalid parameters: input_buffer=%p, output=%p, length=%zu", input_buffer, output, input_size);
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  pb_istream_t stream = pb_istream_from_buffer(input_buffer, input_size);
  bool status = pb_decode(&stream, UniversalMessage_RoutableMessage_fields, output);
  if (!status) {
    LOG_ERROR("[parse_universal_message] Decoding failed: %s", PB_GET_ERROR(&stream));
    return TeslaBLE_Status_E_ERROR_PB_DECODING;
  }

  // If the response includes a signature_data.AES_GCM_Response_data field, then the protobuf_message_as_bytes payload
  // is encrypted. Otherwise, the payload is plaintext.
  // TODO

  return TeslaBLE_Status_E_OK;
}
int Client::parse_universal_message_ble(pb_byte_t *input_buffer, size_t input_buffer_length,
                                        UniversalMessage_RoutableMessage *output) {
  std::vector<pb_byte_t> temp(input_buffer_length - 2);
  memcpy(temp.data(), input_buffer + 2, input_buffer_length - 2);
  return parse_universal_message(temp.data(), temp.size(), output);
}

int Client::parse_payload_session_info(UniversalMessage_RoutableMessage_session_info_t *input_buffer,
                                       Signatures_SessionInfo *output) {
  // Validate input parameters
  if (input_buffer == nullptr || output == nullptr) {
    LOG_ERROR("Invalid parameters: input_buffer=%p, output=%p", input_buffer, output);
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
  bool status = pb_decode(&stream, Signatures_SessionInfo_fields, output);
  if (!status) {
    LOG_ERROR("[parse_payload_session_info] Decoding failed: %s", PB_GET_ERROR(&stream));
    return TeslaBLE_Status_E_ERROR_PB_DECODING;
  }

  return TeslaBLE_Status_E_OK;
}

int Client::parse_payload_unsigned_message(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                           VCSEC_UnsignedMessage *output) {
  pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
  bool status = pb_decode(&stream, VCSEC_UnsignedMessage_fields, output);
  if (!status) {
    LOG_ERROR("[parse_payload_unsigned_message] Decoding failed: %s", PB_GET_ERROR(&stream));
    return TeslaBLE_Status_E_ERROR_PB_DECODING;
  }

  return TeslaBLE_Status_E_OK;
}

int Client::parse_payload_car_server_response(
    UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
    Signatures_SignatureData *signature_data, pb_size_t which_sub_sig_data,
    UniversalMessage_MessageFault_E signed_message_fault, CarServer_Response *output) {
  // If encrypted, decrypt the payload
  if (which_sub_sig_data != 0) {
    switch (signature_data->which_sig_type) {
      case Signatures_SignatureData_AES_GCM_Response_data_tag: {
        LOG_DEBUG("AES_GCM_Response_data found in signature_data");
        auto *session = this->get_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
        if (!session->is_initialized()) {
          LOG_ERROR("Session not initialized");
          return TeslaBLE_Status_E_ERROR_INVALID_SESSION;
        }

        UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t decrypt_buffer;
        size_t decrypt_length;
        int return_code = session->decrypt_response(
            input_buffer->bytes, input_buffer->size, signature_data->sig_type.AES_GCM_Response_data.nonce,
            signature_data->sig_type.AES_GCM_Response_data.tag, last_request_hash_.data(),
            this->last_request_hash_length_, UniversalMessage_Flags_FLAG_ENCRYPT_RESPONSE, signed_message_fault,
            decrypt_buffer.bytes, sizeof(decrypt_buffer.bytes), &decrypt_length);
        if (return_code != 0) {
          LOG_ERROR("[parse_payload_car_server_response] Failed to decrypt response");
          return TeslaBLE_Status_E_ERROR_DECRYPT;
        }

        // Set the size of the decrypted buffer
        decrypt_buffer.size = decrypt_length;

        pb_istream_t stream = pb_istream_from_buffer(decrypt_buffer.bytes, decrypt_buffer.size);
        bool status = pb_decode(&stream, CarServer_Response_fields, output);
        if (!status) {
          LOG_ERROR("[parse_payload_car_server_response] Decoding failed: %s", PB_GET_ERROR(&stream));
          return TeslaBLE_Status_E_ERROR_PB_DECODING;
        }
        break;
      }
      default:
        LOG_DEBUG("No AES_GCM_Response_data found in signature_data");
        return TeslaBLE_Status_E_ERROR_DECRYPT;
    }
  } else {
    pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
    bool status = pb_decode(&stream, CarServer_Response_fields, output);
    if (!status) {
      LOG_ERROR("[parse_payload_car_server_response] Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }
  }

  return TeslaBLE_Status_E_OK;
}

int Client::build_universal_message_with_payload(pb_byte_t *payload, size_t payload_length,
                                                 UniversalMessage_Domain domain, pb_byte_t *output_buffer,
                                                 size_t *output_length, bool encrypt_payload) {
  LOG_DEBUG("[build_universal_message_with_payload] Called with payload=%p, payload_length=%zu, domain=%d", payload,
            payload_length, domain);

  // Reject empty or null payloads
  if (payload == nullptr || payload_length == 0) {
    LOG_ERROR("[build_universal_message_with_payload] Payload is null or empty (payload=%p, length=%zu)", payload,
              payload_length);
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  UniversalMessage_RoutableMessage universal_message = UniversalMessage_RoutableMessage_init_default;

  UniversalMessage_Destination to_destination = UniversalMessage_Destination_init_default;
  to_destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
  to_destination.sub_destination.domain = domain;
  universal_message.has_to_destination = true;
  universal_message.to_destination = to_destination;

  LOG_DEBUG("Building message for domain: %d", domain);
  auto *session = this->get_peer(domain);

  UniversalMessage_Destination from_destination = UniversalMessage_Destination_init_default;
  from_destination.which_sub_destination = UniversalMessage_Destination_routing_address_tag;
  memcpy(from_destination.sub_destination.routing_address.bytes, connection_id_.data(), connection_id_.size());
  from_destination.sub_destination.routing_address.size = connection_id_.size();
  universal_message.has_from_destination = true;
  universal_message.from_destination = from_destination;

  universal_message.which_payload = UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag;

  // The `flags` field is a bit mask of `universal_message.Flags` values.
  // Vehicles authenticate this value, but ignore unrecognized bits. Clients
  // should always set the `FLAG_ENCRYPT_RESPONSE` bit, which instructs vehicles
  // with compatible firmware (2024.38+) to encrypt the response.
  universal_message.flags = (1 << UniversalMessage_Flags_FLAG_ENCRYPT_RESPONSE);

  if (encrypt_payload) {
    if (!session->is_initialized()) {
      LOG_ERROR("Session not initialized");
      return TeslaBLE_Status_E_ERROR_INVALID_SESSION;
    }

    session->increment_counter();

    pb_byte_t signature[16];  // AES-GCM tag
    pb_byte_t encrypted_payload[100];
    size_t encrypted_output_length = 0;
    uint32_t expires_at = session->generate_expires_at(5);
    const pb_byte_t *epoch = session->get_epoch();

    // Construct AD buffer for encryption
    pb_byte_t ad_buffer[56];
    size_t ad_buffer_length = 0;
    session->construct_ad_buffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED, vin_.c_str(), expires_at,
                                 ad_buffer, &ad_buffer_length, universal_message.flags);

    // Generate nonce and encrypt payload
    pb_byte_t nonce[12];
    int return_code = session->encrypt(payload, payload_length, encrypted_payload, sizeof(encrypted_payload),
                                       &encrypted_output_length,
                                       signature,  // This will contain the AES-GCM tag
                                       ad_buffer, ad_buffer_length, nonce);

    if (return_code != 0) {
      LOG_ERROR("Failed to encrypt payload");
      return TeslaBLE_Status_E_ERROR_ENCRYPT;
    }

    // Set encrypted payload
    memcpy(universal_message.payload.protobuf_message_as_bytes.bytes, encrypted_payload, encrypted_output_length);
    universal_message.payload.protobuf_message_as_bytes.size = encrypted_output_length;

    // Prepare signature data
    Signatures_SignatureData signature_data = Signatures_SignatureData_init_default;

    // Set signer identity (public key)
    Signatures_KeyIdentity signer_identity = Signatures_KeyIdentity_init_default;
    signer_identity.which_identity_type = Signatures_KeyIdentity_public_key_tag;
    memcpy(signer_identity.identity_type.public_key.bytes, public_key_.data(), public_key_size_);
    signer_identity.identity_type.public_key.size = public_key_size_;
    signature_data.has_signer_identity = true;
    signature_data.signer_identity = signer_identity;

    // Set AES-GCM signature data
    Signatures_AES_GCM_Personalized_Signature_Data aes_gcm_signature_data =
        Signatures_AES_GCM_Personalized_Signature_Data_init_default;
    signature_data.which_sig_type = Signatures_SignatureData_AES_GCM_Personalized_data_tag;
    signature_data.sig_type.AES_GCM_Personalized_data.counter = session->get_counter();
    signature_data.sig_type.AES_GCM_Personalized_data.expires_at = expires_at;
    memcpy(signature_data.sig_type.AES_GCM_Personalized_data.nonce, nonce, sizeof nonce);
    memcpy(signature_data.sig_type.AES_GCM_Personalized_data.epoch, epoch, 16);
    memcpy(signature_data.sig_type.AES_GCM_Personalized_data.tag, signature, sizeof signature);

    // After storing the signature/tag, construct and store request hash for later use in decrypting responses
    pb_byte_t request_hash[17];  // Max size: 1 byte type + 16 bytes tag
    size_t request_hash_length;
    return_code = session->construct_request_hash(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
                                                  signature,  // The tag we just generated
                                                  sizeof(signature), request_hash, &request_hash_length);

    if (return_code != 0) {
      LOG_ERROR("Failed to construct request hash");
      return return_code;
    }

    // Store the request hash for later use
    std::copy(request_hash, request_hash + request_hash_length, last_request_hash_.begin());
    this->last_request_hash_length_ = request_hash_length;

    // Store the tag for later use in request hash construction
    std::copy(signature, signature + sizeof(signature), last_request_tag_.begin());
    this->last_request_type_ = Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED;

    universal_message.which_sub_sigData = UniversalMessage_RoutableMessage_signature_data_tag;
    universal_message.sub_sigData.signature_data = signature_data;
  } else {
    memcpy(universal_message.payload.protobuf_message_as_bytes.bytes, payload, payload_length);
    universal_message.payload.protobuf_message_as_bytes.size = payload_length;
  }

  // random 16 bytes using C++11 random
  pb_byte_t uuid[16];
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> distrib(0, 255);
  for (unsigned char &i : uuid) {
    i = static_cast<unsigned char>(distrib(gen));
  }
  memcpy(universal_message.uuid.bytes, uuid, sizeof(uuid));
  universal_message.uuid.size = sizeof(uuid);

  int return_code =
      pb_encode_fields(output_buffer, output_length, UniversalMessage_RoutableMessage_fields, &universal_message);
  if (return_code != 0) {
    LOG_ERROR("[build_universal_message_with_payload] Failed to encode universal message");
    return TeslaBLE_Status_E_ERROR_PB_ENCODING;
  }
  return TeslaBLE_Status_E_OK;
}

/*
 * This build the message to ask the car for his
 * ephemeral public key
 *
 * @param output_buffer Pointer to the output buffer
 * @param output_length Size of the output buffer
 * @return int result code 0 for successful
 */
int Client::build_session_info_request_message(UniversalMessage_Domain domain, pb_byte_t *output_buffer,
                                               size_t *output_length) {
  // Strict validation: require private key to be loaded
  if (public_key_size_ == 0 || !crypto_context_.is_private_key_initialized()) {
    LOG_ERROR("Cannot build session info request: private key not loaded");
    return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
  }

  UniversalMessage_RoutableMessage universal_message = UniversalMessage_RoutableMessage_init_default;

  UniversalMessage_Destination to_destination = UniversalMessage_Destination_init_default;
  to_destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
  to_destination.sub_destination.domain = domain;
  universal_message.has_to_destination = true;
  universal_message.to_destination = to_destination;

  UniversalMessage_Destination from_destination = UniversalMessage_Destination_init_default;
  from_destination.which_sub_destination = UniversalMessage_Destination_routing_address_tag;
  memcpy(from_destination.sub_destination.routing_address.bytes, connection_id_.data(), connection_id_.size());
  from_destination.sub_destination.routing_address.size = connection_id_.size();
  universal_message.has_from_destination = true;
  universal_message.from_destination = from_destination;

  universal_message.which_payload = UniversalMessage_RoutableMessage_session_info_request_tag;
  UniversalMessage_SessionInfoRequest session_info_request = UniversalMessage_SessionInfoRequest_init_default;
  memcpy(session_info_request.public_key.bytes, public_key_.data(), public_key_size_);
  session_info_request.public_key.size = this->public_key_size_;
  universal_message.payload.session_info_request = session_info_request;

  // generate unique uuid for the request
  pb_byte_t uuid[16];
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> distrib(0, 255);
  for (unsigned char &i : uuid) {
    i = static_cast<unsigned char>(distrib(gen));
  }
  memcpy(universal_message.uuid.bytes, uuid, sizeof(uuid));
  universal_message.uuid.size = sizeof(uuid);

  size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
  std::vector<pb_byte_t> universal_encode_buffer(universal_encode_buffer_size);
  int return_code = pb_encode_fields(universal_encode_buffer.data(), &universal_encode_buffer_size,
                                     UniversalMessage_RoutableMessage_fields, &universal_message);
  if (return_code != 0) {
    LOG_ERROR("[buildSessionInfoRequest] Failed to encode universal message");
    return TeslaBLE_Status_E_ERROR_PB_ENCODING;
  }
  TeslaBLE::Client::prepend_length(universal_encode_buffer.data(), universal_encode_buffer_size, output_buffer,
                                   output_length);

  return TeslaBLE_Status_E_OK;
}

/*
 * This will build an unsigned message
 *
 * @param message Pointer to the message
 * @param output_buffer Pointer to the output buffer
 * @param output_length Size of the output buffer
 * @return int result code 0 for successful
 */
int Client::build_unsigned_message_payload(VCSEC_UnsignedMessage *message, pb_byte_t *output_buffer,
                                           size_t *output_length, bool encrypt_payload) {
  pb_byte_t payload_buffer[VCSEC_UnsignedMessage_size];
  size_t payload_length;
  // printf("message: %p\n", message);
  // printf("message.which_sub_message: %d\n", message->which_sub_message);
  int return_code = pb_encode_fields(payload_buffer, &payload_length, VCSEC_UnsignedMessage_fields, message);
  if (return_code != 0) {
    LOG_ERROR("[build_unsigned_message_payload] Failed to encode unsigned message");
    return TeslaBLE_Status_E_ERROR_PB_ENCODING;
  }

  // build universal message
  return this->build_universal_message_with_payload(payload_buffer, payload_length,
                                                    UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, output_buffer,
                                                    output_length, encrypt_payload);
}

int Client::build_key_summary(pb_byte_t *output_buffer, size_t *output_length) {
  VCSEC_InformationRequest information_request = VCSEC_InformationRequest_init_default;
  information_request.informationRequestType = VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_WHITELIST_INFO;

  VCSEC_UnsignedMessage payload = VCSEC_UnsignedMessage_init_default;
  payload.which_sub_message = VCSEC_UnsignedMessage_InformationRequest_tag;
  payload.sub_message.InformationRequest = information_request;

  size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
  std::vector<pb_byte_t> universal_encode_buffer(universal_encode_buffer_size);
  int status = this->build_unsigned_message_payload(&payload, universal_encode_buffer.data(),
                                                    &universal_encode_buffer_size, false);
  if (status != 0) {
    LOG_ERROR("[build_key_summary] Failed to build unsigned message\n");
    return status;
  }
  TeslaBLE::Client::prepend_length(universal_encode_buffer.data(), universal_encode_buffer_size, output_buffer,
                                   output_length);
  return TeslaBLE_Status_E_OK;
}

int Client::build_car_server_action_payload(CarServer_Action *action, pb_byte_t *output_buffer, size_t *output_length) {
  pb_byte_t payload_buffer[UniversalMessage_RoutableMessage_size];
  size_t payload_length = 0;
  int return_code = pb_encode_fields(payload_buffer, &payload_length, CarServer_Action_fields, action);
  if (return_code != 0) {
    LOG_ERROR("Failed to encode car action message");
    return TeslaBLE_Status_E_ERROR_PB_ENCODING;
  }

  // build universal message
  return_code = this->build_universal_message_with_payload(
      payload_buffer, payload_length, UniversalMessage_Domain_DOMAIN_INFOTAINMENT, output_buffer, output_length, true);
  if (return_code != 0) {
    LOG_ERROR("Failed to build car action message");
    return 1;
  }
  return TeslaBLE_Status_E_OK;
}

int Client::build_car_server_get_vehicle_data_message(pb_byte_t *output_buffer, size_t *output_length,
                                                      int32_t which_vehicle_data) {
  CarServer_Action action = CarServer_Action_init_default;
  action.which_action_msg = CarServer_Action_vehicleAction_tag;

  CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
  vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_getVehicleData_tag;
  CarServer_GetVehicleData get_vehicle_data = CarServer_GetVehicleData_init_default;

  switch (which_vehicle_data) {
    case CarServer_GetVehicleData_getChargeState_tag:
      get_vehicle_data.getChargeState = CarServer_GetChargeState_init_default;
      get_vehicle_data.has_getChargeState = true;
      break;
    case CarServer_GetVehicleData_getClimateState_tag:
      get_vehicle_data.getClimateState = CarServer_GetClimateState_init_default;
      get_vehicle_data.has_getClimateState = true;
      break;
    case CarServer_GetVehicleData_getDriveState_tag:
      get_vehicle_data.getDriveState = CarServer_GetDriveState_init_default;
      get_vehicle_data.has_getDriveState = true;
      break;
    case CarServer_GetVehicleData_getLocationState_tag:
      get_vehicle_data.getLocationState = CarServer_GetLocationState_init_default;
      get_vehicle_data.has_getLocationState = true;
      break;
    case CarServer_GetVehicleData_getClosuresState_tag:
      get_vehicle_data.getClosuresState = CarServer_GetClosuresState_init_default;
      get_vehicle_data.has_getClosuresState = true;
      break;
    case CarServer_GetVehicleData_getChargeScheduleState_tag:
      get_vehicle_data.getChargeScheduleState = CarServer_GetChargeScheduleState_init_default;
      get_vehicle_data.has_getChargeScheduleState = true;
      break;
    case CarServer_GetVehicleData_getPreconditioningScheduleState_tag:
      get_vehicle_data.getPreconditioningScheduleState = CarServer_GetPreconditioningScheduleState_init_default;
      get_vehicle_data.has_getPreconditioningScheduleState = true;
      break;
    case CarServer_GetVehicleData_getTirePressureState_tag:
      get_vehicle_data.getTirePressureState = CarServer_GetTirePressureState_init_default;
      get_vehicle_data.has_getTirePressureState = true;
      break;
    case CarServer_GetVehicleData_getMediaState_tag:
      get_vehicle_data.getMediaState = CarServer_GetMediaState_init_default;
      get_vehicle_data.has_getMediaState = true;
      break;
    case CarServer_GetVehicleData_getMediaDetailState_tag:
      get_vehicle_data.getMediaDetailState = CarServer_GetMediaDetailState_init_default;
      get_vehicle_data.has_getMediaDetailState = true;
      break;
    case CarServer_GetVehicleData_getSoftwareUpdateState_tag:
      get_vehicle_data.getSoftwareUpdateState = CarServer_GetSoftwareUpdateState_init_default;
      get_vehicle_data.has_getSoftwareUpdateState = true;
      break;
    case CarServer_GetVehicleData_getParentalControlsState_tag:
      get_vehicle_data.getParentalControlsState = CarServer_GetParentalControlsState_init_default;
      get_vehicle_data.has_getParentalControlsState = true;
      break;
    default:
      LOG_ERROR("Invalid vehicle data type");
      return 1;
  }

  vehicle_action.vehicle_action_msg.getVehicleData = get_vehicle_data;
  action.action_msg.vehicleAction = vehicle_action;

  size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
  std::vector<pb_byte_t> universal_encode_buffer(universal_encode_buffer_size);
  int status =
      this->build_car_server_action_payload(&action, universal_encode_buffer.data(), &universal_encode_buffer_size);
  if (status != 0) {
    LOG_ERROR("Failed to build car action message");
    return status;
  }
  TeslaBLE::Client::prepend_length(universal_encode_buffer.data(), universal_encode_buffer_size, output_buffer,
                                   output_length);
  return TeslaBLE_Status_E_OK;
}

int Client::build_car_server_vehicle_action_message(pb_byte_t *output_buffer, size_t *output_length,
                                                    int32_t which_vehicle_action, const void *action_data) {
  // Validate input parameters
  if (output_buffer == nullptr || output_length == nullptr) {
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  // Create action structure
  CarServer_Action action = CarServer_Action_init_default;
  action.which_action_msg = CarServer_Action_vehicleAction_tag;

  // Create vehicle action and set the action type
  CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
  vehicle_action.which_vehicle_action_msg = which_vehicle_action;

  // Use the VehicleActionBuilder to handle all action types
  // Find the appropriate builder function
  const auto &builders = VehicleActionBuilder::get_builders();
  auto it = builders.find(which_vehicle_action);
  if (it == builders.end()) {
    LOG_ERROR("Unsupported vehicle action type: %d", which_vehicle_action);
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  // Build the specific action using the builder
  int build_status = it->second(vehicle_action, action_data);
  if (build_status != TeslaBLE_Status_E_OK) {
    return build_status;
  }

  // Assign the built vehicle action to the main action
  action.action_msg.vehicleAction = vehicle_action;

  // Encode the action into a universal message
  size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
  std::vector<pb_byte_t> universal_encode_buffer(universal_encode_buffer_size);
  int status =
      this->build_car_server_action_payload(&action, universal_encode_buffer.data(), &universal_encode_buffer_size);
  if (status != 0) {
    LOG_ERROR("Failed to build car action message");
    return status;
  }

  TeslaBLE::Client::prepend_length(universal_encode_buffer.data(), universal_encode_buffer_size, output_buffer,
                                   output_length);
  return TeslaBLE_Status_E_OK;
}

int Client::set_cabin_overheat_protection(pb_byte_t *output_buffer, size_t *output_length, bool on, bool fan_only) {
  CarServer_SetCabinOverheatProtectionAction cop_action = CarServer_SetCabinOverheatProtectionAction_init_default;
  cop_action.on = on;
  cop_action.fan_only = fan_only;

  return this->build_car_server_vehicle_action_message(
      output_buffer, output_length, CarServer_VehicleAction_setCabinOverheatProtectionAction_tag, &cop_action);
}

int Client::schedule_software_update(pb_byte_t *output_buffer, size_t *output_length, int32_t offset_sec) {
  return this->build_car_server_vehicle_action_message(
      output_buffer, output_length, CarServer_VehicleAction_vehicleControlScheduleSoftwareUpdateAction_tag,
      &offset_sec);
}

int Client::cancel_software_update(pb_byte_t *output_buffer, size_t *output_length) {
  return this->build_car_server_vehicle_action_message(
      output_buffer, output_length, CarServer_VehicleAction_vehicleControlCancelSoftwareUpdateAction_tag, nullptr);
}

int Client::build_vcsec_action_message(const VCSEC_RKEAction_E action, pb_byte_t *output_buffer,
                                       size_t *output_length) {
  VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_default;
  unsigned_message.which_sub_message = VCSEC_UnsignedMessage_RKEAction_tag;
  unsigned_message.sub_message.RKEAction = action;

  size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
  std::vector<pb_byte_t> universal_encode_buffer(universal_encode_buffer_size);
  int status = this->build_unsigned_message_payload(&unsigned_message, universal_encode_buffer.data(),
                                                    &universal_encode_buffer_size, true);
  if (status != 0) {
    LOG_ERROR("Failed to build unsigned message");
    return status;
  }
  TeslaBLE::Client::prepend_length(universal_encode_buffer.data(), universal_encode_buffer_size, output_buffer,
                                   output_length);
  return TeslaBLE_Status_E_OK;
}

int Client::build_vcsec_information_request_message(VCSEC_InformationRequestType request_type, pb_byte_t *output_buffer,
                                                    size_t *output_length, uint32_t key_slot) {
  VCSEC_InformationRequest information_request = VCSEC_InformationRequest_init_zero;
  information_request.informationRequestType = request_type;

  if (key_slot != 0xFFFFFFFF) {
    // printf("Adding key slot info");
    information_request.which_key = VCSEC_InformationRequest_slot_tag;
    information_request.key.slot = key_slot;
  }

  VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_default;
  unsigned_message.which_sub_message = VCSEC_UnsignedMessage_InformationRequest_tag;
  unsigned_message.sub_message.InformationRequest = information_request;

  size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
  std::vector<pb_byte_t> universal_encode_buffer(universal_encode_buffer_size);
  int status = this->build_unsigned_message_payload(&unsigned_message, universal_encode_buffer.data(),
                                                    &universal_encode_buffer_size, false);
  if (status != 0) {
    LOG_ERROR("Failed to build unsigned message");
    return status;
  }
  TeslaBLE::Client::prepend_length(universal_encode_buffer.data(), universal_encode_buffer_size, output_buffer,
                                   output_length);
  return TeslaBLE_Status_E_OK;
}

int Client::build_vcsec_closure_message(const VCSEC_ClosureMoveRequest *closure_request, pb_byte_t *output_buffer,
                                        size_t *output_length) {
  if (closure_request == nullptr || output_buffer == nullptr || output_length == nullptr) {
    LOG_ERROR("[build_vcsec_closure_message] Invalid parameters");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_default;
  unsigned_message.which_sub_message = VCSEC_UnsignedMessage_closureMoveRequest_tag;
  unsigned_message.sub_message.closureMoveRequest = *closure_request;

  size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
  std::vector<pb_byte_t> universal_encode_buffer(universal_encode_buffer_size);
  int status = this->build_unsigned_message_payload(&unsigned_message, universal_encode_buffer.data(),
                                                    &universal_encode_buffer_size, true);
  if (status != 0) {
    LOG_ERROR("[build_vcsec_closure_message] Failed to build unsigned message");
    return status;
  }
  TeslaBLE::Client::prepend_length(universal_encode_buffer.data(), universal_encode_buffer_size, output_buffer,
                                   output_length);
  return TeslaBLE_Status_E_OK;
}
}  // namespace TeslaBLE
// #endif // MBEDTLS_CONFIG_FILE
