// https://github.com/platformio/platform-espressif32/issues/957
// specifically set when compiling with ESP-IDF
#ifdef ESP_PLATFORM
#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#endif

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>

#include <pb_decode.h>
#include <pb_encode.h>

#include "client.h"
#include "crypto_context.h"
#include "message_builders.h"
#include "message_builders.h"
#include "car_server.pb.h"
#include "keys.pb.h"
#include "universal_message.pb.h"
#include "vcsec.pb.h"
#include "vehicle.pb.h"
#include "tb_utils.h"
#include "errors.h"

namespace TeslaBLE
{
    Client::Client()
    {
        initializePeers();
    }

    void Client::initializePeers()
    {
        auto crypto_context_shared = std::shared_ptr<CryptoContext>(&crypto_context_, [](CryptoContext*){});
        
        session_vcsec_ = std::make_unique<Peer>(
            UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
            crypto_context_shared,
            vin_);

        session_infotainment_ = std::make_unique<Peer>(
            UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
            crypto_context_shared,
            vin_);
    }

    void Client::setVIN(const std::string& vin)
    {
        if (!ParameterValidator::isValidVIN(vin.c_str())) {
            LOG_WARNING("Invalid VIN format: %s", vin.c_str());
        }
        
        vin_ = vin;
        
        // Update peers with new VIN
        if (session_vcsec_) {
            session_vcsec_->setVIN(vin);
        }
        if (session_infotainment_) {
            session_infotainment_->setVIN(vin);
        }
    }

    void Client::setConnectionID(const pb_byte_t* connection_id)
    {
        if (!ParameterValidator::isValidConnectionID(connection_id)) {
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
    int Client::createPrivateKey()
    {
        int result = crypto_context_.createPrivateKey();
        if (result != TeslaBLE_Status_E_OK) {
            return result;
        }

        result = generatePublicKeyData();
        if (result != TeslaBLE_Status_E_OK) {
            return result;
        }

        return TeslaBLE_Status_E_OK;
    }

    int Client::loadPrivateKey(const uint8_t* private_key_buffer, size_t private_key_length)
    {
        int result = crypto_context_.loadPrivateKey(private_key_buffer, private_key_length);
        if (result != TeslaBLE_Status_E_OK) {
            return result;
        }

        result = generatePublicKeyData();
        if (result != TeslaBLE_Status_E_OK) {
            return result;
        }

        return TeslaBLE_Status_E_OK;
    }

    int Client::getPrivateKey(pb_byte_t* output_buffer, size_t output_buffer_length, size_t* output_length)
    {
        return crypto_context_.getPrivateKey(output_buffer, output_buffer_length, output_length);
    }

    int Client::getPublicKey(pb_byte_t* output_buffer, size_t* output_buffer_length)
    {
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

    int Client::generatePublicKeyData()
    {
        // Set the buffer size to maximum capacity before calling generatePublicKey
        public_key_size_ = public_key_.size();
        
        int result = crypto_context_.generatePublicKey(public_key_.data(), &public_key_size_);
        if (result != TeslaBLE_Status_E_OK) {
            return result;
        }

        return generateKeyId();
    }

    int Client::generateKeyId()
    {
        return crypto_context_.generateKeyId(public_key_.data(), public_key_size_, public_key_id_.data());
    }

    Peer* Client::getPeer(UniversalMessage_Domain domain)
    {
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

    const Peer* Client::getPeer(UniversalMessage_Domain domain) const
    {
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
  void Client::prependLength(const pb_byte_t *input_buffer,
                             size_t input_buffer_length,
                             pb_byte_t *output_buffer,
                             size_t *output_buffer_length)
  {
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
  int Client::buildWhiteListMessage(Keys_Role role,
                                    VCSEC_KeyFormFactor form_factor,
                                    pb_byte_t *output_buffer,
                                    size_t *output_length)
  {
    // printf("Building whitelist message\n");
    if (!crypto_context_.isPrivateKeyInitialized())
    {
      LOG_ERROR("[buildWhiteListMessage] Private key is not initialized");
      return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
    }

    // Validate role parameter - Tesla protocol requires specific role values
    if (role < _Keys_Role_MIN || role > _Keys_Role_MAX) {
      LOG_ERROR("[buildWhiteListMessage] Invalid role value: %d (valid range: %d-%d)", 
                role, _Keys_Role_MIN, _Keys_Role_MAX);
      return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
    }

    VCSEC_PermissionChange permissions_action =
        VCSEC_PermissionChange_init_default;
    permissions_action.has_key = true;
    memcpy(permissions_action.key.PublicKeyRaw.bytes, public_key_.data(),
           this->public_key_size_);
    permissions_action.key.PublicKeyRaw.size = this->public_key_size_;
    permissions_action.keyRole = role;
    // permissions_action.secondsToBeActive = 0;

    VCSEC_WhitelistOperation whitelist = VCSEC_WhitelistOperation_init_default;
    whitelist.has_metadataForKey = true;
    whitelist.metadataForKey.keyFormFactor = form_factor;

    whitelist.which_sub_message =
        VCSEC_WhitelistOperation_addKeyToWhitelistAndAddPermissions_tag;
    whitelist.sub_message.addKeyToWhitelistAndAddPermissions = permissions_action;

    VCSEC_UnsignedMessage payload = VCSEC_UnsignedMessage_init_default;
    payload.which_sub_message =
        VCSEC_UnsignedMessage_WhitelistOperation_tag;
    payload.sub_message.WhitelistOperation = whitelist;

    // printf("Encoding whitelist message\n");
    pb_byte_t payload_buffer[VCSEC_UnsignedMessage_size];
    size_t payload_length;
    int return_code = pb_encode_fields(payload_buffer, &payload_length, VCSEC_UnsignedMessage_fields, &payload);
    if (return_code != 0)
    {
      LOG_ERROR("Failed to encode whitelist message");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }

    // printf("Building VCSEC to VCSEC message\n");
    VCSEC_ToVCSECMessage vcsec_message = VCSEC_ToVCSECMessage_init_default;
    VCSEC_SignedMessage signed_message = VCSEC_SignedMessage_init_default;
    vcsec_message.has_signedMessage = true;

    signed_message.signatureType =
        VCSEC_SignatureType_SIGNATURE_TYPE_PRESENT_KEY;
    memcpy(signed_message.protobufMessageAsBytes.bytes,
           &payload_buffer, payload_length);
    signed_message.protobufMessageAsBytes.size = payload_length;
    vcsec_message.signedMessage = signed_message;

    // printf("Encoding VCSEC to VCSEC message\n");
    pb_byte_t vcsec_encode_buffer[VCSEC_ToVCSECMessage_size];
    size_t vcsec_encode_buffer_size;
    return_code = pb_encode_fields(vcsec_encode_buffer, &vcsec_encode_buffer_size, VCSEC_ToVCSECMessage_fields, &vcsec_message);
    if (return_code != 0)
    {
      LOG_ERROR("[buildWhiteListMessage] Failed to encode VCSEC to VCSEC message");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }

    // printf("Prepending length\n");
    this->prependLength(vcsec_encode_buffer, vcsec_encode_buffer_size,
                        output_buffer, output_length);
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
  int Client::parseFromVCSECMessage(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                    VCSEC_FromVCSECMessage *output_message)
  {
    pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
    bool status =
        pb_decode(&stream, VCSEC_FromVCSECMessage_fields, output_message);
    if (!status)
    {
      LOG_ERROR("[parseFromVCSECMessage] Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }

    return TeslaBLE_Status_E_OK;
  }

  int Client::parseVCSECInformationRequest(
      UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
      VCSEC_InformationRequest *output)
  {
    pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
    bool status =
        pb_decode(&stream, VCSEC_InformationRequest_fields, output);
    if (!status)
    {
      LOG_ERROR("[parseVCSECInformationRequest] Decoding failed: %s", PB_GET_ERROR(&stream));
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

  int Client::parseUniversalMessage(pb_byte_t *input_buffer,
                                    size_t input_buffer_length,
                                    UniversalMessage_RoutableMessage *output)
  {
    // Validate input parameters
    if (input_buffer == nullptr || output == nullptr || input_buffer_length == 0)
    {
      LOG_ERROR("Invalid parameters: input_buffer=%p, output=%p, length=%zu", 
                input_buffer, output, input_buffer_length);
      return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
    }

    pb_istream_t stream = pb_istream_from_buffer(input_buffer, input_buffer_length);
    bool status =
        pb_decode(&stream, UniversalMessage_RoutableMessage_fields, output);
    if (!status)
    {
      LOG_ERROR("[parseUniversalMessage] Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }

    // If the response includes a signature_data.AES_GCM_Response_data field, then the protobuf_message_as_bytes payload is encrypted. Otherwise, the payload is plaintext.
    // TODO

    return TeslaBLE_Status_E_OK;
  }
  int Client::parseUniversalMessageBLE(pb_byte_t *input_buffer,
                                       size_t input_buffer_length,
                                       UniversalMessage_RoutableMessage *output)
  {
    pb_byte_t temp[input_buffer_length - 2];
    memcpy(&temp, input_buffer + 2, input_buffer_length - 2);
    return parseUniversalMessage(temp, sizeof(temp), output);
  }

  int Client::parsePayloadSessionInfo(UniversalMessage_RoutableMessage_session_info_t *input_buffer,
                                      Signatures_SessionInfo *output)
  {
    // Validate input parameters
    if (input_buffer == nullptr || output == nullptr)
    {
      LOG_ERROR("Invalid parameters: input_buffer=%p, output=%p", input_buffer, output);
      return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
    }

    pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
    bool status =
        pb_decode(&stream, Signatures_SessionInfo_fields, output);
    if (!status)
    {
      LOG_ERROR("[parsePayloadSessionInfo] Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }

    return TeslaBLE_Status_E_OK;
  }

  int Client::parsePayloadUnsignedMessage(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                          VCSEC_UnsignedMessage *output)
  {
    pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
    bool status =
        pb_decode(&stream, VCSEC_UnsignedMessage_fields, output);
    if (!status)
    {
      LOG_ERROR("[parsePayloadUnsignedMessage] Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }

    return TeslaBLE_Status_E_OK;
  }

  int Client::parsePayloadCarServerResponse(
      UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
      Signatures_SignatureData *signature_data,
      pb_size_t which_sub_sigData,
      UniversalMessage_MessageFault_E signed_message_fault,
      CarServer_Response *output)
  {
    // If encrypted, decrypt the payload
    if (which_sub_sigData != 0)
    {
    switch (signature_data->which_sig_type)
    {
      case Signatures_SignatureData_AES_GCM_Response_data_tag:
      {
        LOG_DEBUG("AES_GCM_Response_data found in signature_data");
        auto session = this->getPeer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
        if (!session->isInitialized())
        {
          LOG_ERROR("Session not initialized");
          return TeslaBLE_Status_E_ERROR_INVALID_SESSION;
        }

        UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t decrypt_buffer;
        size_t decrypt_length;
        int return_code = session->decryptResponse(
            input_buffer->bytes,
            input_buffer->size,
            signature_data->sig_type.AES_GCM_Response_data.nonce,
            signature_data->sig_type.AES_GCM_Response_data.tag,
            last_request_hash_.data(),
            this->last_request_hash_length_,
            UniversalMessage_Flags_FLAG_ENCRYPT_RESPONSE,
            signed_message_fault,
            decrypt_buffer.bytes,
            sizeof(decrypt_buffer.bytes),
            &decrypt_length);
        if (return_code != 0)
        {
          LOG_ERROR("[parsePayloadCarServerResponse] Failed to decrypt response");
          return TeslaBLE_Status_E_ERROR_DECRYPT;
        }

        // Set the size of the decrypted buffer
        decrypt_buffer.size = decrypt_length;

        pb_istream_t stream = pb_istream_from_buffer(decrypt_buffer.bytes, decrypt_buffer.size);
        bool status =
            pb_decode(&stream, CarServer_Response_fields, output);
        if (!status)
        {
          LOG_ERROR("[parsePayloadCarServerResponse] Decoding failed: %s", PB_GET_ERROR(&stream));
          return TeslaBLE_Status_E_ERROR_PB_DECODING;
        }
        break;
      }
      default:
        LOG_DEBUG("No AES_GCM_Response_data found in signature_data");
        return TeslaBLE_Status_E_ERROR_DECRYPT;
      }
    }
    else {
    pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
    bool status =
        pb_decode(&stream, CarServer_Response_fields, output);
    if (!status)
    {
      LOG_ERROR("[parsePayloadCarServerResponse] Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
      }
    }

    return TeslaBLE_Status_E_OK;
  }

  int Client::buildUniversalMessageWithPayload(pb_byte_t *payload,
                                               size_t payload_length,
                                               UniversalMessage_Domain domain,
                                               pb_byte_t *output_buffer,
                                               size_t *output_length,
                                               bool encryptPayload)
  {
  LOG_DEBUG("[buildUniversalMessageWithPayload] Called with payload=%p, payload_length=%zu, domain=%d", 
            payload, payload_length, domain);
  
  // Reject empty or null payloads
  if (payload == nullptr || payload_length == 0) {
    LOG_ERROR("[buildUniversalMessageWithPayload] Payload is null or empty (payload=%p, length=%zu)", 
              payload, payload_length);
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  UniversalMessage_RoutableMessage universal_message = UniversalMessage_RoutableMessage_init_default;

    UniversalMessage_Destination to_destination = UniversalMessage_Destination_init_default;
    to_destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
    to_destination.sub_destination.domain = domain;
    universal_message.has_to_destination = true;
    universal_message.to_destination = to_destination;

    LOG_DEBUG("Building message for domain: %d", domain);
    auto session = this->getPeer(domain);

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

    if (encryptPayload)
    {
      if (!session->isInitialized())
      {
        LOG_ERROR("Session not initialized");
        return TeslaBLE_Status_E_ERROR_INVALID_SESSION;
      }

      session->incrementCounter();

      pb_byte_t signature[16]; // AES-GCM tag
      pb_byte_t encrypted_payload[100];
      size_t encrypted_output_length = 0;
      uint32_t expires_at = session->generateExpiresAt(5);
      const pb_byte_t *epoch = session->getEpoch();

      // Construct AD buffer for encryption
      pb_byte_t ad_buffer[56];
      size_t ad_buffer_length = 0;
      session->constructADBuffer(
          Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
          vin_.c_str(),
          expires_at,
          ad_buffer,
          &ad_buffer_length,
          universal_message.flags
      );

      // Generate nonce and encrypt payload
      pb_byte_t nonce[12];
      int return_code = session->encrypt(
          payload,
          payload_length,
          encrypted_payload,
          sizeof(encrypted_payload),
          &encrypted_output_length,
          signature, // This will contain the AES-GCM tag
          ad_buffer,
          ad_buffer_length,
          nonce);

      if (return_code != 0)
      {
        LOG_ERROR("Failed to encrypt payload");
        return TeslaBLE_Status_E_ERROR_ENCRYPT;
      }

      // Set encrypted payload
      memcpy(universal_message.payload.protobuf_message_as_bytes.bytes,
            encrypted_payload,
            encrypted_output_length);
      universal_message.payload.protobuf_message_as_bytes.size = encrypted_output_length;

      // Prepare signature data
      Signatures_SignatureData signature_data = Signatures_SignatureData_init_default;
      
      // Set signer identity (public key)
      Signatures_KeyIdentity signer_identity = Signatures_KeyIdentity_init_default;
      signer_identity.which_identity_type = Signatures_KeyIdentity_public_key_tag;
      memcpy(signer_identity.identity_type.public_key.bytes,
            public_key_.data(),
            public_key_size_);
      signer_identity.identity_type.public_key.size = public_key_size_;
      signature_data.has_signer_identity = true;
      signature_data.signer_identity = signer_identity;

      // Set AES-GCM signature data
      Signatures_AES_GCM_Personalized_Signature_Data aes_gcm_signature_data = Signatures_AES_GCM_Personalized_Signature_Data_init_default;
      signature_data.which_sig_type = Signatures_SignatureData_AES_GCM_Personalized_data_tag;
      signature_data.sig_type.AES_GCM_Personalized_data.counter = session->getCounter();
      signature_data.sig_type.AES_GCM_Personalized_data.expires_at = expires_at;
      memcpy(signature_data.sig_type.AES_GCM_Personalized_data.nonce, nonce, sizeof nonce);
      memcpy(signature_data.sig_type.AES_GCM_Personalized_data.epoch, epoch, 16);
      memcpy(signature_data.sig_type.AES_GCM_Personalized_data.tag, signature, sizeof signature);

      // After storing the signature/tag, construct and store request hash for later use in decrypting responses
      pb_byte_t request_hash[17]; // Max size: 1 byte type + 16 bytes tag
      size_t request_hash_length;
      return_code = session->constructRequestHash(
          Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
          signature, // The tag we just generated
          sizeof(signature),
          request_hash,
          &request_hash_length);
          
      if (return_code != 0)
      {
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
    }
    else
    {
      memcpy(universal_message.payload.protobuf_message_as_bytes.bytes, payload, payload_length);
      universal_message.payload.protobuf_message_as_bytes.size = payload_length;
    }

    // random 16 bytes using rand()
    pb_byte_t uuid[16];
    for (int i = 0; i < sizeof(uuid); i++)
    {
      uuid[i] = rand() % 256;
    }
    memcpy(universal_message.uuid.bytes, uuid, sizeof(uuid));
    universal_message.uuid.size = sizeof(uuid);

    int return_code = pb_encode_fields(output_buffer, output_length, UniversalMessage_RoutableMessage_fields, &universal_message);
    if (return_code != 0)
    {
      LOG_ERROR("[buildUniversalMessageWithPayload] Failed to encode universal message");
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
  int Client::buildSessionInfoRequestMessage(UniversalMessage_Domain domain,
                                             pb_byte_t *output_buffer,
                                             size_t *output_length)
  {
  // Strict validation: require private key to be loaded
  if (public_key_size_ == 0 || !crypto_context_.isPrivateKeyInitialized()) {
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
    for (int i = 0; i < sizeof(uuid); i++)
    {
      uuid[i] = rand() % 256;
    }
    memcpy(universal_message.uuid.bytes, uuid, sizeof(uuid));
    universal_message.uuid.size = sizeof(uuid);

    size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int return_code = pb_encode_fields(universal_encode_buffer, &universal_encode_buffer_size, UniversalMessage_RoutableMessage_fields, &universal_message);
    if (return_code != 0)
    {
      LOG_ERROR("[buildSessionInfoRequest] Failed to encode universal message");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }
    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);

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
  int Client::buildUnsignedMessagePayload(VCSEC_UnsignedMessage *message,
                                          pb_byte_t *output_buffer,
                                          size_t *output_length,
                                          bool encryptPayload)
  {
    pb_byte_t payload_buffer[VCSEC_UnsignedMessage_size];
    size_t payload_length;
    // printf("message: %p\n", message);
    // printf("message.which_sub_message: %d\n", message->which_sub_message);
    int return_code = pb_encode_fields(payload_buffer, &payload_length, VCSEC_UnsignedMessage_fields, message);
    if (return_code != 0)
    {
      LOG_ERROR("[buildUnsignedMessagePayload] Failed to encode unsigned message");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }

    // build universal message
    return this->buildUniversalMessageWithPayload(
        payload_buffer, payload_length, UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
        output_buffer, output_length, encryptPayload);
  }

  int Client::buildKeySummary(pb_byte_t *output_buffer,
                              size_t *output_length)
  {
    VCSEC_InformationRequest informationRequest = VCSEC_InformationRequest_init_default;
    informationRequest.informationRequestType = VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_WHITELIST_INFO;

    VCSEC_UnsignedMessage payload = VCSEC_UnsignedMessage_init_default;
    payload.which_sub_message = VCSEC_UnsignedMessage_InformationRequest_tag;
    payload.sub_message.InformationRequest = informationRequest;

    size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildUnsignedMessagePayload(&payload, universal_encode_buffer, &universal_encode_buffer_size, false);
    if (status != 0)
    {
      LOG_ERROR("[buildKeySummary] Failed to build unsigned message\n");
      return status;
    }
    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);
    return TeslaBLE_Status_E_OK;
  }

  int Client::buildCarServerActionPayload(CarServer_Action *action,
                                          pb_byte_t *output_buffer,
                                          size_t *output_length)
  {
    pb_byte_t payload_buffer[UniversalMessage_RoutableMessage_size];
    size_t payload_length = 0;
    int return_code = pb_encode_fields(payload_buffer, &payload_length, CarServer_Action_fields, action);
    if (return_code != 0)
    {
      LOG_ERROR("Failed to encode car action message");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }

    // build universal message
    return_code = this->buildUniversalMessageWithPayload(
        payload_buffer, payload_length, UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
        output_buffer, output_length, true);
    if (return_code != 0)
    {
      LOG_ERROR("Failed to build car action message");       
      return 1;
    }
    return TeslaBLE_Status_E_OK;
  }

  int Client::buildCarServerGetVehicleDataMessage(pb_byte_t *output_buffer,
                                                  size_t *output_length,
                                                  int32_t which_vehicle_data
                                                )
  {
    CarServer_Action action = CarServer_Action_init_default;
    action.which_action_msg = CarServer_Action_vehicleAction_tag;

    CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
    vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_getVehicleData_tag;
    CarServer_GetVehicleData get_vehicle_data = CarServer_GetVehicleData_init_default;

    switch (which_vehicle_data)
    {
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
    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildCarServerActionPayload(&action, universal_encode_buffer, &universal_encode_buffer_size);
    if (status != 0)
    {
      LOG_ERROR("Failed to build car action message");
      return status;
    }
    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);
    return TeslaBLE_Status_E_OK;
  }

  int Client::buildCarServerVehicleActionMessage(pb_byte_t *output_buffer,
                                                size_t *output_length,
                                                int32_t which_vehicle_action,
                                                const void *action_data)
  {
    // Validate input parameters
    if (output_buffer == nullptr || output_length == nullptr)
    {
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
    const auto& builders = VehicleActionBuilder::getBuilders();
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
    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildCarServerActionPayload(&action, universal_encode_buffer, &universal_encode_buffer_size);
    if (status != 0)
    {
      LOG_ERROR("Failed to build car action message");
      return status;
    }
    
    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);
    return TeslaBLE_Status_E_OK;
  }

  int Client::buildVCSECActionMessage(const VCSEC_RKEAction_E action, pb_byte_t *output_buffer,
                                      size_t *output_length)
  {
    VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_default;
    unsigned_message.which_sub_message = VCSEC_UnsignedMessage_RKEAction_tag;
    unsigned_message.sub_message.RKEAction = action;

    size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildUnsignedMessagePayload(&unsigned_message, universal_encode_buffer, &universal_encode_buffer_size, true);
    if (status != 0)
    {
      LOG_ERROR("Failed to build unsigned message");
      return status;
    }
    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);
    return TeslaBLE_Status_E_OK;
  }

  int Client::buildVCSECInformationRequestMessage(VCSEC_InformationRequestType request_type,
                                                  pb_byte_t *output_buffer,
                                                  size_t *output_length,
                                                  uint32_t key_slot)
  {
    VCSEC_InformationRequest information_request = VCSEC_InformationRequest_init_zero;
    information_request.informationRequestType = request_type;

    if (key_slot != 0xFFFFFFFF)
    {
      // printf("Adding key slot info");
      information_request.which_key = VCSEC_InformationRequest_slot_tag;
      information_request.key.slot = key_slot;
    }

    VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_default;
    unsigned_message.which_sub_message = VCSEC_UnsignedMessage_InformationRequest_tag;
    unsigned_message.sub_message.InformationRequest = information_request;

    size_t universal_encode_buffer_size = UniversalMessage_RoutableMessage_size;
    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildUnsignedMessagePayload(&unsigned_message, universal_encode_buffer, &universal_encode_buffer_size, false);
    if (status != 0)
    {
      LOG_ERROR("Failed to build unsigned message");
      return status;
    }
    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);
    return TeslaBLE_Status_E_OK;
  }

  int Client::extractSOCFromChargeState(
      CarServer_ChargeState* charge_state,
      int32_t* battery_level,
      int32_t* usable_battery_level)
  {
    if (!charge_state || !battery_level || !usable_battery_level) {
      return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
    }
    
    // Extract battery level
    if (charge_state->which_optional_battery_level == CarServer_ChargeState_battery_level_tag) {
      *battery_level = charge_state->optional_battery_level.battery_level;
    } else {
      *battery_level = -1; // Indicates field not present
    }
    
    // Extract usable battery level  
    if (charge_state->which_optional_usable_battery_level == CarServer_ChargeState_usable_battery_level_tag) {
      *usable_battery_level = charge_state->optional_usable_battery_level.usable_battery_level;
    } else {
      *usable_battery_level = -1; // Indicates field not present
    }
    
    return TeslaBLE_Status_E_OK;
  }

  int Client::populateSOCData(
      CarServer_ChargeState* charge_state,
      SOCData* soc_data)
  {
    if (!charge_state || !soc_data) {
      return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
    }
    
    // Initialize structure
    *soc_data = SOCData{};
    
    // Extract battery level
    if (charge_state->which_optional_battery_level == CarServer_ChargeState_battery_level_tag) {
      soc_data->battery_level = charge_state->optional_battery_level.battery_level;
    }
    
    // Extract usable battery level  
    if (charge_state->which_optional_usable_battery_level == CarServer_ChargeState_usable_battery_level_tag) {
      soc_data->usable_battery_level = charge_state->optional_usable_battery_level.usable_battery_level;
    }
    
    // Extract charge limit
    if (charge_state->which_optional_charge_limit_soc == CarServer_ChargeState_charge_limit_soc_tag) {
      soc_data->charge_limit_soc = charge_state->optional_charge_limit_soc.charge_limit_soc;
    }
    
    // Mark as valid if we got at least one SOC value
    soc_data->valid = (soc_data->battery_level != -1 || soc_data->usable_battery_level != -1);
    
    return TeslaBLE_Status_E_OK;
  }

  int Client::parseChargeStateFromVehicleData(
      CarServer_VehicleData* vehicle_data,
      CarServer_ChargeState** charge_state)
  {
    if (!vehicle_data || !charge_state) {
      return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
    }
    
    if (!vehicle_data->has_charge_state) {
      return TeslaBLE_Status_E_ERROR_INTERNAL;
    }
    
    *charge_state = &vehicle_data->charge_state;
    return TeslaBLE_Status_E_OK;
  }

  int Client::extractSOCFromVehicleData(
      CarServer_VehicleData* vehicle_data,
      SOCData* soc_data)
  {
    if (!vehicle_data || !soc_data) {
      return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
    }
    
    CarServer_ChargeState* charge_state;
    int result = parseChargeStateFromVehicleData(vehicle_data, &charge_state);
    if (result != TeslaBLE_Status_E_OK) {
      return result;
    }
    
    return populateSOCData(charge_state, soc_data);
  }
} // namespace TeslaBLE
// #endif // MBEDTLS_CONFIG_FILE
