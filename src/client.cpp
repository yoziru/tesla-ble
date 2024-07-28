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
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha1.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <sstream>

#include "car_server.pb.h"
#include "client.h"
#include "keys.pb.h"
#include "universal_message.pb.h"
#include "vcsec.pb.h"
#include "peer.h"
#include "tb_utils.h"
#include "errors.h"

namespace TeslaBLE
{
  void Client::setVIN(const char *vin)
  {
    this->VIN = vin;
  }

  void Client::setConnectionID(const pb_byte_t *connection_id)
  {
    memcpy(this->connectionID, connection_id, 16);
  }

  void Client::generateNonce()
  {
    // random 12 bytes using rand()
    for (int i = 0; i < 12; i++)
    {
      this->nonce_[i] = rand() % 256;
    }
  }

  /*
   * This will create a new private key, public key
   * and generates the key_id
   *
   * @return int result code 0 for successful
   */
  int Client::createPrivateKey()
  {
    mbedtls_entropy_context entropy_context;
    mbedtls_entropy_init(&entropy_context);
    mbedtls_pk_init(&this->private_key_context_);
    mbedtls_ctr_drbg_init(&this->drbg_context_);

    int return_code = mbedtls_ctr_drbg_seed(&drbg_context_, mbedtls_entropy_func,
                                            &entropy_context, nullptr, 0);
    if (return_code != 0)
    {
      LOG_ERROR("Last error was: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    return_code = mbedtls_pk_setup(
        &this->private_key_context_,
        mbedtls_pk_info_from_type((mbedtls_pk_type_t)MBEDTLS_PK_ECKEY));

    if (return_code != 0)
    {
      LOG_ERROR("Last error was: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    return_code = mbedtls_ecp_gen_key(
        MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(this->private_key_context_),
        mbedtls_ctr_drbg_random, &this->drbg_context_);

    if (return_code != 0)
    {
      LOG_ERROR("Last error was: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    return this->generatePublicKey();
  }

  /*
   * This will load an existing private key
   * and generates the public key and key_id
   *
   * @return int result code 0 for successful
   */
  int Client::loadPrivateKey(const uint8_t *private_key_buffer,
                             size_t private_key_length)
  {
    mbedtls_entropy_context entropy_context;
    mbedtls_entropy_init(&entropy_context);
    mbedtls_pk_init(&this->private_key_context_);
    mbedtls_ctr_drbg_init(&this->drbg_context_);

    int return_code = mbedtls_ctr_drbg_seed(&drbg_context_, mbedtls_entropy_func,
                                            &entropy_context, nullptr, 0);
    if (return_code != 0)
    {
      LOG_ERROR("Last error was: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    pb_byte_t password[0];
    return_code = mbedtls_pk_parse_key(
        &this->private_key_context_, private_key_buffer, private_key_length,
        password, 0, mbedtls_ctr_drbg_random, &this->drbg_context_);

    if (return_code != 0)
    {
      LOG_ERROR("Last error was: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    return this->generatePublicKey();
  }

  /*
   * This will return the private key in the pem format
   *
   * @param output_buffer Pointer of the buffer where should be written to
   * @param output_buffer_length Size of the output buffer
   * @param output_length Pointer to size_t that will store the written length
   * @return int result code 0 for successful
   */
  int Client::getPrivateKey(pb_byte_t *output_buffer,
                            size_t output_buffer_length, size_t *output_length)
  {
    int return_code = mbedtls_pk_write_key_pem(
        &this->private_key_context_, output_buffer, output_buffer_length);

    if (return_code != 0)
    {
      LOG_ERROR("Failed to write private key");
      return 1;
    }

    *output_length = strlen((char *)output_buffer) + 1;
    return 0;
  }

  int Client::getPublicKey(pb_byte_t *output_buffer,
                           size_t *output_buffer_length)
  {
    memcpy(output_buffer, this->public_key_, this->public_key_size_);
    *output_buffer_length = this->public_key_size_;
    return 0;
  }

  /*
   * This generates the public key from the private key
   *
   * @return int result code 0 for successful
   */
  int Client::generatePublicKey()
  {
    int return_code = mbedtls_ecp_point_write_binary(
        &mbedtls_pk_ec(this->private_key_context_)->private_grp,
        &mbedtls_pk_ec(this->private_key_context_)->private_Q,
        MBEDTLS_ECP_PF_UNCOMPRESSED, &this->public_key_size_, this->public_key_,
        sizeof(this->public_key_));

    if (return_code != 0)
    {
      LOG_ERROR("Last error was: -0x%04x", (unsigned int)-return_code);
      return 1;
    }
    return this->GenerateKeyId();
  }

  /*
   * This generates the key id from the public key
   *
   * @return int result code 0 for successful
   */
  int Client::GenerateKeyId()
  {
    pb_byte_t buffer[20];
    int return_code = mbedtls_sha1(this->public_key_, this->public_key_size_, buffer);
    if (return_code != 0)
    {
      LOG_ERROR("SHA1 KeyId hash error: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    // we only need the first 4 bytes
    memcpy(this->key_id_, buffer, 4);
    return 0;
  }

  /*
   * This will load the cars public key and
   * generates the shared secret
   *
   * @param public_key_buffer Pointer to where the public key buffer
   * @param public_key_size Size of the cars public key
   * @return int result code 0 for successful
   */
  int Client::loadTeslaKey(bool isInfotainment,
                           const uint8_t *public_key_buffer,
                           size_t public_key_size)
  {
    mbedtls_ecp_keypair &tesla_key = isInfotainment ? this->tesla_key_infotainment_
                                                    : this->tesla_key_vcsec_;
    pb_byte_t shared_secret[MBEDTLS_ECP_MAX_BYTES];
    size_t shared_secret_olen;
    pb_byte_t shared_secret_sha1[20];

    mbedtls_ecp_keypair_init(&tesla_key);

    int return_code = mbedtls_ecp_group_load(&tesla_key.private_grp, MBEDTLS_ECP_DP_SECP256R1);
    if (return_code != 0)
    {
      LOG_ERROR("Group load error: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    return_code = mbedtls_ecp_point_read_binary(&tesla_key.private_grp, &tesla_key.private_Q,
                                                public_key_buffer, public_key_size);
    if (return_code != 0)
    {
      LOG_ERROR("Point read error: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    mbedtls_ecdh_init(&this->ecdh_context_);

    return_code = mbedtls_ecdh_get_params(
        &this->ecdh_context_, mbedtls_pk_ec(this->private_key_context_),
        MBEDTLS_ECDH_OURS);

    if (return_code != 0)
    {
      LOG_ERROR("ECDH Get Params (private) error: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    return_code = mbedtls_ecdh_get_params(&this->ecdh_context_, &tesla_key,
                                          MBEDTLS_ECDH_THEIRS);

    if (return_code != 0)
    {
      LOG_ERROR("ECDH Get Params (tesla) error: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    // pb_byte_t temp_shared_secret[MBEDTLS_ECP_MAX_BYTES];
    // size_t temp_shared_secret_length = 0;
    return_code =
        mbedtls_ecdh_calc_secret(&this->ecdh_context_, &shared_secret_olen,
                                 shared_secret, sizeof(shared_secret),
                                 mbedtls_ctr_drbg_random, &this->drbg_context_);

    if (return_code != 0)
    {
      LOG_ERROR("ECDH calc secret error: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    // Now hash the shared secret
    // printf("shared_secret_olen: %u\n", shared_secret_olen);
    return_code = mbedtls_sha1(shared_secret, shared_secret_olen, shared_secret_sha1);
    if (return_code != 0)
    {
      LOG_ERROR("SHA 1 error: -0x%04x", (unsigned int)-return_code);
      return 1;
    }

    if (isInfotainment)
    {
      memcpy(this->shared_secret_infotainment_sha1_, shared_secret_sha1, this->SHARED_KEY_SIZE_BYTES); // we only need the first 16 bytes
    }
    else
    {
      memcpy(this->shared_secret_vcsec_sha1_, shared_secret_sha1, this->SHARED_KEY_SIZE_BYTES); // we only need the first 16 bytes
    }

    Peer &session = isInfotainment ? this->session_infotainment_ : this->session_vcsec_;
    session.setIsAuthenticated(true);

    return 0;
  }

  /*
   * This will load the cars public key and
   * generates the shared secret
   *
   * @param input_buffer Pointer to the input buffer
   * @param input_buffer_length Size of the input buffer
   * @param output_buffer Pointer to the output buffer
   * @param output_buffer_length Size of the output buffer
   * @param output_length Pointer to size_t that will store the written length
   * @param signature_buffer Pointer to the signature buffer
   * @return int result code 0 for successful
   */
  int Client::Encrypt(pb_byte_t *input_buffer, size_t input_buffer_length,
                      pb_byte_t *output_buffer, size_t output_buffer_length,
                      size_t *output_length, pb_byte_t *signature_buffer,
                      pb_byte_t *ad_buffer, size_t ad_buffer_length,
                      UniversalMessage_Domain domain)
  {
    if (!mbedtls_pk_can_do(&this->private_key_context_, MBEDTLS_PK_ECKEY))
    {
      LOG_ERROR("[Encrypt] Private key is not initialized");
      return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
    }

    mbedtls_gcm_context aes_context;
    mbedtls_gcm_init(&aes_context);

    pb_byte_t *shared_secret = domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT ? this->shared_secret_infotainment_sha1_ : this->shared_secret_vcsec_sha1_;
    size_t shared_secret_size = this->SHARED_KEY_SIZE_BYTES;

    if (shared_secret_size != this->SHARED_KEY_SIZE_BYTES)
    {
      LOG_ERROR("[Encrypt] Shared secret SHA1 is not 16 bytes (actual size = %u)", shared_secret_size);
      return TeslaBLE_Status_E_ERROR_ENCRYPT;
    }

    // Use 128-bit key as specified in the protocol
    int return_code = mbedtls_gcm_setkey(&aes_context, MBEDTLS_CIPHER_ID_AES, shared_secret, 128);
    if (return_code != 0)
    {
      LOG_ERROR("[Encrypt] GCM set key error: -0x%04x", (unsigned int)-return_code);
      return TeslaBLE_Status_E_ERROR_ENCRYPT;
    }

    // Generate a new nonce for each encryption
    this->generateNonce();

    return_code = mbedtls_gcm_starts(&aes_context, MBEDTLS_GCM_ENCRYPT, this->nonce_, sizeof(this->nonce_));
    if (return_code != 0)
    {
      LOG_ERROR("[Encrypt] GCM start error: -0x%04x", (unsigned int)-return_code);
      return TeslaBLE_Status_E_ERROR_ENCRYPT;
    }

    // Hash the AD buffer to create the AAD as per the protocol
    unsigned char ad_hash[32]; // SHA256 produces a 32-byte hash
    return_code = mbedtls_sha256(ad_buffer, ad_buffer_length, ad_hash, 0);
    if (return_code != 0)
    {
      LOG_ERROR("[Encrypt] AD metadata SHA256 hash error: -0x%04x", (unsigned int)-return_code);
      return TeslaBLE_Status_E_ERROR_ENCRYPT;
    }
    // Use the hash as the AAD for AES-GCM
    mbedtls_gcm_update_ad(&aes_context, ad_hash, sizeof(ad_hash));

    return_code = mbedtls_gcm_update(&aes_context, input_buffer, input_buffer_length,
                                     output_buffer, output_buffer_length, output_length);
    if (return_code != 0)
    {
      LOG_ERROR("[Encrypt] Encryption error in gcm_update: -0x%04x", (unsigned int)-return_code);
      return TeslaBLE_Status_E_ERROR_ENCRYPT;
    }

    size_t finish_buffer_length = 0;
    pb_byte_t finish_buffer[15]; // output_size never needs to be more than 15.
    // Finalize the encryption and get the tag
    size_t tag_length = 16; // AES-GCM typically uses a 16-byte tag
    return_code = mbedtls_gcm_finish(&aes_context, finish_buffer, sizeof(finish_buffer),
                                     &finish_buffer_length, signature_buffer, tag_length);
    if (return_code != 0)
    {
      LOG_ERROR("[Encrypt] Finalization error in gcm_finish: -0x%04x", (unsigned int)-return_code);
      return TeslaBLE_Status_E_ERROR_ENCRYPT;
    }

    mbedtls_gcm_free(&aes_context);

    return 0;
  }

  /*
   * This will clean up the contexts used
   */
  void Client::cleanup()
  {
    mbedtls_pk_free(&this->private_key_context_);
    mbedtls_ecp_keypair_free(&this->tesla_key_vcsec_);
    mbedtls_ecp_keypair_free(&this->tesla_key_infotainment_);
    mbedtls_ecdh_free(&this->ecdh_context_);
    mbedtls_ctr_drbg_free(&this->drbg_context_);
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
    if (!mbedtls_pk_can_do(&this->private_key_context_, MBEDTLS_PK_ECKEY))
    {
      LOG_ERROR("[buildWhiteListMessage] Private key is not initialized");
      return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
    }

    VCSEC_PermissionChange permissions_action =
        VCSEC_PermissionChange_init_default;
    permissions_action.has_key = true;
    memcpy(permissions_action.key.PublicKeyRaw.bytes, this->public_key_,
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
    pb_byte_t payload_buffer[80];
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
    pb_byte_t vcsec_encode_buffer[86];
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
    return 0;
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

    return 0;
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
      LOG_ERROR("Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }

    return 0;
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
    pb_istream_t stream = pb_istream_from_buffer(input_buffer, input_buffer_length);
    bool status =
        pb_decode(&stream, UniversalMessage_RoutableMessage_fields, output);
    if (!status)
    {
      LOG_ERROR("Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }

    return 0;
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
    pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
    bool status =
        pb_decode(&stream, Signatures_SessionInfo_fields, output);
    if (!status)
    {
      LOG_ERROR("Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }

    return 0;
  }

  int Client::parsePayloadUnsignedMessage(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                          VCSEC_UnsignedMessage *output)
  {
    pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
    bool status =
        pb_decode(&stream, VCSEC_UnsignedMessage_fields, output);
    if (!status)
    {
      LOG_ERROR("Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }

    return 0;
  }

  int Client::parsePayloadCarServerResponse(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                            CarServer_Response *output)
  {
    pb_istream_t stream = pb_istream_from_buffer(input_buffer->bytes, input_buffer->size);
    bool status =
        pb_decode(&stream, CarServer_Response_fields, output);
    if (!status)
    {
      LOG_ERROR("Decoding failed: %s", PB_GET_ERROR(&stream));
      return TeslaBLE_Status_E_ERROR_PB_DECODING;
    }

    return 0;
  }

  int Client::ConstructADBuffer(
      Signatures_SignatureType signature_type,
      UniversalMessage_Domain domain,
      const char *VIN,
      pb_byte_t *epoch,
      uint32_t expires_at,
      uint32_t counter,
      pb_byte_t *output_buffer,
      size_t *output_length)
  {
    size_t index = 0;

    // Signature type
    output_buffer[index++] = Signatures_Tag_TAG_SIGNATURE_TYPE;
    output_buffer[index++] = 0x01;
    output_buffer[index++] = signature_type;

    // Domain
    output_buffer[index++] = Signatures_Tag_TAG_DOMAIN;
    output_buffer[index++] = 0x01;
    output_buffer[index++] = domain;

    // Personalization (VIN)
    size_t vin_length = strlen(VIN);
    output_buffer[index++] = Signatures_Tag_TAG_PERSONALIZATION;
    output_buffer[index++] = vin_length;
    memcpy(output_buffer + index, VIN, vin_length);
    index += vin_length;

    // Epoch
    output_buffer[index++] = Signatures_Tag_TAG_EPOCH;
    output_buffer[index++] = 0x10; // Assuming epoch is always 16 bytes
    memcpy(output_buffer + index, epoch, 16);
    index += 16;

    // Expires at
    output_buffer[index++] = Signatures_Tag_TAG_EXPIRES_AT;
    output_buffer[index++] = 0x04;
    output_buffer[index++] = (expires_at >> 24) & 0xFF;
    output_buffer[index++] = (expires_at >> 16) & 0xFF;
    output_buffer[index++] = (expires_at >> 8) & 0xFF;
    output_buffer[index++] = expires_at & 0xFF;

    // Counter
    output_buffer[index++] = Signatures_Tag_TAG_COUNTER;
    output_buffer[index++] = 0x04;
    output_buffer[index++] = (counter >> 24) & 0xFF;
    output_buffer[index++] = (counter >> 16) & 0xFF;
    output_buffer[index++] = (counter >> 8) & 0xFF;
    output_buffer[index++] = counter & 0xFF;

    // Terminal byte
    output_buffer[index++] = Signatures_Tag_TAG_END;

    // // ad buffer needs to be multiple of 16
    // while (index % 16 != 0)
    // {
    //   output_buffer[index++] = 0x00;
    // }

    *output_length = index;

    return 0;
  }

  int Client::buildUniversalMessageWithPayload(pb_byte_t *payload,
                                               size_t payload_length,
                                               UniversalMessage_Domain domain,
                                               pb_byte_t *output_buffer,
                                               size_t *output_length,
                                               bool encryptPayload)
  {
    UniversalMessage_RoutableMessage universal_message = UniversalMessage_RoutableMessage_init_default;

    UniversalMessage_Destination to_destination = UniversalMessage_Destination_init_default;
    to_destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
    to_destination.sub_destination.domain = domain;
    universal_message.has_to_destination = true;
    universal_message.to_destination = to_destination;

    Peer &session = domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT ? this->session_infotainment_ : this->session_vcsec_;
    session.incrementCounter();

    UniversalMessage_Destination from_destination = UniversalMessage_Destination_init_default;
    from_destination.which_sub_destination = UniversalMessage_Destination_routing_address_tag;
    memcpy(from_destination.sub_destination.routing_address, this->connectionID, sizeof(this->connectionID));
    universal_message.has_from_destination = true;
    universal_message.from_destination = from_destination;

    universal_message.which_payload = UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag;
    if (encryptPayload)
    {
      auto epoch = session.getEpoch();
      // got epoch
      // log epoch as hex
      char epoch_hex[33];
      for (int i = 0; i < 16; i++)
      {
        snprintf(epoch_hex + (i * 2), 3, "%02x", epoch[i]);
      }
      epoch_hex[32] = '\0';
      LOG_DEBUG("Epoch: %s", epoch_hex);

      // raise an error on empty / default epoch (e.g. epoch == 00000000000000000000000000000000)
      if (epoch == nullptr)
      {
        LOG_ERROR("Epoch can not be empty");
        return TeslaBLE_Status_E_ERROR_INVALID_SESSION;
      }
      else
      {
        for (int i = 0; i < 16; i++)
        {
          if (epoch[i] != 0)
          {
            break;
          }
          if (i == 15)
          {
            LOG_ERROR("Epoch can not be empty");
            return TeslaBLE_Status_E_ERROR_INVALID_SESSION;
          }
        }
      }

      pb_byte_t signature[16];
      // encrypt the payload
      pb_byte_t encrypted_payload[100];
      size_t encrypted_output_length = 0;

      uint32_t expires_at = session.generateExpiresAt(5);

      // Next, we construct the serialized metadata string from values in the table
      // below. The metadata string is used as the associated authenticated data (AAD)
      // field of AES-GCM.
      pb_byte_t ad_buffer[56];
      size_t ad_buffer_length = 0;
      this->ConstructADBuffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED, domain, this->VIN, epoch, expires_at, session.getCounter(), ad_buffer, &ad_buffer_length);

      int return_code = this->Encrypt(payload, payload_length, encrypted_payload, sizeof encrypted_payload, &encrypted_output_length, signature, ad_buffer, ad_buffer_length, domain);
      if (return_code != 0)
      {
        LOG_ERROR("Failed to encrypt payload");
        return TeslaBLE_Status_E_ERROR_ENCRYPT;
      }

      // payload length
      memcpy(universal_message.payload.protobuf_message_as_bytes.bytes, encrypted_payload, encrypted_output_length);
      universal_message.payload.protobuf_message_as_bytes.size = encrypted_output_length;

      // set signature
      // set public key
      Signatures_SignatureData signature_data = Signatures_SignatureData_init_default;
      Signatures_KeyIdentity signer_identity = Signatures_KeyIdentity_init_default;
      signer_identity.which_identity_type = Signatures_KeyIdentity_public_key_tag;
      memcpy(signer_identity.identity_type.public_key.bytes, this->public_key_, this->public_key_size_);
      signer_identity.identity_type.public_key.size = this->public_key_size_;
      signature_data.has_signer_identity = true;
      signature_data.signer_identity = signer_identity;

      Signatures_AES_GCM_Personalized_Signature_Data aes_gcm_signature_data = Signatures_AES_GCM_Personalized_Signature_Data_init_default;
      signature_data.which_sig_type = Signatures_SignatureData_AES_GCM_Personalized_data_tag;
      signature_data.sig_type.AES_GCM_Personalized_data.counter = session.getCounter();
      signature_data.sig_type.AES_GCM_Personalized_data.expires_at = expires_at;
      memcpy(signature_data.sig_type.AES_GCM_Personalized_data.nonce, this->nonce_, sizeof this->nonce_);
      memcpy(signature_data.sig_type.AES_GCM_Personalized_data.epoch, epoch, 16);
      memcpy(signature_data.sig_type.AES_GCM_Personalized_data.tag, signature, sizeof signature);

      universal_message.which_sub_sigData = UniversalMessage_RoutableMessage_signature_data_tag;
      universal_message.sub_sigData.signature_data = signature_data;
    }
    else
    {
      memcpy(universal_message.payload.protobuf_message_as_bytes.bytes, payload, payload_length);
      universal_message.payload.protobuf_message_as_bytes.size = payload_length;
    }

    // set gcm data
    if (encryptPayload)
    {
    }

    // random 16 bytes using rand()
    pb_byte_t uuid[16];
    for (int i = 0; i < sizeof(uuid); i++)
    {
      uuid[i] = rand() % 256;
    }
    memcpy(universal_message.uuid, uuid, sizeof(uuid));

    int return_code = pb_encode_fields(output_buffer, output_length, UniversalMessage_RoutableMessage_fields, &universal_message);
    if (return_code != 0)
    {
      LOG_ERROR("[buildUniversalMessageWithPayload] Failed to encode universal message");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }
    return 0;
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
    UniversalMessage_RoutableMessage universal_message = UniversalMessage_RoutableMessage_init_default;

    UniversalMessage_Destination to_destination = UniversalMessage_Destination_init_default;
    to_destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
    to_destination.sub_destination.domain = domain;
    universal_message.has_to_destination = true;
    universal_message.to_destination = to_destination;

    UniversalMessage_Destination from_destination = UniversalMessage_Destination_init_default;
    from_destination.which_sub_destination = UniversalMessage_Destination_routing_address_tag;
    memcpy(from_destination.sub_destination.routing_address, this->connectionID, sizeof(this->connectionID));
    universal_message.has_from_destination = true;
    universal_message.from_destination = from_destination;

    universal_message.which_payload = UniversalMessage_RoutableMessage_session_info_request_tag;
    UniversalMessage_SessionInfoRequest session_info_request = UniversalMessage_SessionInfoRequest_init_default;
    memcpy(session_info_request.public_key.bytes, this->public_key_, this->public_key_size_);
    session_info_request.public_key.size = this->public_key_size_;
    universal_message.payload.session_info_request = session_info_request;

    // generate unique uuid for the request
    pb_byte_t uuid[16];
    for (int i = 0; i < sizeof(uuid); i++)
    {
      uuid[i] = rand() % 256;
    }
    memcpy(universal_message.uuid, uuid, sizeof(uuid));

    size_t universal_encode_buffer_size = this->MAX_BLE_MESSAGE_SIZE - 2;
    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int return_code = pb_encode_fields(universal_encode_buffer, &universal_encode_buffer_size, UniversalMessage_RoutableMessage_fields, &universal_message);
    if (return_code != 0)
    {
      LOG_ERROR("[buildSessionInfoRequest] Failed to encode universal message");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }
    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);

    return 0;
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
    pb_byte_t payload_buffer[100];
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

    size_t universal_encode_buffer_size = this->MAX_BLE_MESSAGE_SIZE - 2;
    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildUnsignedMessagePayload(&payload, universal_encode_buffer, &universal_encode_buffer_size, false);
    if (status != 0)
    {
      LOG_ERROR("[buildKeySummary] Failed to build unsigned message\n");
      return status;
    }
    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);
    return 0;
  }

  int Client::buildCarActionToMessage(CarServer_Action *action,
                                      pb_byte_t *output_buffer,
                                      size_t *output_length)
  {
    pb_byte_t payload_buffer[100];
    size_t payload_length = 0;
    int return_code = pb_encode_fields(payload_buffer, &payload_length, CarServer_Action_fields, action);
    if (return_code != 0)
    {
      LOG_ERROR("Failed to encode car action message");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }

    // build universal message
    return this->buildUniversalMessageWithPayload(
        payload_buffer, payload_length, UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
        output_buffer, output_length, true);
  }

  /*/
   * This will build an carserver action message to for
   * example open the trunk
   *
   * @param message Pointer to the message
   * @param output_buffer Pointer to the output buffer
   * @param output_length Size of the output buffer
   * @return int result code 0 for successful
   */

  int Client::buildCarServerActionMessage(const CarServer_VehicleAction *vehicle_action,
                                          pb_byte_t *output_buffer,
                                          size_t *output_length)
  {
    CarServer_Action action = CarServer_Action_init_default;
    action.which_action_msg = CarServer_Action_vehicleAction_tag;
    action.action_msg.vehicleAction = *vehicle_action;

    size_t universal_encode_buffer_size = this->MAX_BLE_MESSAGE_SIZE - 2;
    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildCarActionToMessage(&action, universal_encode_buffer, &universal_encode_buffer_size);
    if (status != 0)
    {
      LOG_ERROR("Failed to build car action message");
      return status;
    }
    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);
    return 0;
  }

  int Client::buildChargingAmpsMessage(int32_t amps,
                                       pb_byte_t *output_buffer,
                                       size_t *output_length)
  {
    CarServer_Action action = CarServer_Action_init_default;
    action.which_action_msg = CarServer_Action_vehicleAction_tag;

    CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
    vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_setChargingAmpsAction_tag;
    CarServer_SetChargingAmpsAction set_charging_amps_action = CarServer_SetChargingAmpsAction_init_default;
    set_charging_amps_action.charging_amps = amps;
    vehicle_action.vehicle_action_msg.setChargingAmpsAction = set_charging_amps_action;
    action.action_msg.vehicleAction = vehicle_action;

    size_t universal_encode_buffer_size = this->MAX_BLE_MESSAGE_SIZE - 2;
    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildCarActionToMessage(&action, universal_encode_buffer, &universal_encode_buffer_size);
    if (status != 0)
    {
      LOG_ERROR("Failed to build car action message");
      return status;
    }
    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);
    return 0;
  }

  int Client::buildChargingSetLimitMessage(int32_t percent,
                                           pb_byte_t *output_buffer,
                                           size_t *output_length)
  {
    CarServer_Action action = CarServer_Action_init_default;
    action.which_action_msg = CarServer_Action_vehicleAction_tag;

    CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
    vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_chargingSetLimitAction_tag;
    CarServer_ChargingSetLimitAction charging_set_limit_action = CarServer_ChargingSetLimitAction_init_default;
    charging_set_limit_action.percent = percent;
    vehicle_action.vehicle_action_msg.chargingSetLimitAction = charging_set_limit_action;
    action.action_msg.vehicleAction = vehicle_action;

    size_t universal_encode_buffer_size = this->MAX_BLE_MESSAGE_SIZE - 2;
    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildCarActionToMessage(&action, universal_encode_buffer, &universal_encode_buffer_size);
    if (status != 0)
    {
      LOG_ERROR("Failed to build car action message");
      return status;
    }
    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);
    return 0;
  }
  int Client::buildChargingSwitchMessage(bool isOn,
                                         pb_byte_t *output_buffer,
                                         size_t *output_length)
  {
    CarServer_Action action = CarServer_Action_init_default;
    action.which_action_msg = CarServer_Action_vehicleAction_tag;

    CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
    vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_chargingStartStopAction_tag;
    CarServer_ChargingStartStopAction vehicle_action_msg = CarServer_ChargingStartStopAction_init_default;
    if (isOn)
    {
      vehicle_action_msg.which_charging_action = CarServer_ChargingStartStopAction_start_tag;
      vehicle_action_msg.charging_action.stop = CarServer_Void_init_default;
    }
    else
    {
      vehicle_action_msg.which_charging_action = CarServer_ChargingStartStopAction_stop_tag;
      vehicle_action_msg.charging_action.start = CarServer_Void_init_default;
    }
    vehicle_action.vehicle_action_msg.chargingStartStopAction = vehicle_action_msg;
    action.action_msg.vehicleAction = vehicle_action;

    size_t universal_encode_buffer_size = this->MAX_BLE_MESSAGE_SIZE - 2;
    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildCarActionToMessage(&action, universal_encode_buffer, &universal_encode_buffer_size);
    if (status != 0)
    {
      LOG_ERROR("Failed to build car action message");
      return status;
    }
    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);
    return 0;
  }

  int Client::buildHVACMessage(bool isOn,
                               pb_byte_t *output_buffer,
                               size_t *output_length)
  {
    CarServer_Action action = CarServer_Action_init_default;
    action.which_action_msg = CarServer_Action_vehicleAction_tag;

    CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
    vehicle_action.which_vehicle_action_msg = CarServer_VehicleAction_hvacAutoAction_tag;
    CarServer_HvacAutoAction vehicle_action_msg = CarServer_HvacAutoAction_init_default;
    vehicle_action_msg.power_on = isOn;
    vehicle_action.vehicle_action_msg.hvacAutoAction = vehicle_action_msg;
    action.action_msg.vehicleAction = vehicle_action;

    size_t universal_encode_buffer_size = this->MAX_BLE_MESSAGE_SIZE - 2;
    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildCarActionToMessage(&action, universal_encode_buffer, &universal_encode_buffer_size);
    if (status != 0)
    {
      LOG_ERROR("Failed to build car action message");
      return status;
    }
    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);
    return 0;
  }

  int Client::buildVCSECActionMessage(const VCSEC_RKEAction_E action, pb_byte_t *output_buffer,
                                      size_t *output_length)
  {
    VCSEC_UnsignedMessage unsigned_message = VCSEC_UnsignedMessage_init_default;
    unsigned_message.which_sub_message = VCSEC_UnsignedMessage_RKEAction_tag;
    unsigned_message.sub_message.RKEAction = action;

    size_t universal_encode_buffer_size = this->MAX_BLE_MESSAGE_SIZE - 2;
    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildUnsignedMessagePayload(&unsigned_message, universal_encode_buffer, &universal_encode_buffer_size, true);
    if (status != 0)
    {
      LOG_ERROR("Failed to build unsigned message");
      return status;
    }
    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);
    return 0;
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

    size_t universal_encode_buffer_size = this->MAX_BLE_MESSAGE_SIZE - 2;
    pb_byte_t universal_encode_buffer[universal_encode_buffer_size];
    int status = this->buildUnsignedMessagePayload(&unsigned_message, universal_encode_buffer, &universal_encode_buffer_size, false);
    if (status != 0)
    {
      LOG_ERROR("Failed to build unsigned message");
      return status;
    }
    this->prependLength(universal_encode_buffer, universal_encode_buffer_size,
                        output_buffer, output_length);
    return 0;
  }

  int Client::buildWakeVehicleMessage(pb_byte_t *output_buffer,
                                      size_t *output_length)
  {
    return buildVCSECActionMessage(VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, output_buffer, output_length);
  }
} // namespace TeslaBLE
// #endif // MBEDTLS_CONFIG_FILE
