#pragma once

#include <string>
#include <memory> // Add this for std::shared_ptr

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha1.h"
#include <chrono>

#include "defs.h"
#include "peer.h"
#include "car_server.pb.h"
#include "universal_message.pb.h"
#include "vcsec.pb.h"
#include "keys.pb.h"

namespace TeslaBLE
{
  class Client
  {
  public:
    Client()
        : private_key_context_(std::make_unique<mbedtls_pk_context>()),
          ecdh_context_(std::make_unique<mbedtls_ecdh_context>()),
          drbg_context_(std::make_unique<mbedtls_ctr_drbg_context>()),
          session_vcsec_(std::make_unique<Peer>(
              UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
              private_key_context_,
              ecdh_context_,
              drbg_context_)),
          session_infotainment_(std::make_unique<Peer>(
              UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
              private_key_context_,
              ecdh_context_,
              drbg_context_))
    {
      mbedtls_pk_init(private_key_context_.get());
      mbedtls_ecdh_init(ecdh_context_.get());
      mbedtls_ctr_drbg_init(drbg_context_.get());
    }

    ~Client()
    {
      if (private_key_context_)
        mbedtls_pk_free(private_key_context_.get());
      if (ecdh_context_)
        mbedtls_ecdh_free(ecdh_context_.get());
      if (drbg_context_)
        mbedtls_ctr_drbg_free(drbg_context_.get());
    }

    int createPrivateKey();

    void setVIN(const char *vin);

    void setConnectionID(const pb_byte_t *connectionID);

    int loadPrivateKey(
        const uint8_t *private_key_buffer,
        size_t key_size);

    int getPrivateKey(
        pb_byte_t *output_buffer,
        size_t output_buffer_length,
        size_t *output_length);

    int getPublicKey(
        pb_byte_t *output_buffer,
        size_t *output_buffer_length);

    int buildWhiteListMessage(
        Keys_Role role,
        VCSEC_KeyFormFactor form_factor,
        pb_byte_t *output_buffer,
        size_t *output_length);

    static int parseFromVCSECMessage(
        UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
        VCSEC_FromVCSECMessage *output);

    static int parseUniversalMessage(
        pb_byte_t *input_buffer,
        size_t input_size,
        UniversalMessage_RoutableMessage *output);

    static int parseUniversalMessageBLE(
        pb_byte_t *input_buffer,
        size_t input_buffer_length,
        UniversalMessage_RoutableMessage *output);

    static int parseVCSECInformationRequest(
        UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
        VCSEC_InformationRequest *output);

    static int parsePayloadSessionInfo(
        UniversalMessage_RoutableMessage_session_info_t *input_buffer,
        Signatures_SessionInfo *output);

    static int parsePayloadUnsignedMessage(
        UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
        VCSEC_UnsignedMessage *output);

    static int parsePayloadCarServerResponse(
        UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
        CarServer_Response *output);

    int buildSessionInfoRequestMessage(
        UniversalMessage_Domain domain,
        pb_byte_t *output_buffer,
        size_t *output_length);

    int buildKeySummary(
        pb_byte_t *output_buffer,
        size_t *output_length);

    int buildUnsignedMessagePayload(
        VCSEC_UnsignedMessage *message,
        pb_byte_t *output_buffer,
        size_t *output_length,
        bool encryptPayload = false);

    int buildCarServerActionPayload(
        CarServer_Action *action,
        pb_byte_t *output_buffer,
        size_t *output_length);

    int buildUniversalMessageWithPayload(
        pb_byte_t *payload,
        size_t payload_length,
        UniversalMessage_Domain domain,
        pb_byte_t *output_buffer,
        size_t *output_length,
        bool encryptPayload = false);

    int buildVCSECInformationRequestMessage(
        VCSEC_InformationRequestType request_type,
        pb_byte_t *output_buffer,
        size_t *output_length,
        uint32_t key_slot = 0);
    int buildVCSECActionMessage(
        const VCSEC_RKEAction_E action,
        pb_byte_t *output_buffer, size_t *output_length);

    int buildCarServerActionMessage(
        const CarServer_VehicleAction *vehicle_action,
        pb_byte_t *output_buffer,
        size_t *output_length);

    int buildChargingAmpsMessage(
        int32_t amps,
        pb_byte_t *output_buffer,
        size_t *output_length);

    int buildChargingSetLimitMessage(
        int32_t percent,
        pb_byte_t *output_buffer,
        size_t *output_length);

    int buildHVACMessage(
        bool isOn,
        pb_byte_t *output_buffer,
        size_t *output_length);

    int buildHVACSteeringHeaterMessage(
        bool isOn,
        pb_byte_t *output_buffer,
        size_t *output_length);

    int buildChargingSwitchMessage(
        bool isOn,
        pb_byte_t *output_buffer,
        size_t *output_length);

    int buildSentrySwitchMessage(
        bool isOn,
        pb_byte_t *output_buffer,
        size_t *output_length);

    int buildOpenChargePortDoorMessage(
        pb_byte_t *output_buffer,
        size_t *output_length);

    int buildCloseChargePortDoorMessage(
        pb_byte_t *output_buffer,
        size_t *output_length);

    Peer *getPeer(UniversalMessage_Domain domain)
    {
      if (domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY)
      {
        return session_vcsec_.get();
      }
      else if (domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT)
      {
        return session_infotainment_.get();
      }
      return nullptr;
    }

  protected:
    std::shared_ptr<mbedtls_pk_context> private_key_context_;
    std::shared_ptr<mbedtls_ecdh_context> ecdh_context_;
    std::shared_ptr<mbedtls_ctr_drbg_context> drbg_context_;
    std::unique_ptr<Peer> session_vcsec_;
    std::unique_ptr<Peer> session_infotainment_;

    unsigned char public_key_id_[4];
    unsigned char public_key_[MBEDTLS_ECP_MAX_BYTES];
    size_t public_key_size_;
    pb_byte_t connectionID[16];
    const char *VIN = "";

    static void prependLength(
        const pb_byte_t *input_buffer,
        size_t input_buffer_length,
        pb_byte_t *output_buffer,
        size_t *output_buffer_length);

    int generatePublicKey();

    int GenerateKeyId();
  };
} // namespace TeslaBLE
