#ifndef TESLA_BLE_CLIENT_H
#define TESLA_BLE_CLIENT_H
// https://github.com/platformio/platform-espressif32/issues/957
// specifically set when compiling with ESP-IDF
#ifdef ESP_PLATFORM
#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#endif
#include <string>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha1.h"
#include <chrono>

#include "peer.h"
#include "car_server.pb.h"
#include "universal_message.pb.h"
#include "vcsec.pb.h"
#include "keys.pb.h"

namespace TeslaBLE
{
  class Client
  {
    static const int SHARED_KEY_SIZE_BYTES = 16;

  private:
    mbedtls_pk_context private_key_context_;
    mbedtls_ecp_keypair tesla_key_vcsec_;
    mbedtls_ecp_keypair tesla_key_infotainment_;
    mbedtls_ecdh_context ecdh_context_;
    mbedtls_ctr_drbg_context drbg_context_;
    pb_byte_t shared_secret_infotainment_sha1_[SHARED_KEY_SIZE_BYTES];
    pb_byte_t shared_secret_vcsec_sha1_[SHARED_KEY_SIZE_BYTES];
    unsigned char key_id_[4];
    unsigned char public_key_[MBEDTLS_ECP_MAX_BYTES];
    size_t public_key_size_;

    // pb_byte_t epoch_[16];
    pb_byte_t nonce_[12];
    // uint32_t counter_ = 1;
    // uint32_t expires_at_ = 0;
    pb_byte_t connectionID[16] = {0x0A, 0x79, 0x62, 0xc1, 0x0d, 0x38, 0xb6, 0x1d, 0xd2, 0xa7, 0x72, 0x27, 0x80, 0xa4, 0xf0, 0x96};
    const char *VIN = "";

    static void prependLength(const pb_byte_t *input_buffer,
                              size_t input_buffer_length,
                              pb_byte_t *output_buffer,
                              size_t *output_buffer_length);

    int generatePublicKey();

    int GenerateKeyId();

    int ConstructADBuffer(Signatures_SignatureType signature_type,
                          UniversalMessage_Domain domain,
                          const char *VIN,
                          pb_byte_t *epoch,
                          uint32_t expires_at,
                          uint32_t counter,
                          pb_byte_t *output_buffer,
                          size_t *output_length);

    int Encrypt(pb_byte_t *input_buffer, size_t input_buffer_length,
                pb_byte_t *output_buffer, size_t output_buffer_length,
                size_t *output_length, pb_byte_t *signature_buffer,
                pb_byte_t *ad_buffer, size_t ad_buffer_length,
                UniversalMessage_Domain domain);

  public:
    Peer session_vcsec_;
    Peer session_infotainment_;
    static const int MAX_BLE_MESSAGE_SIZE = 1024;

    int createPrivateKey();

    void generateNonce();

    void setVIN(const char *vin);

    void setConnectionID(const pb_byte_t *connectionID);

    int loadPrivateKey(const uint8_t *private_key_buffer, size_t key_size);

    int getPrivateKey(pb_byte_t *output_buffer, size_t output_buffer_length,
                      size_t *output_length);
    int getPublicKey(pb_byte_t *output_buffer, size_t *output_buffer_length);

    int loadTeslaKey(bool isInfotainment, const uint8_t *public_key_buffer, size_t key_size);

    void cleanup();

    int buildWhiteListMessage(Keys_Role role,
                              VCSEC_KeyFormFactor form_factor,
                              pb_byte_t *output_buffer,
                              size_t *output_length);

    static int parseFromVCSECMessage(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                     VCSEC_FromVCSECMessage *output);

    static int parseUniversalMessage(pb_byte_t *input_buffer,
                                     size_t input_size,
                                     UniversalMessage_RoutableMessage *output);

    static int parseUniversalMessageBLE(pb_byte_t *input_buffer,
                                        size_t input_buffer_length,
                                        UniversalMessage_RoutableMessage *output);
    static int parseVCSECInformationRequest(
        UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
        VCSEC_InformationRequest *output);

    static int parsePayloadSessionInfo(UniversalMessage_RoutableMessage_session_info_t *input_buffer,
                                       Signatures_SessionInfo *output);
    static int parsePayloadUnsignedMessage(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                           VCSEC_UnsignedMessage *output);
    static int parsePayloadCarServerAction(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                           CarServer_Action *output);

    int buildEphemeralKeyMessage(UniversalMessage_Domain domain,
                                 pb_byte_t *output_buffer,
                                 size_t *output_length);

    int buildKeySummary(pb_byte_t *output_buffer,
                        size_t *output_length);

    int buildUnsignedMessagePayload(VCSEC_UnsignedMessage *message,
                                    pb_byte_t *output_buffer,
                                    size_t *output_length,
                                    bool encryptPayload = false);

    int buildCarActionToMessage(CarServer_Action *action,
                                pb_byte_t *output_buffer,
                                size_t *output_length);

    int buildUniversalMessageWithPayload(pb_byte_t *payload,
                                         size_t payload_length,
                                         UniversalMessage_Domain domain,
                                         pb_byte_t *output_buffer,
                                         size_t *output_length,
                                         bool encryptPayload = false);

    int buildVCSECActionMessage(const VCSEC_RKEAction_E action,
                                pb_byte_t *output_buffer, size_t *output_length);

    int buildCarServerActionMessage(const CarServer_VehicleAction *vehicle_action,
                                    pb_byte_t *output_buffer,
                                    size_t *output_length);

    int buildChargingAmpsMessage(int32_t amps,
                                 pb_byte_t *output_buffer,
                                 size_t *output_length);

    int buildChargingSetLimitMessage(int32_t percent,
                                     pb_byte_t *output_buffer,
                                     size_t *output_length);

    int buildHVACMessage(bool isOn,
                         pb_byte_t *output_buffer,
                         size_t *output_length);

    int buildWakeVehicleMessage(pb_byte_t *output_buffer,
                                size_t *output_length);

    int buildChargingSwitchMessage(bool isOn,
                                   pb_byte_t *output_buffer,
                                   size_t *output_length);
  };
} // namespace TeslaBLE
// #endif // MBEDTLS_CONFIG_FILE
#endif // TESLA_BLE_CLIENT_H
