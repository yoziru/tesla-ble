#pragma once

#include <memory>
#include <string>
#include <array>

#include "crypto_context.h"
#include "message_builders.h"
#include "peer.h"
#include <car_server.pb.h>
#include <universal_message.pb.h>
#include <vcsec.pb.h>
#include <keys.pb.h>
#include "errors.h"

namespace TeslaBLE
{
    /**
     * @brief Main client class for Tesla BLE communication
     * 
     * This class provides a high-level interface for communicating with Tesla vehicles
     * over BLE. It manages cryptographic contexts, sessions, and message building/parsing.
     */
    class Client
    {
    public:
        /**
         * @brief Constructor
         * Initializes crypto context and peer sessions
         */
        Client();

        /**
         * @brief Destructor
         */
        ~Client() = default;

        // Delete copy constructor and assignment operator
        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;

        // Allow move constructor and assignment
        Client(Client&&) = default;
        Client& operator=(Client&&) = default;

        // Configuration methods
        void setVIN(const std::string& vin);
        void setConnectionID(const pb_byte_t* connectionID);

        // Key management
        int createPrivateKey();
        int loadPrivateKey(const uint8_t* private_key_buffer, size_t key_size);
        int getPrivateKey(pb_byte_t* output_buffer, size_t output_buffer_length, size_t* output_length);
        int getPublicKey(pb_byte_t* output_buffer, size_t* output_buffer_length);

        // Message building
        int buildWhiteListMessage(
            Keys_Role role,
            VCSEC_KeyFormFactor form_factor,
            pb_byte_t* output_buffer,
            size_t* output_length);

        int buildSessionInfoRequestMessage(
            UniversalMessage_Domain domain,
            pb_byte_t* output_buffer,
            size_t* output_length);

        int buildKeySummary(
            pb_byte_t* output_buffer,
            size_t* output_length);

        int buildUnsignedMessagePayload(
            VCSEC_UnsignedMessage* message,
            pb_byte_t* output_buffer,
            size_t* output_length,
            bool encryptPayload = false);

        int buildCarServerActionPayload(
            CarServer_Action* action,
            pb_byte_t* output_buffer,
            size_t* output_length);

        int buildUniversalMessageWithPayload(
            pb_byte_t* payload,
            size_t payload_length,
            UniversalMessage_Domain domain,
            pb_byte_t* output_buffer,
            size_t* output_length,
            bool encryptPayload = false);

        int buildVCSECInformationRequestMessage(
            VCSEC_InformationRequestType request_type,
            pb_byte_t* output_buffer,
            size_t* output_length,
            uint32_t key_slot = 0);

        int buildVCSECActionMessage(
            const VCSEC_RKEAction_E action,
            pb_byte_t* output_buffer,
            size_t* output_length);

        int buildCarServerGetVehicleDataMessage(
            pb_byte_t* output_buffer,
            size_t* output_length,
            int32_t which_vehicle_data);

        /**
         * @brief Build a vehicle action message using the new factory pattern
         * @param output_buffer Buffer to write the encoded message
         * @param output_length Pointer to size variable that will contain the output length
         * @param which_vehicle_action The type of action to build
         * @param action_data Optional data for the action (can be nullptr for simple actions)
         * @return Error code (0 on success)
         */
        int buildCarServerVehicleActionMessage(
            pb_byte_t* output_buffer,
            size_t* output_length,
            int32_t which_vehicle_action,
            const void* action_data = nullptr);

        // Session management (public for testing)
        Peer* getPeer(UniversalMessage_Domain domain);
        const Peer* getPeer(UniversalMessage_Domain domain) const;

        // Message parsing (public for testing)
        int parseFromVCSECMessage(
            UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t* input_buffer,
            VCSEC_FromVCSECMessage* output);

        int parseUniversalMessage(
            pb_byte_t* input_buffer,
            size_t input_size,
            UniversalMessage_RoutableMessage* output);

        int parseUniversalMessageBLE(
            pb_byte_t* input_buffer,
            size_t input_buffer_length,
            UniversalMessage_RoutableMessage* output);

        int parseVCSECInformationRequest(
            UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t* input_buffer,
            VCSEC_InformationRequest* output);

        int parsePayloadSessionInfo(
            UniversalMessage_RoutableMessage_session_info_t* input_buffer,
            Signatures_SessionInfo* output);

        int parsePayloadUnsignedMessage(
            UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t* input_buffer,
            VCSEC_UnsignedMessage* output);

        int parsePayloadCarServerResponse(
            UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t* input_buffer,
            Signatures_SignatureData* signature_data,
            pb_size_t which_sub_sigData,
            UniversalMessage_MessageFault_E signed_message_fault,
            CarServer_Response* output);

    private:
        // Legacy implementation - to be phased out
        int buildCarServerVehicleActionMessageLegacy(
            pb_byte_t* output_buffer,
            size_t* output_length,
            int32_t which_vehicle_action,
            const void* action_data = nullptr);

    private:
        // Core components
        CryptoContext crypto_context_;
        std::unique_ptr<Peer> session_vcsec_;
        std::unique_ptr<Peer> session_infotainment_;

        // Vehicle identification
        std::string vin_;
        std::array<pb_byte_t, 16> connection_id_{};

        // Key data
        std::array<pb_byte_t, 4> public_key_id_{};
        std::array<pb_byte_t, MBEDTLS_ECP_MAX_PT_LEN> public_key_{};
        size_t public_key_size_ = 0;

        // Request tracking for response validation
        std::array<pb_byte_t, 16> last_request_tag_{};
        Signatures_SignatureType last_request_type_ = static_cast<Signatures_SignatureType>(0);
        std::array<pb_byte_t, 17> last_request_hash_{}; // 1 byte type + 16 bytes tag
        size_t last_request_hash_length_ = 0;

        // Helper methods
        static void prependLength(
            const pb_byte_t* input_buffer,
            size_t input_buffer_length,
            pb_byte_t* output_buffer,
            size_t* output_buffer_length);

        int generatePublicKeyData();
        int generateKeyId();

        // Initialize peer sessions
        void initializePeers();
    };

} // namespace TeslaBLE
