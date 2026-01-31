#pragma once

#include <memory>
#include <string>
#include <array>

#include "crypto_context.h"
#include "peer.h"
#include "car_server.pb.h"
#include "universal_message.pb.h"
#include "vcsec.pb.h"
#include "keys.pb.h"

namespace TeslaBLE {
/**
 * @brief Main client class for Tesla BLE communication
 *
 * This class provides a high-level interface for communicating with Tesla vehicles
 * over BLE. It manages cryptographic contexts, sessions, and message building/parsing.
 */
class Client {
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
  Client(const Client &) = delete;
  Client &operator=(const Client &) = delete;

  // Allow move constructor and assignment
  Client(Client &&) = default;
  Client &operator=(Client &&) = default;

  // Configuration methods
  void set_vin(const std::string &vin);
  void set_connection_id(const pb_byte_t *connection_id);

  // Key management
  int create_private_key();
  int load_private_key(const uint8_t *private_key_buffer, size_t private_key_length);
  int get_private_key(pb_byte_t *output_buffer, size_t output_buffer_length, size_t *output_length);
  int get_public_key(pb_byte_t *output_buffer, size_t *output_buffer_length);

  // Message building
  int build_white_list_message(Keys_Role role, VCSEC_KeyFormFactor form_factor, pb_byte_t *output_buffer,
                               size_t *output_length);

  int build_session_info_request_message(UniversalMessage_Domain domain, pb_byte_t *output_buffer,
                                         size_t *output_length);

  int build_key_summary(pb_byte_t *output_buffer, size_t *output_length);

  int build_unsigned_message_payload(VCSEC_UnsignedMessage *message, pb_byte_t *output_buffer, size_t *output_length,
                                     bool encrypt_payload = false);

  int build_car_server_action_payload(CarServer_Action *action, pb_byte_t *output_buffer, size_t *output_length);

  int build_universal_message_with_payload(pb_byte_t *payload, size_t payload_length, UniversalMessage_Domain domain,
                                           pb_byte_t *output_buffer, size_t *output_length,
                                           bool encrypt_payload = false);

  int build_vcsec_information_request_message(VCSEC_InformationRequestType request_type, pb_byte_t *output_buffer,
                                              size_t *output_length, uint32_t key_slot = 0);

  int build_vcsec_action_message(const VCSEC_RKEAction_E action, pb_byte_t *output_buffer, size_t *output_length);

  int build_vcsec_closure_message(const VCSEC_ClosureMoveRequest *closure_request, pb_byte_t *output_buffer,
                                  size_t *output_length);

  int build_car_server_get_vehicle_data_message(pb_byte_t *output_buffer, size_t *output_length,
                                                int32_t which_vehicle_data);

  /**
   * @brief Build a vehicle action message using the new factory pattern
   * @param output_buffer Buffer to write the encoded message
   * @param output_length Pointer to size variable that will contain the output length
   * @param which_vehicle_action The type of action to build
   * @param action_data Optional data for the action (can be nullptr for simple actions)
   * @return Error code (0 on success)
   */
  int build_car_server_vehicle_action_message(pb_byte_t *output_buffer, size_t *output_length,
                                              int32_t which_vehicle_action, const void *action_data = nullptr);

  int set_cabin_overheat_protection(pb_byte_t *output_buffer, size_t *output_length, bool on, bool fan_only = false);

  int schedule_software_update(pb_byte_t *output_buffer, size_t *output_length, int32_t offset_sec);

  int cancel_software_update(pb_byte_t *output_buffer, size_t *output_length);

  // Session management (public for testing)
  Peer *get_peer(UniversalMessage_Domain domain);
  const Peer *get_peer(UniversalMessage_Domain domain) const;

  // Message parsing (public for testing)
  int parse_from_vcsec_message(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                               VCSEC_FromVCSECMessage *output);

  int parse_universal_message(pb_byte_t *input_buffer, size_t input_size, UniversalMessage_RoutableMessage *output);

  int parse_universal_message_ble(pb_byte_t *input_buffer, size_t input_buffer_length,
                                  UniversalMessage_RoutableMessage *output);

  int parse_vcsec_information_request(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                      VCSEC_InformationRequest *output);

  int parse_payload_session_info(UniversalMessage_RoutableMessage_session_info_t *input_buffer,
                                 Signatures_SessionInfo *output);

  int parse_payload_unsigned_message(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                     VCSEC_UnsignedMessage *output);
  int parse_payload_car_server_response(UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *input_buffer,
                                        Signatures_SignatureData *signature_data, pb_size_t which_sub_sig_data,
                                        UniversalMessage_MessageFault_E signed_message_fault,
                                        CarServer_Response *output);

 private:
  // Legacy implementation - to be phased out
  int build_car_server_vehicle_action_message_legacy(pb_byte_t *output_buffer, size_t *output_length,
                                                     int32_t which_vehicle_action, const void *action_data = nullptr);

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
  std::array<pb_byte_t, 17> last_request_hash_{};  // 1 byte type + 16 bytes tag
  size_t last_request_hash_length_ = 0;

  // Helper methods
  static void prepend_length(const pb_byte_t *input_buffer, size_t input_buffer_length, pb_byte_t *output_buffer,
                             size_t *output_buffer_length);

  int generate_public_key_data();
  int generate_key_id();

  // Initialize peer sessions
  void initialize_peers();
};

}  // namespace TeslaBLE
