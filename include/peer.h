#pragma once

#include <array>
#include <cstdint>
#include <mutex>
#include <memory>
#include <string>

#include <pb.h>

#include "errors.h"
#include "signatures.pb.h"
#include "universal_message.pb.h"
#include "crypto_context.h"
#include "sliding_window.h"

namespace TeslaBLE {

/**
 * @brief Manages a cryptographic session with a Tesla vehicle
 *
 * This class encapsulates the session state and cryptographic operations
 * for communicating with a specific domain (VCSEC or Infotainment) of a Tesla vehicle.
 */
class Peer {
 public:
  static constexpr int SHARED_KEY_SIZE_BYTES = 16;
  static constexpr int EPOCH_SIZE_BYTES = 16;
  static constexpr int NONCE_SIZE_BYTES = 12;
  static constexpr int TAG_SIZE_BYTES = 16;

  /**
   * @brief Constructor
   * @param domain The communication domain (VCSEC or Infotainment)
   * @param crypto_context Shared pointer to the crypto context for cryptographic operations
   * @param vin Vehicle identification number
   */
  Peer(UniversalMessage_Domain domain, std::shared_ptr<CryptoContext> crypto_context, std::string vin = "");

  // Copy and move operations (deleted because of mutexes)
  Peer(const Peer &) = delete;
  Peer &operator=(const Peer &) = delete;
  Peer(Peer &&) = delete;
  Peer &operator=(Peer &&) = delete;

  // State queries
  bool is_initialized() const;
  bool has_valid_epoch() const;
  bool is_valid() const { return is_valid_; }
  bool is_private_key_initialized() const;

  /**
   * @brief Check if this peer can send a command
   *
   * A comprehensive check that verifies:
   * - Crypto context is valid
   * - Private key is initialized
   * - Session is valid
   * - Epoch is valid
   */
  bool can_send_command() const;

  /**
   * @brief Clear shared secret and reset session for full re-authentication
   */
  void clear_shared_secret();

  // Getters
  uint32_t get_time_zero() const { return time_zero_; }
  uint32_t get_counter() const;
  const pb_byte_t *get_epoch() const { return epoch_.data(); }
  UniversalMessage_Domain get_domain() const { return domain_; }
  const pb_byte_t *get_shared_secret() const { return shared_secret_sha1_.data(); }
  size_t get_shared_secret_size() const { return SHARED_KEY_SIZE_BYTES; }
  bool has_shared_secret() const { return has_shared_secret_; }
  uint32_t get_clock_time() const { return clock_time_; }

  // Setters
  void set_counter(uint32_t counter);
  void increment_counter();
  int set_epoch(const pb_byte_t *epoch);
  void set_time_zero(uint32_t time_zero) { time_zero_ = time_zero; }
  void set_vin(const std::string &vin) { vin_ = vin; }

  // Session operations
  uint32_t generate_expires_at(int seconds) const;
  void generate_nonce(pb_byte_t *nonce) const;
  int load_tesla_key(const uint8_t *public_key_buffer, size_t public_key_size);
  int update_session(Signatures_SessionInfo *session_info);

  /**
   * @brief Force update session with new info, bypassing anti-replay protection
   *
   * This is used for session recovery after errors like ERROR_TIME_EXPIRED
   * where the vehicle sends new session info with a potentially lower counter.
   *
   * @param session_info The new session info from the vehicle
   * @return Error code (0 on success)
   */
  int force_update_session(Signatures_SessionInfo *session_info);

  /**
   * @brief Set the session validity state
   *
   * Used for testing and to invalidate sessions on errors.
   *
   * @param valid true to mark session as valid, false to invalidate
   */
  void set_is_valid(bool valid) { is_valid_ = valid; }

  // Cryptographic operations
  int construct_ad_buffer(Signatures_SignatureType signature_type, const char *vin, uint32_t expires_at,
                          pb_byte_t *output_buffer, size_t *output_length, uint32_t flags = 0,
                          const pb_byte_t *request_hash = nullptr, size_t request_hash_length = 0,
                          uint32_t fault = 0) const;

  int encrypt(pb_byte_t *input_buffer, size_t input_buffer_length, pb_byte_t *output_buffer,
              size_t output_buffer_length, size_t *output_length, pb_byte_t *signature_buffer, pb_byte_t *ad_buffer,
              size_t ad_buffer_length, pb_byte_t nonce[NONCE_SIZE_BYTES]) const;

  // Response handling
  int construct_request_hash(Signatures_SignatureType auth_type, const pb_byte_t *auth_tag, size_t auth_tag_length,
                             pb_byte_t *request_hash, size_t *request_hash_length) const;

  int decrypt_response(const pb_byte_t *input_buffer, size_t input_length, const pb_byte_t *nonce, const pb_byte_t *tag,
                       const pb_byte_t *request_hash, size_t request_hash_length, uint32_t flags, uint32_t fault,
                       pb_byte_t *output_buffer, size_t output_buffer_length, size_t *output_length) const;

  /**
   * @brief Validate a response counter using sliding window anti-replay
   * @param counter The counter value from the response
   * @return true if the counter is valid (not a replay)
   */
  bool validate_response_counter(uint32_t counter);

  /**
   * @brief Reset the response counter window (used per-request)
   */
  void reset_response_window();

  /**
   * @brief Reset the peer to initial state (for fresh authentication)
   *
   * This clears all session state, counters, and crypto material,
   * forcing a complete re-handshake on next command.
   */
  void reset();

 private:
  static void write_uint32_be(pb_byte_t *buffer, uint32_t value) {
    buffer[0] = (value >> 24) & 0xFF;
    buffer[1] = (value >> 16) & 0xFF;
    buffer[2] = (value >> 8) & 0xFF;
    buffer[3] = value & 0xFF;
  }

  // Domain and identification
  UniversalMessage_Domain domain_;
  std::string vin_;

  // Session validity
  bool is_valid_ = false;

  // Epoch and timing
  std::array<pb_byte_t, EPOCH_SIZE_BYTES> epoch_{};
  uint32_t counter_ = 0;
  uint32_t time_zero_ = 0;
  uint32_t clock_time_ = 0;  // Last received clock_time (like signer.go setTime)

  // Cryptographic context
  std::shared_ptr<CryptoContext> crypto_context_;

  // Shared secret and Tesla public key
  std::array<pb_byte_t, SHARED_KEY_SIZE_BYTES> shared_secret_sha1_{};
  std::array<pb_byte_t, 65> tesla_public_key_{};  // Store for validation (65 bytes uncompressed EC point)
  bool has_shared_secret_ = false;

  // Anti-replay protection using efficient sliding window
  SlidingWindow response_window_;

  // Thread safety
  mutable std::mutex session_mutex_;
  mutable std::mutex counter_mutex_;
};

}  // namespace TeslaBLE
