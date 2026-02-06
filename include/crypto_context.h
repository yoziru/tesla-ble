#pragma once

#include <memory>
#include "errors.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "pb.h"

namespace TeslaBLE {
/**
 * @brief RAII wrapper for mbedTLS contexts
 *
 * This class provides automatic cleanup of mbedTLS contexts and
 * centralizes cryptographic operations.
 */
class CryptoContext {
 public:
  CryptoContext();
  ~CryptoContext();

  // Delete copy constructor and assignment operator
  CryptoContext(const CryptoContext &) = delete;
  CryptoContext &operator=(const CryptoContext &) = delete;

  // Allow move constructor and assignment
  CryptoContext(CryptoContext &&) noexcept;
  CryptoContext &operator=(CryptoContext &&) noexcept;

  /**
   * @brief Initialize the crypto context with entropy
   * @return Error code (0 on success)
   */
  TeslaBLE_Status_E initialize();

  /**
   * @brief Create a new private key
   * @return Error code (0 on success)
   */
  TeslaBLE_Status_E create_private_key();

  /**
   * @brief Load a private key from buffer
   * @param private_key_buffer Buffer containing the private key
   * @param key_size Size of the key buffer
   * @return Error code (0 on success)
   */
  TeslaBLE_Status_E load_private_key(const uint8_t *private_key_buffer, size_t key_size);

  /**
   * @brief Get the private key in PEM format
   * @param output_buffer Buffer to write the key
   * @param buffer_length Size of the output buffer
   * @param output_length Actual length written
   * @return Error code (0 on success)
   */
  TeslaBLE_Status_E get_private_key(pb_byte_t *output_buffer, size_t buffer_length, size_t *output_length);

  /**
   * @brief Generate public key from private key
   * @param output_buffer Buffer to write the public key
   * @param output_length Size of the output buffer
   * @return Error code (0 on success)
   */
  TeslaBLE_Status_E generate_public_key(pb_byte_t *output_buffer, size_t *output_length);

  /**
   * @brief Generate a 4-byte key ID from public key
   * @param public_key The public key bytes
   * @param key_size Size of the public key
   * @param key_id Output buffer for the 4-byte key ID
   * @return Error code (0 on success)
   */
  TeslaBLE_Status_E generate_key_id(const pb_byte_t *public_key, size_t key_size, pb_byte_t *key_id);

  /**
   * @brief Perform Tesla ECDH key exchange and derive session key
   * @param tesla_public_key Tesla's 65-byte uncompressed public key
   * @param tesla_key_size Size of Tesla's public key (must be 65)
   * @param session_key Output buffer for 16-byte session key
   * @return TeslaBLE_Status_E_OK on success, error code otherwise
   */
  TeslaBLE_Status_E perform_tesla_ecdh(const uint8_t *tesla_public_key, size_t tesla_key_size, uint8_t *session_key);

  /**
   * @brief Generate random bytes using this context's DRBG
   * @param output Output buffer for random bytes
   * @param length Number of bytes to generate
   * @return TeslaBLE_Status_E_OK on success, error code otherwise
   */
  TeslaBLE_Status_E generate_random_bytes(uint8_t *output, size_t length);

  /**
   * @brief Check if the private key is initialized
   * @return true if initialized, false otherwise
   */
  bool is_private_key_initialized() const;

  // Getters for contexts (needed by Peer class)
  std::shared_ptr<mbedtls_pk_context> get_private_key_context() const { return private_key_context_; }
  std::shared_ptr<mbedtls_ecdh_context> get_ecdh_context() const { return ecdh_context_; }
  std::shared_ptr<mbedtls_ctr_drbg_context> get_drbg_context() const { return drbg_context_; }

 private:
  std::shared_ptr<mbedtls_pk_context> private_key_context_;
  std::shared_ptr<mbedtls_ecdh_context> ecdh_context_;
  std::shared_ptr<mbedtls_ctr_drbg_context> drbg_context_;
  std::unique_ptr<mbedtls_entropy_context> entropy_context_;

  bool initialized_ = false;

  TeslaBLE_Status_E ensure_initialized_();
  void reset_private_key_();
  void cleanup_();
};

/**
 * @brief Utility class for common cryptographic operations
 */
class CryptoUtils {
 public:
  /**
   * @brief Generate random bytes
   * @param output Buffer to write random bytes
   * @param length Number of bytes to generate
   * @param drbg_context Random number generator context
   * @return Error code (0 on success)
   */
  static TeslaBLE_Status_E generate_random_bytes(pb_byte_t *output, size_t length,
                                                 mbedtls_ctr_drbg_context *drbg_context);

  /**
   * @brief Calculate SHA1 hash
   * @param input Input data
   * @param input_length Length of input data
   * @param output Output buffer (must be at least 20 bytes)
   * @return Error code (0 on success)
   */
  static TeslaBLE_Status_E sha1_hash(const pb_byte_t *input, size_t input_length, pb_byte_t *output);

  /**
   * @brief Secure memory comparison
   * @param a First buffer
   * @param b Second buffer
   * @param length Length to compare
   * @return true if equal, false otherwise
   */
  static bool secure_memory_compare(const pb_byte_t *a, const pb_byte_t *b, size_t length);

  /**
   * @brief Clear sensitive memory
   * @param memory Memory to clear
   * @param length Length to clear
   */
  static void clear_sensitive_memory(void *memory, size_t length);

  /**
   * @brief Derive SESSION_INFO_KEY = HMAC-SHA256(K, "session info")
   * @param shared_key The shared session key (K)
   * @param shared_key_len Length of the shared key (should be 16)
   * @param out_key Output buffer for the derived key (must be at least 32 bytes)
   * @param out_key_len Length of the output buffer
   * @return TeslaBLE_Status_E_OK on success, error code otherwise
   */
  static TeslaBLE_Status_E derive_session_info_key(const uint8_t *shared_key, size_t shared_key_len, uint8_t *out_key,
                                                   size_t out_key_len);

  /**
   * @brief Compute HMAC-SHA256
   * @param key HMAC key
   * @param key_len Length of key
   * @param data Input data
   * @param data_len Length of data
   * @param out Output buffer (must be at least 32 bytes)
   * @param out_len Length of output buffer
   * @return TeslaBLE_Status_E_OK on success, error code otherwise
   */
  static TeslaBLE_Status_E hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                                       uint8_t *out, size_t out_len);
};

}  // namespace TeslaBLE
