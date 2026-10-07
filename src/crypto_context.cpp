#ifdef ESP_PLATFORM
#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#endif

#include "crypto_context.h"

#include "defs.h"
#include "errors.h"

extern "C" {
#include <mbedtls/constant_time.h>
}
#include <mbedtls/pk.h>
#include <mbedtls/platform_util.h>
#include <psa/crypto.h>

#include <array>
#include <cstring>
#include <vector>

// Mbed TLS 4.x moved the crypto core into TF-PSA-Crypto, whose headers define
// TF_PSA_CRYPTO_VERSION_MAJOR. The only API difference this file has to care
// about is mbedtls_pk_parse_key(), which lost its RNG arguments in 4.x.
#ifdef TF_PSA_CRYPTO_VERSION_MAJOR
#define TESLABLE_PK_PARSE_KEY_HAS_RNG 0
#else
#define TESLABLE_PK_PARSE_KEY_HAS_RNG 1
#endif

namespace TeslaBLE {
namespace {

constexpr psa_key_type_t P256_KEY_PAIR = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
constexpr size_t P256_BITS = 256;
constexpr size_t AES_KEY_BYTES = 16;
constexpr size_t GCM_NONCE_BYTES = 12;
constexpr size_t GCM_TAG_BYTES = 16;
constexpr psa_algorithm_t GCM_ALG = PSA_ALG_GCM;  // 16-byte tag

#if TESLABLE_PK_PARSE_KEY_HAS_RNG
int psa_rng(void * /*unused*/, unsigned char *output, size_t length) {
  return psa_generate_random(output, length) == PSA_SUCCESS ? 0 : -1;
}
#endif

// Imports a 16-byte AES key for one GCM operation. Caller destroys it.
psa_status_t import_gcm_key(const uint8_t *key, psa_key_usage_t usage, psa_key_id_t *key_id) {
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attributes, AES_KEY_BYTES * 8);
  psa_set_key_usage_flags(&attributes, usage);
  psa_set_key_algorithm(&attributes, GCM_ALG);
  psa_status_t status = psa_import_key(&attributes, key, AES_KEY_BYTES, key_id);
  psa_reset_key_attributes(&attributes);
  return status;
}

}  // namespace

CryptoContext::CryptoContext() = default;

CryptoContext::~CryptoContext() { cleanup_(); }

CryptoContext::CryptoContext(CryptoContext &&other) noexcept
    : private_key_id_(other.private_key_id_), initialized_(other.initialized_) {
  other.private_key_id_ = PSA_KEY_ID_NULL;
  other.initialized_ = false;
}

CryptoContext &CryptoContext::operator=(CryptoContext &&other) noexcept {
  if (this != &other) {
    cleanup_();

    private_key_id_ = other.private_key_id_;
    initialized_ = other.initialized_;

    other.private_key_id_ = PSA_KEY_ID_NULL;
    other.initialized_ = false;
  }
  return *this;
}

void CryptoContext::cleanup_() { reset_private_key_(); }

void CryptoContext::reset_private_key_() {
  if (private_key_id_ != PSA_KEY_ID_NULL) {
    psa_destroy_key(private_key_id_);
    private_key_id_ = PSA_KEY_ID_NULL;
  }
}

TeslaBLE_Status_E CryptoContext::ensure_initialized_() {
  if (initialized_) {
    return TeslaBLE_Status_E_OK;
  }
  return initialize();
}

TeslaBLE_Status_E CryptoContext::initialize() {
  if (initialized_) {
    return TeslaBLE_Status_E_OK;
  }

  if (!CryptoUtils::ensure_psa_initialized()) {
    return TeslaBLE_Status_E_ERROR_INTERNAL;
  }

  initialized_ = true;
  return TeslaBLE_Status_E_OK;
}

TeslaBLE_Status_E CryptoContext::create_private_key() {
  TeslaBLE_Status_E status = ensure_initialized_();
  if (status != TeslaBLE_Status_E_OK) {
    return status;
  }

  reset_private_key_();

  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attributes, P256_KEY_PAIR);
  psa_set_key_bits(&attributes, P256_BITS);
  // EXPORT: the key is saved as PEM (get_private_key) so it survives reboots.
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
  psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);

  psa_status_t result = psa_generate_key(&attributes, &private_key_id_);
  psa_reset_key_attributes(&attributes);
  if (result != PSA_SUCCESS) {
    private_key_id_ = PSA_KEY_ID_NULL;
    LOG_ERROR("Failed to generate private key: %d", static_cast<int>(result));
    return TeslaBLE_Status_E_ERROR_INTERNAL;
  }

  return TeslaBLE_Status_E_OK;
}

TeslaBLE_Status_E CryptoContext::load_private_key(const uint8_t *private_key_buffer, size_t key_size) {
  if (!private_key_buffer || key_size == 0) {
    LOG_ERROR("Invalid private key buffer");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  TeslaBLE_Status_E status = ensure_initialized_();
  if (status != TeslaBLE_Status_E_OK) {
    return status;
  }

  reset_private_key_();

  // Parse the stored PEM with mbedtls_pk, then hand the key to PSA.
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

#if TESLABLE_PK_PARSE_KEY_HAS_RNG
  int result = mbedtls_pk_parse_key(&pk, private_key_buffer, key_size, nullptr, 0, psa_rng, nullptr);
#else
  int result = mbedtls_pk_parse_key(&pk, private_key_buffer, key_size, nullptr, 0);
#endif

  if (result != 0) {
    mbedtls_pk_free(&pk);
    LOG_ERROR("Failed to parse private key: -0x%04x", (unsigned int) -result);
    return TeslaBLE_Status_E_ERROR_INTERNAL;
  }

  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  result = mbedtls_pk_get_psa_attributes(&pk, PSA_KEY_USAGE_DERIVE, &attributes);
  if (result != 0) {
    mbedtls_pk_free(&pk);
    LOG_ERROR("Failed to read private key attributes: -0x%04x", (unsigned int) -result);
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  // Tesla protocol validation - an EC key pair on SECP256R1 (P-256)
  if (psa_get_key_type(&attributes) != P256_KEY_PAIR || psa_get_key_bits(&attributes) != P256_BITS) {
    psa_reset_key_attributes(&attributes);
    mbedtls_pk_free(&pk);
    LOG_ERROR("Private key is not an EC SECP256R1 (P-256) key - Tesla protocol requires this curve");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
  psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
  result = mbedtls_pk_import_into_psa(&pk, &attributes, &private_key_id_);
  psa_reset_key_attributes(&attributes);
  mbedtls_pk_free(&pk);

  if (result != 0) {
    private_key_id_ = PSA_KEY_ID_NULL;
    LOG_ERROR("Failed to import private key: -0x%04x", (unsigned int) -result);
    return TeslaBLE_Status_E_ERROR_INTERNAL;
  }

  return TeslaBLE_Status_E_OK;
}

TeslaBLE_Status_E CryptoContext::get_private_key(pb_byte_t *output_buffer, size_t buffer_length,
                                                 size_t *output_length) {
  if (!output_buffer || !output_length) {
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  if (!is_private_key_initialized()) {
    LOG_ERROR("Private key not initialized");
    return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
  }

  // Same SEC1 "EC PRIVATE KEY" PEM as before the PSA port, so stored keys
  // stay readable by older and newer builds alike.
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  int write_result = mbedtls_pk_copy_from_psa(private_key_id_, &pk);
  if (write_result == 0) {
    write_result = mbedtls_pk_write_key_pem(&pk, output_buffer, buffer_length);
  }
  mbedtls_pk_free(&pk);

  if (write_result != 0) {
    LOG_ERROR("Failed to write private key: -0x%04x", (unsigned int) -write_result);
    return TeslaBLE_Status_E_ERROR_INTERNAL;
  }

  *output_length = std::strlen(reinterpret_cast<char *>(output_buffer)) + 1;
  return TeslaBLE_Status_E_OK;
}

TeslaBLE_Status_E CryptoContext::generate_public_key(pb_byte_t *output_buffer, size_t *output_length) {
  if (!output_buffer || !output_length) {
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  if (!is_private_key_initialized()) {
    LOG_ERROR("Private key not initialized");
    return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
  }

  // PSA exports EC public keys as the uncompressed point (0x04 || X || Y).
  size_t max_output_length = *output_length;
  psa_status_t result = psa_export_public_key(private_key_id_, output_buffer, max_output_length, output_length);

  if (result != PSA_SUCCESS) {
    LOG_ERROR("Failed to generate public key: %d", static_cast<int>(result));
    return TeslaBLE_Status_E_ERROR_INTERNAL;
  }

  return TeslaBLE_Status_E_OK;
}

TeslaBLE_Status_E CryptoContext::generate_key_id(const pb_byte_t *public_key, size_t key_size, pb_byte_t *key_id) {
  if (!public_key || !key_id || key_size == 0) {
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  std::array<pb_byte_t, 20> hash_buffer{};
  TeslaBLE_Status_E result = CryptoUtils::sha1_hash(public_key, key_size, hash_buffer.data());
  if (result != TeslaBLE_Status_E_OK) {
    return result;
  }

  // Copy first 4 bytes as key ID
  std::memcpy(key_id, hash_buffer.data(), 4);
  return TeslaBLE_Status_E_OK;
}

TeslaBLE_Status_E CryptoContext::perform_tesla_ecdh(const uint8_t *tesla_public_key, size_t tesla_key_size,
                                                    uint8_t *session_key) {
  if (!tesla_public_key || !session_key || tesla_key_size != 65) {
    LOG_ERROR("Invalid parameters for Tesla ECDH");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  if (tesla_public_key[0] != 0x04) {
    LOG_ERROR("Invalid Tesla public key format: expected uncompressed point (0x04)");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  TeslaBLE_Status_E status = ensure_initialized_();
  if (status != TeslaBLE_Status_E_OK) {
    return status;
  }

  if (!is_private_key_initialized()) {
    LOG_ERROR("Private key not initialized for ECDH");
    return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
  }

  LOG_DEBUG("Starting Tesla ECDH key exchange");

  // Raw ECDH output is the X coordinate of the shared point (32 bytes for P-256)
  uint8_t shared_secret[32];
  size_t shared_secret_length = 0;
  psa_status_t result = psa_raw_key_agreement(PSA_ALG_ECDH, private_key_id_, tesla_public_key, tesla_key_size,
                                              shared_secret, sizeof(shared_secret), &shared_secret_length);
  if (result != PSA_SUCCESS || shared_secret_length != sizeof(shared_secret)) {
    mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
    LOG_ERROR("Failed to compute shared secret: %d", static_cast<int>(result));
    return TeslaBLE_Status_E_ERROR_CRYPTO;
  }

  LOG_DEBUG("Computed shared secret (%zu bytes)", sizeof(shared_secret));

  // Derive session key: K = SHA1(shared_secret)[:16] (Tesla protocol)
  uint8_t sha1_hash[20];
  status = CryptoUtils::sha1_hash(shared_secret, sizeof(shared_secret), sha1_hash);
  mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
  if (status != TeslaBLE_Status_E_OK) {
    mbedtls_platform_zeroize(sha1_hash, sizeof(sha1_hash));
    LOG_ERROR("Failed to hash shared secret");
    return TeslaBLE_Status_E_ERROR_CRYPTO;
  }

  // Copy first 16 bytes as session key
  std::memcpy(session_key, sha1_hash, 16);
  mbedtls_platform_zeroize(sha1_hash, sizeof(sha1_hash));

  LOG_DEBUG("Tesla ECDH completed successfully");
  LOG_VERBOSE("Session key: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
              session_key[0], session_key[1], session_key[2], session_key[3], session_key[4], session_key[5],
              session_key[6], session_key[7], session_key[8], session_key[9], session_key[10], session_key[11],
              session_key[12], session_key[13], session_key[14], session_key[15]);

  return TeslaBLE_Status_E_OK;
}

TeslaBLE_Status_E CryptoContext::generate_random_bytes(uint8_t *output, size_t length) {
  if (!output || length == 0) {
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  TeslaBLE_Status_E status = ensure_initialized_();
  if (status != TeslaBLE_Status_E_OK) {
    return status;
  }

  status = CryptoUtils::generate_random_bytes(output, length);
  return status == TeslaBLE_Status_E_OK ? status : TeslaBLE_Status_E_ERROR_CRYPTO;
}

bool CryptoContext::is_private_key_initialized() const { return private_key_id_ != PSA_KEY_ID_NULL; }

// CryptoUtils implementation
bool CryptoUtils::ensure_psa_initialized() {
  // psa_crypto_init() is cheap after the first successful call.
  psa_status_t status = psa_crypto_init();
  if (status != PSA_SUCCESS) {
    LOG_ERROR("Failed to initialize PSA Crypto: %d", static_cast<int>(status));
    return false;
  }
  return true;
}

TeslaBLE_Status_E CryptoUtils::generate_random_bytes(pb_byte_t *output, size_t length) {
  if (!output || length == 0) {
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  if (!ensure_psa_initialized()) {
    return TeslaBLE_Status_E_ERROR_INTERNAL;
  }

  psa_status_t result = psa_generate_random(output, length);
  if (result != PSA_SUCCESS) {
    LOG_ERROR("Failed to generate random bytes: %d", static_cast<int>(result));
    return TeslaBLE_Status_E_ERROR_INTERNAL;
  }

  return TeslaBLE_Status_E_OK;
}

TeslaBLE_Status_E CryptoUtils::sha1_hash(const pb_byte_t *input, size_t input_length, pb_byte_t *output) {
  if (!input || !output || input_length == 0) {
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  if (!ensure_psa_initialized()) {
    return TeslaBLE_Status_E_ERROR_INTERNAL;
  }

  size_t hash_length = 0;
  psa_status_t result = psa_hash_compute(PSA_ALG_SHA_1, input, input_length, output, 20, &hash_length);
  if (result != PSA_SUCCESS) {
    LOG_ERROR("SHA1 hash failed: %d", static_cast<int>(result));
    return TeslaBLE_Status_E_ERROR_INTERNAL;
  }

  return TeslaBLE_Status_E_OK;
}

TeslaBLE_Status_E CryptoUtils::sha256_hash(const pb_byte_t *input, size_t input_length, pb_byte_t *output) {
  if (!output || (!input && input_length != 0)) {
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  if (!ensure_psa_initialized()) {
    return TeslaBLE_Status_E_ERROR_INTERNAL;
  }

  size_t hash_length = 0;
  psa_status_t result = psa_hash_compute(PSA_ALG_SHA_256, input, input_length, output, 32, &hash_length);
  if (result != PSA_SUCCESS) {
    LOG_ERROR("SHA256 hash failed: %d", static_cast<int>(result));
    return TeslaBLE_Status_E_ERROR_INTERNAL;
  }

  return TeslaBLE_Status_E_OK;
}

TeslaBLE_Status_E CryptoUtils::aes_gcm_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *additional_data,
                                               size_t additional_data_length, const uint8_t *input, size_t input_length,
                                               uint8_t *output, size_t output_size, uint8_t *tag) {
  if (!key || !nonce || !output || !tag || (!input && input_length != 0) || output_size < input_length) {
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  if (!ensure_psa_initialized()) {
    return TeslaBLE_Status_E_ERROR_INTERNAL;
  }

  psa_key_id_t key_id = PSA_KEY_ID_NULL;
  psa_status_t result = import_gcm_key(key, PSA_KEY_USAGE_ENCRYPT, &key_id);
  if (result != PSA_SUCCESS) {
    LOG_ERROR("GCM key import failed: %d", static_cast<int>(result));
    return TeslaBLE_Status_E_ERROR_ENCRYPT;
  }

  // PSA's one-shot AEAD writes ciphertext || tag into a single buffer.
  std::vector<uint8_t> sealed(input_length + GCM_TAG_BYTES);
  size_t sealed_length = 0;
  result = psa_aead_encrypt(key_id, GCM_ALG, nonce, GCM_NONCE_BYTES, additional_data, additional_data_length, input,
                            input_length, sealed.data(), sealed.size(), &sealed_length);
  psa_destroy_key(key_id);

  if (result != PSA_SUCCESS || sealed_length != sealed.size()) {
    mbedtls_platform_zeroize(sealed.data(), sealed.size());
    LOG_ERROR("GCM encrypt failed: %d", static_cast<int>(result));
    return TeslaBLE_Status_E_ERROR_ENCRYPT;
  }

  if (input_length > 0) {
    std::memcpy(output, sealed.data(), input_length);
  }
  std::memcpy(tag, sealed.data() + input_length, GCM_TAG_BYTES);
  return TeslaBLE_Status_E_OK;
}

TeslaBLE_Status_E CryptoUtils::aes_gcm_decrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *additional_data,
                                               size_t additional_data_length, const uint8_t *input, size_t input_length,
                                               const uint8_t *tag, uint8_t *output, size_t output_size) {
  if (!key || !nonce || !tag || !output || (!input && input_length != 0) || output_size < input_length) {
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  if (!ensure_psa_initialized()) {
    return TeslaBLE_Status_E_ERROR_INTERNAL;
  }

  psa_key_id_t key_id = PSA_KEY_ID_NULL;
  psa_status_t result = import_gcm_key(key, PSA_KEY_USAGE_DECRYPT, &key_id);
  if (result != PSA_SUCCESS) {
    LOG_ERROR("GCM key import failed: %d", static_cast<int>(result));
    return TeslaBLE_Status_E_ERROR_DECRYPT;
  }

  std::vector<uint8_t> sealed(input_length + GCM_TAG_BYTES);
  if (input_length > 0) {
    std::memcpy(sealed.data(), input, input_length);
  }
  std::memcpy(sealed.data() + input_length, tag, GCM_TAG_BYTES);

  size_t plain_length = 0;
  result = psa_aead_decrypt(key_id, GCM_ALG, nonce, GCM_NONCE_BYTES, additional_data, additional_data_length,
                            sealed.data(), sealed.size(), output, output_size, &plain_length);
  psa_destroy_key(key_id);

  if (result != PSA_SUCCESS || plain_length != input_length) {
    LOG_ERROR("GCM decrypt/authentication failed: %d", static_cast<int>(result));
    return TeslaBLE_Status_E_ERROR_DECRYPT;
  }

  return TeslaBLE_Status_E_OK;
}

bool CryptoUtils::secure_memory_compare(const pb_byte_t *a, const pb_byte_t *b, size_t length) {
  if (!a || !b || length == 0) {
    return false;
  }
  return mbedtls_ct_memcmp(a, b, length) == 0;
}

void CryptoUtils::clear_sensitive_memory(void *memory, size_t length) {
  if (memory) {
    mbedtls_platform_zeroize(memory, length);
  }
}

// Derive SESSION_INFO_KEY = HMAC-SHA256(K, "session info")
TeslaBLE_Status_E CryptoUtils::derive_session_info_key(const uint8_t *shared_key, size_t shared_key_len,
                                                       uint8_t *out_key, size_t out_key_len) {
  // out_key must be at least 32 bytes (SHA256 output)
  if (!shared_key || shared_key_len == 0 || !out_key || out_key_len < 32) {
    if (out_key && out_key_len > 0) {
      mbedtls_platform_zeroize(out_key, out_key_len);
    }
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }
  static const char SESSION_INFO[] = "session info";
  return hmac_sha256(shared_key, shared_key_len, reinterpret_cast<const uint8_t *>(SESSION_INFO),
                     sizeof(SESSION_INFO) - 1, out_key, out_key_len);
}

TeslaBLE_Status_E CryptoUtils::hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len,
                                           uint8_t *out, size_t out_len) {
  if (!key || key_len == 0 || !data || data_len == 0 || !out || out_len < 32) {
    if (out && out_len > 0) {
      mbedtls_platform_zeroize(out, out_len);
    }
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  if (!ensure_psa_initialized()) {
    mbedtls_platform_zeroize(out, out_len);
    return TeslaBLE_Status_E_ERROR_INTERNAL;
  }

  constexpr psa_algorithm_t hmac_alg = PSA_ALG_HMAC(PSA_ALG_SHA_256);
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
  psa_set_key_bits(&attributes, key_len * 8);
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
  psa_set_key_algorithm(&attributes, hmac_alg);

  psa_key_id_t key_id = PSA_KEY_ID_NULL;
  psa_status_t result = psa_import_key(&attributes, key, key_len, &key_id);
  psa_reset_key_attributes(&attributes);
  if (result != PSA_SUCCESS) {
    mbedtls_platform_zeroize(out, out_len);
    return TeslaBLE_Status_E_ERROR_CRYPTO;
  }

  size_t mac_length = 0;
  result = psa_mac_compute(key_id, hmac_alg, data, data_len, out, out_len, &mac_length);
  psa_destroy_key(key_id);

  if (result != PSA_SUCCESS || mac_length != 32) {
    mbedtls_platform_zeroize(out, out_len);
    return TeslaBLE_Status_E_ERROR_CRYPTO;
  }

  return TeslaBLE_Status_E_OK;
}

}  // namespace TeslaBLE
