// https://github.com/platformio/platform-espressif32/issues/957
// specifically set when compiling with ESP-IDF
#ifdef ESP_PLATFORM
#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#endif

#ifndef TESLA_LOG_TAG
#define TESLA_LOG_TAG "TeslaBLE::Peer"
#endif

#include "peer.h"

#include "crypto_context.h"
#include "defs.h"
#include "errors.h"
#include "tb_logging.h"
#include "tb_utils.h"

#include "signatures.pb.h"

#include <pb.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha1.h>

#include <chrono>
#include <cinttypes>
#include <cstring>

namespace TeslaBLE {
Peer::Peer(UniversalMessage_Domain domain, std::shared_ptr<CryptoContext> crypto_context, std::string vin)
    : domain_(domain), vin_(std::move(vin)), crypto_context_(std::move(crypto_context)) {}

bool Peer::is_initialized() const {
  if (crypto_context_ == nullptr) {
    LOG_ERROR("Crypto context is null");
    return false;
  }

  if (!is_private_key_initialized()) {
    LOG_ERROR("Private key is not initialized");
    return false;
  }

  if (!is_valid()) {
    LOG_ERROR("Session is not valid");
    return false;
  }

  if (!has_valid_epoch()) {
    LOG_ERROR("Peer has invalid epoch");
    return false;
  }

  return true;
}

bool Peer::can_send_command() const {
  return crypto_context_ != nullptr && is_private_key_initialized() && is_valid() && has_valid_epoch();
}

void Peer::clear_shared_secret() {
  LOG_INFO("Resetting peer session state for domain %s", domain_to_string(domain_));

  // Ensure atomic reset of all session parameters
  std::scoped_lock lock(session_mutex_, counter_mutex_);

  is_valid_ = false;
  has_shared_secret_ = false;

  shared_secret_sha1_.fill(0);
  tesla_public_key_.fill(0);
  epoch_.fill(0);

  counter_ = 0;
  clock_time_ = 0;
  time_zero_ = 0;

  response_window_.reset();

  LOG_INFO("Session reset complete for %s - ready for fresh authentication", domain_to_string(domain_));
}

bool Peer::is_private_key_initialized() const {
  return crypto_context_ && crypto_context_->is_private_key_initialized();
}

bool Peer::has_valid_epoch() const {
  // make sure epoch is not all zeros
  for (auto i : epoch_) {
    if (i != 0) {
      return true;
    }
  }
  LOG_ERROR("Epoch is empty");
  return false;
}

void Peer::set_counter(uint32_t counter) { counter_ = counter; }

void Peer::increment_counter() { counter_++; }

int Peer::set_epoch(const pb_byte_t *epoch) {
  if (epoch == nullptr) {
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }
  std::copy(epoch, epoch + epoch_.size(), epoch_.begin());
  return TeslaBLE_Status_E_OK;
}

uint32_t Peer::get_counter() const { return counter_; }

uint32_t Peer::generate_expires_at(int seconds) const {
  uint32_t expires_at =
      std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + std::chrono::seconds(seconds)) -
      time_zero_;
  return expires_at;
}

void Peer::generate_nonce(pb_byte_t *nonce) const {
  if (nonce == nullptr || crypto_context_ == nullptr) {
    LOG_ERROR("Invalid nonce buffer or crypto context");
    return;
  }

  int result = crypto_context_->generate_random_bytes(nonce, NONCE_SIZE_BYTES);
  if (result != TeslaBLE_Status_E_OK) {
    LOG_ERROR("Failed to generate nonce: %d", result);
  }
}

int Peer::load_tesla_key(const uint8_t *public_key_buffer, size_t public_key_size) {
  if (public_key_buffer == nullptr || public_key_size == 0) {
    LOG_ERROR("Invalid public key buffer");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  if (crypto_context_ == nullptr) {
    LOG_ERROR("Crypto context is null");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  LOG_DEBUG("Loading Tesla public key (%zu bytes) during recovery", public_key_size);

  // Print first few bytes for debugging
  LOG_VERBOSE("Tesla key data: %02x %02x %02x %02x %02x %02x %02x %02x...", public_key_buffer[0], public_key_buffer[1],
              public_key_buffer[2], public_key_buffer[3], public_key_buffer[4], public_key_buffer[5],
              public_key_buffer[6], public_key_buffer[7]);

  // Validate Tesla public key format (should be 65 bytes uncompressed EC point)
  if (public_key_size != 65 || public_key_buffer[0] != 0x04) {
    LOG_ERROR(
        "Invalid Tesla public key format: expected 65 bytes starting with 0x04, got %zu bytes starting with 0x%02x",
        public_key_size, public_key_buffer[0]);
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  // Use CryptoContext's Tesla ECDH method instead of duplicating crypto initialization
  LOG_DEBUG("Performing Tesla ECDH during key load using stored private key");
  int ret = crypto_context_->perform_tesla_ecdh(public_key_buffer, public_key_size, shared_secret_sha1_.data());
  if (ret != TeslaBLE_Status_E_OK) {
    LOG_ERROR("Failed to perform Tesla ECDH: %d", ret);
    return ret;
  }

  // Store the Tesla public key for future validation (to detect if vehicle re-keys)
  std::memcpy(tesla_public_key_.data(), public_key_buffer, public_key_size);
  has_shared_secret_ = true;

  is_valid_ = true;
  LOG_DEBUG("Tesla key loaded and session established successfully");
  LOG_VERBOSE(
      "Session key (first 16 bytes): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
      shared_secret_sha1_[0], shared_secret_sha1_[1], shared_secret_sha1_[2], shared_secret_sha1_[3],
      shared_secret_sha1_[4], shared_secret_sha1_[5], shared_secret_sha1_[6], shared_secret_sha1_[7],
      shared_secret_sha1_[8], shared_secret_sha1_[9], shared_secret_sha1_[10], shared_secret_sha1_[11],
      shared_secret_sha1_[12], shared_secret_sha1_[13], shared_secret_sha1_[14], shared_secret_sha1_[15]);

  return TeslaBLE_Status_E_OK;
}

int Peer::update_session(Signatures_SessionInfo *session_info) {
  LOG_DEBUG("Updating session..");
  if (session_info == nullptr) {
    LOG_ERROR("Session info is null");
    return TeslaBLE_Status_E_ERROR_INVALID_SESSION;
  }

  // Check if epoch or time is changing
  // Following vehicle-command's UpdateSessionInfo behavior (signer.go:104-111):
  //   if !bytes.Equal(s.epoch[:], info.Epoch) || (s.setTime <= info.ClockTime) {
  //       if s.counter < info.Counter { s.counter = info.Counter }
  //       copy(s.epoch[:], info.Epoch)
  //       s.setTime = info.ClockTime
  //       s.timeZero = epochStartTime(info.ClockTime)
  //   }
  bool epoch_changed = (std::memcmp(epoch_.data(), session_info->epoch, epoch_.size()) != 0);
  bool time_advanced = (clock_time_ <= session_info->clock_time);
  bool should_update = epoch_changed || time_advanced;

  LOG_DEBUG("Session update check: epoch_changed=%d, time_advanced=%d (local=%u, vehicle=%u)", epoch_changed,
            time_advanced, clock_time_, session_info->clock_time);

  if (!epoch_changed && session_info->counter < counter_) {
    LOG_WARNING("Session counter replay detected (vehicle=%u, local=%u)", session_info->counter, counter_);
    return TeslaBLE_Status_E_ERROR_COUNTER_REPLAY;
  }

  // Update counter based on error state or normal progression
  // Go implementation logic: if counter < info.Counter { counter = info.Counter }
  // This applies strictly: even if epoch changes, we only accept higher counters.
  // This ensures anti-replay protection is maintained even across epoch boundaries
  // unless the vehicle explicitly signals a reset that we handle otherwise.

  // Update counter based on official protocol logic:
  // ONLY update if vehicle counter is higher. This preserves anti-replay monotonicity
  // even across epoch changes, matching signer.go behavior.
  if (should_update && session_info->counter > counter_) {
    LOG_INFO("Updating counter to %u (old_counter=%u)", session_info->counter, counter_);
    set_counter(session_info->counter);
  } else if (should_update) {
    LOG_DEBUG("Keeping higher local counter %u (vehicle sent %u)", counter_, session_info->counter);
  }

  // Update epoch and time only when conditions are met
  if (should_update) {
    int status = set_epoch(session_info->epoch);
    if (status != TeslaBLE_Status_E_OK) {
      LOG_ERROR("Failed to set epoch");
      return status;
    }
    clock_time_ = session_info->clock_time;

    uint32_t generated_at = std::time(nullptr);
    uint32_t time_zero = generated_at - session_info->clock_time;
    set_time_zero(time_zero);
  } else {
    LOG_DEBUG("Session info not newer - skipping update");
  }

  // Handle Tesla public key - force derivation of shared secret to ensure freshness
  // This handles both initial session establishment and recovery from INVALID_SIGNATURE
  int status = TeslaBLE_Status_E_OK;
  if (session_info->publicKey.size > 0) {
    LOG_DEBUG("Deriving shared secret from session info public key");
    status = load_tesla_key(session_info->publicKey.bytes, session_info->publicKey.size);
    if (status != TeslaBLE_Status_E_OK) {
      LOG_ERROR("Failed to load Tesla public key from session info: %d", status);
      return status;
    }
  }

  LOG_DEBUG("Updated session: counter=%d, clock_time=%d, time_zero=%d", counter_, session_info->clock_time, time_zero_);

  // Successful update clears error state and restores session validity
  // This matches Go's UpdateSessionInfo behavior where successful updates restore session
  // Successful update restores session validity
  is_valid_ = true;
  has_shared_secret_ = true;

  return TeslaBLE_Status_E_OK;
}

int Peer::force_update_session(Signatures_SessionInfo *session_info) {
  if (session_info == nullptr) {
    LOG_ERROR("Session info is null");
    return TeslaBLE_Status_E_ERROR_INVALID_SESSION;
  }

  LOG_WARNING("Force updating session (bypassing counter checks): vehicle=%u local=%u", session_info->counter,
              counter_);

  int status = set_epoch(session_info->epoch);
  if (status != TeslaBLE_Status_E_OK) {
    LOG_ERROR("Failed to set epoch during force update");
    return status;
  }

  set_counter(session_info->counter);
  clock_time_ = session_info->clock_time;
  uint32_t generated_at = std::time(nullptr);
  uint32_t time_zero = generated_at - session_info->clock_time;
  set_time_zero(time_zero);

  if (session_info->publicKey.size > 0) {
    LOG_DEBUG("Deriving shared secret from session info public key (force update)");
    status = load_tesla_key(session_info->publicKey.bytes, session_info->publicKey.size);
    if (status != TeslaBLE_Status_E_OK) {
      LOG_ERROR("Failed to load Tesla public key from session info: %d", status);
      return status;
    }
  }

  is_valid_ = true;
  has_shared_secret_ = true;

  LOG_INFO("Force updated session: counter=%u, clock_time=%u, time_zero=%u", counter_, clock_time_, time_zero_);
  return TeslaBLE_Status_E_OK;
}

int Peer::construct_ad_buffer(Signatures_SignatureType signature_type, const char *vin, uint32_t expires_at,
                              pb_byte_t *output_buffer, size_t *output_length, uint32_t flags,
                              const pb_byte_t *request_hash, size_t request_hash_length, uint32_t fault) const {
  if (output_buffer == nullptr || output_length == nullptr || vin == nullptr) {
    LOG_ERROR("Invalid parameters for AD buffer construction");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  // Theoretical maximum AD buffer size per protocol spec:
  // Request: Type(3) + Domain(3) + VIN(19) + Epoch(18) + Expires(6) + Counter(6) + Flags(6) + Terminal(1) = 62 bytes
  // VCSEC Response: Type(3) + Domain(3) + VIN(19) + Counter(6) + Flags(6) + ReqHash(2+17=19) + Fault(6) + Terminal(1) =
  // 63 bytes INFOTAINMENT Response: Type(3) + Domain(3) + VIN(19) + Counter(6) + Flags(6) + ReqHash(2+33=35) + Fault(6)
  // + Terminal(1) = 79 bytes (Request hash: 1 auth method byte + 16-byte AES-GCM tag = 17 bytes for VCSEC, 33 bytes for
  // INFOTAINMENT)
  static constexpr size_t MAX_AD_BUFFER_SIZE = 80;

  size_t index = 0;
  auto append_tlv = [&](pb_byte_t tag, const pb_byte_t *value, size_t value_length) {
    if (value_length > 255) {
      return false;
    }
    output_buffer[index++] = tag;
    output_buffer[index++] = static_cast<pb_byte_t>(value_length);
    if (value_length > 0) {
      std::memcpy(output_buffer + index, value, value_length);
      index += value_length;
    }
    return true;
  };

  pb_byte_t signature_value = static_cast<pb_byte_t>(signature_type);
  if (!append_tlv(Signatures_Tag_TAG_SIGNATURE_TYPE, &signature_value, 1)) {
    LOG_ERROR("Failed to append signature type to AD buffer");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  pb_byte_t domain_value = static_cast<pb_byte_t>(domain_);
  if (!append_tlv(Signatures_Tag_TAG_DOMAIN, &domain_value, 1)) {
    LOG_ERROR("Failed to append domain to AD buffer");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  size_t vin_length = strlen(vin);
  vin_length = std::min<size_t>(vin_length, 17);  // vin is max 17 characters
  if (!append_tlv(Signatures_Tag_TAG_PERSONALIZATION, reinterpret_cast<const pb_byte_t *>(vin), vin_length)) {
    LOG_ERROR("Failed to append VIN to AD buffer");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  // Epoch (TLV format) - Requests ONLY
  if (signature_type != Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_RESPONSE) {
    if (!append_tlv(Signatures_Tag_TAG_EPOCH, epoch_.data(), epoch_.size())) {
      LOG_ERROR("Failed to append epoch to AD buffer");
      return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
    }

    pb_byte_t expires_bytes[4];
    write_uint32_be(expires_bytes, expires_at);
    if (!append_tlv(Signatures_Tag_TAG_EXPIRES_AT, expires_bytes, sizeof(expires_bytes))) {
      LOG_ERROR("Failed to append expires_at to AD buffer");
      return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
    }
  }

  // Counter (TLV format)
  pb_byte_t counter_bytes[4];
  write_uint32_be(counter_bytes, counter_);
  if (!append_tlv(Signatures_Tag_TAG_COUNTER, counter_bytes, sizeof(counter_bytes))) {
    LOG_ERROR("Failed to append counter to AD buffer");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  // Flags handling per protocol:
  // - For REQUESTS: Only included if flags > 0 (backwards compatibility)
  // - For RESPONSES: ALWAYS included (protocol requirement)
  if (signature_type == Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_RESPONSE || flags > 0) {
    pb_byte_t flag_bytes[4];
    write_uint32_be(flag_bytes, flags);
    if (!append_tlv(Signatures_Tag_TAG_FLAGS, flag_bytes, sizeof(flag_bytes))) {
      LOG_ERROR("Failed to append flags to AD buffer");
      return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
    }
  }

  // Response-specific fields (only for responses)
  if (signature_type == Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_RESPONSE) {
    // Request hash (TLV format)
    if (request_hash != nullptr && request_hash_length > 0) {
      // Validate request hash length fits in TLV length field (max 255)
      if (!append_tlv(Signatures_Tag_TAG_REQUEST_HASH, request_hash, request_hash_length)) {
        LOG_ERROR("Request hash length %zu exceeds TLV maximum of 255", request_hash_length);
        return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
      }
    }

    // Fault (TLV format) - always included for responses
    pb_byte_t fault_bytes[4];
    write_uint32_be(fault_bytes, fault);
    if (!append_tlv(Signatures_Tag_TAG_FAULT, fault_bytes, sizeof(fault_bytes))) {
      LOG_ERROR("Failed to append fault to AD buffer");
      return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
    }
  }

  // Terminal byte (important!)
  if (index >= MAX_AD_BUFFER_SIZE) {
    LOG_ERROR("AD buffer would exceed maximum size of %zu bytes", MAX_AD_BUFFER_SIZE);
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }
  output_buffer[index++] = Signatures_Tag_TAG_END;

  *output_length = index;
  return TeslaBLE_Status_E_OK;
}

int Peer::construct_request_hash(Signatures_SignatureType auth_type, const pb_byte_t *auth_tag, size_t auth_tag_length,
                                 pb_byte_t *request_hash, size_t *request_hash_length) const {
  if (auth_tag == nullptr || request_hash == nullptr || request_hash_length == nullptr) {
    LOG_ERROR("Invalid parameters for request hash construction");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  // Request hash = 1 byte (auth method) + auth tag
  // Protocol states: "truncated to 17 bytes" for VCSEC, full length for INFOTAINMENT

  // First byte: authentication method
  request_hash[0] = static_cast<pb_byte_t>(auth_type);

  // Copy auth tag
  size_t tag_copy_length = auth_tag_length;

  // For VCSEC domain: truncate to 16 bytes of tag (17 total with auth method byte)
  if (domain_ == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY) {
    if (auth_tag_length > 16) {
      tag_copy_length = 16;
    }
  }
  // For INFOTAINMENT domain: use full tag length (no truncation)

  std::memcpy(request_hash + 1, auth_tag, tag_copy_length);
  *request_hash_length = 1 + tag_copy_length;

  return TeslaBLE_Status_E_OK;
}

int Peer::decrypt_response(const pb_byte_t *input_buffer, size_t input_length, const pb_byte_t *nonce,
                           const pb_byte_t *tag, const pb_byte_t *request_hash, size_t request_hash_length,
                           uint32_t flags, uint32_t fault, pb_byte_t *output_buffer, size_t output_buffer_length,
                           size_t *output_length) const {
  if (!is_private_key_initialized()) {
    LOG_ERROR("[DecryptResponse] Private key not initialized");
    return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
  }

  mbedtls_gcm_context aes_context;
  mbedtls_gcm_init(&aes_context);

  // Set up AES-GCM with the shared key
  int return_code = mbedtls_gcm_setkey(&aes_context, MBEDTLS_CIPHER_ID_AES, shared_secret_sha1_.data(), 128);
  if (return_code != 0) {
    LOG_ERROR("[DecryptResponse] GCM set key error: -0x%04x", (unsigned int) -return_code);
    return TeslaBLE_Status_E_ERROR_DECRYPT;
  }

  // Construct AD buffer for response (max 79 bytes)
  pb_byte_t ad_buffer[80];
  size_t ad_length;
  return_code = construct_ad_buffer(Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_RESPONSE, vin_.c_str(),
                                    0,  // expires_at not used for responses
                                    ad_buffer, &ad_length, flags, request_hash, request_hash_length, fault);

  if (return_code != 0) {
    LOG_ERROR("[DecryptResponse] Failed to construct AD buffer");
    return return_code;
  }

  // Hash the AD buffer
  unsigned char ad_hash[32];
  return_code = mbedtls_sha256(ad_buffer, ad_length, ad_hash, 0);
  if (return_code != 0) {
    LOG_ERROR("[DecryptResponse] AD metadata SHA256 hash error: -0x%04x", (unsigned int) -return_code);
    return TeslaBLE_Status_E_ERROR_DECRYPT;
  }

  // Start decryption
  return_code = mbedtls_gcm_starts(&aes_context, MBEDTLS_GCM_DECRYPT, nonce, 12);  // nonce is always 12 bytes
  if (return_code != 0) {
    LOG_ERROR("[DecryptResponse] GCM start error: -0x%04x", (unsigned int) -return_code);
    return TeslaBLE_Status_E_ERROR_DECRYPT;
  }

  // Set AD hash as AAD
  mbedtls_gcm_update_ad(&aes_context, ad_hash, sizeof(ad_hash));

  // Decrypt the message
  return_code =
      mbedtls_gcm_update(&aes_context, input_buffer, input_length, output_buffer, output_buffer_length, output_length);
  if (return_code != 0) {
    LOG_ERROR("[DecryptResponse] Decryption error in gcm_update: -0x%04x", (unsigned int) -return_code);
    return TeslaBLE_Status_E_ERROR_DECRYPT;
  }

  // Finalize and verify the tag
  size_t finish_length = 0;
  pb_byte_t finish_buffer[16];
  pb_byte_t tag_copy[16];
  std::memcpy(tag_copy, tag, sizeof(tag_copy));
  return_code = mbedtls_gcm_finish(&aes_context, finish_buffer, sizeof(finish_buffer), &finish_length, tag_copy,
                                   sizeof(tag_copy));  // tag is always 16 bytes
  if (return_code != 0) {
    LOG_ERROR("[DecryptResponse] Authentication failed in gcm_finish: -0x%04x", (unsigned int) -return_code);
    return TeslaBLE_Status_E_ERROR_DECRYPT;
  }

  mbedtls_gcm_free(&aes_context);
  return TeslaBLE_Status_E_OK;
}

int Peer::encrypt(pb_byte_t *input_buffer, size_t input_buffer_length, pb_byte_t *output_buffer,
                  size_t output_buffer_length, size_t *output_length, pb_byte_t *signature_buffer, pb_byte_t *ad_buffer,
                  size_t ad_buffer_length, pb_byte_t nonce[NONCE_SIZE_BYTES]) const {
  if (!is_private_key_initialized()) {
    LOG_ERROR("[Encrypt] Private key is not initialized");
    return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
  }

  mbedtls_gcm_context aes_context;
  mbedtls_gcm_init(&aes_context);

  // Use 128-bit key as specified in the protocol
  int return_code = mbedtls_gcm_setkey(&aes_context, MBEDTLS_CIPHER_ID_AES, shared_secret_sha1_.data(), 128);
  if (return_code != 0) {
    LOG_ERROR("[Encrypt] GCM set key error: -0x%04x", (unsigned int) -return_code);
    mbedtls_gcm_free(&aes_context);
    return TeslaBLE_Status_E_ERROR_ENCRYPT;
  }

  // Generate a new nonce for each encryption
  generate_nonce(nonce);

  return_code = mbedtls_gcm_starts(&aes_context, MBEDTLS_GCM_ENCRYPT, nonce, 12);
  if (return_code != 0) {
    LOG_ERROR("[Encrypt] GCM start error: -0x%04x", (unsigned int) -return_code);
    mbedtls_gcm_free(&aes_context);
    return TeslaBLE_Status_E_ERROR_ENCRYPT;
  }

  // Hash the AD buffer to create the AAD as per the protocol
  unsigned char ad_hash[32];
  return_code = mbedtls_sha256(ad_buffer, ad_buffer_length, ad_hash, 0);
  if (return_code != 0) {
    LOG_ERROR("[Encrypt] AD metadata SHA256 hash error: -0x%04x", (unsigned int) -return_code);
    mbedtls_gcm_free(&aes_context);
    return TeslaBLE_Status_E_ERROR_ENCRYPT;
  }

  mbedtls_gcm_update_ad(&aes_context, ad_hash, sizeof(ad_hash));

  // Validate buffer sizes before encryption
  if (output_buffer_length < input_buffer_length) {
    LOG_ERROR("[Encrypt] Output buffer too small: %zu < %zu", output_buffer_length, input_buffer_length);
    mbedtls_gcm_free(&aes_context);
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  return_code = mbedtls_gcm_update(&aes_context, input_buffer, input_buffer_length, output_buffer, output_buffer_length,
                                   output_length);
  if (return_code != 0) {
    LOG_ERROR("[Encrypt] Encryption error in gcm_update: -0x%04x", (unsigned int) -return_code);
    mbedtls_gcm_free(&aes_context);
    return TeslaBLE_Status_E_ERROR_ENCRYPT;
  }

  size_t finish_buffer_length = 0;
  pb_byte_t finish_buffer[16];
  return_code = mbedtls_gcm_finish(&aes_context, finish_buffer, sizeof(finish_buffer), &finish_buffer_length,
                                   signature_buffer, 16);
  if (return_code != 0) {
    LOG_ERROR("[Encrypt] Finalization error in gcm_finish: -0x%04x", (unsigned int) -return_code);
    mbedtls_gcm_free(&aes_context);
    return TeslaBLE_Status_E_ERROR_ENCRYPT;
  }

  mbedtls_gcm_free(&aes_context);

  LOG_VERBOSE("[Encrypt] Nonce: %s, Ciphertext: %s, Tag: %s", format_hex(nonce, 12).c_str(),
              format_hex(output_buffer, *output_length).c_str(), format_hex(signature_buffer, 16).c_str());

  return TeslaBLE_Status_E_OK;
}

bool Peer::validate_response_counter(uint32_t counter) {
  std::scoped_lock lock(counter_mutex_);

  // Use efficient sliding window for anti-replay
  if (!response_window_.add(counter)) {
    LOG_ERROR("Counter %" PRIu32 " is a replay (highest: %" PRIu32 ")", counter,
              response_window_.get_highest_counter());
    return false;
  }

  return true;
}

void Peer::reset_response_window() {
  std::scoped_lock lock(counter_mutex_);
  response_window_.reset();
  LOG_DEBUG("Response counter window reset");
}

void Peer::reset() { clear_shared_secret(); }

}  // namespace TeslaBLE
