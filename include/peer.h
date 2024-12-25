#pragma once

#include <array>
#include <cstdint>
#include <pb.h>
#include <mutex>
#include <memory>
#include <map>
#include <set>
#include <string>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha1.h"
#include "signatures.pb.h"
#include "universal_message.pb.h"
#include "defs.h"

namespace TeslaBLE
{
  class Peer
  {
    static const int SHARED_KEY_SIZE_BYTES = 16;

  public:
    Peer(UniversalMessage_Domain domain,
         std::shared_ptr<mbedtls_pk_context> private_key_context,
         std::shared_ptr<mbedtls_ecdh_context> ecdh_context,
         std::shared_ptr<mbedtls_ctr_drbg_context> drbg_context,
         const std::string& vin = "")
        : domain(domain),
          vin_(vin),
          private_key_context_(private_key_context),
          ecdh_context_(ecdh_context),
          drbg_context_(drbg_context)
    {
    }

    // Existing methods
    bool isInitialized() const;
    bool hasValidEpoch() const;
    bool isValid() const { return this->is_valid_; };
    bool isPrivateKeyInitialized() const;

    uint32_t generateExpiresAt(int seconds) const;
    void generateNonce(pb_byte_t *nonce) const;

    uint32_t getTimeZero() const { return this->time_zero_; };
    uint32_t getCounter() const { return this->counter_; };
    const pb_byte_t *getEpoch() const;

    void incrementCounter();
    void setCounter(uint32_t counter);
    int setEpoch(const pb_byte_t *epoch);
    void setIsValid(bool is_valid);
    void setTimeZero(uint32_t time_zero);
    void setVIN(const std::string& vin) { vin_ = vin; }
    void setPrivateKeyContext(std::shared_ptr<mbedtls_pk_context> private_key_context)
    {
      this->private_key_context_ = private_key_context;
    }

    // Existing complex operations
    int loadTeslaKey(
        const uint8_t *public_key_buffer,
        size_t public_key_size);
    int updateSession(Signatures_SessionInfo *session_info);
    
    // Updated AD buffer construction with new parameters
    int ConstructADBuffer(
        Signatures_SignatureType signature_type,
        const char *VIN,
        uint32_t expires_at,
        pb_byte_t *output_buffer,
        size_t *output_length,
        const pb_byte_t* request_hash = nullptr,
        size_t request_hash_length = 0,
        uint32_t flags = 0,
        uint32_t fault = 0) const;

    // Existing encryption method
    int Encrypt(
        pb_byte_t *input_buffer, size_t input_buffer_length,
        pb_byte_t *output_buffer, size_t output_buffer_length,
        size_t *output_length, pb_byte_t *signature_buffer,
        pb_byte_t *ad_buffer, size_t ad_buffer_length,
        pb_byte_t nonce[12]) const;

    // New methods for response handling
    int ConstructRequestHash(
        Signatures_SignatureType auth_type,
        const pb_byte_t* auth_tag,
        size_t auth_tag_length,
        pb_byte_t* request_hash,
        size_t* request_hash_length) const;

    int DecryptResponse(
        const pb_byte_t* input_buffer,
        size_t input_length,
        const pb_byte_t* nonce,
        pb_byte_t* tag,
        const pb_byte_t* request_hash,
        size_t request_hash_length,
        uint32_t flags,
        uint32_t fault,
        pb_byte_t* output_buffer,
        size_t output_buffer_length,
        size_t* output_length) const;

    bool ValidateResponseCounter(uint32_t counter, uint32_t request_id);

  protected:
    std::mutex update_mutex_;
    std::mutex counter_mutex_;  // New mutex for counter validation
    UniversalMessage_Domain domain;

    pb_byte_t epoch_[16];
    uint32_t counter_ = 0;
    uint32_t time_zero_ = 0;
    bool is_valid_ = false;

    std::string vin_;  // Store VIN for use in response decryption
    std::map<uint32_t, std::set<uint32_t>> response_counters_;  // request_id -> set of used counters

    pb_byte_t shared_secret_sha1_[SHARED_KEY_SIZE_BYTES];
    std::shared_ptr<mbedtls_pk_context> private_key_context_;
    std::shared_ptr<mbedtls_ecdh_context> ecdh_context_;
    std::shared_ptr<mbedtls_ctr_drbg_context> drbg_context_;
  };

} // namespace TeslaBLE