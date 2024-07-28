#pragma once

#include <array>
#include <cstdint>
#include <pb.h>
#include <mutex>

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
         std::shared_ptr<mbedtls_ctr_drbg_context> drbg_context)
        : domain(domain),
          private_key_context_(private_key_context),
          ecdh_context_(ecdh_context),
          drbg_context_(drbg_context)
    {
    }

    bool isInitialized() const;
    uint32_t generateExpiresAt(int seconds) const;
    void generateNonce(pb_byte_t *nonce) const;

    uint32_t getTimeZero() const { return this->time_zero_; };
    uint32_t getCounter() const { return this->counter_; };
    const pb_byte_t *getEpoch() const;
    void logEpoch() const;

    bool getIsAuthenticated() const { return this->is_authenticated_; };

    void incrementCounter();
    void setCounter(uint32_t counter);
    int setEpoch(const pb_byte_t *epoch);
    void setIsAuthenticated(bool is_authenticated);
    void setTimeZero(uint32_t time_zero);

    int loadTeslaKey(const uint8_t *public_key_buffer,
                     size_t public_key_size);
    int updateSession(Signatures_SessionInfo *session_info);
    int ConstructADBuffer(
        Signatures_SignatureType signature_type,
        const char *VIN,
        uint32_t expires_at,
        pb_byte_t *output_buffer,
        size_t *output_length) const;
    int Encrypt(pb_byte_t *input_buffer, size_t input_buffer_length,
                pb_byte_t *output_buffer, size_t output_buffer_length,
                size_t *output_length, pb_byte_t *signature_buffer,
                pb_byte_t *ad_buffer, size_t ad_buffer_length,
                pb_byte_t nonce[12]) const;

    void setPrivateKeyContext(std::shared_ptr<mbedtls_pk_context> private_key_context)
    {
      this->private_key_context_ = private_key_context;
    }

    bool isPrivateKeyInitialized() const
    {
      return private_key_context_ && mbedtls_pk_can_do(private_key_context_.get(), MBEDTLS_PK_ECKEY);
    }

  private:
    std::mutex update_mutex_;
    UniversalMessage_Domain domain;

    pb_byte_t epoch_[16];
    uint32_t counter_ = 0;
    uint32_t time_zero_ = 0;
    bool is_authenticated_ = false;

    pb_byte_t shared_secret_sha1_[SHARED_KEY_SIZE_BYTES];
    std::shared_ptr<mbedtls_pk_context> private_key_context_;
    std::shared_ptr<mbedtls_ecdh_context> ecdh_context_;
    std::shared_ptr<mbedtls_ctr_drbg_context> drbg_context_;
  };
  ;

} // namespace TeslaBLE
