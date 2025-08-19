#ifdef ESP_PLATFORM
#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#endif

#include "crypto_context.h"
#include "defs.h"
#include <cstring>
#include <mbedtls/entropy.h>
#include <mbedtls/sha1.h>
#include <mbedtls/platform_util.h>

namespace TeslaBLE
{
    CryptoContext::CryptoContext()
        : private_key_context_(std::make_shared<mbedtls_pk_context>()),
          ecdh_context_(std::make_shared<mbedtls_ecdh_context>()),
          drbg_context_(std::make_shared<mbedtls_ctr_drbg_context>()),
          entropy_context_(std::make_unique<mbedtls_entropy_context>())
    {
        mbedtls_pk_init(private_key_context_.get());
        mbedtls_ecdh_init(ecdh_context_.get());
        mbedtls_ctr_drbg_init(drbg_context_.get());
        mbedtls_entropy_init(entropy_context_.get());
    }

    CryptoContext::~CryptoContext()
    {
        cleanup();
    }

    CryptoContext::CryptoContext(CryptoContext&& other) noexcept
        : private_key_context_(std::move(other.private_key_context_)),
          ecdh_context_(std::move(other.ecdh_context_)),
          drbg_context_(std::move(other.drbg_context_)),
          entropy_context_(std::move(other.entropy_context_)),
          initialized_(other.initialized_)
    {
        other.initialized_ = false;
    }

    CryptoContext& CryptoContext::operator=(CryptoContext&& other) noexcept
    {
        if (this != &other) {
            cleanup();
            
            private_key_context_ = std::move(other.private_key_context_);
            ecdh_context_ = std::move(other.ecdh_context_);
            drbg_context_ = std::move(other.drbg_context_);
            entropy_context_ = std::move(other.entropy_context_);
            initialized_ = other.initialized_;
            
            other.initialized_ = false;
        }
        return *this;
    }

    void CryptoContext::cleanup()
    {
        if (private_key_context_) {
            mbedtls_pk_free(private_key_context_.get());
        }
        if (ecdh_context_) {
            mbedtls_ecdh_free(ecdh_context_.get());
        }
        if (drbg_context_) {
            mbedtls_ctr_drbg_free(drbg_context_.get());
        }
        if (entropy_context_) {
            mbedtls_entropy_free(entropy_context_.get());
        }
    }

    int CryptoContext::initialize()
    {
        if (initialized_) {
            return TeslaBLE_Status_E_OK;
        }

        int result = mbedtls_ctr_drbg_seed(
            drbg_context_.get(),
            mbedtls_entropy_func,
            entropy_context_.get(),
            nullptr,
            0);

        if (result != 0) {
            LOG_ERROR("Failed to seed DRBG: -0x%04x", (unsigned int)-result);
            return TeslaBLE_Status_E_ERROR_INTERNAL;
        }

        initialized_ = true;
        return TeslaBLE_Status_E_OK;
    }

    int CryptoContext::createPrivateKey()
    {
        if (!initialized_) {
            int result = initialize();
            if (result != TeslaBLE_Status_E_OK) {
                return result;
            }
        }

        // Free existing key if any
        mbedtls_pk_free(private_key_context_.get());
        mbedtls_pk_init(private_key_context_.get());

        int result = mbedtls_pk_setup(
            private_key_context_.get(),
            mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));

        if (result != 0) {
            LOG_ERROR("Failed to setup private key: -0x%04x", (unsigned int)-result);
            return TeslaBLE_Status_E_ERROR_INTERNAL;
        }

        result = mbedtls_ecp_gen_key(
            MBEDTLS_ECP_DP_SECP256R1,
            mbedtls_pk_ec(*private_key_context_.get()),
            mbedtls_ctr_drbg_random,
            drbg_context_.get());

        if (result != 0) {
            LOG_ERROR("Failed to generate private key: -0x%04x", (unsigned int)-result);
            return TeslaBLE_Status_E_ERROR_INTERNAL;
        }

        return TeslaBLE_Status_E_OK;
    }

    int CryptoContext::loadPrivateKey(const uint8_t* private_key_buffer, size_t key_size)
    {
        if (!private_key_buffer || key_size == 0) {
            LOG_ERROR("Invalid private key buffer");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        if (!initialized_) {
            int result = initialize();
            if (result != TeslaBLE_Status_E_OK) {
                return result;
            }
        }

        // Free existing key if any
        mbedtls_pk_free(private_key_context_.get());
        mbedtls_pk_init(private_key_context_.get());

        // Let mbedtls handle the basic PEM parsing
        int result = mbedtls_pk_parse_key(
            private_key_context_.get(),
            private_key_buffer,
            key_size,
            nullptr, // No password
            0,
            mbedtls_ctr_drbg_random,
            drbg_context_.get());

        if (result != 0) {
            LOG_ERROR("Failed to parse private key: -0x%04x", (unsigned int)-result);
            return TeslaBLE_Status_E_ERROR_INTERNAL;
        }

        // Tesla protocol validation - ensure it's an EC key
        if (!mbedtls_pk_can_do(private_key_context_.get(), MBEDTLS_PK_ECKEY)) {
            LOG_ERROR("Private key is not an EC key - Tesla protocol requires ECDSA");
            mbedtls_pk_free(private_key_context_.get());
            mbedtls_pk_init(private_key_context_.get());
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        // Tesla protocol validation - verify it's a SECP256R1 (P-256) key
        mbedtls_ecp_keypair* ec_key = mbedtls_pk_ec(*private_key_context_.get());
        if (mbedtls_ecp_keypair_get_group_id(ec_key) != MBEDTLS_ECP_DP_SECP256R1) {
            LOG_ERROR("Private key is not SECP256R1 (P-256) - Tesla protocol requires this curve");
            mbedtls_pk_free(private_key_context_.get());
            mbedtls_pk_init(private_key_context_.get());
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        return TeslaBLE_Status_E_OK;
    }

    int CryptoContext::getPrivateKey(pb_byte_t* output_buffer, size_t buffer_length, size_t* output_length)
    {
        if (!output_buffer || !output_length) {
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        if (!isPrivateKeyInitialized()) {
            LOG_ERROR("Private key not initialized");
            return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
        }

        int result = mbedtls_pk_write_key_pem(
            private_key_context_.get(),
            output_buffer,
            buffer_length);

        if (result != 0) {
            LOG_ERROR("Failed to write private key: -0x%04x", (unsigned int)-result);
            return TeslaBLE_Status_E_ERROR_INTERNAL;
        }

        *output_length = strlen(reinterpret_cast<char*>(output_buffer)) + 1;
        return TeslaBLE_Status_E_OK;
    }

    int CryptoContext::generatePublicKey(pb_byte_t* output_buffer, size_t* output_length)
    {
        if (!output_buffer || !output_length) {
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        if (!isPrivateKeyInitialized()) {
            LOG_ERROR("Private key not initialized");
            return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
        }
        
        // Verify the private key context is properly set up
        if (!private_key_context_.get()) {
            LOG_ERROR("Private key context is null");
            return TeslaBLE_Status_E_ERROR_INTERNAL;
        }
        
        if (mbedtls_pk_get_type(private_key_context_.get()) != MBEDTLS_PK_ECKEY) {
            LOG_ERROR("Private key is not an EC key, type: %d", mbedtls_pk_get_type(private_key_context_.get()));
            return TeslaBLE_Status_E_ERROR_INTERNAL;
        }
        
        mbedtls_ecp_keypair* ec_key = mbedtls_pk_ec(*private_key_context_.get());
        if (!ec_key) {
            LOG_ERROR("Failed to get EC keypair from PK context");
            return TeslaBLE_Status_E_ERROR_INTERNAL;
        }

        // Set the maximum buffer size for the output
        size_t max_output_length = *output_length;
        
        int result = mbedtls_ecp_point_write_binary(
            &ec_key->MBEDTLS_PRIVATE(grp),
            &ec_key->MBEDTLS_PRIVATE(Q),
            MBEDTLS_ECP_PF_UNCOMPRESSED,
            output_length,
            output_buffer,
            max_output_length);

        if (result != 0) {
            LOG_ERROR("Failed to generate public key: -0x%04x", (unsigned int)-result);
            return TeslaBLE_Status_E_ERROR_INTERNAL;
        }

        return TeslaBLE_Status_E_OK;
    }

    int CryptoContext::generateKeyId(const pb_byte_t* public_key, size_t key_size, pb_byte_t* key_id)
    {
        if (!public_key || !key_id || key_size == 0) {
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        std::array<pb_byte_t, 20> hash_buffer{};
        int result = CryptoUtils::sha1Hash(public_key, key_size, hash_buffer.data());
        if (result != TeslaBLE_Status_E_OK) {
            return result;
        }

        // Copy first 4 bytes as key ID
        std::memcpy(key_id, hash_buffer.data(), 4);
        return TeslaBLE_Status_E_OK;
    }

    int CryptoContext::performTeslaEcdh(const uint8_t* tesla_public_key, size_t tesla_key_size, uint8_t* session_key)
    {
        if (!tesla_public_key || !session_key || tesla_key_size != 65) {
            LOG_ERROR("Invalid parameters for Tesla ECDH");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        if (tesla_public_key[0] != 0x04) {
            LOG_ERROR("Invalid Tesla public key format: expected uncompressed point (0x04)");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        if (!initialized_) {
            int result = initialize();
            if (result != TeslaBLE_Status_E_OK) {
                return result;
            }
        }

        if (!isPrivateKeyInitialized()) {
            LOG_ERROR("Private key not initialized for ECDH");
            return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
        }

        LOG_DEBUG("Starting Tesla ECDH key exchange");

        // Use the loaded private key instead of generating ephemeral keys
        if (!mbedtls_pk_can_do(private_key_context_.get(), MBEDTLS_PK_ECKEY)) {
            LOG_ERROR("Loaded key is not an EC key");
            return TeslaBLE_Status_E_ERROR_INTERNAL;
        }

        // Get the ECP keypair from the loaded private key
        mbedtls_ecp_keypair* our_keypair = mbedtls_pk_ec(*private_key_context_.get());
        if (!our_keypair) {
            LOG_ERROR("Failed to get ECP keypair from loaded private key");
            return TeslaBLE_Status_E_ERROR_INTERNAL;
        }

        LOG_DEBUG("Using loaded private key for ECDH");

        int ret = TeslaBLE_Status_E_ERROR_CRYPTO;

        do {
            // Import Tesla's public key point
            LOG_DEBUG("Importing Tesla public key");
            mbedtls_ecp_point tesla_point;
            mbedtls_ecp_point_init(&tesla_point);
            
            ret = mbedtls_ecp_point_read_binary(&our_keypair->MBEDTLS_PRIVATE(grp), 
                                                &tesla_point, 
                                                tesla_public_key, 
                                                tesla_key_size);
            if (ret != 0) {
                LOG_ERROR("Failed to import Tesla public key: -0x%04x", -ret);
                mbedtls_ecp_point_free(&tesla_point);
                break;
            }

            // Compute shared secret using ECP point multiplication
            LOG_DEBUG("Computing ECDH shared secret");
            mbedtls_ecp_point shared_point;
            mbedtls_ecp_point_init(&shared_point);
            
            ret = mbedtls_ecp_mul(&our_keypair->MBEDTLS_PRIVATE(grp), 
                                  &shared_point, 
                                  &our_keypair->MBEDTLS_PRIVATE(d), 
                                  &tesla_point, 
                                  mbedtls_ctr_drbg_random, 
                                  drbg_context_.get());
            
            mbedtls_ecp_point_free(&tesla_point);
            
            if (ret != 0) {
                LOG_ERROR("Failed to compute shared secret: -0x%04x", -ret);
                mbedtls_ecp_point_free(&shared_point);
                break;
            }

            // Extract X coordinate from the shared point (this is the shared secret)
            uint8_t shared_secret[32];  // P-256 shared secret is 32 bytes
            ret = mbedtls_mpi_write_binary(&shared_point.MBEDTLS_PRIVATE(X), shared_secret, sizeof(shared_secret));
            mbedtls_ecp_point_free(&shared_point);
            
            if (ret != 0) {
                LOG_ERROR("Failed to write shared secret: -0x%04x", -ret);
                break;
            }

            LOG_DEBUG("Computed shared secret (%zu bytes)", sizeof(shared_secret));

            // Derive session key: K = SHA1(shared_secret)[:16] (Tesla protocol)
            uint8_t sha1_hash[20];
            ret = mbedtls_sha1(shared_secret, sizeof(shared_secret), sha1_hash);
            if (ret != 0) {
                LOG_ERROR("Failed to hash shared secret: -0x%04x", -ret);
                break;
            }

            // Copy first 16 bytes as session key
            std::memcpy(session_key, sha1_hash, 16);
            
            LOG_DEBUG("Tesla ECDH completed successfully");
            LOG_DEBUG("Session key: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                      session_key[0], session_key[1], session_key[2], session_key[3],
                      session_key[4], session_key[5], session_key[6], session_key[7],
                      session_key[8], session_key[9], session_key[10], session_key[11],
                      session_key[12], session_key[13], session_key[14], session_key[15]);

            ret = TeslaBLE_Status_E_OK;

        } while (false);

        // No cleanup needed - we used the loaded keypair, not a temporary one

        return ret;
    }

    int CryptoContext::generateRandomBytes(uint8_t* output, size_t length)
    {
        if (!output || length == 0) {
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        if (!initialized_) {
            int result = initialize();
            if (result != TeslaBLE_Status_E_OK) {
                return result;
            }
        }

        int ret = mbedtls_ctr_drbg_random(drbg_context_.get(), output, length);
        if (ret != 0) {
            LOG_ERROR("Failed to generate random bytes: -0x%04x", -ret);
            return TeslaBLE_Status_E_ERROR_CRYPTO;
        }

        return TeslaBLE_Status_E_OK;
    }

    bool CryptoContext::isPrivateKeyInitialized() const
    {
        return private_key_context_ && 
               mbedtls_pk_can_do(private_key_context_.get(), MBEDTLS_PK_ECKEY);
    }

    // CryptoUtils implementation
    int CryptoUtils::generateRandomBytes(
        pb_byte_t* output, 
        size_t length, 
        mbedtls_ctr_drbg_context* drbg_context)
    {
        if (!output || !drbg_context || length == 0) {
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        int result = mbedtls_ctr_drbg_random(drbg_context, output, length);
        if (result != 0) {
            LOG_ERROR("Failed to generate random bytes: -0x%04x", (unsigned int)-result);
            return TeslaBLE_Status_E_ERROR_INTERNAL;
        }

        return TeslaBLE_Status_E_OK;
    }

    int CryptoUtils::sha1Hash(const pb_byte_t* input, size_t input_length, pb_byte_t* output)
    {
        if (!input || !output || input_length == 0) {
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        int result = mbedtls_sha1(input, input_length, output);
        if (result != 0) {
            LOG_ERROR("SHA1 hash failed: -0x%04x", (unsigned int)-result);
            return TeslaBLE_Status_E_ERROR_INTERNAL;
        }

        return TeslaBLE_Status_E_OK;
    }

    bool CryptoUtils::secureMemoryCompare(const pb_byte_t* a, const pb_byte_t* b, size_t length)
    {
        if (!a || !b || length == 0) {
            return false;
        }

        // Use constant-time comparison to prevent timing attacks
        int result = 0;
        for (size_t i = 0; i < length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    void CryptoUtils::clearSensitiveMemory(void* memory, size_t length)
    {
        if (memory && length > 0) {
            mbedtls_platform_zeroize(memory, length);
        }
    }

} // namespace TeslaBLE
