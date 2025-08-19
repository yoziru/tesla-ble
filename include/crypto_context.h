#pragma once

#include <memory>
#include <array>
#include "mbedtls/pk.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "pb.h"
#include "errors.h"

namespace TeslaBLE
{
    /**
     * @brief RAII wrapper for mbedTLS contexts
     * 
     * This class provides automatic cleanup of mbedTLS contexts and
     * centralizes cryptographic operations.
     */
    class CryptoContext
    {
    public:
        CryptoContext();
        ~CryptoContext();

        // Delete copy constructor and assignment operator
        CryptoContext(const CryptoContext&) = delete;
        CryptoContext& operator=(const CryptoContext&) = delete;

        // Allow move constructor and assignment
        CryptoContext(CryptoContext&&) noexcept;
        CryptoContext& operator=(CryptoContext&&) noexcept;

        /**
         * @brief Initialize the crypto context with entropy
         * @return Error code (0 on success)
         */
        int initialize();

        /**
         * @brief Create a new private key
         * @return Error code (0 on success)
         */
        int createPrivateKey();

        /**
         * @brief Load a private key from buffer
         * @param private_key_buffer Buffer containing the private key
         * @param key_size Size of the key buffer
         * @return Error code (0 on success)
         */
        int loadPrivateKey(const uint8_t* private_key_buffer, size_t key_size);

        /**
         * @brief Get the private key in PEM format
         * @param output_buffer Buffer to write the key
         * @param buffer_length Size of the output buffer
         * @param output_length Actual length written
         * @return Error code (0 on success)
         */
        int getPrivateKey(pb_byte_t* output_buffer, size_t buffer_length, size_t* output_length);

        /**
         * @brief Generate public key from private key
         * @param output_buffer Buffer to write the public key
         * @param output_length Size of the output buffer
         * @return Error code (0 on success)
         */
        int generatePublicKey(pb_byte_t* output_buffer, size_t* output_length);

        /**
         * @brief Generate a 4-byte key ID from public key
         * @param public_key The public key bytes
         * @param key_size Size of the public key
         * @param key_id Output buffer for the 4-byte key ID
         * @return Error code (0 on success)
         */
        int generateKeyId(const pb_byte_t* public_key, size_t key_size, pb_byte_t* key_id);

        /**
         * @brief Perform Tesla ECDH key exchange and derive session key
         * @param tesla_public_key Tesla's 65-byte uncompressed public key
         * @param tesla_key_size Size of Tesla's public key (must be 65)
         * @param session_key Output buffer for 16-byte session key
         * @return TeslaBLE_Status_E_OK on success, error code otherwise
         */
        int performTeslaEcdh(const uint8_t* tesla_public_key, size_t tesla_key_size, uint8_t* session_key);

        /**
         * @brief Generate random bytes using this context's DRBG
         * @param output Output buffer for random bytes
         * @param length Number of bytes to generate
         * @return TeslaBLE_Status_E_OK on success, error code otherwise
         */
        int generateRandomBytes(uint8_t* output, size_t length);

        /**
         * @brief Check if the private key is initialized
         * @return true if initialized, false otherwise
         */
        bool isPrivateKeyInitialized() const;

        // Getters for contexts (needed by Peer class)
        std::shared_ptr<mbedtls_pk_context> getPrivateKeyContext() const { return private_key_context_; }
        std::shared_ptr<mbedtls_ecdh_context> getEcdhContext() const { return ecdh_context_; }
        std::shared_ptr<mbedtls_ctr_drbg_context> getDrbgContext() const { return drbg_context_; }

    private:
        std::shared_ptr<mbedtls_pk_context> private_key_context_;
        std::shared_ptr<mbedtls_ecdh_context> ecdh_context_;
        std::shared_ptr<mbedtls_ctr_drbg_context> drbg_context_;
        std::unique_ptr<mbedtls_entropy_context> entropy_context_;

        bool initialized_ = false;

        void cleanup();
    };

    /**
     * @brief Utility class for common cryptographic operations
     */
    class CryptoUtils
    {
    public:
        /**
         * @brief Generate random bytes
         * @param output Buffer to write random bytes
         * @param length Number of bytes to generate
         * @param drbg_context Random number generator context
         * @return Error code (0 on success)
         */
        static int generateRandomBytes(
            pb_byte_t* output, 
            size_t length, 
            mbedtls_ctr_drbg_context* drbg_context);

        /**
         * @brief Calculate SHA1 hash
         * @param input Input data
         * @param input_length Length of input data
         * @param output Output buffer (must be at least 20 bytes)
         * @return Error code (0 on success)
         */
        static int sha1Hash(const pb_byte_t* input, size_t input_length, pb_byte_t* output);

        /**
         * @brief Secure memory comparison
         * @param a First buffer
         * @param b Second buffer
         * @param length Length to compare
         * @return true if equal, false otherwise
         */
        static bool secureMemoryCompare(const pb_byte_t* a, const pb_byte_t* b, size_t length);

        /**
         * @brief Clear sensitive memory
         * @param memory Memory to clear
         * @param length Length to clear
         */
        static void clearSensitiveMemory(void* memory, size_t length);
    };

} // namespace TeslaBLE
