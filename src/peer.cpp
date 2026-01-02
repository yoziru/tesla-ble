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
#include <inttypes.h>

namespace TeslaBLE
{
    Peer::Peer(UniversalMessage_Domain domain,
               std::shared_ptr<CryptoContext> crypto_context,
               const std::string& vin)
        : domain_(domain),
          vin_(vin),
          crypto_context_(crypto_context)
    {
    }

    bool Peer::isInitialized() const
    {
        if (crypto_context_ == nullptr)
        {
            LOG_ERROR("Crypto context is null");
            return false;
        }

        if (!isPrivateKeyInitialized())
        {
            LOG_ERROR("Private key is not initialized");
            return false;
        }

        if (!isValid())
        {
            LOG_ERROR("Session is not valid");
            return false;
        }

        if (!hasValidEpoch())
        {
            LOG_ERROR("Peer has invalid epoch");
            return false;
        }

        return true;
    }

    bool Peer::isPrivateKeyInitialized() const
    {
        return crypto_context_ && crypto_context_->isPrivateKeyInitialized();
    }

    bool Peer::hasValidEpoch() const
    {
        // make sure epoch is not all zeros
        for (size_t i = 0; i < epoch_.size(); i++)
        {
            if (epoch_[i] != 0)
            {
                return true;
            }
        }
        LOG_ERROR("Epoch is empty");
        return false;
    }

    void Peer::setCounter(uint32_t counter)
    {
        counter_ = counter;
    }

    void Peer::incrementCounter()
    {
        counter_++;
    }

    int Peer::setEpoch(const pb_byte_t *epoch)
    {
        if (epoch == nullptr) {
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }
        std::copy(epoch, epoch + epoch_.size(), epoch_.begin());
        return TeslaBLE_Status_E_OK;
    }

    uint32_t Peer::getCounter() const
    {
        return counter_;
    }

    uint32_t Peer::generateExpiresAt(int seconds) const
    {
        uint32_t expiresAt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + std::chrono::seconds(seconds)) - time_zero_;
        return expiresAt;
    }

    void Peer::generateNonce(pb_byte_t* nonce) const
    {
        if (nonce == nullptr || crypto_context_ == nullptr)
        {
            LOG_ERROR("Invalid nonce buffer or crypto context");
            return;
        }
        
        int result = crypto_context_->generateRandomBytes(nonce, NONCE_SIZE_BYTES);
        if (result != TeslaBLE_Status_E_OK)
        {
            LOG_ERROR("Failed to generate nonce: %d", result);
        }
    }

    int Peer::loadTeslaKey(const uint8_t* public_key_buffer, size_t public_key_size)
    {
        if (public_key_buffer == nullptr || public_key_size == 0)
        {
            LOG_ERROR("Invalid public key buffer");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        if (crypto_context_ == nullptr)
        {
            LOG_ERROR("Crypto context is null");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        LOG_DEBUG("Loading Tesla public key (%zu bytes)", public_key_size);
        
        // Print first few bytes for debugging
        LOG_DEBUG("Tesla key data: %02x %02x %02x %02x %02x %02x %02x %02x...",
                  public_key_buffer[0], public_key_buffer[1], public_key_buffer[2], public_key_buffer[3],
                  public_key_buffer[4], public_key_buffer[5], public_key_buffer[6], public_key_buffer[7]);

        // Validate Tesla public key format (should be 65 bytes uncompressed EC point)
        if (public_key_size != 65 || public_key_buffer[0] != 0x04)
        {
            LOG_ERROR("Invalid Tesla public key format: expected 65 bytes starting with 0x04, got %zu bytes starting with 0x%02x", 
                      public_key_size, public_key_buffer[0]);
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        // Use CryptoContext's Tesla ECDH method instead of duplicating crypto initialization
        LOG_DEBUG("Performing Tesla ECDH using CryptoContext");
        int ret = crypto_context_->performTeslaEcdh(public_key_buffer, public_key_size, shared_secret_sha1_.data());
        if (ret != TeslaBLE_Status_E_OK)
        {
            LOG_ERROR("Failed to perform Tesla ECDH: %d", ret);
            return ret;
        }

        is_valid_ = true;
        LOG_DEBUG("Tesla key loaded and session established successfully");
        LOG_DEBUG("Session key (first 16 bytes): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                  shared_secret_sha1_[0], shared_secret_sha1_[1], shared_secret_sha1_[2], shared_secret_sha1_[3],
                  shared_secret_sha1_[4], shared_secret_sha1_[5], shared_secret_sha1_[6], shared_secret_sha1_[7],
                  shared_secret_sha1_[8], shared_secret_sha1_[9], shared_secret_sha1_[10], shared_secret_sha1_[11],
                  shared_secret_sha1_[12], shared_secret_sha1_[13], shared_secret_sha1_[14], shared_secret_sha1_[15]);
        
        return TeslaBLE_Status_E_OK;
    }

    int Peer::updateSession(Signatures_SessionInfo *session_info)
    {
        LOG_DEBUG("Updating session..");
        if (session_info == nullptr)
        {
            LOG_ERROR("Session info is null");
            return TeslaBLE_Status_E_ERROR_INVALID_SESSION;
        }

        // Check if epoch is changing
        bool epoch_changed = false;
        if (memcmp(epoch_.data(), session_info->epoch, epoch_.size()) != 0) {
            epoch_changed = true;
        }

        // Anti-replay: if epoch is unchanged, only allow counter to increase
        if (!epoch_changed && session_info->counter < counter_) {
            LOG_ERROR("Counter anti-replay: attempted to set counter backwards (current: %u, new: %u)", counter_, session_info->counter);
            return TeslaBLE_Status_E_ERROR_COUNTER_REPLAY;
        }

        int status = setEpoch(session_info->epoch);
        if (status != TeslaBLE_Status_E_OK)
        {
            LOG_ERROR("Failed to set epoch");
            return status;
        }

        setCounter(session_info->counter);

        uint32_t generated_at = std::time(nullptr);
        uint32_t time_zero = generated_at - session_info->clock_time;
        setTimeZero(time_zero);

        // Load Tesla's public key if provided
        if (session_info->publicKey.size > 0) {
            status = loadTeslaKey(session_info->publicKey.bytes, session_info->publicKey.size);
            if (status != TeslaBLE_Status_E_OK) {
                LOG_ERROR("Failed to load Tesla public key from session info");
                return status;
            }
        }

        LOG_DEBUG("Updated session: counter=%d, clock_time=%d, time_zero=%d",
                  session_info->counter, session_info->clock_time, time_zero);

        return TeslaBLE_Status_E_OK;
    }

    int Peer::constructADBuffer(
        Signatures_SignatureType signature_type,
        const char *VIN,
        uint32_t expires_at,
        pb_byte_t *output_buffer,
        size_t *output_length,
        uint32_t flags,
        const pb_byte_t *request_hash,
        size_t request_hash_length,
        uint32_t fault) const
    {
        if (output_buffer == nullptr || output_length == nullptr || VIN == nullptr)
        {
            LOG_ERROR("Invalid parameters for AD buffer construction");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        // Calculate maximum possible buffer size to prevent overflow
        // Maximum: 3 + 3 + 2+17 + 2+16 + 6 + 6 + 6 + 2+255 + 6 + 1 = 325 bytes
        static constexpr size_t MAX_AD_BUFFER_SIZE = 256; // Standard buffer size used throughout codebase
        
        size_t index = 0;

        // Signature type (TLV format)
        output_buffer[index++] = Signatures_Tag_TAG_SIGNATURE_TYPE;
        output_buffer[index++] = 0x01;
        output_buffer[index++] = static_cast<pb_byte_t>(signature_type);

        // Domain (TLV format)
        output_buffer[index++] = Signatures_Tag_TAG_DOMAIN;
        output_buffer[index++] = 0x01;
        output_buffer[index++] = static_cast<pb_byte_t>(domain_);

        // Personalization (VIN) (TLV format)
        size_t vin_length = strlen(VIN);
        if (vin_length > 17) vin_length = 17; // VIN is max 17 characters
        output_buffer[index++] = Signatures_Tag_TAG_PERSONALIZATION;
        output_buffer[index++] = static_cast<pb_byte_t>(vin_length);
        memcpy(output_buffer + index, VIN, vin_length);
        index += vin_length;

        // Epoch (TLV format)
        output_buffer[index++] = Signatures_Tag_TAG_EPOCH;
        output_buffer[index++] = static_cast<pb_byte_t>(epoch_.size());
        std::copy(epoch_.begin(), epoch_.end(), output_buffer + index);
        index += epoch_.size();

        // Expires at (TLV format)
        output_buffer[index++] = Signatures_Tag_TAG_EXPIRES_AT;
        output_buffer[index++] = 0x04;  // 4 bytes for uint32_t
        output_buffer[index++] = (expires_at >> 24) & 0xFF;
        output_buffer[index++] = (expires_at >> 16) & 0xFF;
        output_buffer[index++] = (expires_at >> 8) & 0xFF;
        output_buffer[index++] = expires_at & 0xFF;

        // Counter (TLV format)
        output_buffer[index++] = Signatures_Tag_TAG_COUNTER;
        output_buffer[index++] = 0x04;  // 4 bytes for uint32_t
        output_buffer[index++] = (counter_ >> 24) & 0xFF;
        output_buffer[index++] = (counter_ >> 16) & 0xFF;
        output_buffer[index++] = (counter_ >> 8) & 0xFF;
        output_buffer[index++] = counter_ & 0xFF;

        // Flags handling per protocol:
        // - For REQUESTS: Only included if flags > 0 (backwards compatibility)
        // - For RESPONSES: ALWAYS included (protocol requirement)
        if (signature_type == Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_RESPONSE || flags > 0) {
            output_buffer[index++] = Signatures_Tag_TAG_FLAGS;
            output_buffer[index++] = 0x04;  // 4 bytes for uint32_t
            output_buffer[index++] = (flags >> 24) & 0xFF;
            output_buffer[index++] = (flags >> 16) & 0xFF;
            output_buffer[index++] = (flags >> 8) & 0xFF;
            output_buffer[index++] = flags & 0xFF;
        }

        // Response-specific fields (only for responses)
        if (signature_type == Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_RESPONSE) {
            // Request hash (TLV format)
            if (request_hash != nullptr && request_hash_length > 0) {
                // Validate request hash length fits in TLV length field (max 255)
                if (request_hash_length > 255) {
                    LOG_ERROR("Request hash length %zu exceeds TLV maximum of 255", request_hash_length);
                    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
                }
                output_buffer[index++] = Signatures_Tag_TAG_REQUEST_HASH;
                output_buffer[index++] = static_cast<pb_byte_t>(request_hash_length);
                memcpy(output_buffer + index, request_hash, request_hash_length);
                index += request_hash_length;
            }

            // Fault (TLV format) - always included for responses
            output_buffer[index++] = Signatures_Tag_TAG_FAULT;
            output_buffer[index++] = 0x04;  // 4 bytes for uint32_t
            output_buffer[index++] = (fault >> 24) & 0xFF;
            output_buffer[index++] = (fault >> 16) & 0xFF;
            output_buffer[index++] = (fault >> 8) & 0xFF;
            output_buffer[index++] = fault & 0xFF;
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

    int Peer::constructRequestHash(
        Signatures_SignatureType auth_type,
        const pb_byte_t* auth_tag,
        size_t auth_tag_length,
        pb_byte_t* request_hash,
        size_t* request_hash_length) const
    {
        if (auth_tag == nullptr || request_hash == nullptr || request_hash_length == nullptr)
        {
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
        
        memcpy(request_hash + 1, auth_tag, tag_copy_length);
        *request_hash_length = 1 + tag_copy_length;

        return TeslaBLE_Status_E_OK;
    }

    int Peer::decryptResponse(
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
        size_t* output_length) const
    {
        if (!isPrivateKeyInitialized()) {
            LOG_ERROR("[DecryptResponse] Private key not initialized");
            return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
        }

        mbedtls_gcm_context aes_context;
        mbedtls_gcm_init(&aes_context);

        // Set up AES-GCM with the shared key
        int return_code = mbedtls_gcm_setkey(&aes_context, MBEDTLS_CIPHER_ID_AES,
                                            shared_secret_sha1_.data(), 128);
        if (return_code != 0) {
            LOG_ERROR("[DecryptResponse] GCM set key error: -0x%04x", (unsigned int)-return_code);
            return TeslaBLE_Status_E_ERROR_DECRYPT;
        }

        // Construct AD buffer for response
        pb_byte_t ad_buffer[256];
        size_t ad_length;
        return_code = constructADBuffer(
            Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_RESPONSE,
            vin_.c_str(),
            0,  // expires_at not used for responses
            ad_buffer,
            &ad_length,
            flags,
            request_hash,
            request_hash_length,
            fault);

        if (return_code != 0) {
            LOG_ERROR("[DecryptResponse] Failed to construct AD buffer");
            return return_code;
        }

        // Hash the AD buffer
        unsigned char ad_hash[32];
        return_code = mbedtls_sha256(ad_buffer, ad_length, ad_hash, 0);
        if (return_code != 0) {
            LOG_ERROR("[DecryptResponse] AD metadata SHA256 hash error: -0x%04x", (unsigned int)-return_code);
            return TeslaBLE_Status_E_ERROR_DECRYPT;
        }

        // Start decryption
        return_code = mbedtls_gcm_starts(&aes_context, MBEDTLS_GCM_DECRYPT,
                                        nonce, 12);  // nonce is always 12 bytes
        if (return_code != 0) {
            LOG_ERROR("[DecryptResponse] GCM start error: -0x%04x", (unsigned int)-return_code);
            return TeslaBLE_Status_E_ERROR_DECRYPT;
        }

        // Set AD hash as AAD
        mbedtls_gcm_update_ad(&aes_context, ad_hash, sizeof(ad_hash));

        // Decrypt the message
        return_code = mbedtls_gcm_update(&aes_context, input_buffer, input_length,
                                        output_buffer, output_buffer_length, output_length);
        if (return_code != 0) {
            LOG_ERROR("[DecryptResponse] Decryption error in gcm_update: -0x%04x", (unsigned int)-return_code);
            return TeslaBLE_Status_E_ERROR_DECRYPT;
        }

        // Finalize and verify the tag
        size_t finish_length = 0;
        pb_byte_t finish_buffer[16];
        return_code = mbedtls_gcm_finish(&aes_context, finish_buffer, sizeof(finish_buffer),
                                        &finish_length, tag, 16);  // tag is always 16 bytes
        if (return_code != 0) {
            LOG_ERROR("[DecryptResponse] Authentication failed in gcm_finish: -0x%04x", (unsigned int)-return_code);
            return TeslaBLE_Status_E_ERROR_DECRYPT;
        }

        mbedtls_gcm_free(&aes_context);
        return TeslaBLE_Status_E_OK;
    }

    int Peer::encrypt(
        pb_byte_t* input_buffer, 
        size_t input_buffer_length,
        pb_byte_t* output_buffer, 
        size_t output_buffer_length,
        size_t* output_length, 
        pb_byte_t* signature_buffer,
        pb_byte_t* ad_buffer, 
        size_t ad_buffer_length,
        pb_byte_t nonce[NONCE_SIZE_BYTES]) const
    {
        if (!isPrivateKeyInitialized()) {
            LOG_ERROR("[Encrypt] Private key is not initialized");
            return TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED;
        }

        mbedtls_gcm_context aes_context;
        mbedtls_gcm_init(&aes_context);

        size_t shared_secret_size = this->SHARED_KEY_SIZE_BYTES;

        if (shared_secret_size != this->SHARED_KEY_SIZE_BYTES) {
            LOG_ERROR("[Encrypt] Shared secret SHA1 is not 16 bytes (actual size = %u)", shared_secret_size);
            return TeslaBLE_Status_E_ERROR_ENCRYPT;
        }

        // Use 128-bit key as specified in the protocol
        int return_code = mbedtls_gcm_setkey(&aes_context, MBEDTLS_CIPHER_ID_AES, shared_secret_sha1_.data(), 128);
        if (return_code != 0) {
            LOG_ERROR("[Encrypt] GCM set key error: -0x%04x", (unsigned int)-return_code);
            return TeslaBLE_Status_E_ERROR_ENCRYPT;
        }

        // Generate a new nonce for each encryption
        generateNonce(nonce);
        size_t nonce_size = 12;

        return_code = mbedtls_gcm_starts(&aes_context, MBEDTLS_GCM_ENCRYPT,
                                         nonce, nonce_size);
        if (return_code != 0) {
            LOG_ERROR("[Encrypt] GCM start error: -0x%04x", (unsigned int)-return_code);
            return TeslaBLE_Status_E_ERROR_ENCRYPT;
        }

        // Hash the AD buffer to create the AAD as per the protocol
        unsigned char ad_hash[32]; // SHA256 produces a 32-byte hash
        return_code = mbedtls_sha256(ad_buffer, ad_buffer_length, ad_hash, 0);
        if (return_code != 0) {
            LOG_ERROR("[Encrypt] AD metadata SHA256 hash error: -0x%04x", (unsigned int)-return_code);
            return TeslaBLE_Status_E_ERROR_ENCRYPT;
        }
        // Use the hash as the AAD for AES-GCM
        mbedtls_gcm_update_ad(&aes_context, ad_hash, sizeof(ad_hash));

        return_code = mbedtls_gcm_update(&aes_context, input_buffer, input_buffer_length,
                                         output_buffer, output_buffer_length, output_length);
        if (return_code != 0) {
            LOG_ERROR("[Encrypt] Encryption error in gcm_update: -0x%04x", (unsigned int)-return_code);
            return TeslaBLE_Status_E_ERROR_ENCRYPT;
        }

        size_t finish_buffer_length = 0;
        pb_byte_t finish_buffer[15]; // output_size never needs to be more than 15.
        // Finalize the encryption and get the tag
        size_t tag_length = 16; // AES-GCM typically uses a 16-byte tag
        return_code = mbedtls_gcm_finish(&aes_context, finish_buffer, sizeof(finish_buffer),
                                         &finish_buffer_length, signature_buffer, tag_length);
        if (return_code != 0) {
            LOG_ERROR("[Encrypt] Finalization error in gcm_finish: -0x%04x", (unsigned int)-return_code);
            return TeslaBLE_Status_E_ERROR_ENCRYPT;
        }

        mbedtls_gcm_free(&aes_context);

        // Log encrypted data (nonce, ciphertext, and tag)
        char nonce_hex[25];
        char output_buffer_hex[output_buffer_length * 2 + 1];
        char signature_buffer_hex[tag_length * 2 + 1];

        // Convert nonce to hex
        for (int i = 0; i < 12; i++) {
            snprintf(nonce_hex + (i * 2), 3, "%02x", nonce[i]);
        }
        nonce_hex[24] = '\0';

        // Convert output buffer to hex
        for (size_t i = 0; i < *output_length; i++) {
            snprintf(output_buffer_hex + (i * 2), 3, "%02x", output_buffer[i]);
        }
        output_buffer_hex[*output_length * 2] = '\0';

        // Convert signature buffer to hex
        for (size_t i = 0; i < tag_length; i++) {
            snprintf(signature_buffer_hex + (i * 2), 3, "%02x", signature_buffer[i]);
        }
        signature_buffer_hex[tag_length * 2] = '\0';

        LOG_DEBUG("[Encrypt] Nonce: %s, Ciphertext: %s, Tag: %s",
                  nonce_hex, output_buffer_hex, signature_buffer_hex);

        return TeslaBLE_Status_E_OK;
    }

    bool Peer::validateResponseCounter(uint32_t counter, uint32_t request_id)
    {
        std::lock_guard<std::mutex> guard(counter_mutex_);
        
        // Check if we've seen this counter for this request before
        auto it = response_counters_.find(request_id);
        if (it != response_counters_.end()) {
            const auto& used_counters = it->second;
            if (used_counters.find(counter) != used_counters.end()) {
                LOG_ERROR("Counter %" PRIu32 " has been previously used for request %" PRIu32, counter, request_id);
                return false;
            }
        }
        
        // Store the counter
        response_counters_[request_id].insert(counter);
        return true;
    }

} // namespace TeslaBLE
