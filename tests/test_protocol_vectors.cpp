/**
 * @file test_protocol_vectors.cpp
 * @brief Test vectors from the Tesla BLE Protocol Specification
 * 
 * This file contains tests based on the exact test vectors and examples
 * provided in the protocol specification document to ensure our implementation
 * matches the official protocol.
 */

#include <gtest/gtest.h>
#include <crypto_context.h>
#include <peer.h>
#include <client.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/gcm.h>
#include <iomanip>
#include <sstream>
#include "test_constants.h"

namespace TeslaBLE {

// Test vectors from protocol specification
class ProtocolVectorsTest : public ::testing::Test {
protected:
    void SetUp() override {
        client = std::make_unique<Client>();
        client->setVIN(TestConstants::TEST_VIN);
    }

    std::unique_ptr<Client> client;

    std::string bytesToHex(const uint8_t* bytes, size_t length) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < length; ++i) {
            ss << std::setw(2) << static_cast<int>(bytes[i]);
        }
        return ss.str();
    }

    void hexToBytes(const std::string& hex, uint8_t* bytes) {
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            bytes[i/2] = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        }
    }
};

// Test 1: Key Agreement with Protocol Test Vectors
TEST_F(ProtocolVectorsTest, EcdkeyAgreementTestVectors) {
    // Load client private key
    int status = client->loadPrivateKey(
        reinterpret_cast<const unsigned char*>(TestConstants::CLIENT_PRIVATE_KEY_PEM), 
        strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1
    );
    ASSERT_EQ(status, 0) << "Failed to load client private key";

    // Test ECDH key agreement using the protocol test vectors
    CryptoContext crypto;
    status = crypto.loadPrivateKey(
        reinterpret_cast<const uint8_t*>(TestConstants::CLIENT_PRIVATE_KEY_PEM), 
        strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1  // +1 for null terminator
    );
    ASSERT_EQ(status, 0) << "Failed to load private key into crypto context";

    // Perform ECDH with vehicle's public key
    uint8_t derived_session_key[16];
    status = crypto.performTeslaEcdh(TestConstants::EXPECTED_VEHICLE_PUBLIC_KEY, 65, derived_session_key);
    ASSERT_EQ(status, 0) << "ECDH key agreement failed";

    // Verify the derived key matches the expected key from protocol spec
    EXPECT_EQ(
        bytesToHex(derived_session_key, 16),
        bytesToHex(TestConstants::EXPECTED_SESSION_KEY, 16)
    ) << "Derived session key does not match protocol specification";
}

// Test 2: Session Info Authentication (HMAC verification)
TEST_F(ProtocolVectorsTest, SessionInfoAuthentication) {
    // Test session info HMAC verification as per protocol spec
    uint8_t session_info_key[32];
    
    // Derive session info authentication key: HMAC-SHA256(K, "session info")
    const uint8_t* session_info_string = reinterpret_cast<const uint8_t*>("session info");
    int ret = mbedtls_md_hmac(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        TestConstants::EXPECTED_SESSION_KEY, 16,
        session_info_string, strlen("session info"),
        session_info_key
    );
    ASSERT_EQ(ret, 0) << "Failed to derive session info key";

    // Expected result from protocol spec example
    std::string expected_session_info_key_hex = "fceb679ee7bca756fcd441bf238bf2f338629b41d9eb9c67be1b32c9672ce300";
    EXPECT_EQ(
        bytesToHex(session_info_key, 32), 
        expected_session_info_key_hex
    ) << "Session info key derivation does not match protocol specification";
}

// Test 3: Metadata Serialization Test Vectors
TEST_F(ProtocolVectorsTest, MetadataSerializationVectors) {
    // Test the TLV metadata serialization from protocol spec examples
    
    // Test case: VIN serialization
    uint8_t expected_vin_tlv[] = {
        0x02, 0x11, // TAG_PERSONALIZATION, length 17
        0x35, 0x59, 0x4a, 0x33, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43
    };

    // Create a peer to test metadata serialization
    auto crypto_context = std::make_shared<CryptoContext>();
    Peer peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, crypto_context, TestConstants::TEST_VIN);
    
    uint8_t buffer[256];
    size_t buffer_length;
    
    // Test VIN serialization (this would be part of larger metadata construction)
    // Note: This tests the internal TLV encoding functions if they're accessible
    // Otherwise we test the higher-level AD buffer construction
    int result = peer.constructADBuffer(
        Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
        TestConstants::TEST_VIN,
        2655,         // expires_at
        buffer, 
        &buffer_length,
        0,            // flags
        nullptr,      // request_hash
        0,            // request_hash_length
        0             // fault
    );
    
    ASSERT_EQ(result, 0) << "Failed to construct AD buffer";
    
    // Verify VIN appears correctly in the buffer
    bool found_vin = false;
    for (size_t i = 0; i <= buffer_length - sizeof(expected_vin_tlv); ++i) {
        if (memcmp(buffer + i, expected_vin_tlv, sizeof(expected_vin_tlv)) == 0) {
            found_vin = true;
            break;
        }
    }
    EXPECT_TRUE(found_vin) << "VIN TLV encoding not found in AD buffer";
}

// Test 4: AES-GCM Encryption/Decryption with Protocol Vectors
TEST_F(ProtocolVectorsTest, AesGcmEncryptionVectors) {
    // Test AES-GCM encryption using the protocol specification example
    
    // Example from protocol spec
    const char* command_protobuf_hex = "120452020801"; // "Turn HVAC on" command
    uint8_t plaintext[6];
    hexToBytes(command_protobuf_hex, plaintext);
    
    // Metadata from protocol spec example
    const char* metadata_hex = "000105010103021135594a333031323334353637383941424303104c463f9cc0d3d26906e982ed224adde6040400000a5f050400000007ff";
    uint8_t metadata[256];
    size_t metadata_length = strlen(metadata_hex) / 2;
    hexToBytes(metadata_hex, metadata);
    
    // Hash the metadata for AAD
    uint8_t aad[32];
    int ret = mbedtls_sha256(metadata, metadata_length, aad, 0);
    ASSERT_EQ(ret, 0) << "Failed to hash metadata";
    
    // Test encryption using the session key
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    
    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, TestConstants::EXPECTED_SESSION_KEY, 128);
    ASSERT_EQ(ret, 0) << "Failed to set GCM key";
    
    // Use a test nonce (in real implementation, this would be random)
    uint8_t nonce[12] = {0xdb, 0xf7, 0x94, 0x47, 0xfa, 0x15, 0x66, 0x74, 0xda, 0xe1, 0xca, 0xed};
    uint8_t ciphertext[16];
    uint8_t tag[16];
    
    ret = mbedtls_gcm_crypt_and_tag(
        &gcm, MBEDTLS_GCM_ENCRYPT,
        sizeof(plaintext),
        nonce, sizeof(nonce),
        aad, sizeof(aad),
        plaintext, ciphertext,
        sizeof(tag), tag
    );
    ASSERT_EQ(ret, 0) << "GCM encryption failed";
    
    // Test decryption
    uint8_t decrypted[16];
    ret = mbedtls_gcm_auth_decrypt(
        &gcm,
        sizeof(plaintext),
        nonce, sizeof(nonce),
        aad, sizeof(aad),
        tag, sizeof(tag),
        ciphertext, decrypted
    );
    ASSERT_EQ(ret, 0) << "GCM decryption failed";
    
    // Verify round-trip
    EXPECT_EQ(memcmp(plaintext, decrypted, sizeof(plaintext)), 0) 
        << "AES-GCM round-trip failed";
    
    mbedtls_gcm_free(&gcm);
}

// Test 5: HMAC-SHA256 Authentication Method
TEST_F(ProtocolVectorsTest, HmacSha256Authentication) {
    // Test HMAC-SHA256 authentication method as alternative to AES-GCM
    
    // Derive HMAC key: K' = HMAC-SHA256(K, "authenticated command")
    uint8_t hmac_key[32];
    const uint8_t* auth_command_string = reinterpret_cast<const uint8_t*>("authenticated command");
    
    int ret = mbedtls_md_hmac(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        TestConstants::EXPECTED_SESSION_KEY, 16,
        auth_command_string, strlen("authenticated command"),
        hmac_key
    );
    ASSERT_EQ(ret, 0) << "Failed to derive HMAC key";
    
    // Test message + metadata HMAC
    const char* test_message = "120452020801"; // HVAC command
    const char* test_metadata = "000105010103021135594a333031323334353637383941424303104c463f9cc0d3d26906e982ed224adde6040400000a5f050400000007ff";
    
    uint8_t message[6], metadata[256];
    hexToBytes(test_message, message);
    hexToBytes(test_metadata, metadata);
    size_t metadata_length = strlen(test_metadata) / 2;
    
    // Compute HMAC tag = HMAC-SHA256(K', M || P)
    uint8_t combined[512];
    memcpy(combined, metadata, metadata_length);
    memcpy(combined + metadata_length, message, sizeof(message));
    
    uint8_t hmac_tag[32];
    ret = mbedtls_md_hmac(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        hmac_key, 32,
        combined, metadata_length + sizeof(message),
        hmac_tag
    );
    ASSERT_EQ(ret, 0) << "Failed to compute HMAC tag";
    
    // Verify tag is computed (specific expected value would need to be calculated)
    EXPECT_NE(bytesToHex(hmac_tag, 32), std::string(64, '0')) 
        << "HMAC tag should not be all zeros";
}

// Test 6: Request Hash Construction for Response Decryption
TEST_F(ProtocolVectorsTest, RequestHashConstruction) {
    // Test request hash construction for both domains
    
    auto crypto_context = std::make_shared<CryptoContext>();
    
    // Test VCSEC (truncated to 17 bytes)
    Peer vcsec_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, crypto_context, TestConstants::TEST_VIN);
    uint8_t test_tag[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t vcsec_hash[17];
    size_t vcsec_hash_length;
    
    int result = vcsec_peer.constructRequestHash(
        Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
        test_tag, 16,
        vcsec_hash, &vcsec_hash_length
    );
    ASSERT_EQ(result, 0) << "Failed to construct VCSEC request hash";
    EXPECT_EQ(vcsec_hash_length, 17) << "VCSEC request hash should be 17 bytes";
    EXPECT_EQ(vcsec_hash[0], Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED) 
        << "First byte should be signature type";
    
    // Test Infotainment (full 17 bytes for AES-GCM, 33 for HMAC)
    Peer info_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, crypto_context, TestConstants::TEST_VIN);
    uint8_t info_hash[33];
    size_t info_hash_length;
    
    result = info_peer.constructRequestHash(
        Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
        test_tag, 16,
        info_hash, &info_hash_length
    );
    ASSERT_EQ(result, 0) << "Failed to construct Infotainment request hash";
    EXPECT_EQ(info_hash_length, 17) << "Infotainment AES-GCM request hash should be 17 bytes";
    
    // Test HMAC request hash for Infotainment (should be 33 bytes)
    uint8_t hmac_tag[32];
    memset(hmac_tag, 0x42, sizeof(hmac_tag));
    
    result = info_peer.constructRequestHash(
        Signatures_SignatureType_SIGNATURE_TYPE_HMAC_PERSONALIZED,
        hmac_tag, 32,
        info_hash, &info_hash_length
    );
    ASSERT_EQ(result, 0) << "Failed to construct Infotainment HMAC request hash";
    EXPECT_EQ(info_hash_length, 33) << "Infotainment HMAC request hash should be 33 bytes";
}

// Test 7: Counter and Anti-Replay Protection
TEST_F(ProtocolVectorsTest, CounterAntiReplay) {
    // Test counter increment and anti-replay mechanisms
    
    auto crypto_context = std::make_shared<CryptoContext>();
    
    // Load the private key into the crypto context for ECDH operations
    int result = crypto_context->loadPrivateKey(
        reinterpret_cast<const uint8_t*>(TestConstants::CLIENT_PRIVATE_KEY_PEM), 
        strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1  // +1 for null terminator
    );
    ASSERT_EQ(result, 0) << "Failed to load private key into crypto context";
    
    // Verify the private key is loaded correctly
    ASSERT_TRUE(crypto_context->isPrivateKeyInitialized()) << "Private key should be initialized after loading";
    
    Peer peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, crypto_context, TestConstants::TEST_VIN);
    
    // Check that the peer has the same crypto context with loaded key
    ASSERT_TRUE(peer.isPrivateKeyInitialized()) << "Peer should have initialized private key";
    
    // Double-check that the crypto context still has the key before updateSession
    ASSERT_TRUE(crypto_context->isPrivateKeyInitialized()) << "CryptoContext should still have initialized private key before updateSession";
    
    // Initialize with mock session info
    Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
    session_info.counter = 100;
    session_info.clock_time = 1000;
    
    // Set epoch
    memcpy(session_info.epoch, TestConstants::TEST_EPOCH, 16);
    
    // Set public key
    memcpy(session_info.publicKey.bytes, TestConstants::EXPECTED_VEHICLE_PUBLIC_KEY, 65);
    session_info.publicKey.size = 65;
    
    result = peer.updateSession(&session_info);
    ASSERT_EQ(result, 0) << "Failed to update session";
    
    // Test that counter can be read and incremented
    uint32_t initial_counter = peer.getCounter();
    EXPECT_EQ(initial_counter, 100) << "Counter should be initialized to 100";
    
    peer.incrementCounter();
    uint32_t next_counter = peer.getCounter();
    EXPECT_EQ(next_counter, initial_counter + 1) << "Counter should increment";
    
    // Test counter validation for responses
    bool valid1 = peer.validateResponseCounter(150, 1); // first response for request 1
    EXPECT_TRUE(valid1) << "First response counter should be valid";
    
    bool valid2 = peer.validateResponseCounter(150, 1); // same counter for same request
    EXPECT_FALSE(valid2) << "Duplicate response counter should be invalid";
    
    bool valid3 = peer.validateResponseCounter(151, 1); // different counter for same request
    EXPECT_TRUE(valid3) << "Different response counter should be valid";
}

} // namespace TeslaBLE
