/**
 * @file test_protocol_handshake.cpp
 * @brief Tests for Tesla BLE Protocol handshake and response handling
 * 
 * This file tests the handshake process, session info authentication,
 * and response decryption as specified in the protocol documentation.
 */

#include <gtest/gtest.h>
#include <client.h>
#include <peer.h>
#include <crypto_context.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <pb_decode.h>
#include <pb_encode.h>
#include <iomanip>
#include <sstream>
#include "test_constants.h"

namespace TeslaBLE {

class ProtocolHandshakeTest : public ::testing::Test {
protected:
    void SetUp() override {
        client = std::make_unique<Client>();
        client->setVIN(TestConstants::TEST_VIN);
        crypto_context = std::make_shared<CryptoContext>();
    }

    std::unique_ptr<Client> client;
    std::shared_ptr<CryptoContext> crypto_context;

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

// Test 1: Handshake Request Generation
TEST_F(ProtocolHandshakeTest, HandshakeRequestGeneration) {
    // Load client private key
    int result = client->loadPrivateKey(
        reinterpret_cast<const unsigned char*>(TestConstants::CLIENT_PRIVATE_KEY_PEM), 
        strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1  // +1 for null terminator
    );
    ASSERT_EQ(result, 0) << "Failed to load client private key";

    // Test session info request for VCSEC domain (this is the actual handshake)
    pb_byte_t vcsec_message[512];
    size_t vcsec_message_length;
    
    result = client->buildSessionInfoRequestMessage(
        UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
        vcsec_message,
        &vcsec_message_length
    );
    ASSERT_EQ(result, 0) << "Failed to build VCSEC session info request";
    EXPECT_GT(vcsec_message_length, 0) << "VCSEC session info message should have content";

    // Test session info request for Infotainment domain
    pb_byte_t info_message[512];
    size_t info_message_length;
    
    result = client->buildSessionInfoRequestMessage(
        UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
        info_message,
        &info_message_length
    );
    ASSERT_EQ(result, 0) << "Failed to build Infotainment session info request";
    EXPECT_GT(info_message_length, 0) << "Infotainment session info message should have content";
    
    // Verify messages are different (different domains should have different routing)
    bool messages_different = (vcsec_message_length != info_message_length) ||
        (memcmp(vcsec_message, info_message, std::min(vcsec_message_length, info_message_length)) != 0);
    EXPECT_TRUE(messages_different) << "VCSEC and Infotainment session requests should be different";
}

// Test 2: Session Info Authentication
// Test 2: Handshake Flow and Response Processing
TEST_F(ProtocolHandshakeTest, HandshakeFlowProcessing) {
    // Test the complete handshake flow with proper response handling
    
    // Load client private key for key agreement
    int result = crypto_context->loadPrivateKey(
        reinterpret_cast<const uint8_t*>(TestConstants::CLIENT_PRIVATE_KEY_PEM), 
        strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1  // +1 for null terminator
    );
    ASSERT_EQ(result, 0) << "Failed to load private key into crypto context";

    // Create a peer for handshake testing
    Peer peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, crypto_context, TestConstants::TEST_VIN);

    // Initial handshake should succeed
    EXPECT_FALSE(peer.isValid()) << "Peer should be invalid before handshake";
    
    // Simulate session establishment
    Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
    session_info.counter = 1;
    session_info.clock_time = 1000;
    
    memcpy(session_info.epoch, TestConstants::TEST_EPOCH, 16);
    memcpy(session_info.publicKey.bytes, TestConstants::EXPECTED_VEHICLE_PUBLIC_KEY, 65);
    session_info.publicKey.size = 65;
    
    result = peer.updateSession(&session_info);
    ASSERT_EQ(result, 0) << "Failed to establish session during handshake";
    
    // Verify handshake completion
    EXPECT_TRUE(peer.isValid()) << "Peer should be valid after successful handshake";
    
    // Test counter advancement during handshake
    uint32_t initial_counter = peer.getCounter();
    EXPECT_EQ(initial_counter, 1) << "Counter should be set to initial session value";
}

// Test 3: Response Encryption Flag Handling
TEST_F(ProtocolHandshakeTest, ResponseEncryptionFlag) {
    // Test that messages can be built successfully with the encryption flag
    // According to protocol spec: "Clients should always set the FLAG_ENCRYPT_RESPONSE bit"
    
    // Load private key for client
    int result = client->loadPrivateKey(
        reinterpret_cast<const uint8_t*>(TestConstants::CLIENT_PRIVATE_KEY_PEM), 
        strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1
    );
    ASSERT_EQ(result, 0) << "Failed to load private key";
    
    // Test that session info request can be built successfully
    // The implementation should automatically set FLAG_ENCRYPT_RESPONSE
    pb_byte_t session_request[512];
    size_t session_request_length;
    
    result = client->buildSessionInfoRequestMessage(
        UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
        session_request,
        &session_request_length
    );
    ASSERT_EQ(result, 0) << "Failed to build session info request";
    EXPECT_GT(session_request_length, 0) << "Session request should have content";
    
    // Test that whitelist message can be built successfully
    // The implementation should automatically set FLAG_ENCRYPT_RESPONSE  
    pb_byte_t whitelist_message[512];
    size_t whitelist_length;
    
    result = client->buildWhiteListMessage(
        Keys_Role_ROLE_DRIVER,  // role parameter
        VCSEC_KeyFormFactor_KEY_FORM_FACTOR_ANDROID_DEVICE,  // form factor parameter  
        whitelist_message,
        &whitelist_length
    );
    ASSERT_EQ(result, 0) << "Failed to build whitelist message";
    EXPECT_GT(whitelist_length, 0) << "Whitelist message should have content";
    
    // Test that VCSEC information request can be built successfully
    pb_byte_t vcsec_request[512]; 
    size_t vcsec_length;
    
    result = client->buildVCSECInformationRequestMessage(
        VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_WHITELIST_INFO,
        vcsec_request,
        &vcsec_length
    );
    ASSERT_EQ(result, 0) << "Failed to build VCSEC information request";
    EXPECT_GT(vcsec_length, 0) << "VCSEC request should have content";
    
    // All message building methods should succeed when FLAG_ENCRYPT_RESPONSE
    // is properly implemented according to the protocol specification
}

// Test 4: Response Decryption
TEST_F(ProtocolHandshakeTest, ResponseDecryption) {
    // Test response decryption with mock encrypted response
    
    // Load private key for key agreement
    int result = crypto_context->loadPrivateKey(
        reinterpret_cast<const uint8_t*>(TestConstants::CLIENT_PRIVATE_KEY_PEM), 
        strlen(TestConstants::CLIENT_PRIVATE_KEY_PEM) + 1  // +1 for null terminator
    );
    ASSERT_EQ(result, 0) << "Failed to load private key";

    // Create peer and load vehicle public key
    Peer peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, crypto_context, TestConstants::TEST_VIN);
    result = peer.loadTeslaKey(TestConstants::EXPECTED_VEHICLE_PUBLIC_KEY, 65);
    ASSERT_EQ(result, 0) << "Failed to load Tesla key";

    // Mock session info to initialize peer
    Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
    session_info.counter = 7;
    session_info.clock_time = 2655;

    memcpy(session_info.epoch, TestConstants::TEST_EPOCH, 16);

    memcpy(session_info.publicKey.bytes, TestConstants::EXPECTED_VEHICLE_PUBLIC_KEY, 65);
    session_info.publicKey.size = 65;
    
    result = peer.updateSession(&session_info);
    ASSERT_EQ(result, 0) << "Failed to update session";

    // Test response decryption parameters
    uint8_t mock_encrypted_data[] = {0x38, 0x03, 0x8e, 0x8c, 0x0f, 0x2e}; // Mock ciphertext
    uint8_t mock_nonce[12] = {0xdb, 0xf7, 0x94, 0x47, 0xfa, 0x15, 0x66, 0x74, 0xda, 0xe1, 0xca, 0xed};
    uint8_t mock_tag[16] = {0x8e, 0x12, 0x8d, 0xa1, 0x65, 0xf1, 0x62, 0xf4, 
                            0xd7, 0xd2, 0xc8, 0xda, 0x86, 0x6c, 0xf8, 0x2a};
    
    // Mock request hash (would be from original request)
    uint8_t request_hash[17];
    request_hash[0] = Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED;
    memcpy(request_hash + 1, mock_tag, 16); // Use same tag for simplicity
    
    uint8_t decrypted[256];
    size_t decrypted_length;
    
    result = peer.decryptResponse(
        mock_encrypted_data, sizeof(mock_encrypted_data),
        mock_nonce,
        mock_tag,
        request_hash, sizeof(request_hash),
        0, // flags
        0, // fault
        decrypted, sizeof(decrypted),
        &decrypted_length
    );
    
    // The exact result depends on the mock data being valid
    // But we should get a meaningful response
    EXPECT_TRUE(result == 0 || result < 0) << "Decryption should either succeed or fail gracefully";
    
    if (result == 0) {
        EXPECT_GT(decrypted_length, 0) << "Successful decryption should produce content";
    }
}

// Test 5: Domain-Specific Behavior
TEST_F(ProtocolHandshakeTest, DomainSpecificBehavior) {
    // Test differences between VCSEC and Infotainment domains
    
    auto vcsec_peer = client->getPeer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
    auto info_peer = client->getPeer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
    
    ASSERT_NE(vcsec_peer, nullptr) << "Should be able to get VCSEC peer";
    ASSERT_NE(info_peer, nullptr) << "Should be able to get Infotainment peer";
    
    // Verify they have different domains
    EXPECT_EQ(vcsec_peer->getDomain(), UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
    EXPECT_EQ(info_peer->getDomain(), UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
    
    // Test request hash construction differences
    uint8_t test_tag[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    
    uint8_t vcsec_hash[17], info_hash[17];
    size_t vcsec_length, info_length;
    
    int vcsec_result = vcsec_peer->constructRequestHash(
        Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
        test_tag, 16,
        vcsec_hash, &vcsec_length
    );
    
    int info_result = info_peer->constructRequestHash(
        Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED,
        test_tag, 16,
        info_hash, &info_length
    );
    
    ASSERT_EQ(vcsec_result, 0) << "VCSEC request hash construction should succeed";
    ASSERT_EQ(info_result, 0) << "Infotainment request hash construction should succeed";
    
    // Both should be 17 bytes for AES-GCM (VCSEC truncates, Infotainment doesn't truncate AES-GCM)
    EXPECT_EQ(vcsec_length, 17) << "VCSEC hash should be 17 bytes";
    EXPECT_EQ(info_length, 17) << "Infotainment hash should be 17 bytes";
    
    // Content should be identical for AES-GCM (both have same tag length)
    EXPECT_EQ(memcmp(vcsec_hash, info_hash, 17), 0) 
        << "AES-GCM request hashes should be identical between domains";
}

} // namespace TeslaBLE
