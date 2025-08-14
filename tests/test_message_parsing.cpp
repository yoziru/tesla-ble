#include <gtest/gtest.h>
#include <client.h>
#include <universal_message.pb.h>
#include <signatures.pb.h>
#include <car_server.pb.h>
#include <cstring>

// Mock data
static const char *MOCK_VIN = "5YJ30123456789ABC";
static const unsigned char MOCK_PRIVATE_KEY[227] = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEILRjIS9VEyG+0K71a2T/lKVF5MllmYu78y14UzHgPQb5oAoGCCqGSM49\nAwEHoUQDQgAEUxC4mUu1EemeRNJFvgU3RHptxzxR1kCc+fVIwxNg4Pxa2AzDDAbZ\njh4MR49c2FBOLVVzYlUnt1F35HFWGjaXsg==\n-----END EC PRIVATE KEY-----";

// Mock received message from VCSEC (from main.cpp)
static pb_byte_t MOCK_VCSEC_MESSAGE[177] = {
    0x32, 0x12, 0x12, 0x10, 0x2f, 0xdd, 0xc1, 0x45, 0xca, 0xcc, 0xca, 0x43, 0x05, 0x66, 0x37, 0x0d, 
    0xf1, 0x49, 0x85, 0x5d, 0x3a, 0x02, 0x08, 0x02, 0x7a, 0x5e, 0x08, 0x01, 0x12, 0x41, 0x04, 0xc7, 
    0xa1, 0xf4, 0x71, 0x38, 0x48, 0x6a, 0xa4, 0x72, 0x99, 0x71, 0x49, 0x48, 0x78, 0xd3, 0x3b, 0x1a, 
    0x24, 0xe3, 0x95, 0x71, 0xf7, 0x48, 0xa6, 0xe1, 0x6c, 0x59, 0x55, 0xb3, 0xd8, 0x77, 0xd3, 0xa6, 
    0xaa, 0xa0, 0xe9, 0x55, 0x16, 0x64, 0x74, 0xaf, 0x5d, 0x32, 0xc4, 0x10, 0xf4, 0x39, 0xa2, 0x23, 
    0x41, 0x37, 0xad, 0x1b, 0xb0, 0x85, 0xfd, 0x4e, 0x88, 0x13, 0xc9, 0x58, 0xf1, 0x1d, 0x97, 0x1a, 
    0x10, 0x4c, 0x46, 0x3f, 0x9c, 0xc0, 0xd3, 0xd2, 0x69, 0x06, 0xe9, 0x82, 0xed, 0x22, 0x4a, 0xdd, 
    0xe6, 0x25, 0x85, 0x4a, 0x00, 0x00, 0x30, 0x06, 0x6a, 0x24, 0x32, 0x22, 0x0a, 0x20, 0x5a, 0x0d, 
    0x3c, 0x7c, 0xb0, 0x2c, 0x04, 0xd9, 0x12, 0xa3, 0x58, 0x8b, 0xc2, 0xa6, 0xfd, 0x8c, 0x00, 0xf2, 
    0x44, 0x09, 0x1b, 0xdd, 0x9d, 0xfe, 0x46, 0xfc, 0xdc, 0x47, 0x06, 0x41, 0x5b, 0x26, 0x92, 0x03, 
    0x10, 0x3c, 0xcc, 0xe3, 0xd5, 0x1a, 0x6f, 0x3c, 0x2a, 0xee, 0xa8, 0x91, 0x36, 0x44, 0xa7, 0x05, 0x84
};

// Mock received message from INFOTAINMENT (from main.cpp)
static pb_byte_t MOCK_INFOTAINMENT_MESSAGE[177] = {
    0x32, 0x12, 0x12, 0x10, 0x8f, 0x3d, 0x24, 0x4b, 0x50, 0xb0, 0x7a, 0x98, 0x42, 0xca, 0xc1, 0x08, 
    0xc9, 0x28, 0xb5, 0xe7, 0x3a, 0x02, 0x08, 0x03, 0x7a, 0x5e, 0x08, 0x01, 0x12, 0x41, 0x04, 0xc7, 
    0xa1, 0xf4, 0x71, 0x38, 0x48, 0x6a, 0xa4, 0x72, 0x99, 0x71, 0x49, 0x48, 0x78, 0xd3, 0x3b, 0x1a, 
    0x24, 0xe3, 0x95, 0x71, 0xf7, 0x48, 0xa6, 0xe1, 0x6c, 0x59, 0x55, 0xb3, 0xd8, 0x77, 0xd3, 0xa6, 
    0xaa, 0xa0, 0xe9, 0x55, 0x16, 0x64, 0x74, 0xaf, 0x5d, 0x32, 0xc4, 0x10, 0xf4, 0x39, 0xa2, 0x23, 
    0x41, 0x37, 0xad, 0x1b, 0xb0, 0x85, 0xfd, 0x4e, 0x88, 0x13, 0xc9, 0x58, 0xf1, 0x1d, 0x97, 0x1a, 
    0x10, 0x4c, 0x46, 0x3f, 0x9c, 0xc0, 0xd3, 0xd2, 0x69, 0x06, 0xe9, 0x82, 0xed, 0x22, 0x4a, 0xdd, 
    0xe6, 0x25, 0x5f, 0x0a, 0x00, 0x00, 0x30, 0x07, 0x6a, 0x24, 0x32, 0x22, 0x0a, 0x20, 0x8e, 0x8d, 
    0xcd, 0x16, 0x4e, 0xf3, 0x61, 0xfd, 0x12, 0x3c, 0x46, 0xc2, 0xb2, 0xbd, 0xfd, 0x1f, 0xc9, 0x30, 
    0x56, 0xf4, 0xef, 0x32, 0xc9, 0x31, 0x1a, 0x27, 0x5d, 0xb9, 0x08, 0xd4, 0xd2, 0x3f, 0x92, 0x03, 
    0x10, 0x0a, 0x40, 0x4e, 0xc0, 0xfc, 0x9a, 0xa8, 0x63, 0xae, 0xc3, 0xe5, 0x01, 0x96, 0xfb, 0xf3, 0x0b
};

class MessageParsingTest : public ::testing::Test {
protected:
    void SetUp() override {
        client = std::make_unique<TeslaBLE::Client>();
        client->setVIN(MOCK_VIN);
        
        // Load private key for testing
        int status = client->loadPrivateKey(MOCK_PRIVATE_KEY, sizeof(MOCK_PRIVATE_KEY));
        ASSERT_EQ(status, 0) << "Failed to load private key for testing";
    }

    void TearDown() override {
        client.reset();
    }

    std::unique_ptr<TeslaBLE::Client> client;
};

TEST_F(MessageParsingTest, ParseValidVCSECUniversalMessage) {
    UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
    
    int result = client->parseUniversalMessage(
        MOCK_VCSEC_MESSAGE, 
        sizeof(MOCK_VCSEC_MESSAGE), 
        &received_message
    );
    
    EXPECT_EQ(result, 0) << "Parsing valid VCSEC universal message should succeed";
    
    // Basic validation of parsed message
    EXPECT_TRUE(received_message.has_to_destination) << "Message should have to_destination";
    EXPECT_TRUE(received_message.has_from_destination) << "Message should have from_destination";
}

TEST_F(MessageParsingTest, ParseValidInfotainmentUniversalMessage) {
    UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
    
    int result = client->parseUniversalMessage(
        MOCK_INFOTAINMENT_MESSAGE, 
        sizeof(MOCK_INFOTAINMENT_MESSAGE), 
        &received_message
    );
    
    EXPECT_EQ(result, 0) << "Parsing valid Infotainment universal message should succeed";
    
    // Basic validation of parsed message
    EXPECT_TRUE(received_message.has_to_destination) << "Message should have to_destination";
    EXPECT_TRUE(received_message.has_from_destination) << "Message should have from_destination";
}

TEST_F(MessageParsingTest, ParseInvalidUniversalMessage) {
    UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
    
    // Test with invalid data
    pb_byte_t invalid_data[] = {0x00, 0x01, 0x02, 0x03};
    int result = client->parseUniversalMessage(
        invalid_data, 
        sizeof(invalid_data), 
        &received_message
    );
    
    EXPECT_NE(result, 0) << "Parsing invalid universal message should fail";
}

TEST_F(MessageParsingTest, ParseEmptyUniversalMessage) {
    UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
    
    int result = client->parseUniversalMessage(nullptr, 0, &received_message);
    EXPECT_NE(result, 0) << "Parsing empty/null universal message should fail";
}

TEST_F(MessageParsingTest, ParseSessionInfoFromVCSECMessage) {
    // First parse the universal message
    UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
    int parse_result = client->parseUniversalMessage(
        MOCK_VCSEC_MESSAGE, 
        sizeof(MOCK_VCSEC_MESSAGE), 
        &received_message
    );
    ASSERT_EQ(parse_result, 0) << "Failed to parse universal message";
    
    // Now parse the session info
    Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
    int session_result = client->parsePayloadSessionInfo(
        &received_message.payload.session_info, 
        &session_info
    );
    
    EXPECT_EQ(session_result, 0) << "Parsing session info from VCSEC message should succeed";
    
    // Basic validation
    EXPECT_GT(session_info.publicKey.size, 0) << "Session info should have a public key";
    EXPECT_GE(session_info.counter, 0) << "Session info should have a valid counter";
}

TEST_F(MessageParsingTest, ParseSessionInfoFromInfotainmentMessage) {
    // First parse the universal message
    UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
    int parse_result = client->parseUniversalMessage(
        MOCK_INFOTAINMENT_MESSAGE, 
        sizeof(MOCK_INFOTAINMENT_MESSAGE), 
        &received_message
    );
    ASSERT_EQ(parse_result, 0) << "Failed to parse universal message";
    
    // Now parse the session info
    Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
    int session_result = client->parsePayloadSessionInfo(
        &received_message.payload.session_info, 
        &session_info
    );
    
    EXPECT_EQ(session_result, 0) << "Parsing session info from Infotainment message should succeed";
    
    // Basic validation
    EXPECT_GT(session_info.publicKey.size, 0) << "Session info should have a public key";
    EXPECT_GE(session_info.counter, 0) << "Session info should have a valid counter";
}

TEST_F(MessageParsingTest, ParseMessageWithNullOutput) {
    int result = client->parseUniversalMessage(
        MOCK_VCSEC_MESSAGE, 
        sizeof(MOCK_VCSEC_MESSAGE), 
        nullptr
    );
    
    EXPECT_NE(result, 0) << "Parsing message with null output should fail";
}

TEST_F(MessageParsingTest, ParseSessionInfoWithNullOutput) {
    // First parse a valid universal message
    UniversalMessage_RoutableMessage received_message = UniversalMessage_RoutableMessage_init_default;
    int parse_result = client->parseUniversalMessage(
        MOCK_VCSEC_MESSAGE, 
        sizeof(MOCK_VCSEC_MESSAGE), 
        &received_message
    );
    ASSERT_EQ(parse_result, 0) << "Failed to parse universal message";
    
    // Try to parse session info with null output
    int session_result = client->parsePayloadSessionInfo(
        &received_message.payload.session_info, 
        nullptr
    );
    
    EXPECT_NE(session_result, 0) << "Parsing session info with null output should fail";
}

TEST_F(MessageParsingTest, ParsePayloadCarServerResponsePlaintext) {
    // Create a minimal valid CarServer Response with just actionStatus
    // Based on protobuf wire format: field 1 (actionStatus) with result = 0 (OK)
    pb_byte_t mock_response_data[] = {
        0x0A, 0x02, 0x08, 0x00  // actionStatus { result: OPERATIONSTATUS_OK }
    };
    
    // Create input buffer structure
    UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t input_buffer;
    input_buffer.size = sizeof(mock_response_data);
    memcpy(input_buffer.bytes, mock_response_data, sizeof(mock_response_data));
    
    // Parse the response (plaintext, no encryption)
    CarServer_Response parsed_response = CarServer_Response_init_default;
    Signatures_SignatureData signature_data = Signatures_SignatureData_init_default;
    
    int result = client->parsePayloadCarServerResponse(
        &input_buffer,
        &signature_data,
        0,  // which_sub_sigData = 0 means plaintext
        UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE,
        &parsed_response
    );
    
    EXPECT_EQ(result, 0) << "Parsing plaintext CarServer response should succeed";
    EXPECT_TRUE(parsed_response.has_actionStatus) << "Parsed response should have action status";
    EXPECT_EQ(parsed_response.actionStatus.result, CarServer_OperationStatus_E_OPERATIONSTATUS_OK) << "Action status should be OK";
}

TEST_F(MessageParsingTest, ParsePayloadCarServerResponseInvalidData) {
    // Create invalid protobuf data
    UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t input_buffer;
    pb_byte_t invalid_data[] = {0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02};
    input_buffer.size = sizeof(invalid_data);
    memcpy(input_buffer.bytes, invalid_data, sizeof(invalid_data));
    
    CarServer_Response parsed_response = CarServer_Response_init_default;
    Signatures_SignatureData signature_data = Signatures_SignatureData_init_default;
    
    int result = client->parsePayloadCarServerResponse(
        &input_buffer,
        &signature_data,
        0,  // plaintext
        UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE,
        &parsed_response
    );
    
    EXPECT_NE(result, 0) << "Parsing invalid CarServer response data should fail";
}

TEST_F(MessageParsingTest, ParsePayloadCarServerResponseEdgeCases) {
    CarServer_Response parsed_response = CarServer_Response_init_default;
    Signatures_SignatureData signature_data = Signatures_SignatureData_init_default;
    
    // Test with buffer containing only invalid protobuf data
    UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t invalid_buffer;
    pb_byte_t invalid_data[] = {0xFF, 0xFF, 0xFF};  // Invalid protobuf wire format
    invalid_buffer.size = sizeof(invalid_data);
    memcpy(invalid_buffer.bytes, invalid_data, sizeof(invalid_data));
    
    int result = client->parsePayloadCarServerResponse(
        &invalid_buffer,
        &signature_data,
        0,
        UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE,
        &parsed_response
    );
    EXPECT_NE(result, 0) << "Parsing with invalid protobuf data should fail";
    
    // Test with truncated valid data
    UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t truncated_buffer;
    pb_byte_t truncated_data[] = {0x0A, 0x02};  // Incomplete actionStatus field
    truncated_buffer.size = sizeof(truncated_data);
    memcpy(truncated_buffer.bytes, truncated_data, sizeof(truncated_data));
    
    int result2 = client->parsePayloadCarServerResponse(
        &truncated_buffer,
        &signature_data,
        0,
        UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE,
        &parsed_response
    );
    EXPECT_NE(result2, 0) << "Parsing with truncated data should fail";
}
