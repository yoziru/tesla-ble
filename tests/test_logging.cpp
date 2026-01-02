#include <gtest/gtest.h>
#include <defs.h>
#include <tb_utils.h>
#include <vector>
#include <string>
#include <cstdarg>

using namespace TeslaBLE;

// Test fixture to capture log calls
class LoggingTest : public ::testing::Test {
protected:
    struct LogCall {
        LogLevel level;
        std::string tag;
        std::string message;
    };
    
    static std::vector<LogCall> captured_logs_;
    static LogCallback original_callback_;
    
    static void test_log_callback(LogLevel level, const char* tag, int line, const char* format, va_list args) {
        char buffer[512];
        vsnprintf(buffer, sizeof(buffer), format, args);
        
        LogCall call;
        call.level = level;
        call.tag = tag ? tag : "";
        call.message = buffer;
        captured_logs_.push_back(call);
    }
    
    void SetUp() override {
        captured_logs_.clear();
        original_callback_ = g_log_callback;
        g_log_callback = test_log_callback;
    }
    
    void TearDown() override {
        g_log_callback = original_callback_;
        captured_logs_.clear();
    }
    
    const std::vector<LogCall>& get_captured_logs() const {
        return captured_logs_;
    }
};

std::vector<LoggingTest::LogCall> LoggingTest::captured_logs_;
LogCallback LoggingTest::original_callback_ = nullptr;

TEST_F(LoggingTest, BasicLogging) {
    LOG_INFO("Test message");
    
    ASSERT_EQ(get_captured_logs().size(), 1);
    EXPECT_EQ(get_captured_logs()[0].level, LogLevel::INFO);
    EXPECT_EQ(get_captured_logs()[0].tag, "TeslaBLE");
    EXPECT_EQ(get_captured_logs()[0].message, "Test message");
}

TEST_F(LoggingTest, LoggingWithFormat) {
    LOG_DEBUG("Value: %d, String: %s", 42, "test");
    
    ASSERT_EQ(get_captured_logs().size(), 1);
    EXPECT_EQ(get_captured_logs()[0].level, LogLevel::DEBUG);
    EXPECT_EQ(get_captured_logs()[0].message, "Value: 42, String: test");
}

TEST_F(LoggingTest, AllLogLevels) {
    LOG_ERROR("error message");
    LOG_WARNING("warning message");
    LOG_INFO("info message");
    LOG_DEBUG("debug message");
    LOG_VERBOSE("verbose message");
    
    ASSERT_EQ(get_captured_logs().size(), 5);
    EXPECT_EQ(get_captured_logs()[0].level, LogLevel::ERROR);
    EXPECT_EQ(get_captured_logs()[1].level, LogLevel::WARN);
    EXPECT_EQ(get_captured_logs()[2].level, LogLevel::INFO);
    EXPECT_EQ(get_captured_logs()[3].level, LogLevel::DEBUG);
    EXPECT_EQ(get_captured_logs()[4].level, LogLevel::VERBOSE);
}

TEST_F(LoggingTest, CustomTagInSource) {
    // This would require compiling a separate source file with a different TESLA_LOG_TAG
    // For now, we test that the default tag works
    LOG_INFO("message");
    EXPECT_EQ(get_captured_logs()[0].tag, "TeslaBLE");
}

TEST_F(LoggingTest, NullFormatHandling) {
    // Test that null format is handled gracefully
    log_internal(LogLevel::INFO, "TestTag", 42, nullptr);
    
    // Should not crash and should not add a log entry
    EXPECT_EQ(get_captured_logs().size(), 0);
}

TEST_F(LoggingTest, NullTagHandling) {
    // Test that null tag defaults to "TeslaBLE"
    log_internal(LogLevel::INFO, nullptr, 42, "message");
    
    ASSERT_EQ(get_captured_logs().size(), 1);
    EXPECT_EQ(get_captured_logs()[0].tag, "TeslaBLE");
    EXPECT_EQ(get_captured_logs()[0].message, "message");
}

TEST_F(LoggingTest, NoCallbackFallback) {
    // Temporarily remove callback to test fallback
    g_log_callback = nullptr;
    
    // This should not crash - it will use the fallback implementation
    EXPECT_NO_THROW(LOG_INFO("Fallback test"));
    
    // Restore callback
    g_log_callback = test_log_callback;
}

TEST_F(LoggingTest, FormatHexUtility) {
    const uint8_t data[] = {0x01, 0x02, 0x03, 0xAB, 0xCD, 0xEF};
    std::string hex = format_hex(data, sizeof(data));
    
    EXPECT_EQ(hex, "010203abcdef");
}

TEST_F(LoggingTest, FormatHexEmptyData) {
    std::string hex1 = format_hex(nullptr, 10);
    EXPECT_EQ(hex1, "");
    
    const uint8_t data[] = {0x01};
    std::string hex2 = format_hex(data, 0);
    EXPECT_EQ(hex2, "");
}

TEST_F(LoggingTest, FormatHexLargeData) {
    std::vector<uint8_t> data(256);
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = static_cast<uint8_t>(i);
    }
    
    std::string hex = format_hex(data.data(), data.size());
    
    // Should be 512 characters (2 per byte)
    EXPECT_EQ(hex.length(), 512);
    
    // Check first few bytes
    EXPECT_EQ(hex.substr(0, 4), "0001");
    
    // Check last byte (255 = 0xFF)
    EXPECT_EQ(hex.substr(510, 2), "ff");
}

TEST_F(LoggingTest, LongMessage) {
    std::string long_message(400, 'x');
    LOG_INFO("%s", long_message.c_str());
    
    ASSERT_EQ(get_captured_logs().size(), 1);
    // Message should be captured (may be truncated by vsnprintf buffer in callback)
    EXPECT_FALSE(get_captured_logs()[0].message.empty());
}

TEST_F(LoggingTest, MultipleMessages) {
    for (int i = 0; i < 10; i++) {
        LOG_INFO("Message %d", i);
    }
    
    EXPECT_EQ(get_captured_logs().size(), 10);
    for (int i = 0; i < 10; i++) {
        EXPECT_EQ(get_captured_logs()[i].message, "Message " + std::to_string(i));
    }
}
