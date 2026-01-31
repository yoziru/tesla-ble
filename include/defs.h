#pragma once

#ifndef TESLA_LOG_TAG
#define TESLA_LOG_TAG "TeslaBLE"
#endif

#include <cstdarg>
#include "adapters.h"

#ifdef ESP_PLATFORM
#include <esp_log.h>
#endif

// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables) - False positive on namespace
namespace TeslaBLE {

enum class LogLevel { ERROR, WARN, INFO, DEBUG, VERBOSE };

using LogCallback = void (*)(LogLevel level, const char *tag, int line, const char *format, va_list args);

void set_log_callback(LogCallback callback);
LogCallback get_log_callback();
void log_internal(LogLevel level, const char *tag, int line, const char *format, ...);

}  // namespace TeslaBLE
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)

#define LOG_ERROR(format, ...) \
  TeslaBLE::log_internal(TeslaBLE::LogLevel::ERROR, TESLA_LOG_TAG, __LINE__, format, ##__VA_ARGS__)
#define LOG_WARNING(format, ...) \
  TeslaBLE::log_internal(TeslaBLE::LogLevel::WARN, TESLA_LOG_TAG, __LINE__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) \
  TeslaBLE::log_internal(TeslaBLE::LogLevel::INFO, TESLA_LOG_TAG, __LINE__, format, ##__VA_ARGS__)
#define LOG_DEBUG(format, ...) \
  TeslaBLE::log_internal(TeslaBLE::LogLevel::DEBUG, TESLA_LOG_TAG, __LINE__, format, ##__VA_ARGS__)
#define LOG_VERBOSE(format, ...) \
  TeslaBLE::log_internal(TeslaBLE::LogLevel::VERBOSE, TESLA_LOG_TAG, __LINE__, format, ##__VA_ARGS__)
