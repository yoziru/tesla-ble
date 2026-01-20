#include <cstdarg>
#include <cstdio>
#include <print>

#include "defs.h"

namespace TeslaBLE {

LogCallback g_log_callback = nullptr;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

void setLogCallback(LogCallback callback) { g_log_callback = callback; }

void log_internal(LogLevel level, const char *tag, int line, const char *format, ...) {
  if (tag == nullptr)
    tag = "TeslaBLE";
  if (format == nullptr)
    return;

  va_list args;
  va_start(args, format);

  if (g_log_callback != nullptr) {
    g_log_callback(level, tag, line, format, args);
  } else {
#ifdef ESP_PLATFORM
    esp_log_level_t esp_level;
    switch (level) {
      case LogLevel::ERROR:
        esp_level = ESP_LOG_ERROR;
        break;
      case LogLevel::WARN:
        esp_level = ESP_LOG_WARN;
        break;
      case LogLevel::INFO:
        esp_level = ESP_LOG_INFO;
        break;
      case LogLevel::DEBUG:
        esp_level = ESP_LOG_DEBUG;
        break;
      case LogLevel::VERBOSE:
        esp_level = ESP_LOG_VERBOSE;
        break;
      default:
        esp_level = ESP_LOG_NONE;
        break;
    }
    esp_log_writev(esp_level, tag, format, args);
#else
    const char *level_str;
    switch (level) {
      case LogLevel::ERROR:
        level_str = "ERROR";
        break;
      case LogLevel::WARN:
        level_str = "WARN ";
        break;
      case LogLevel::INFO:
        level_str = "INFO ";
        break;
      case LogLevel::DEBUG:
        level_str = "DEBUG";
        break;
      case LogLevel::VERBOSE:
        level_str = "VERBOSE";
        break;
    }
    std::print("[{}][{}] ", level_str, tag);
    vprintf(format, args);
    std::println("");
#endif
  }

  va_end(args);
}

}  // namespace TeslaBLE
