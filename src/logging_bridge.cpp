#include "defs.h"

#include <cstdarg>
#include <cstdio>

namespace TeslaBLE {

// Global callback - encapsulated with getter/setter for const-correctness
static LogCallback g_log_callback = nullptr;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

void set_log_callback(LogCallback callback) { g_log_callback = callback; }

LogCallback get_log_callback() { return g_log_callback; }

void log_internal(LogLevel level, const char *tag, int line, const char *format, ...) {
  (void) line;  // Line number available for future use

  if (tag == nullptr)
    tag = "TeslaBLE";
  if (format == nullptr)
    return;

  va_list args;
  va_start(args, format);
  if (g_log_callback != nullptr) {
    g_log_callback(level, tag, line, format, args);
    va_end(args);
    return;
  }

  char buffer[1024];
  vsnprintf(buffer, sizeof(buffer), format, args);  // NOLINT(clang-analyzer-valist.Uninitialized)
  va_end(args);

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
  esp_log_write(esp_level, tag, "%s\n", buffer);
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
    default:
      level_str = "INFO ";
      break;
  }
  FILE *out = (level == LogLevel::ERROR) ? stderr : stdout;
  fprintf(out, "[%s][%s] %s\n", level_str, tag, buffer);  // NOLINT(modernize-use-std-print)
  fflush(out);
#endif
}

}  // namespace TeslaBLE
