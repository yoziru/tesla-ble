#pragma once

// https://github.com/platformio/platform-espressif32/issues/957
// specifically set when compiling with ESP-IDF
#ifdef ESP_PLATFORM
#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#endif

#ifdef ESP_PLATFORM
#include "esp_log.h"
static const char *const TAG = "tesla_ble";
#define LOG_ERROR(...) ESP_LOGE(TAG, __VA_ARGS__)
#define LOG_DEBUG(...) ESP_LOGE(TAG, __VA_ARGS__)
#define LOG_INFO(...) ESP_LOGE(TAG, __VA_ARGS__)
#else
#include <cstdio>
#include <cstdarg>

inline void LOG_ERROR(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    printf("\033[1;31m[E] ");
    vprintf(format, args);
    printf("\033[0m\n");
    va_end(args);
}

inline void LOG_DEBUG(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    printf("\033[1;34m[D] ");
    vprintf(format, args);
    printf("\033[0m\n");
    va_end(args);
}

inline void LOG_INFO(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    printf("\033[1;32m[i] ");
    vprintf(format, args);
    printf("\033[0m\n");
    va_end(args);
}
#endif
