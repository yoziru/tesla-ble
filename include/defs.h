#pragma once

#ifdef ESP_PLATFORM

#include "esp_log.h"
static const char *const TAG = "tesla_ble";
#define CONFIG_LOG_DEFAULT_LEVEL_DEBUG
#define LOG(...) ESP_LOGI(TAG, __VA_ARGS__)
#define LOG_INFO(...) ESP_LOGI(TAG, __VA_ARGS__)
#define LOG_DEBUG(...) ESP_LOGD(TAG, __VA_ARGS__)
#define LOG_ERROR(...) ESP_LOGE(TAG, __VA_ARGS__)
#define LOG_WARNING(...) ESP_LOGW(TAG, __VA_ARGS__)

#else

#include <cstdio>
#include <cstring>
#define RESET_COLOR "\x1B[0m"
#define INFO_COLOR "\x1B[1;34m"
#define DEBUG_COLOR "\x1B[1;30m"
#define WARNING_COLOR "\x1B[1;33m"
#define ERROR_COLOR "\x1B[31m"
#define LOG(...) log("[LOG]", RESET_COLOR, __VA_ARGS__)
#define LOG_INFO(...) log("[INFO]", INFO_COLOR, __VA_ARGS__)
#define LOG_DEBUG(...) log("[DEBUG]", DEBUG_COLOR, __VA_ARGS__)
#define LOG_WARNING(...) log("[WARNING]", WARNING_COLOR, __VA_ARGS__)
#define LOG_ERROR(...) log("[ERROR]", ERROR_COLOR, __VA_ARGS__)
template <typename... Args>
void log(const char *type, const char *color, const char *s, Args... args)
{
    printf("%s%s - ", color, type);
    printf(s, args...);
    printf("%s\n", RESET_COLOR);
}

#endif
