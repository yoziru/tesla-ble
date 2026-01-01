#pragma once

#ifdef ESP_PLATFORM

#ifndef LOG_LOCAL_LEVEL
#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#endif
#include "esp_log.h"
static const char *const TAG = "tesla_ble";
#define LOG(format, ...) ESP_LOGI(TAG, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) ESP_LOGI(TAG, format, ##__VA_ARGS__)
#define LOG_DEBUG(format, ...) ESP_LOGD(TAG, format, ##__VA_ARGS__)
#define LOG_ERROR(format, ...) ESP_LOGE(TAG, format, ##__VA_ARGS__)
#define LOG_WARNING(format, ...) ESP_LOGW(TAG, format, ##__VA_ARGS__)
#define LOG_VERBOSE(format, ...) ESP_LOGV(TAG, format, ##__VA_ARGS__)

#else

#include <cstdio>
#include <cstring>
#include <iostream>

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
#define LOG_VERBOSE(...) log("[VERBOSE]", DEBUG_COLOR, __VA_ARGS__)
template <typename... Args>
void log(const char *type, const char *color, const char *s, Args... args)
{
    printf("%s%s - ", color, type);
    if constexpr (sizeof...(args) > 0) {
        printf(s, args...);
    } else {
        printf("%s", s);
    }
    printf("%s\n", RESET_COLOR);
}

#endif
