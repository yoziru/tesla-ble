#ifndef TESLA_BLE_ERRORS_H
#define TESLA_BLE_ERRORS_H

#ifdef __cplusplus
#include <map>
#include <string>
namespace TeslaBLE {
#endif

// Enum class for Tesla BLE status codes
enum class TeslaBLEStatus : int {
  OK = 0,
  ERROR_INTERNAL = 1,
  ERROR_PB_ENCODING = 2,
  ERROR_PB_DECODING = 3,
  ERROR_PRIVATE_KEY_NOT_INITIALIZED = 4,
  ERROR_INVALID_SESSION = 5,
  ERROR_ENCRYPT = 6,
  ERROR_DECRYPT = 7,
  ERROR_INVALID_PARAMS = 8,
  ERROR_CRYPTO = 9,
  ERROR_COUNTER_REPLAY = 10,
  ERROR_SESSION_NOT_VALID = 11,
  ERROR_NEEDS_REAUTH = 12
};

#ifdef __cplusplus
// Add helper functions to convert error codes to strings
const char *teslable_status_to_string(TeslaBLEStatus status);

// Helper function to get all error codes and their string representations for testing
std::map<TeslaBLEStatus, std::string> get_all_error_codes_and_strings();
}
#endif

#endif  // TESLA_BLE_ERRORS_H
