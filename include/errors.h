#ifndef TESLA_BLE_ERRORS_H
#define TESLA_BLE_ERRORS_H

#ifdef __cplusplus
#include <map>
#include <string>
namespace TeslaBLE {
#endif

// Macro to define error codes and their string representations
#define TESLA_BLE_ERROR_CODES \
  TESLA_BLE_ERROR_DEF(TeslaBLE_Status_E_OK, 0, "OK") \
  TESLA_BLE_ERROR_DEF(TeslaBLE_Status_E_ERROR_INTERNAL, 1, "ERROR_INTERNAL") \
  TESLA_BLE_ERROR_DEF(TeslaBLE_Status_E_ERROR_PB_ENCODING, 2, "ERROR_PB_ENCODING") \
  TESLA_BLE_ERROR_DEF(TeslaBLE_Status_E_ERROR_PB_DECODING, 3, "ERROR_PB_DECODING") \
  TESLA_BLE_ERROR_DEF(TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED, 4, "ERROR_PRIVATE_KEY_NOT_INITIALIZED") \
  TESLA_BLE_ERROR_DEF(TeslaBLE_Status_E_ERROR_INVALID_SESSION, 5, "ERROR_INVALID_SESSION") \
  TESLA_BLE_ERROR_DEF(TeslaBLE_Status_E_ERROR_ENCRYPT, 6, "ERROR_ENCRYPT") \
  TESLA_BLE_ERROR_DEF(TeslaBLE_Status_E_ERROR_DECRYPT, 7, "ERROR_DECRYPT") \
  TESLA_BLE_ERROR_DEF(TeslaBLE_Status_E_ERROR_INVALID_PARAMS, 8, "ERROR_INVALID_PARAMS") \
  TESLA_BLE_ERROR_DEF(TeslaBLE_Status_E_ERROR_CRYPTO, 9, "ERROR_CRYPTO") \
  TESLA_BLE_ERROR_DEF(TeslaBLE_Status_E_ERROR_COUNTER_REPLAY, 10, "ERROR_COUNTER_REPLAY") \
  TESLA_BLE_ERROR_DEF(TeslaBLE_Status_E_ERROR_SESSION_NOT_VALID, 11, "ERROR_SESSION_NOT_VALID") \
  TESLA_BLE_ERROR_DEF(TeslaBLE_Status_E_ERROR_NEEDS_REAUTH, 12, "ERROR_NEEDS_REAUTH")

// Define the enum using the macro
// NOLINTBEGIN(bugprone-reserved-identifier, cppcoreguidelines-use-enum-class, readability-identifier-naming)
#define TESLA_BLE_ERROR_DEF(name, value, string) name = (value),
using TeslaBLE_Status_E = enum TeslaBLE_Status_E_ { TESLA_BLE_ERROR_CODES };
// NOLINTEND(bugprone-reserved-identifier, cppcoreguidelines-use-enum-class, readability-identifier-naming)
#undef TESLA_BLE_ERROR_DEF

#ifdef __cplusplus
// Add helper functions to convert error codes to strings
const char *teslable_status_to_string(TeslaBLE_Status_E status);

// Helper function to get all error codes and their string representations for testing
std::map<TeslaBLE_Status_E, std::string> get_all_error_codes_and_strings();
}
#endif

#endif  // TESLA_BLE_ERRORS_H
