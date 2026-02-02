#include "errors.h"

#include <map>
#include <string>

namespace TeslaBLE {
// add helper functions to convert error codes to strings
const char *teslable_status_to_string(TeslaBLEStatus status) {
  switch (status) {
    case TeslaBLEStatus::OK:
      return "OK";
    case TeslaBLEStatus::ERROR_INTERNAL:
      return "ERROR_INTERNAL";
    case TeslaBLEStatus::ERROR_PB_ENCODING:
      return "ERROR_PB_ENCODING";
    case TeslaBLEStatus::ERROR_PB_DECODING:
      return "ERROR_PB_DECODING";
    case TeslaBLEStatus::ERROR_PRIVATE_KEY_NOT_INITIALIZED:
      return "ERROR_PRIVATE_KEY_NOT_INITIALIZED";
    case TeslaBLEStatus::ERROR_INVALID_SESSION:
      return "ERROR_INVALID_SESSION";
    case TeslaBLEStatus::ERROR_ENCRYPT:
      return "ERROR_ENCRYPT";
    case TeslaBLEStatus::ERROR_DECRYPT:
      return "ERROR_DECRYPT";
    case TeslaBLEStatus::ERROR_INVALID_PARAMS:
      return "ERROR_INVALID_PARAMS";
    case TeslaBLEStatus::ERROR_CRYPTO:
      return "ERROR_CRYPTO";
    case TeslaBLEStatus::ERROR_COUNTER_REPLAY:
      return "ERROR_COUNTER_REPLAY";
    case TeslaBLEStatus::ERROR_SESSION_NOT_VALID:
      return "ERROR_SESSION_NOT_VALID";
    case TeslaBLEStatus::ERROR_NEEDS_REAUTH:
      return "ERROR_NEEDS_REAUTH";
    default:
      return "ERROR_UNKNOWN";
  }
}

// Helper function to get all error codes and their string representations for testing
std::map<TeslaBLEStatus, std::string> get_all_error_codes_and_strings() {
  std::map<TeslaBLEStatus, std::string> error_map;
  error_map[TeslaBLEStatus::OK] = "OK";
  error_map[TeslaBLEStatus::ERROR_INTERNAL] = "ERROR_INTERNAL";
  error_map[TeslaBLEStatus::ERROR_PB_ENCODING] = "ERROR_PB_ENCODING";
  error_map[TeslaBLEStatus::ERROR_PB_DECODING] = "ERROR_PB_DECODING";
  error_map[TeslaBLEStatus::ERROR_PRIVATE_KEY_NOT_INITIALIZED] = "ERROR_PRIVATE_KEY_NOT_INITIALIZED";
  error_map[TeslaBLEStatus::ERROR_INVALID_SESSION] = "ERROR_INVALID_SESSION";
  error_map[TeslaBLEStatus::ERROR_ENCRYPT] = "ERROR_ENCRYPT";
  error_map[TeslaBLEStatus::ERROR_DECRYPT] = "ERROR_DECRYPT";
  error_map[TeslaBLEStatus::ERROR_INVALID_PARAMS] = "ERROR_INVALID_PARAMS";
  error_map[TeslaBLEStatus::ERROR_CRYPTO] = "ERROR_CRYPTO";
  error_map[TeslaBLEStatus::ERROR_COUNTER_REPLAY] = "ERROR_COUNTER_REPLAY";
  error_map[TeslaBLEStatus::ERROR_SESSION_NOT_VALID] = "ERROR_SESSION_NOT_VALID";
  error_map[TeslaBLEStatus::ERROR_NEEDS_REAUTH] = "ERROR_NEEDS_REAUTH";
  return error_map;
}
}  // namespace TeslaBLE
