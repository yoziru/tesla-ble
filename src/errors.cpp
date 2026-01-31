#include "errors.h"

#include <map>
#include <string>

namespace TeslaBLE {
// add helper functions to convert error codes to strings
const char *teslable_status_to_string(int status) {
  TeslaBLE_Status_E status_enum = static_cast<TeslaBLE_Status_E>(status);
  switch (status_enum) {
#define TESLA_BLE_ERROR_DEF(name, value, string) \
  case name: \
    return string;
    TESLA_BLE_ERROR_CODES
#undef TESLA_BLE_ERROR_DEF
    default:
      return "ERROR_UNKNOWN";
  }
}

// Helper function to get all error codes and their string representations for testing
std::map<TeslaBLE_Status_E, std::string> getAllErrorCodesAndStrings() {
  std::map<TeslaBLE_Status_E, std::string> error_map;
#define TESLA_BLE_ERROR_DEF(name, value, string) error_map[name] = string;
  TESLA_BLE_ERROR_CODES
#undef TESLA_BLE_ERROR_DEF
  return error_map;
}
}  // namespace TeslaBLE
