#include "errors.h"

#include <map>
#include <string>

namespace TeslaBLE {
// add helper functions to convert error codes to strings
const char *teslable_status_to_string(TeslaBLE_Status_E status) {
  switch (status) {
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
std::map<TeslaBLE_Status_E, std::string> get_all_error_codes_and_strings() {
  return {
#define TESLA_BLE_ERROR_DEF(name, value, string) {name, string},
      TESLA_BLE_ERROR_CODES
#undef TESLA_BLE_ERROR_DEF
  };
}
}  // namespace TeslaBLE
