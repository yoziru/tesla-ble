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
}  // namespace TeslaBLE
