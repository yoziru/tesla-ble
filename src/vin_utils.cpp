/**
 * @file vin_utils.cpp
 * @brief Implementation of VIN-based vehicle identification utilities
 */

#include "vin_utils.h"

#include <mbedtls/sha1.h>

#include <cctype>
#include <cstring>

namespace TeslaBLE {

std::string get_vin_advertisement_name(const char *vin) {
  if (!vin || strlen(vin) != 17) {
    return "";
  }

  // Calculate SHA1 of the VIN
  unsigned char sha1_hash[20];
  int status = mbedtls_sha1(reinterpret_cast<const unsigned char *>(vin), 17, sha1_hash);
  if (status != 0) {
    return "";
  }

  // Build result: 'S' + 16 hex chars (first 8 bytes) + 'C'
  char name[19];
  name[0] = 'S';

  for (int i = 0; i < 8; ++i) {
    snprintf(&name[1 + (i * 2)], 3, "%02x", sha1_hash[i]);
  }

  name[17] = 'C';
  name[18] = '\0';

  return std::string(name);
}

std::string get_vin_advertisement_name(const std::string &vin) { return get_vin_advertisement_name(vin.c_str()); }

bool is_tesla_vehicle_name(const char *name) {
  if (!name) {
    return false;
  }
  const size_t length = strlen(name);

  // Old scheme: 'S' + 16 hex chars + one of C/R/D/P (center/rear/driver/passenger beacon).
  if (length == 18 && name[0] == 'S' && strchr("CDRP", toupper(static_cast<unsigned char>(name[17])))) {
    for (int i = 1; i < 17; ++i) {
      if (!isxdigit(static_cast<unsigned char>(name[i]))) {
        return false;
      }
    }
    return true;
  }

  // New scheme (2023+): "Tesla " + last 6 characters of the VIN.
  if (length == 12 && strncmp(name, "Tesla ", 6) == 0) {
    for (int i = 6; i < 12; ++i) {
      if (!isalnum(static_cast<unsigned char>(name[i]))) {
        return false;
      }
    }
    return true;
  }

  return false;
}

bool is_tesla_vehicle_name(const std::string &name) { return is_tesla_vehicle_name(name.c_str()); }

bool matches_vin(const char *device_name, const char *vin) {
  if (!device_name || !vin || strlen(vin) != 17) {
    return false;
  }
  std::string expected_name = get_vin_advertisement_name(vin);
  if (expected_name.empty()) {
    return false;
  }
  std::string actual(device_name);
  // Old scheme: same "S<16 hex>" prefix; the last character selects the
  // beacon (center/rear/driver/passenger) and may differ from the default 'C'.
  if (actual.size() == 18 && actual.compare(0, 17, expected_name, 0, 17) == 0 &&
      strchr("CDRP", toupper(static_cast<unsigned char>(actual[17])))) {
    return true;
  }
  // New scheme: "Tesla " + last 6 characters of the VIN.
  return std::string("Tesla ") + (vin + 11) == actual;
}

bool matches_vin(const std::string &device_name, const std::string &vin) {
  return matches_vin(device_name.c_str(), vin.c_str());
}

}  // namespace TeslaBLE
