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
  if (vin == nullptr || strlen(vin) != 17) {
    return "";
  }

  // Calculate SHA1 of the VIN
  unsigned char sha1_hash[20];
  int ret = mbedtls_sha1(reinterpret_cast<const unsigned char *>(vin), 17, sha1_hash);

  if (ret != 0) {
    return "";
  }

  // Build result: 'S' + 16 hex chars (first 8 bytes) + 'C'
  char result[19];
  result[0] = 'S';

  for (int i = 0; i < 8; i++) {
    snprintf(&result[1 + (i * 2)], 3, "%02x", sha1_hash[i]);
  }

  result[17] = 'C';
  result[18] = '\0';

  return std::string(result);
}

std::string get_vin_advertisement_name(const std::string &vin) { return get_vin_advertisement_name(vin.c_str()); }

bool is_tesla_vehicle_name(const char *name) {
  if (name == nullptr) {
    return false;
  }

  size_t len = strlen(name);
  if (len != 18) {
    return false;
  }

  if (name[0] != 'S' || name[17] != 'C') {
    return false;
  }

  // Check that the middle 16 characters are valid hex
  for (int i = 1; i < 17; i++) {
    if (!isxdigit(static_cast<unsigned char>(name[i]))) {
      return false;
    }
  }

  return true;
}

bool is_tesla_vehicle_name(const std::string &name) { return is_tesla_vehicle_name(name.c_str()); }

bool matches_vin(const char *device_name, const char *vin) {
  if (device_name == nullptr || vin == nullptr) {
    return false;
  }
  std::string expected_name = get_vin_advertisement_name(vin);
  if (expected_name.empty()) {
    return false;
  }
  return expected_name == device_name;
}

bool matches_vin(const std::string &device_name, const std::string &vin) {
  return matches_vin(device_name.c_str(), vin.c_str());
}

}  // namespace TeslaBLE
