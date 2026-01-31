/**
 * @file vin_utils.h
 * @brief Utility functions for VIN-based vehicle identification
 */

#ifndef TESLABLE_VIN_UTILS_H
#define TESLABLE_VIN_UTILS_H

#include <string>

namespace TeslaBLE {

/**
 * @brief Get the BLE advertisement local name for a Tesla vehicle.
 *
 * Tesla vehicles advertise with a name in the format `S<ID>C`, where `<ID>` is the
 * lower-case hex-encoding of the first eight bytes of the SHA1 digest of the
 * Vehicle Identification Number (VIN).
 *
 * For example, if the VIN is `5YJS0000000000000`, then the BLE advertisement
 * Local Name is `S1a87a5a75f3df858C`.
 *
 * @param vin The 17-character Vehicle Identification Number
 * @return The BLE advertisement name (e.g., "S1a87a5a75f3df858C"), or empty string on error
 */
std::string get_vin_advertisement_name(const char *vin);
std::string get_vin_advertisement_name(const std::string &vin);

/**
 * @brief Check if a BLE device name matches the Tesla vehicle advertisement pattern.
 *
 * Tesla vehicles advertise with names like "S1a87a5a75f3df858C".
 *
 * @param name The BLE device name to check
 * @return true if the name matches the Tesla pattern
 */
bool is_tesla_vehicle_name(const char *name);
bool is_tesla_vehicle_name(const std::string &name);

/**
 * @brief Check if a BLE device name matches a specific VIN.
 *
 * @param deviceName The BLE advertisement name
 * @param vin The 17-character VIN to match
 * @return true if the device name corresponds to this VIN
 */
bool matches_vin(const char *device_name, const char *vin);
bool matches_vin(const std::string &device_name, const std::string &vin);

}  // namespace TeslaBLE

#endif  // TESLABLE_VIN_UTILS_H
