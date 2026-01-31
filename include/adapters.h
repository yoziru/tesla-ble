#pragma once

#include <vector>
#include <cstdint>
#include <string>

// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables) - False positive on namespace
namespace TeslaBLE {

/**
 * @brief Abstract interface for BLE operations.
 *
 * Platforms (ESPHome, Python/Bleak) must implement this to handle
 * low-level BLE communication.
 */
class BleAdapter {
 public:
  virtual ~BleAdapter() = default;

  /**
   * @brief Connect to a specific BLE device.
   * @param address The MAC address or identifier of the device.
   */
  virtual void connect(const std::string &address) = 0;

  /**
   * @brief Disconnect from the current device.
   */
  virtual void disconnect() = 0;

  /**
   * @brief Write data to the vehicle.
   *
   * The implementation should handle writing to the correct RX characteristic
   * of the Tesla service.
   *
   * @param data The raw bytes to send.
   * @return true if written successfully (enqueued), false otherwise.
   */
  virtual bool write(const std::vector<uint8_t> &data) = 0;

  // Callbacks for data reception and connection state should be handled
  // by registering the Vehicle instance with the platform's BLE handler,
  // or by the platform calling Vehicle::on_rx_data().
};

/**
 * @brief Abstract interface for persistent storage.
 *
 * Used to securely store session keys, counters, and tokens.
 */
class StorageAdapter {
 public:
  virtual ~StorageAdapter() = default;

  /**
   * @brief Load a value from storage.
   * @param key The unique key identifier.
   * @param buffer Output buffer to store the loaded data.
   * @return true if found and loaded, false otherwise.
   */
  virtual bool load(const std::string &key, std::vector<uint8_t> &buffer) = 0;

  /**
   * @brief Save a value to storage.
   * @param key The unique key identifier.
   * @param buffer The data to save.
   * @return true if saved successfully, false otherwise.
   */
  virtual bool save(const std::string &key, const std::vector<uint8_t> &buffer) = 0;

  /**
   * @brief Remove a value from storage.
   * @param key The unique key identifier.
   * @return true if removed successfully, false otherwise.
   */
  virtual bool remove(const std::string &key) = 0;
};

}  // namespace TeslaBLE
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)
