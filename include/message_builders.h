#pragma once

#include <unordered_map>

#include "car_server.pb.h"

namespace TeslaBLE {
/**
 * @brief Factory class for building vehicle action messages.
 *
 * This class provides a clean, extensible way to build different types
 * of vehicle action messages without code duplication.
 */
class VehicleActionBuilder {
 public:
  using BuilderFunction = int (*)(CarServer_VehicleAction &, const void *);

  /**
   * @brief Get the map of builders for direct access
   * @return Reference to the builders map
   */
  static const std::unordered_map<pb_size_t, BuilderFunction> &get_builders() { return builders_; }

 private:
  // Builder functions for different action types
  static int build_charging_set_limit(CarServer_VehicleAction &action, const void *data);
  static int build_charging_start_stop(CarServer_VehicleAction &action, const void *data);
  static int build_set_charging_amps(CarServer_VehicleAction &action, const void *data);
  static int build_charge_port_door_open(CarServer_VehicleAction &action, const void *data);
  static int build_charge_port_door_close(CarServer_VehicleAction &action, const void *data);
  static int build_scheduled_charging(CarServer_VehicleAction &action, const void *data);
  static int build_hvac_auto_action(CarServer_VehicleAction &action, const void *data);
  static int build_hvac_steering_wheel_heater(CarServer_VehicleAction &action, const void *data);
  static int build_vehicle_control_flash_lights(CarServer_VehicleAction &action, const void *data);
  static int build_vehicle_control_honk_horn(CarServer_VehicleAction &action, const void *data);
  static int build_vehicle_control_set_sentry_mode(CarServer_VehicleAction &action, const void *data);
  static int build_vehicle_control_cancel_software_update(CarServer_VehicleAction &action, const void *data);
  static int build_vehicle_control_reset_valet_pin(CarServer_VehicleAction &action, const void *data);
  static int build_vehicle_control_reset_pin_to_drive(CarServer_VehicleAction &action, const void *data);
  static int build_driving_clear_speed_limit_pin_admin(CarServer_VehicleAction &action, const void *data);
  static int build_vehicle_control_reset_pin_to_drive_admin(CarServer_VehicleAction &action, const void *data);
  static int build_media_play_action(CarServer_VehicleAction &action, const void *data);
  static int build_media_next_favorite(CarServer_VehicleAction &action, const void *data);
  static int build_media_previous_favorite(CarServer_VehicleAction &action, const void *data);
  static int build_media_next_track(CarServer_VehicleAction &action, const void *data);
  static int build_media_previous_track(CarServer_VehicleAction &action, const void *data);
  static int build_ping_action(CarServer_VehicleAction &action, const void *data);
  static int build_vehicle_control_window_action(CarServer_VehicleAction &action, const void *data);
  static int build_hvac_set_preconditioning_max(CarServer_VehicleAction &action, const void *data);
  static int build_hvac_temperature_adjustment(CarServer_VehicleAction &action, const void *data);
  static int build_hvac_climate_keeper(CarServer_VehicleAction &action, const void *data);
  static int build_hvac_bioweapon_mode(CarServer_VehicleAction &action, const void *data);
  static int build_vehicle_control_schedule_software_update(CarServer_VehicleAction &action, const void *data);
  static int build_set_cabin_overheat_protection(CarServer_VehicleAction &action, const void *data);

  // Map of action types to their builder functions
  static const std::unordered_map<pb_size_t, BuilderFunction> builders_;

  // Helper functions
  static int validate_input_parameters(const pb_byte_t *output_buffer, const size_t *output_length);
  static int validate_charging_limit(int32_t percent);
  static int validate_charging_amps(int32_t amps);
};

/**
 * @brief Utility class for parameter validation
 */
class ParameterValidator {
 public:
  static bool is_valid_charging_limit(int32_t percent);
  static bool is_valid_charging_amps(int32_t amps);
  static bool is_valid_ping_value(int32_t ping_value);
  static bool is_valid_vin(const char *vin);
  static bool is_valid_connection_id(const pb_byte_t *connection_id);
};

}  // namespace TeslaBLE
