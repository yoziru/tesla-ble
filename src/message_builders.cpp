#include "message_builders.h"
#include "defs.h"
#include "car_server.pb.h"
#include "errors.h"

namespace TeslaBLE {

// Forward declarations of builder functions
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

// Initialize the static builder map
const std::unordered_map<pb_size_t, VehicleActionBuilder::BuilderFunction> VehicleActionBuilder::builders_ = {
    {CarServer_VehicleAction_chargingSetLimitAction_tag, build_charging_set_limit},
    {CarServer_VehicleAction_chargingStartStopAction_tag, build_charging_start_stop},
    {CarServer_VehicleAction_setChargingAmpsAction_tag, build_set_charging_amps},
    {CarServer_VehicleAction_chargePortDoorOpen_tag, build_charge_port_door_open},
    {CarServer_VehicleAction_chargePortDoorClose_tag, build_charge_port_door_close},
    {CarServer_VehicleAction_scheduledChargingAction_tag, build_scheduled_charging},
    {CarServer_VehicleAction_hvacAutoAction_tag, build_hvac_auto_action},
    {CarServer_VehicleAction_hvacSteeringWheelHeaterAction_tag, build_hvac_steering_wheel_heater},
    {CarServer_VehicleAction_vehicleControlFlashLightsAction_tag, build_vehicle_control_flash_lights},
    {CarServer_VehicleAction_vehicleControlHonkHornAction_tag, build_vehicle_control_honk_horn},
    {CarServer_VehicleAction_vehicleControlSetSentryModeAction_tag, build_vehicle_control_set_sentry_mode},
    {CarServer_VehicleAction_vehicleControlCancelSoftwareUpdateAction_tag,
     build_vehicle_control_cancel_software_update},
    {CarServer_VehicleAction_vehicleControlResetValetPinAction_tag, build_vehicle_control_reset_valet_pin},
    {CarServer_VehicleAction_vehicleControlResetPinToDriveAction_tag, build_vehicle_control_reset_pin_to_drive},
    {CarServer_VehicleAction_drivingClearSpeedLimitPinAdminAction_tag, build_driving_clear_speed_limit_pin_admin},
    {CarServer_VehicleAction_vehicleControlResetPinToDriveAdminAction_tag,
     build_vehicle_control_reset_pin_to_drive_admin},
    {CarServer_VehicleAction_mediaPlayAction_tag, build_media_play_action},
    {CarServer_VehicleAction_mediaNextFavorite_tag, build_media_next_favorite},
    {CarServer_VehicleAction_mediaPreviousFavorite_tag, build_media_previous_favorite},
    {CarServer_VehicleAction_mediaNextTrack_tag, build_media_next_track},
    {CarServer_VehicleAction_mediaPreviousTrack_tag, build_media_previous_track},
    {CarServer_VehicleAction_ping_tag, build_ping_action},
    {CarServer_VehicleAction_vehicleControlWindowAction_tag, build_vehicle_control_window_action},
    {CarServer_VehicleAction_hvacSetPreconditioningMaxAction_tag, build_hvac_set_preconditioning_max},
    {CarServer_VehicleAction_hvacTemperatureAdjustmentAction_tag, build_hvac_temperature_adjustment},
    {CarServer_VehicleAction_hvacClimateKeeperAction_tag, build_hvac_climate_keeper},
    {CarServer_VehicleAction_hvacBioweaponModeAction_tag, build_hvac_bioweapon_mode},
    {CarServer_VehicleAction_vehicleControlScheduleSoftwareUpdateAction_tag,
     build_vehicle_control_schedule_software_update},
    {CarServer_VehicleAction_setCabinOverheatProtectionAction_tag, build_set_cabin_overheat_protection}};

// Builder implementations
int VehicleActionBuilder::build_charging_set_limit(CarServer_VehicleAction &action, const void *data) {
  if (!data) {
    LOG_ERROR("Charging set limit action requires int32_t data");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  int32_t percent = *static_cast<const int32_t *>(data);
  int result = validate_charging_limit(percent);
  if (result != TeslaBLE_Status_E_OK) {
    return result;
  }

  action.vehicle_action_msg.chargingSetLimitAction = CarServer_ChargingSetLimitAction_init_default;
  action.vehicle_action_msg.chargingSetLimitAction.percent = percent;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_charging_start_stop(CarServer_VehicleAction &action, const void *data) {
  if (!data) {
    LOG_ERROR("Charging start/stop action requires boolean data");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  bool start = *static_cast<const bool *>(data);
  action.vehicle_action_msg.chargingStartStopAction = CarServer_ChargingStartStopAction_init_default;

  if (start) {
    action.vehicle_action_msg.chargingStartStopAction.which_charging_action =
        CarServer_ChargingStartStopAction_start_tag;
    action.vehicle_action_msg.chargingStartStopAction.charging_action.start = CarServer_Void_init_default;
  } else {
    action.vehicle_action_msg.chargingStartStopAction.which_charging_action =
        CarServer_ChargingStartStopAction_stop_tag;
    action.vehicle_action_msg.chargingStartStopAction.charging_action.stop = CarServer_Void_init_default;
  }

  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_set_charging_amps(CarServer_VehicleAction &action, const void *data) {
  if (!data) {
    LOG_ERROR("Set charging amps action requires int32_t data");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  int32_t amps = *static_cast<const int32_t *>(data);
  int result = validate_charging_amps(amps);
  if (result != TeslaBLE_Status_E_OK) {
    return result;
  }

  action.vehicle_action_msg.setChargingAmpsAction = CarServer_SetChargingAmpsAction_init_default;
  action.vehicle_action_msg.setChargingAmpsAction.charging_amps = amps;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_charge_port_door_open(CarServer_VehicleAction &action, const void *data) {
  action.vehicle_action_msg.chargePortDoorOpen = CarServer_ChargePortDoorOpen_init_default;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_charge_port_door_close(CarServer_VehicleAction &action, const void *data) {
  action.vehicle_action_msg.chargePortDoorClose = CarServer_ChargePortDoorClose_init_default;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_scheduled_charging(CarServer_VehicleAction &action, const void *data) {
  if (!data) {
    LOG_ERROR("Scheduled charging action requires CarServer_ScheduledChargingAction data");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  const auto *sched_data = static_cast<const CarServer_ScheduledChargingAction *>(data);
  action.vehicle_action_msg.scheduledChargingAction = *sched_data;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_hvac_auto_action(CarServer_VehicleAction &action, const void *data) {
  if (!data) {
    LOG_ERROR("HVAC auto action requires boolean data");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  bool is_on = *static_cast<const bool *>(data);
  action.vehicle_action_msg.hvacAutoAction = CarServer_HvacAutoAction_init_default;
  action.vehicle_action_msg.hvacAutoAction.power_on = is_on;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_hvac_steering_wheel_heater(CarServer_VehicleAction &action, const void *data) {
  if (!data) {
    LOG_ERROR("HVAC steering wheel heater action requires boolean data");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  bool is_on = *static_cast<const bool *>(data);
  action.vehicle_action_msg.hvacSteeringWheelHeaterAction = CarServer_HvacSteeringWheelHeaterAction_init_default;
  action.vehicle_action_msg.hvacSteeringWheelHeaterAction.power_on = is_on;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_vehicle_control_flash_lights(CarServer_VehicleAction &action, const void *data) {
  action.vehicle_action_msg.vehicleControlFlashLightsAction = CarServer_VehicleControlFlashLightsAction_init_default;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_vehicle_control_honk_horn(CarServer_VehicleAction &action, const void *data) {
  action.vehicle_action_msg.vehicleControlHonkHornAction = CarServer_VehicleControlHonkHornAction_init_default;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_vehicle_control_set_sentry_mode(CarServer_VehicleAction &action, const void *data) {
  if (!data) {
    LOG_ERROR("Vehicle control set sentry mode action requires boolean data");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  bool is_on = *static_cast<const bool *>(data);
  action.vehicle_action_msg.vehicleControlSetSentryModeAction =
      CarServer_VehicleControlSetSentryModeAction_init_default;
  action.vehicle_action_msg.vehicleControlSetSentryModeAction.on = is_on;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_vehicle_control_cancel_software_update(CarServer_VehicleAction &action,
                                                                       const void *data) {
  action.vehicle_action_msg.vehicleControlCancelSoftwareUpdateAction =
      CarServer_VehicleControlCancelSoftwareUpdateAction_init_default;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_vehicle_control_reset_valet_pin(CarServer_VehicleAction &action, const void *data) {
  action.vehicle_action_msg.vehicleControlResetValetPinAction =
      CarServer_VehicleControlResetValetPinAction_init_default;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_vehicle_control_reset_pin_to_drive(CarServer_VehicleAction &action, const void *data) {
  action.vehicle_action_msg.vehicleControlResetPinToDriveAction =
      CarServer_VehicleControlResetPinToDriveAction_init_default;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_driving_clear_speed_limit_pin_admin(CarServer_VehicleAction &action, const void *data) {
  action.vehicle_action_msg.drivingClearSpeedLimitPinAdminAction =
      CarServer_DrivingClearSpeedLimitPinAdminAction_init_default;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_vehicle_control_reset_pin_to_drive_admin(CarServer_VehicleAction &action,
                                                                         const void *data) {
  action.vehicle_action_msg.vehicleControlResetPinToDriveAdminAction =
      CarServer_VehicleControlResetPinToDriveAdminAction_init_default;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_media_play_action(CarServer_VehicleAction &action, const void *data) {
  action.vehicle_action_msg.mediaPlayAction = CarServer_MediaPlayAction_init_default;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_media_next_favorite(CarServer_VehicleAction &action, const void *data) {
  action.vehicle_action_msg.mediaNextFavorite = CarServer_MediaNextFavorite_init_default;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_media_previous_favorite(CarServer_VehicleAction &action, const void *data) {
  action.vehicle_action_msg.mediaPreviousFavorite = CarServer_MediaPreviousFavorite_init_default;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_media_next_track(CarServer_VehicleAction &action, const void *data) {
  action.vehicle_action_msg.mediaNextTrack = CarServer_MediaNextTrack_init_default;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_media_previous_track(CarServer_VehicleAction &action, const void *data) {
  action.vehicle_action_msg.mediaPreviousTrack = CarServer_MediaPreviousTrack_init_default;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_ping_action(CarServer_VehicleAction &action, const void *data) {
  if (!data) {
    LOG_ERROR("Ping action requires int32_t data");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  int32_t ping_value = *static_cast<const int32_t *>(data);
  action.vehicle_action_msg.ping = CarServer_Ping_init_default;
  action.vehicle_action_msg.ping.ping_id = ping_value;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_vehicle_control_window_action(CarServer_VehicleAction &action, const void *data) {
  if (!data) {
    LOG_ERROR("Vehicle control window action requires int32_t data (0=vent, 1=close)");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  int32_t window_action = *static_cast<const int32_t *>(data);
  action.vehicle_action_msg.vehicleControlWindowAction = CarServer_VehicleControlWindowAction_init_default;

  if (window_action == 0) {
    // Vent windows
    action.vehicle_action_msg.vehicleControlWindowAction.which_action = CarServer_VehicleControlWindowAction_vent_tag;
    action.vehicle_action_msg.vehicleControlWindowAction.action.vent = CarServer_Void_init_default;
  } else {
    // Close windows
    action.vehicle_action_msg.vehicleControlWindowAction.which_action = CarServer_VehicleControlWindowAction_close_tag;
    action.vehicle_action_msg.vehicleControlWindowAction.action.close = CarServer_Void_init_default;
  }

  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_hvac_set_preconditioning_max(CarServer_VehicleAction &action, const void *data) {
  if (!data) {
    LOG_ERROR("HVAC set preconditioning max action requires boolean data");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  bool is_on = *static_cast<const bool *>(data);
  action.vehicle_action_msg.hvacSetPreconditioningMaxAction = CarServer_HvacSetPreconditioningMaxAction_init_default;
  action.vehicle_action_msg.hvacSetPreconditioningMaxAction.on = is_on;
  action.vehicle_action_msg.hvacSetPreconditioningMaxAction.manual_override = true;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_hvac_temperature_adjustment(CarServer_VehicleAction &action, const void *data) {
  if (!data) {
    LOG_ERROR("HVAC temperature adjustment action requires float data");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  float temp_celsius = *static_cast<const float *>(data);

  // Validate temperature is within reasonable range (15-28°C like the UI)
  if (temp_celsius < 15.0f || temp_celsius > 28.0f) {
    LOG_WARNING("Temperature %.1f°C outside normal range (15-28°C)", temp_celsius);
  }

  action.vehicle_action_msg.hvacTemperatureAdjustmentAction = CarServer_HvacTemperatureAdjustmentAction_init_default;
  // Set driver and passenger to same temperature for now
  action.vehicle_action_msg.hvacTemperatureAdjustmentAction.driver_temp_celsius = temp_celsius;
  action.vehicle_action_msg.hvacTemperatureAdjustmentAction.passenger_temp_celsius = temp_celsius;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_hvac_climate_keeper(CarServer_VehicleAction &action, const void *data) {
  if (!data) {
    LOG_ERROR("HVAC climate keeper action requires int data");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  int mode = *static_cast<const int *>(data);
  action.vehicle_action_msg.hvacClimateKeeperAction = CarServer_HvacClimateKeeperAction_init_default;
  action.vehicle_action_msg.hvacClimateKeeperAction.ClimateKeeperAction =
      static_cast<CarServer_HvacClimateKeeperAction_ClimateKeeperAction_E>(mode);
  action.vehicle_action_msg.hvacClimateKeeperAction.manual_override = true;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_hvac_bioweapon_mode(CarServer_VehicleAction &action, const void *data) {
  if (!data) {
    LOG_ERROR("HVAC bioweapon mode action requires boolean data");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  bool is_on = *static_cast<const bool *>(data);
  action.vehicle_action_msg.hvacBioweaponModeAction = CarServer_HvacBioweaponModeAction_init_default;
  action.vehicle_action_msg.hvacBioweaponModeAction.on = is_on;
  action.vehicle_action_msg.hvacBioweaponModeAction.manual_override = true;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_vehicle_control_schedule_software_update(CarServer_VehicleAction &action,
                                                                         const void *data) {
  if (!data) {
    LOG_ERROR("Schedule software update action requires int32_t data");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  int32_t offset_sec = *static_cast<const int32_t *>(data);
  action.vehicle_action_msg.vehicleControlScheduleSoftwareUpdateAction =
      CarServer_VehicleControlScheduleSoftwareUpdateAction_init_default;
  action.vehicle_action_msg.vehicleControlScheduleSoftwareUpdateAction.offset_sec = offset_sec;
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::build_set_cabin_overheat_protection(CarServer_VehicleAction &action, const void *data) {
  if (!data) {
    LOG_ERROR("Set cabin overheat protection action requires data");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }

  const auto *cop_data = static_cast<const CarServer_SetCabinOverheatProtectionAction *>(data);
  action.vehicle_action_msg.setCabinOverheatProtectionAction = *cop_data;
  return TeslaBLE_Status_E_OK;
}

// Helper functions
int VehicleActionBuilder::validate_input_parameters(const pb_byte_t *output_buffer, const size_t *output_length) {
  if (!output_buffer || !output_length) {
    LOG_ERROR("Invalid parameters: output_buffer and output_length cannot be null");
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::validate_charging_limit(int32_t percent) {
  if (!ParameterValidator::is_valid_charging_limit(percent)) {
    LOG_ERROR("Invalid charging limit percentage: %d (must be 50-100)", percent);
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }
  return TeslaBLE_Status_E_OK;
}

int VehicleActionBuilder::validate_charging_amps(int32_t amps) {
  if (!ParameterValidator::is_valid_charging_amps(amps)) {
    LOG_ERROR("Invalid charging amps value: %d (must be 0-80)", amps);
    return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
  }
  return TeslaBLE_Status_E_OK;
}

// Parameter validation implementations
bool ParameterValidator::is_valid_charging_limit(int32_t percent) { return percent >= 50 && percent <= 100; }

bool ParameterValidator::is_valid_charging_amps(int32_t amps) {
  return amps >= 0 && amps <= 80;  // Allow 0 to stop charging
}

bool ParameterValidator::is_valid_ping_value(int32_t ping_value) {
  return ping_value >= 0;  // Any non-negative value should be valid
}

bool ParameterValidator::is_valid_vin(const char *vin) {
  if (!vin)
    return false;
  size_t len = strlen(vin);
  return len == 17;  // Standard VIN length
}

bool ParameterValidator::is_valid_connection_id(const pb_byte_t *connection_id) {
  return connection_id != nullptr;  // Basic null check, could be enhanced
}

}  // namespace TeslaBLE
