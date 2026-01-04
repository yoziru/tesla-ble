#include "message_builders.h"

#include "defs.h"
#include "tb_utils.h"

#include "car_server.pb.h"
#include "universal_message.pb.h"

namespace TeslaBLE
{

    // Forward declarations of builder functions  
    static int buildChargingSetLimit(CarServer_VehicleAction& action, const void* data);
    static int buildChargingStartStop(CarServer_VehicleAction& action, const void* data);
    static int buildSetChargingAmps(CarServer_VehicleAction& action, const void* data);
    static int buildChargePortDoorOpen(CarServer_VehicleAction& action, const void* data);
    static int buildChargePortDoorClose(CarServer_VehicleAction& action, const void* data);
    static int buildScheduledCharging(CarServer_VehicleAction& action, const void* data);
    static int buildHvacAutoAction(CarServer_VehicleAction& action, const void* data);
    static int buildHvacSteeringWheelHeater(CarServer_VehicleAction& action, const void* data);
    static int buildVehicleControlFlashLights(CarServer_VehicleAction& action, const void* data);
    static int buildVehicleControlHonkHorn(CarServer_VehicleAction& action, const void* data);
    static int buildVehicleControlSetSentryMode(CarServer_VehicleAction& action, const void* data);
    static int buildMediaPlayAction(CarServer_VehicleAction& action, const void* data);
    static int buildMediaNextFavorite(CarServer_VehicleAction& action, const void* data);
    static int buildMediaPreviousFavorite(CarServer_VehicleAction& action, const void* data);
    static int buildMediaNextTrack(CarServer_VehicleAction& action, const void* data);
    static int buildMediaPreviousTrack(CarServer_VehicleAction& action, const void* data);
    static int buildPingAction(CarServer_VehicleAction& action, const void* data);
    static int buildVehicleControlWindowAction(CarServer_VehicleAction& action, const void* data);
    static int buildHvacSetPreconditioningMax(CarServer_VehicleAction& action, const void* data);
    static int buildHvacTemperatureAdjustment(CarServer_VehicleAction& action, const void* data);
    static int buildHvacClimateKeeper(CarServer_VehicleAction& action, const void* data);
    static int buildHvacBioweaponMode(CarServer_VehicleAction& action, const void* data);
    static int buildVehicleControlScheduleSoftwareUpdate(CarServer_VehicleAction& action, const void* data);
    static int buildSetCabinOverheatProtection(CarServer_VehicleAction& action, const void* data);

    // Initialize the static builder map
    const std::unordered_map<pb_size_t, VehicleActionBuilder::BuilderFunction> 
    VehicleActionBuilder::builders_ = {
        {CarServer_VehicleAction_chargingSetLimitAction_tag, buildChargingSetLimit},
        {CarServer_VehicleAction_chargingStartStopAction_tag, buildChargingStartStop},
        {CarServer_VehicleAction_setChargingAmpsAction_tag, buildSetChargingAmps},
        {CarServer_VehicleAction_chargePortDoorOpen_tag, buildChargePortDoorOpen},
        {CarServer_VehicleAction_chargePortDoorClose_tag, buildChargePortDoorClose},
        {CarServer_VehicleAction_scheduledChargingAction_tag, buildScheduledCharging},
        {CarServer_VehicleAction_hvacAutoAction_tag, buildHvacAutoAction},
        {CarServer_VehicleAction_hvacSteeringWheelHeaterAction_tag, buildHvacSteeringWheelHeater},
        {CarServer_VehicleAction_vehicleControlFlashLightsAction_tag, buildVehicleControlFlashLights},
        {CarServer_VehicleAction_vehicleControlHonkHornAction_tag, buildVehicleControlHonkHorn},
        {CarServer_VehicleAction_vehicleControlSetSentryModeAction_tag, buildVehicleControlSetSentryMode},
        {CarServer_VehicleAction_vehicleControlCancelSoftwareUpdateAction_tag, buildVehicleControlCancelSoftwareUpdate},
        {CarServer_VehicleAction_vehicleControlResetValetPinAction_tag, buildVehicleControlResetValetPin},
        {CarServer_VehicleAction_vehicleControlResetPinToDriveAction_tag, buildVehicleControlResetPinToDrive},
        {CarServer_VehicleAction_drivingClearSpeedLimitPinAdminAction_tag, buildDrivingClearSpeedLimitPinAdmin},
        {CarServer_VehicleAction_vehicleControlResetPinToDriveAdminAction_tag, buildVehicleControlResetPinToDriveAdmin},
        {CarServer_VehicleAction_mediaPlayAction_tag, buildMediaPlayAction},
        {CarServer_VehicleAction_mediaNextFavorite_tag, buildMediaNextFavorite},
        {CarServer_VehicleAction_mediaPreviousFavorite_tag, buildMediaPreviousFavorite},
        {CarServer_VehicleAction_mediaNextTrack_tag, buildMediaNextTrack},
        {CarServer_VehicleAction_mediaPreviousTrack_tag, buildMediaPreviousTrack},
        {CarServer_VehicleAction_ping_tag, buildPingAction},
        {CarServer_VehicleAction_vehicleControlWindowAction_tag, buildVehicleControlWindowAction},
        {CarServer_VehicleAction_hvacSetPreconditioningMaxAction_tag, buildHvacSetPreconditioningMax},
        {CarServer_VehicleAction_hvacTemperatureAdjustmentAction_tag, buildHvacTemperatureAdjustment},
        {CarServer_VehicleAction_hvacClimateKeeperAction_tag, buildHvacClimateKeeper},
        {CarServer_VehicleAction_hvacBioweaponModeAction_tag, buildHvacBioweaponMode},
        {CarServer_VehicleAction_vehicleControlScheduleSoftwareUpdateAction_tag, buildVehicleControlScheduleSoftwareUpdate},
        {CarServer_VehicleAction_setCabinOverheatProtectionAction_tag, buildSetCabinOverheatProtection}
    };

    // Builder implementations
    int VehicleActionBuilder::buildChargingSetLimit(CarServer_VehicleAction& action, const void* data)
    {
        if (!data) {
            LOG_ERROR("Charging set limit action requires int32_t data");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        int32_t percent = *static_cast<const int32_t*>(data);
        int result = validateChargingLimit(percent);
        if (result != TeslaBLE_Status_E_OK) {
            return result;
        }

        action.vehicle_action_msg.chargingSetLimitAction = CarServer_ChargingSetLimitAction_init_default;
        action.vehicle_action_msg.chargingSetLimitAction.percent = percent;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildChargingStartStop(CarServer_VehicleAction& action, const void* data)
    {
        if (!data) {
            LOG_ERROR("Charging start/stop action requires boolean data");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        bool start = *static_cast<const bool*>(data);
        action.vehicle_action_msg.chargingStartStopAction = CarServer_ChargingStartStopAction_init_default;
        
        if (start) {
            action.vehicle_action_msg.chargingStartStopAction.which_charging_action = 
                CarServer_ChargingStartStopAction_start_tag;
            action.vehicle_action_msg.chargingStartStopAction.charging_action.start = 
                CarServer_Void_init_default;
        } else {
            action.vehicle_action_msg.chargingStartStopAction.which_charging_action = 
                CarServer_ChargingStartStopAction_stop_tag;
            action.vehicle_action_msg.chargingStartStopAction.charging_action.stop = 
                CarServer_Void_init_default;
        }
        
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildSetChargingAmps(CarServer_VehicleAction& action, const void* data)
    {
        if (!data) {
            LOG_ERROR("Set charging amps action requires int32_t data");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        int32_t amps = *static_cast<const int32_t*>(data);
        int result = validateChargingAmps(amps);
        if (result != TeslaBLE_Status_E_OK) {
            return result;
        }

        action.vehicle_action_msg.setChargingAmpsAction = CarServer_SetChargingAmpsAction_init_default;
        action.vehicle_action_msg.setChargingAmpsAction.charging_amps = amps;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildChargePortDoorOpen(CarServer_VehicleAction& action, const void* data)
    {
        action.vehicle_action_msg.chargePortDoorOpen = CarServer_ChargePortDoorOpen_init_default;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildChargePortDoorClose(CarServer_VehicleAction& action, const void* data)
    {
        action.vehicle_action_msg.chargePortDoorClose = CarServer_ChargePortDoorClose_init_default;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildScheduledCharging(CarServer_VehicleAction& action, const void* data)
    {
        if (!data) {
            LOG_ERROR("Scheduled charging action requires CarServer_ScheduledChargingAction data");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        const auto* sched_data = static_cast<const CarServer_ScheduledChargingAction*>(data);
        action.vehicle_action_msg.scheduledChargingAction = *sched_data;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildHvacAutoAction(CarServer_VehicleAction& action, const void* data)
    {
        if (!data) {
            LOG_ERROR("HVAC auto action requires boolean data");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        bool isOn = *static_cast<const bool*>(data);
        action.vehicle_action_msg.hvacAutoAction = CarServer_HvacAutoAction_init_default;
        action.vehicle_action_msg.hvacAutoAction.power_on = isOn;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildHvacSteeringWheelHeater(CarServer_VehicleAction& action, const void* data)
    {
        if (!data) {
            LOG_ERROR("HVAC steering wheel heater action requires boolean data");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        bool isOn = *static_cast<const bool*>(data);
        action.vehicle_action_msg.hvacSteeringWheelHeaterAction = CarServer_HvacSteeringWheelHeaterAction_init_default;
        action.vehicle_action_msg.hvacSteeringWheelHeaterAction.power_on = isOn;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildVehicleControlFlashLights(CarServer_VehicleAction& action, const void* data)
    {
        action.vehicle_action_msg.vehicleControlFlashLightsAction = CarServer_VehicleControlFlashLightsAction_init_default;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildVehicleControlHonkHorn(CarServer_VehicleAction& action, const void* data)
    {
        action.vehicle_action_msg.vehicleControlHonkHornAction = CarServer_VehicleControlHonkHornAction_init_default;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildVehicleControlSetSentryMode(CarServer_VehicleAction& action, const void* data)
    {
        if (!data) {
            LOG_ERROR("Vehicle control set sentry mode action requires boolean data");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        bool isOn = *static_cast<const bool*>(data);
        action.vehicle_action_msg.vehicleControlSetSentryModeAction = CarServer_VehicleControlSetSentryModeAction_init_default;
        action.vehicle_action_msg.vehicleControlSetSentryModeAction.on = isOn;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildVehicleControlCancelSoftwareUpdate(CarServer_VehicleAction& action, const void* data)
    {
        action.vehicle_action_msg.vehicleControlCancelSoftwareUpdateAction = CarServer_VehicleControlCancelSoftwareUpdateAction_init_default;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildVehicleControlResetValetPin(CarServer_VehicleAction& action, const void* data)
    {
        action.vehicle_action_msg.vehicleControlResetValetPinAction = CarServer_VehicleControlResetValetPinAction_init_default;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildVehicleControlResetPinToDrive(CarServer_VehicleAction& action, const void* data)
    {
        action.vehicle_action_msg.vehicleControlResetPinToDriveAction = CarServer_VehicleControlResetPinToDriveAction_init_default;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildDrivingClearSpeedLimitPinAdmin(CarServer_VehicleAction& action, const void* data)
    {
        action.vehicle_action_msg.drivingClearSpeedLimitPinAdminAction = CarServer_DrivingClearSpeedLimitPinAdminAction_init_default;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildVehicleControlResetPinToDriveAdmin(CarServer_VehicleAction& action, const void* data)
    {
        action.vehicle_action_msg.vehicleControlResetPinToDriveAdminAction = CarServer_VehicleControlResetPinToDriveAdminAction_init_default;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildMediaPlayAction(CarServer_VehicleAction& action, const void* data)
    {
        action.vehicle_action_msg.mediaPlayAction = CarServer_MediaPlayAction_init_default;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildMediaNextFavorite(CarServer_VehicleAction& action, const void* data)
    {
        action.vehicle_action_msg.mediaNextFavorite = CarServer_MediaNextFavorite_init_default;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildMediaPreviousFavorite(CarServer_VehicleAction& action, const void* data)
    {
        action.vehicle_action_msg.mediaPreviousFavorite = CarServer_MediaPreviousFavorite_init_default;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildMediaNextTrack(CarServer_VehicleAction& action, const void* data)
    {
        action.vehicle_action_msg.mediaNextTrack = CarServer_MediaNextTrack_init_default;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildMediaPreviousTrack(CarServer_VehicleAction& action, const void* data)
    {
        action.vehicle_action_msg.mediaPreviousTrack = CarServer_MediaPreviousTrack_init_default;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildPingAction(CarServer_VehicleAction& action, const void* data)
    {
        if (!data) {
            LOG_ERROR("Ping action requires int32_t data");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        int32_t ping_value = *static_cast<const int32_t*>(data);
        action.vehicle_action_msg.ping = CarServer_Ping_init_default;
        action.vehicle_action_msg.ping.ping_id = ping_value;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildVehicleControlWindowAction(CarServer_VehicleAction& action, const void* data)
    {
        if (!data) {
            LOG_ERROR("Vehicle control window action requires int32_t data (0=vent, 1=close)");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        int32_t window_action = *static_cast<const int32_t*>(data);
        action.vehicle_action_msg.vehicleControlWindowAction = CarServer_VehicleControlWindowAction_init_default;
        
        if (window_action == 0) {
            // Vent windows
            action.vehicle_action_msg.vehicleControlWindowAction.which_action = 
                CarServer_VehicleControlWindowAction_vent_tag;
            action.vehicle_action_msg.vehicleControlWindowAction.action.vent = 
                CarServer_Void_init_default;
        } else {
            // Close windows
            action.vehicle_action_msg.vehicleControlWindowAction.which_action = 
                CarServer_VehicleControlWindowAction_close_tag;
            action.vehicle_action_msg.vehicleControlWindowAction.action.close = 
                CarServer_Void_init_default;
        }
        
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildHvacSetPreconditioningMax(CarServer_VehicleAction& action, const void* data)
    {
        if (!data) {
            LOG_ERROR("HVAC set preconditioning max action requires boolean data");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        bool isOn = *static_cast<const bool*>(data);
        action.vehicle_action_msg.hvacSetPreconditioningMaxAction = CarServer_HvacSetPreconditioningMaxAction_init_default;
        action.vehicle_action_msg.hvacSetPreconditioningMaxAction.on = isOn;
        action.vehicle_action_msg.hvacSetPreconditioningMaxAction.manual_override = true;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildHvacTemperatureAdjustment(CarServer_VehicleAction& action, const void* data)
    {
        if (!data) {
            LOG_ERROR("HVAC temperature adjustment action requires float data");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        float temp_celsius = *static_cast<const float*>(data);
        
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

    int VehicleActionBuilder::buildHvacClimateKeeper(CarServer_VehicleAction& action, const void* data)
    {
        if (!data) {
            LOG_ERROR("HVAC climate keeper action requires int data");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        int mode = *static_cast<const int*>(data);
        action.vehicle_action_msg.hvacClimateKeeperAction = CarServer_HvacClimateKeeperAction_init_default;
        action.vehicle_action_msg.hvacClimateKeeperAction.ClimateKeeperAction = 
            static_cast<CarServer_HvacClimateKeeperAction_ClimateKeeperAction_E>(mode);
        action.vehicle_action_msg.hvacClimateKeeperAction.manual_override = true;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildHvacBioweaponMode(CarServer_VehicleAction& action, const void* data)
    {
        if (!data) {
            LOG_ERROR("HVAC bioweapon mode action requires boolean data");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        bool isOn = *static_cast<const bool*>(data);
        action.vehicle_action_msg.hvacBioweaponModeAction = CarServer_HvacBioweaponModeAction_init_default;
        action.vehicle_action_msg.hvacBioweaponModeAction.on = isOn;
        action.vehicle_action_msg.hvacBioweaponModeAction.manual_override = true;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildVehicleControlScheduleSoftwareUpdate(CarServer_VehicleAction& action, const void* data)
    {
        if (!data) {
            LOG_ERROR("Schedule software update action requires int32_t data");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        int32_t offset_sec = *static_cast<const int32_t*>(data);
        action.vehicle_action_msg.vehicleControlScheduleSoftwareUpdateAction = CarServer_VehicleControlScheduleSoftwareUpdateAction_init_default;
        action.vehicle_action_msg.vehicleControlScheduleSoftwareUpdateAction.offset_sec = offset_sec;
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::buildSetCabinOverheatProtection(CarServer_VehicleAction& action, const void* data)
    {
        if (!data) {
            LOG_ERROR("Set cabin overheat protection action requires data");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        const auto* cop_data = static_cast<const CarServer_SetCabinOverheatProtectionAction*>(data);
        action.vehicle_action_msg.setCabinOverheatProtectionAction = *cop_data;
        return TeslaBLE_Status_E_OK;
    }

    // Helper functions
    int VehicleActionBuilder::validateInputParameters(pb_byte_t* output_buffer, size_t* output_length)
    {
        if (!output_buffer || !output_length) {
            LOG_ERROR("Invalid parameters: output_buffer and output_length cannot be null");
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::validateChargingLimit(int32_t percent)
    {
        if (!ParameterValidator::isValidChargingLimit(percent)) {
            LOG_ERROR("Invalid charging limit percentage: %d (must be 50-100)", percent);
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }
        return TeslaBLE_Status_E_OK;
    }

    int VehicleActionBuilder::validateChargingAmps(int32_t amps)
    {
        if (!ParameterValidator::isValidChargingAmps(amps)) {
            LOG_ERROR("Invalid charging amps value: %d (must be 0-80)", amps);
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }
        return TeslaBLE_Status_E_OK;
    }

    // Parameter validation implementations
    bool ParameterValidator::isValidChargingLimit(int32_t percent)
    {
        return percent >= 50 && percent <= 100;
    }

    bool ParameterValidator::isValidChargingAmps(int32_t amps)
    {
        return amps >= 0 && amps <= 80; // Allow 0 to stop charging
    }

    bool ParameterValidator::isValidPingValue(int32_t ping_value)
    {
        return ping_value >= 0; // Any non-negative value should be valid
    }

    bool ParameterValidator::isValidVIN(const char* vin)
    {
        if (!vin) return false;
        size_t len = strlen(vin);
        return len == 17; // Standard VIN length
    }

    bool ParameterValidator::isValidConnectionID(const pb_byte_t* connection_id)
    {
        return connection_id != nullptr; // Basic null check, could be enhanced
    }

} // namespace TeslaBLE
