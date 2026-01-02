#include "message_builders.h"

#include "defs.h"
#include "tb_utils.h"

#include "car_server.pb.h"
#include "universal_message.pb.h"

namespace TeslaBLE
{
    // Helper function to complete the encoding - will be moved to Client class
    static int completeVehicleActionEncoding(
        CarServer_Action& action,
        pb_byte_t* output_buffer,
        size_t* output_length)
    {
        // For now, return error to indicate incomplete implementation
        // This will be completed when we integrate with Client class
        return TeslaBLE_Status_E_ERROR_INTERNAL;
    }

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
        {CarServer_VehicleAction_ping_tag, buildPingAction}
    };

    int VehicleActionBuilder::buildVehicleAction(
        pb_size_t action_type,
        const void* action_data,
        pb_byte_t* output_buffer,
        size_t* output_length)
    {
        // Validate input parameters
        int result = validateInputParameters(output_buffer, output_length);
        if (result != TeslaBLE_Status_E_OK) {
            return result;
        }

        // Find the appropriate builder
        auto it = builders_.find(action_type);
        if (it == builders_.end()) {
            LOG_ERROR("Unsupported vehicle action type: %d", action_type);
            return TeslaBLE_Status_E_ERROR_INVALID_PARAMS;
        }

        // Create the action structure
        CarServer_Action action = CarServer_Action_init_default;
        action.which_action_msg = CarServer_Action_vehicleAction_tag;

        CarServer_VehicleAction vehicle_action = CarServer_VehicleAction_init_default;
        vehicle_action.which_vehicle_action_msg = action_type;

        // Build the specific action
        result = it->second(vehicle_action, action_data);
        if (result != TeslaBLE_Status_E_OK) {
            return result;
        }

        action.action_msg.vehicleAction = vehicle_action;

        // Complete the encoding using the helper function
        return completeVehicleActionEncoding(action, output_buffer, output_length);
    }

    const std::unordered_map<pb_size_t, VehicleActionBuilder::BuilderFunction>& 
    VehicleActionBuilder::getBuilders() {
        return builders_;
    }

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
