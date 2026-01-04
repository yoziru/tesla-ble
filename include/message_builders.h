#pragma once

#include <memory>
#include <unordered_map>

#include "car_server.pb.h"
#include "errors.h"
#include "defs.h"

namespace TeslaBLE
{
    /**
     * @brief Factory class for building vehicle action messages.
     * 
     * This class provides a clean, extensible way to build different types
     * of vehicle action messages without code duplication.
     */
    class VehicleActionBuilder
    {
    public:
        using BuilderFunction = int(*)(CarServer_VehicleAction&, const void*);
        
        /**
         * @brief Get the map of builders for direct access
         * @return Reference to the builders map
         */
        static const std::unordered_map<pb_size_t, BuilderFunction>& getBuilders() {
            return builders_;
        }

    private:
        // Builder functions for different action types
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
        static int buildVehicleControlCancelSoftwareUpdate(CarServer_VehicleAction& action, const void* data);
        static int buildVehicleControlResetValetPin(CarServer_VehicleAction& action, const void* data);
        static int buildVehicleControlResetPinToDrive(CarServer_VehicleAction& action, const void* data);
        static int buildDrivingClearSpeedLimitPinAdmin(CarServer_VehicleAction& action, const void* data);
        static int buildVehicleControlResetPinToDriveAdmin(CarServer_VehicleAction& action, const void* data);
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

        // Map of action types to their builder functions
        static const std::unordered_map<pb_size_t, BuilderFunction> builders_;
        
        // Helper functions
        static int validateInputParameters(pb_byte_t* output_buffer, size_t* output_length);
        static int validateChargingLimit(int32_t percent);
        static int validateChargingAmps(int32_t amps);
    };

    /**
     * @brief Utility class for parameter validation
     */
    class ParameterValidator
    {
    public:
        static bool isValidChargingLimit(int32_t percent);
        static bool isValidChargingAmps(int32_t amps);
        static bool isValidPingValue(int32_t ping_value);
        static bool isValidVIN(const char* vin);
        static bool isValidConnectionID(const pb_byte_t* connection_id);
    };

} // namespace TeslaBLE
