#include <gtest/gtest.h>

#include "state_text.h"
#include "vcsec.pb.h"
#include "vehicle.pb.h"

using namespace TeslaBLE::state_text;

namespace {
void expect_opt(const std::optional<bool> &opt, bool expected) {
  ASSERT_TRUE(opt.has_value());
  EXPECT_EQ(opt.value(), expected);
}
}  // namespace

TEST(StateTextTest, SleepStatus) {
  expect_opt(sleep_status(VCSEC_VehicleSleepStatus_E_VEHICLE_SLEEP_STATUS_AWAKE), false);
  expect_opt(sleep_status(VCSEC_VehicleSleepStatus_E_VEHICLE_SLEEP_STATUS_ASLEEP), true);
  EXPECT_FALSE(sleep_status(VCSEC_VehicleSleepStatus_E_VEHICLE_SLEEP_STATUS_UNKNOWN).has_value());
  EXPECT_FALSE(sleep_status(99).has_value());
}

TEST(StateTextTest, LockStatus) {
  expect_opt(lock_status(VCSEC_VehicleLockState_E_VEHICLELOCKSTATE_UNLOCKED), true);
  expect_opt(lock_status(VCSEC_VehicleLockState_E_VEHICLELOCKSTATE_SELECTIVE_UNLOCKED), true);
  expect_opt(lock_status(VCSEC_VehicleLockState_E_VEHICLELOCKSTATE_LOCKED), false);
  expect_opt(lock_status(VCSEC_VehicleLockState_E_VEHICLELOCKSTATE_INTERNAL_LOCKED), false);
  EXPECT_FALSE(lock_status(99).has_value());
}

TEST(StateTextTest, UserPresence) {
  expect_opt(user_presence(VCSEC_UserPresence_E_VEHICLE_USER_PRESENCE_PRESENT), true);
  expect_opt(user_presence(VCSEC_UserPresence_E_VEHICLE_USER_PRESENCE_NOT_PRESENT), false);
  EXPECT_FALSE(user_presence(VCSEC_UserPresence_E_VEHICLE_USER_PRESENCE_UNKNOWN).has_value());
  EXPECT_FALSE(user_presence(99).has_value());
}

TEST(StateTextTest, IsCharging) {
  EXPECT_TRUE(is_charging(CarServer_ChargeState_ChargingState_Charging_tag));
  EXPECT_TRUE(is_charging(CarServer_ChargeState_ChargingState_Starting_tag));
  EXPECT_FALSE(is_charging(CarServer_ChargeState_ChargingState_Complete_tag));
  EXPECT_FALSE(is_charging(CarServer_ChargeState_ChargingState_Stopped_tag));
  EXPECT_FALSE(is_charging(CarServer_ChargeState_ChargingState_Disconnected_tag));
  EXPECT_FALSE(is_charging(CarServer_ChargeState_ChargingState_NoPower_tag));
  EXPECT_FALSE(is_charging(CarServer_ChargeState_ChargingState_Unknown_tag));
  EXPECT_FALSE(is_charging(99));
}

TEST(StateTextTest, ChargingStateText) {
  EXPECT_EQ(charging_state(CarServer_ChargeState_ChargingState_Disconnected_tag), "Disconnected");
  EXPECT_EQ(charging_state(CarServer_ChargeState_ChargingState_NoPower_tag), "No Power");
  EXPECT_EQ(charging_state(CarServer_ChargeState_ChargingState_Starting_tag), "Starting");
  EXPECT_EQ(charging_state(CarServer_ChargeState_ChargingState_Charging_tag), "Charging");
  EXPECT_EQ(charging_state(CarServer_ChargeState_ChargingState_Complete_tag), "Complete");
  EXPECT_EQ(charging_state(CarServer_ChargeState_ChargingState_Stopped_tag), "Stopped");
  EXPECT_EQ(charging_state(CarServer_ChargeState_ChargingState_Calibrating_tag), "Calibrating");
  EXPECT_EQ(charging_state(CarServer_ChargeState_ChargingState_Unknown_tag), "Unknown");
  EXPECT_EQ(charging_state(99), "Unknown");
}

TEST(StateTextTest, ChargerConnected) {
  EXPECT_FALSE(charger_connected(CarServer_ChargeState_ChargingState_Disconnected_tag));
  EXPECT_FALSE(charger_connected(CarServer_ChargeState_ChargingState_Unknown_tag));
  EXPECT_TRUE(charger_connected(CarServer_ChargeState_ChargingState_NoPower_tag));
  EXPECT_TRUE(charger_connected(CarServer_ChargeState_ChargingState_Starting_tag));
  EXPECT_TRUE(charger_connected(CarServer_ChargeState_ChargingState_Charging_tag));
  EXPECT_TRUE(charger_connected(CarServer_ChargeState_ChargingState_Complete_tag));
  EXPECT_TRUE(charger_connected(CarServer_ChargeState_ChargingState_Stopped_tag));
  EXPECT_TRUE(charger_connected(CarServer_ChargeState_ChargingState_Calibrating_tag));
}

TEST(StateTextTest, Iec61851StateText) {
  EXPECT_EQ(iec61851_state(CarServer_ChargeState_ChargingState_Disconnected_tag), "A");
  EXPECT_EQ(iec61851_state(CarServer_ChargeState_ChargingState_NoPower_tag), "E");
  EXPECT_EQ(iec61851_state(CarServer_ChargeState_ChargingState_Starting_tag), "C");
  EXPECT_EQ(iec61851_state(CarServer_ChargeState_ChargingState_Charging_tag), "C");
  EXPECT_EQ(iec61851_state(CarServer_ChargeState_ChargingState_Calibrating_tag), "C");
  EXPECT_EQ(iec61851_state(CarServer_ChargeState_ChargingState_Complete_tag), "B");
  EXPECT_EQ(iec61851_state(CarServer_ChargeState_ChargingState_Stopped_tag), "B");
  EXPECT_EQ(iec61851_state(CarServer_ChargeState_ChargingState_Unknown_tag), "F");
  EXPECT_EQ(iec61851_state(99), "F");
}

TEST(StateTextTest, SoftwareUpdateStatusText) {
  EXPECT_EQ(software_update_status(CarServer_SoftwareUpdateState_SoftwareUpdateStatus_Unknown_tag), "Up to date");
  EXPECT_EQ(software_update_status(CarServer_SoftwareUpdateState_SoftwareUpdateStatus_Installing_tag), "Installing");
  EXPECT_EQ(software_update_status(CarServer_SoftwareUpdateState_SoftwareUpdateStatus_Scheduled_tag), "Scheduled");
  EXPECT_EQ(software_update_status(CarServer_SoftwareUpdateState_SoftwareUpdateStatus_Available_tag), "Available");
  EXPECT_EQ(software_update_status(CarServer_SoftwareUpdateState_SoftwareUpdateStatus_DownloadingWifiWait_tag),
            "Downloading (waiting for Wi-Fi)");
  EXPECT_EQ(software_update_status(CarServer_SoftwareUpdateState_SoftwareUpdateStatus_Downloading_tag), "Downloading");
  EXPECT_EQ(software_update_status(0), "Unknown");
  EXPECT_EQ(software_update_status(99), "Unknown");
}

TEST(StateTextTest, ShiftStateText) {
  EXPECT_EQ(shift_state(CarServer_ShiftState_P_tag), "P");
  EXPECT_EQ(shift_state(CarServer_ShiftState_R_tag), "R");
  EXPECT_EQ(shift_state(CarServer_ShiftState_N_tag), "N");
  EXPECT_EQ(shift_state(CarServer_ShiftState_D_tag), "D");
  EXPECT_EQ(shift_state(CarServer_ShiftState_SNA_tag), "SNA");
  EXPECT_EQ(shift_state(CarServer_ShiftState_Invalid_tag), "Invalid");
  EXPECT_EQ(shift_state(99), "Unknown");
}

TEST(StateTextTest, IsParked) {
  EXPECT_TRUE(is_parked(CarServer_ShiftState_P_tag));
  EXPECT_FALSE(is_parked(CarServer_ShiftState_R_tag));
  EXPECT_FALSE(is_parked(CarServer_ShiftState_N_tag));
  EXPECT_FALSE(is_parked(CarServer_ShiftState_D_tag));
  EXPECT_FALSE(is_parked(CarServer_ShiftState_Invalid_tag));
}

TEST(StateTextTest, ChargeLimitReasonText) {
  EXPECT_EQ(charge_limit_reason(CarServer_ChargeState_ChargeLimitReason_ChargeLimitReasonNone), "None");
  EXPECT_EQ(charge_limit_reason(CarServer_ChargeState_ChargeLimitReason_ChargeLimitReasonEvse), "EVSE");
  EXPECT_EQ(charge_limit_reason(CarServer_ChargeState_ChargeLimitReason_ChargeLimitReasonBattTempLow), "BattTempLow");
  EXPECT_EQ(charge_limit_reason(CarServer_ChargeState_ChargeLimitReason_ChargeLimitReasonHighSoc), "HighSoc");
  EXPECT_EQ(charge_limit_reason(CarServer_ChargeState_ChargeLimitReason_ChargeLimitReasonCabin), "Cabin");
  EXPECT_EQ(charge_limit_reason(CarServer_ChargeState_ChargeLimitReason_ChargeLimitReasonUnknown), "Unknown");
  EXPECT_EQ(charge_limit_reason(99), "Unknown");
}
