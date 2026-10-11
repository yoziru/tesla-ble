#include "state_text.h"

#include "vcsec.pb.h"
#include "vehicle.pb.h"

namespace TeslaBLE {
namespace state_text {

std::optional<bool> sleep_status(int status) {
  switch (status) {
    case VCSEC_VehicleSleepStatus_E_VEHICLE_SLEEP_STATUS_AWAKE:
      return false;
    case VCSEC_VehicleSleepStatus_E_VEHICLE_SLEEP_STATUS_ASLEEP:
      return true;
    default:
      return std::nullopt;
  }
}

std::optional<bool> lock_status(int status) {
  switch (status) {
    case VCSEC_VehicleLockState_E_VEHICLELOCKSTATE_UNLOCKED:
    case VCSEC_VehicleLockState_E_VEHICLELOCKSTATE_SELECTIVE_UNLOCKED:
      return true;
    case VCSEC_VehicleLockState_E_VEHICLELOCKSTATE_LOCKED:
    case VCSEC_VehicleLockState_E_VEHICLELOCKSTATE_INTERNAL_LOCKED:
      return false;
    default:
      return std::nullopt;
  }
}

std::optional<bool> user_presence(int presence) {
  switch (presence) {
    case VCSEC_UserPresence_E_VEHICLE_USER_PRESENCE_PRESENT:
      return true;
    case VCSEC_UserPresence_E_VEHICLE_USER_PRESENCE_NOT_PRESENT:
      return false;
    default:
      return std::nullopt;
  }
}

bool is_charging(int which_type) {
  return which_type == CarServer_ChargeState_ChargingState_Charging_tag ||
         which_type == CarServer_ChargeState_ChargingState_Starting_tag;
}

std::string charging_state(int which_type) {
  switch (which_type) {
    case CarServer_ChargeState_ChargingState_Disconnected_tag:
      return "Disconnected";
    case CarServer_ChargeState_ChargingState_NoPower_tag:
      return "No Power";
    case CarServer_ChargeState_ChargingState_Starting_tag:
      return "Starting";
    case CarServer_ChargeState_ChargingState_Charging_tag:
      return "Charging";
    case CarServer_ChargeState_ChargingState_Complete_tag:
      return "Complete";
    case CarServer_ChargeState_ChargingState_Stopped_tag:
      return "Stopped";
    case CarServer_ChargeState_ChargingState_Calibrating_tag:
      return "Calibrating";
    default:
      return "Unknown";
  }
}

bool charger_connected(int which_type) {
  switch (which_type) {
    case CarServer_ChargeState_ChargingState_Disconnected_tag:
    case CarServer_ChargeState_ChargingState_Unknown_tag:
      return false;
    default:
      return true;
  }
}

std::string iec61851_state(int which_type) {
  switch (which_type) {
    case CarServer_ChargeState_ChargingState_Disconnected_tag:
      return "A";
    case CarServer_ChargeState_ChargingState_NoPower_tag:
      return "E";
    case CarServer_ChargeState_ChargingState_Starting_tag:
    case CarServer_ChargeState_ChargingState_Charging_tag:
    case CarServer_ChargeState_ChargingState_Calibrating_tag:
      return "C";
    case CarServer_ChargeState_ChargingState_Complete_tag:
    case CarServer_ChargeState_ChargingState_Stopped_tag:
      return "B";
    default:
      return "F";
  }
}

std::string shift_state(int which_type) {
  switch (which_type) {
    case CarServer_ShiftState_P_tag:
      return "P";
    case CarServer_ShiftState_R_tag:
      return "R";
    case CarServer_ShiftState_N_tag:
      return "N";
    case CarServer_ShiftState_D_tag:
      return "D";
    case CarServer_ShiftState_SNA_tag:
      return "SNA";
    case CarServer_ShiftState_Invalid_tag:
      return "Invalid";
    default:
      return "Unknown";
  }
}

bool is_parked(int which_type) { return which_type == CarServer_ShiftState_P_tag; }

std::string charge_limit_reason(int reason) {
  switch (reason) {
    case CarServer_ChargeState_ChargeLimitReason_ChargeLimitReasonNone:
      return "None";
    case CarServer_ChargeState_ChargeLimitReason_ChargeLimitReasonEvse:
      return "EVSE";
    case CarServer_ChargeState_ChargeLimitReason_ChargeLimitReasonBattTempLow:
      return "BattTempLow";
    case CarServer_ChargeState_ChargeLimitReason_ChargeLimitReasonHighSoc:
      return "HighSoc";
    case CarServer_ChargeState_ChargeLimitReason_ChargeLimitReasonCabin:
      return "Cabin";
    default:
      return "Unknown";
  }
}

std::string software_update_status(int which_type) {
  switch (which_type) {
    case CarServer_SoftwareUpdateState_SoftwareUpdateStatus_Unknown_tag:
      return "Up to date";
    case CarServer_SoftwareUpdateState_SoftwareUpdateStatus_Installing_tag:
      return "Installing";
    case CarServer_SoftwareUpdateState_SoftwareUpdateStatus_Scheduled_tag:
      return "Scheduled";
    case CarServer_SoftwareUpdateState_SoftwareUpdateStatus_Available_tag:
      return "Available";
    case CarServer_SoftwareUpdateState_SoftwareUpdateStatus_DownloadingWifiWait_tag:
      return "Downloading (waiting for Wi-Fi)";
    case CarServer_SoftwareUpdateState_SoftwareUpdateStatus_Downloading_tag:
      return "Downloading";
    default:
      return "Unknown";
  }
}

std::string closure_state_text(int state) {
  switch (state) {
    case VCSEC_ClosureState_E_CLOSURESTATE_CLOSED:
      return "closed";
    case VCSEC_ClosureState_E_CLOSURESTATE_OPEN:
      return "open";
    case VCSEC_ClosureState_E_CLOSURESTATE_AJAR:
      return "ajar";
    case VCSEC_ClosureState_E_CLOSURESTATE_OPENING:
      return "opening";
    case VCSEC_ClosureState_E_CLOSURESTATE_CLOSING:
      return "closing";
    case VCSEC_ClosureState_E_CLOSURESTATE_FAILED_UNLATCH:
      return "failed_unlatch";
    default:
      return "unknown";
  }
}

bool closure_is_open(int state) {
  return state == VCSEC_ClosureState_E_CLOSURESTATE_OPEN || state == VCSEC_ClosureState_E_CLOSURESTATE_AJAR ||
         state == VCSEC_ClosureState_E_CLOSURESTATE_OPENING;
}

bool sentry_mode_active(int state) {
  return state == CarServer_ClosuresState_SentryModeState_Armed_tag ||
         state == CarServer_ClosuresState_SentryModeState_Aware_tag ||
         state == CarServer_ClosuresState_SentryModeState_Panic_tag;
}

}  // namespace state_text
}  // namespace TeslaBLE
