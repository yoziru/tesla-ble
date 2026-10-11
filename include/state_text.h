#pragma once

#include <optional>
#include <string>

namespace TeslaBLE {
namespace state_text {

// Interpretation of protobuf enum/oneof tags for host entities. The tags are
// passed as plain ints so consumers do not need the generated headers; the
// implementation is compiled against them, so mismatches are caught at build
// time. See the nanopb headers vcsec.pb.h and vehicle.pb.h for the tags.

// VCSEC sleep status: true when asleep, nullopt when unknown.
std::optional<bool> sleep_status(int status);

// VCSEC lock state: true when (selectively) unlocked, nullopt when unknown.
std::optional<bool> lock_status(int status);

// VCSEC user presence: true when present, nullopt when unknown.
std::optional<bool> user_presence(int presence);

// Whether a charge-state tag means the car is actively charging.
bool is_charging(int which_type);

std::string charging_state(int which_type);

// Whether a charge-state tag means an EVSE is connected.
bool charger_connected(int which_type);

// IEC 61851 control pilot state (A/B/C/E/F).
std::string iec61851_state(int which_type);

std::string shift_state(int which_type);

bool is_parked(int which_type);

std::string charge_limit_reason(int reason);

// VCSEC closure state: "closed", "open", "ajar", "opening", "closing",
// "failed_unlatch" or "unknown".
std::string closure_state_text(int state);

// CarServer software update status tag: "Up to date" (no update pending),
// "Installing", "Scheduled", "Available", "Downloading (waiting for Wi-Fi)" or
// "Downloading". Unrecognized tags report "Unknown".
std::string software_update_status(int which_type);

// Whether a closure state means the closure is (partially) open.
bool closure_is_open(int state);

// Whether a CarServer sentry mode state tag means sentry is active
// (armed, aware or panic).
bool sentry_mode_active(int state);

}  // namespace state_text
}  // namespace TeslaBLE
