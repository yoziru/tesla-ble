#include "charging_power.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <numbers>

namespace TeslaBLE {

ChargingPower ChargingPowerEstimator::update(const CarServer_ChargeState &state) {
  ChargingPower result;
  const auto charging = state.has_charging_state ? state.charging_state.which_type : 0;
  if (charging == CarServer_ChargeState_ChargingState_Disconnected_tag) {
    *this = ChargingPowerEstimator{};
    result.power_w = 0;
    result.source = "disconnected";
    return result;
  }

  if (state.which_optional_fast_charger_present) {
    result.is_ac = !state.optional_fast_charger_present.fast_charger_present;
  }
  const auto cable = state.conn_charge_cable.which_type;
  if (cable == CarServer_ChargeState_CableType_GB_DC_tag) {
    result.is_ac = false;
  } else if (!result.is_ac.has_value() && cable == CarServer_ChargeState_CableType_GB_AC_tag) {
    result.is_ac = true;
  }

  if (state.which_optional_charger_power) {
    const auto kw = state.optional_charger_power.charger_power;
    if (kw >= 0 && kw <= 1000) {
      result.power_w = kw * 1000.0;
      result.source = "reported";
    }
  }

  if (charging != CarServer_ChargeState_ChargingState_Charging_tag || result.is_ac != true || !result.power_w ||
      *result.power_w <= 0 || !state.which_optional_charger_voltage || !state.which_optional_charger_actual_current) {
    candidate_ = samples_ = 0;
    return result;
  }

  const auto voltage = state.optional_charger_voltage.charger_voltage;
  const auto current = state.optional_charger_actual_current.charger_actual_current;
  const auto phases = state.which_optional_charger_phases ? state.optional_charger_phases.charger_phases : 0;
  if (voltage <= 0 || voltage > 600 || current <= 0 || current > 100) {
    candidate_ = samples_ = 0;
    return result;
  }

  const double base = static_cast<double>(voltage) * current;
  constexpr std::array<double, 4> multipliers{1.0, 2.0, 3.0, std::numbers::sqrt3};
  int candidate = 0;
  for (size_t i = 0; i < multipliers.size(); ++i) {
    // ponytail: allow unknown kW rounding and measurement error; tighten only
    // with verified telemetry precision.
    if (std::abs((base * multipliers[i]) - *result.power_w) <= 1000.0 + (*result.power_w * 0.02)) {
      if (candidate != 0) {
        candidate_ = samples_ = 0;
        return result;
      }
      candidate = static_cast<int>(i) + 1;
    }
  }

  if (candidate == 0) {
    candidate_ = samples_ = 0;
    return result;
  }
  if (candidate != candidate_ || current != last_current_ || phases != last_phases_ ||
      std::abs(voltage - last_voltage_) > last_voltage_ * 0.05) {
    samples_ = 0;
  }
  candidate_ = candidate;
  last_current_ = current;
  last_voltage_ = voltage;
  last_phases_ = phases;
  samples_ = std::min(samples_ + 1, 3);
  if (samples_ == 3) {
    result.multiplier = multipliers[candidate - 1];
    result.effective_phases = candidate == 4 ? 3 : candidate;
    result.power_w = base * *result.multiplier;
    result.source = "estimated";
  }
  return result;
}

}  // namespace TeslaBLE
