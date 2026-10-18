#pragma once

#include "vehicle.pb.h"

#include <optional>

namespace TeslaBLE {

struct ChargingPower {
  std::optional<double> power_w;
  std::optional<double> multiplier;
  std::optional<int> effective_phases;
  std::optional<bool> is_ac;
  const char *source = "unavailable";
};

class ChargingPowerEstimator {
 public:
  ChargingPower update(const CarServer_ChargeState &state);

 private:
  int candidate_ = 0;
  int samples_ = 0;
  int last_current_ = 0;
  int last_voltage_ = 0;
  int last_phases_ = 0;
};

}  // namespace TeslaBLE
