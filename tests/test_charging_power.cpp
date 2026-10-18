#include "charging_power.h"

#include <gtest/gtest.h>

using namespace TeslaBLE;

namespace {

CarServer_ChargeState sample(int volts, int amps, int phases, int kw) {
  CarServer_ChargeState s = CarServer_ChargeState_init_default;
  s.has_charging_state = true;
  s.charging_state.which_type = CarServer_ChargeState_ChargingState_Charging_tag;
  s.which_optional_fast_charger_present = CarServer_ChargeState_fast_charger_present_tag;
  s.optional_fast_charger_present.fast_charger_present = false;
  s.which_optional_charger_voltage = CarServer_ChargeState_charger_voltage_tag;
  s.optional_charger_voltage.charger_voltage = volts;
  s.which_optional_charger_actual_current = CarServer_ChargeState_charger_actual_current_tag;
  s.optional_charger_actual_current.charger_actual_current = amps;
  s.which_optional_charger_phases = CarServer_ChargeState_charger_phases_tag;
  s.optional_charger_phases.charger_phases = phases;
  s.which_optional_charger_power = CarServer_ChargeState_charger_power_tag;
  s.optional_charger_power.charger_power = kw;
  return s;
}

ChargingPower settle(ChargingPowerEstimator &estimator, const CarServer_ChargeState &s) {
  estimator.update(s);
  estimator.update(s);
  return estimator.update(s);
}

}  // namespace

TEST(ChargingPower, FieldReportsAndSyntheticSupplyVariants) {
  struct Case {
    int volts, amps, raw_phases, kw, effective_phases;
    double watts;
    bool has_phases = true;
  };
  const Case cases[] = {
      // https://github.com/yoziru/ha-tesla-ble/issues/15
      {233, 16, 2, 11, 3, 11184},
      // https://github.com/teslamate-org/teslamate/issues/290#issuecomment-565049246
      {218, 19, 3, 7, 3, 7174.154444950289},
      // Synthetic controls: normal EU, US split-phase, US 120V, genuine two inputs.
      {230, 16, 3, 11, 3, 11040},
      {240, 32, 1, 8, 1, 7680},
      {120, 12, 1, 1, 1, 1440},
      {230, 32, 2, 15, 2, 14720},
      // Unknown/invalid raw phases must never become a power multiplier.
      {233, 16, 0, 11, 3, 11184},
      {233, 16, 4, 11, 3, 11184},
      {233, 16, 2, 11, 3, 11184, false},
  };
  for (const auto &c : cases) {
    SCOPED_TRACE(c.raw_phases);
    ChargingPowerEstimator estimator;
    auto s = sample(c.volts, c.amps, c.raw_phases, c.kw);
    if (!c.has_phases) {
      s.which_optional_charger_phases = 0;
    }
    const auto power = settle(estimator, s);
    EXPECT_STREQ(power.source, "estimated");
    EXPECT_EQ(power.effective_phases, c.effective_phases);
    ASSERT_TRUE(power.power_w);
    EXPECT_NEAR(*power.power_w, c.watts, 0.001);
  }
}

TEST(ChargingPower, AmbiguityAndOutliersFallBackWithoutPoisoningLaterSamples) {
  ChargingPowerEstimator estimator;
  // Synthetic low-current case: both two and three phases fit integer-kW telemetry.
  EXPECT_STREQ(settle(estimator, sample(230, 5, 2, 3)).source, "reported");
  auto s = sample(233, 16, 2, 11);
  ASSERT_STREQ(settle(estimator, s).source, "estimated");
  // Terminal current collapse with old power: TeslaMate #5586, synthetic row.
  const auto outlier = estimator.update(sample(233, 1, 2, 11));
  EXPECT_EQ(outlier.power_w, 11000);
  EXPECT_FALSE(outlier.multiplier);
  EXPECT_STREQ(estimator.update(s).source, "reported");
  EXPECT_STREQ(settle(estimator, s).source, "estimated");
  // EVSE switches from three to single phase without updating the raw phase field.
  s.optional_charger_power.charger_power = 4;
  EXPECT_EQ(estimator.update(s).power_w, 4000);
  const auto switched = settle(estimator, s);
  EXPECT_EQ(switched.effective_phases, 1);
  EXPECT_EQ(switched.power_w, 3728);
}

TEST(ChargingPower, CurrentChangesAndAmbiguousVoltageReferenceRequireFreshEvidence) {
  ChargingPowerEstimator estimator;
  auto s = sample(233, 16, 2, 11);
  ASSERT_STREQ(settle(estimator, s).source, "estimated");
  s.optional_charger_actual_current.charger_actual_current = 10;
  s.optional_charger_power.charger_power = 7;
  EXPECT_STREQ(estimator.update(s).source, "reported");
  EXPECT_STREQ(estimator.update(s).source, "reported");
  EXPECT_EQ(estimator.update(s).power_w, 6990);
  // Both sqrt(3) and 2 fit: raw phases cannot resolve voltage-reference ambiguity.
  for (int phases : {0, 1, 2, 3, 4}) {
    const auto ambiguous = settle(estimator, sample(230, 16, phases, 7));
    EXPECT_STREQ(ambiguous.source, "reported");
    EXPECT_FALSE(ambiguous.effective_phases);
  }
}

TEST(ChargingPower, MissingInvalidAndDcReadingsNeverReuseAcInputs) {
  const auto valid = sample(233, 16, 2, 11);
  for (int missing = 0; missing < 7; ++missing) {
    ChargingPowerEstimator estimator;
    ASSERT_STREQ(settle(estimator, valid).source, "estimated");
    auto s = valid;
    switch (missing) {
      case 0:
        s.which_optional_charger_voltage = 0;
        break;
      case 1:
        s.which_optional_charger_actual_current = 0;
        break;
      case 2:
        s.which_optional_charger_power = 0;
        break;
      case 3:
        s.which_optional_fast_charger_present = 0;
        break;
      case 4:
        s.optional_fast_charger_present.fast_charger_present = true;
        break;
      case 5:
        s.optional_charger_voltage.charger_voltage = -1;
        break;
      case 6:
        s.optional_charger_actual_current.charger_actual_current = 0;
        break;
    }
    const auto result = estimator.update(s);
    EXPECT_FALSE(result.multiplier);
    if (missing == 2) {
      EXPECT_FALSE(result.power_w);
    } else {
      EXPECT_EQ(result.power_w, 11000);
    }
    EXPECT_STREQ(estimator.update(valid).source, "reported");
  }
  ChargingPowerEstimator estimator;
  auto dc = sample(400, 200, 0, 80);
  dc.optional_fast_charger_present.fast_charger_present = true;
  EXPECT_EQ(settle(estimator, dc).power_w, 80000);
  EXPECT_EQ(estimator.update(dc).is_ac, false);
  auto invalid = valid;
  invalid.optional_charger_power.charger_power = -1;
  EXPECT_FALSE(estimator.update(invalid).power_w);
  // At 920 VA only multiplier=1 fits the tolerance around zero: do not learn it.
  const auto zero = settle(estimator, sample(230, 4, 1, 0));
  EXPECT_EQ(zero.power_w, 0);
  EXPECT_FALSE(zero.effective_phases);
}

TEST(ChargingPower, CableClassificationDoesNotMistakeDcOrUnknownForAc) {
  struct Case {
    int cable;
    bool has_fast, fast;
    std::optional<bool> is_ac;
  };
  const Case cases[] = {
      {CarServer_ChargeState_CableType_GB_AC_tag, false, false, true},
      {CarServer_ChargeState_CableType_GB_DC_tag, true, false, false},
      {CarServer_ChargeState_CableType_GB_AC_tag, true, true, false},
      {CarServer_ChargeState_CableType_IEC_tag, false, false, std::nullopt},
      {CarServer_ChargeState_CableType_SAE_tag, false, false, std::nullopt},
  };
  for (const auto &c : cases) {
    SCOPED_TRACE(c.cable);
    ChargingPowerEstimator estimator;
    auto s = sample(233, 16, 2, 11);
    s.conn_charge_cable.which_type = c.cable;
    s.which_optional_fast_charger_present = c.has_fast ? CarServer_ChargeState_fast_charger_present_tag : 0;
    s.optional_fast_charger_present.fast_charger_present = c.fast;
    const auto power = settle(estimator, s);
    EXPECT_EQ(power.is_ac, c.is_ac);
    EXPECT_EQ(power.power_w, c.is_ac == true ? 11184 : 11000);
    EXPECT_EQ(power.multiplier.has_value(), c.is_ac == true);
  }
}

TEST(ChargingPower, UnplugAndNonChargingStatesResetLearning) {
  for (auto tag :
       {CarServer_ChargeState_ChargingState_Disconnected_tag, CarServer_ChargeState_ChargingState_Starting_tag,
        CarServer_ChargeState_ChargingState_Complete_tag}) {
    ChargingPowerEstimator estimator;
    auto s = sample(233, 16, 2, 11);
    ASSERT_STREQ(settle(estimator, s).source, "estimated");
    s.charging_state.which_type = tag;
    const auto result = estimator.update(s);
    EXPECT_FALSE(result.multiplier);
    EXPECT_EQ(result.power_w, tag == CarServer_ChargeState_ChargingState_Disconnected_tag ? 0 : 11000);
    s.charging_state.which_type = CarServer_ChargeState_ChargingState_Charging_tag;
    EXPECT_STREQ(estimator.update(s).source, "reported");
  }
}
