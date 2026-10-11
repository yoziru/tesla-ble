#pragma once

#include <array>
#include <string>
#include <vector>

#include "client.h"
#include "crypto_context.h"
#include "universal_message.pb.h"
#include "vehicle.pb.h"
#include "vehicle.h"

namespace tesla_ble_python {

/**
 * @brief Protocol-valid test double of a Tesla vehicle.
 *
 * Answers session info requests with HMAC-signed session info responses and
 * replies to commands/polls with plaintext VCSEC status and CarServer
 * responses built from its simulated state. Meant for offline tests of the
 * Python bindings and of host integrations; never used against a real car.
 *
 * The simulated state is deliberately simple: setters update one field at a
 * time and every response reports the current state.
 */
class SimulatedVehicle {
 public:
  explicit SimulatedVehicle(std::string vin = "5YJ30123456789ABC");

  // Feed one framed message from the client (2-byte length prefix + payload).
  // Returns the list of framed messages to send back to the client.
  std::vector<std::vector<uint8_t>> on_client_frame(const std::vector<uint8_t> &frame);

  // Simulated state controls
  void set_paired(bool paired) { paired_ = paired; }
  void set_locked(bool locked) { locked_ = locked; }
  void set_sleeping(bool asleep) { asleep_ = asleep; }
  void set_user_present(bool present) { user_present_ = present; }
  void set_battery_level(int level);
  void set_battery_range(float range);
  void set_charging_state(int tag);            // CarServer_ChargeState_ChargingState_*_tag, 0 clears
  void set_scheduled_charging_mode(int mode);  // raw CarServer_ChargeState_ScheduledChargingMode
  void set_charge_limit(int soc);
  void set_charging_amps(int amps);
  void set_charger_power(float kw);
  void set_charger_voltage(int volts);
  void set_charger_actual_current(int amps);
  void set_charger_pilot_current(int amps);
  void set_charger_phases(int phases);
  void set_charge_port_door_open(bool open);
  void set_charge_port_latch(int state);  // raw CarServer_ChargePortLatchState
  void set_inside_temp(float celsius);
  void set_outside_temp(float celsius);
  void set_climate_on(bool on);
  void set_climate_keeper_mode(int mode);
  void set_cabin_overheat_protection(int mode);  // raw CarServer_ClimateState_CabinOverheatProtection_E
  void set_seat_heater(TeslaBLE::SeatPosition seat, int level);
  void set_seat_cooler(TeslaBLE::SeatPosition seat, int level);
  void set_auto_seat_climate(TeslaBLE::SeatPosition seat, bool enabled);
  void set_steering_wheel_heat(bool enabled);
  void set_cabin_overheat_protection_temp(int level);
  void set_bioweapon_mode(bool enable);
  void set_shift_state(int tag);  // CarServer_ShiftState_*_tag
  void set_odometer_miles(float miles);
  void set_door_open(const std::string &door, bool open);
  void set_window_open(const std::string &window, bool open);
  void set_tpms(int wheel, float bar);  // wheel: 0=FL 1=FR 2=RL 3=RR
  void set_sentry_mode(bool enabled);
  void set_sentry_mode_state(int tag);         // raw CarServer_ClosuresState_SentryModeState_*_tag
  void set_software_update_state(int status);  // raw CarServer_SoftwareUpdateState_SoftwareUpdateStatus
  void set_sunroof_percent(int percent);

  const std::string &vin() const { return vin_; }
  int frames_received() const { return frames_received_; }

 private:
  std::vector<uint8_t> respond_to_session_info_request_(const UniversalMessage_RoutableMessage &request);
  std::vector<uint8_t> respond_to_vcsec_(const UniversalMessage_RoutableMessage &request);
  std::vector<std::vector<uint8_t>> respond_to_carserver_(const UniversalMessage_RoutableMessage &request,
                                                          const CarServer_GetVehicleData *poll);
  bool decode_payload_(const UniversalMessage_RoutableMessage &request, UniversalMessage_Domain domain,
                       std::vector<pb_byte_t> &payload);
  bool apply_vcsec_action_(const std::vector<pb_byte_t> &payload);
  bool apply_carserver_action_(const CarServer_Action &action);

  TeslaBLE::CryptoContext crypto_;
  std::array<pb_byte_t, 65> public_key_{};
  size_t public_key_size_ = 0;
  std::array<pb_byte_t, 16> epoch_{};
  std::array<uint32_t, 2> request_counters_ = {100, 100};
  uint32_t clock_time_ = 1000;

  std::string vin_;
  bool paired_ = true;
  bool locked_ = true;
  bool asleep_ = false;
  bool user_present_ = false;

  CarServer_ChargeState charge_state_;
  CarServer_ClimateState climate_state_;
  CarServer_DriveState drive_state_;
  CarServer_TirePressureState tire_state_;
  CarServer_ClosuresState closures_state_;
  CarServer_MediaState media_state_;
  CarServer_SoftwareUpdateState software_update_state_ = CarServer_SoftwareUpdateState_init_default;
  std::array<bool, 4> doors_open_ = {false, false, false, false};
  bool charge_port_open_ = false;
  bool front_trunk_open_ = false;
  bool rear_trunk_open_ = false;

  int frames_received_ = 0;
};

}  // namespace tesla_ble_python
