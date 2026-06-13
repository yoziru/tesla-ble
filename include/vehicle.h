#pragma once

#include "adapters.h"
#include "client.h"
#include "universal_message.pb.h"
#include "message_processor.h"
#include "command_error.h"

#include <memory>
#include <functional>
#include <queue>
#include <vector>
#include <string>
#include <chrono>

#include "keys.pb.h"

namespace TeslaBLE {

class Client;

enum class SleepState {
  UNKNOWN,
  ASLEEP,
  AWAKE,
};

enum class WakePolicy {
  NO_WAKE_SKIP,
  NO_WAKE_FAIL,
  WAKE_IF_NEEDED,
};

enum class OperationPhase {
  QUEUED,
  ENSURING_VCSEC_SESSION,
  ENSURING_AWAKE,
  ENSURING_INFOTAINMENT_SESSION,
  SENDING_REQUEST,
  AWAITING_RESPONSE,
  TERMINAL,
};

enum class OperationOutcome {
  SUCCESS,
  SKIPPED,
  FAILED,
};

enum class OperationTerminalReason {
  NONE,
  VEHICLE_ASLEEP,
};

class OperationResult {
 public:
  static OperationResult success(OperationTerminalReason reason = OperationTerminalReason::NONE) {
    return OperationResult(OperationOutcome::SUCCESS, reason, nullptr);
  }

  static OperationResult skipped(OperationTerminalReason reason) {
    return OperationResult(OperationOutcome::SKIPPED, reason, nullptr);
  }

  static OperationResult failure(std::unique_ptr<CommandError> error,
                                 OperationTerminalReason reason = OperationTerminalReason::NONE) {
    return OperationResult(OperationOutcome::FAILED, reason, std::move(error));
  }

  OperationResult(OperationResult &&) = default;
  OperationResult &operator=(OperationResult &&) = default;

  OperationResult(const OperationResult &) = delete;
  OperationResult &operator=(const OperationResult &) = delete;

  OperationOutcome outcome() const { return outcome_; }
  OperationTerminalReason reason() const { return reason_; }
  bool is_success() const { return outcome_ == OperationOutcome::SUCCESS; }
  bool is_skipped() const { return outcome_ == OperationOutcome::SKIPPED; }
  bool is_failure() const { return outcome_ == OperationOutcome::FAILED; }
  bool compatible_success() const { return outcome_ != OperationOutcome::FAILED; }
  const CommandError *error() const { return error_.get(); }
  std::unique_ptr<CommandError> release_error() { return std::move(error_); }

 private:
  OperationResult(OperationOutcome outcome, OperationTerminalReason reason, std::unique_ptr<CommandError> error)
      : outcome_(outcome), reason_(reason), error_(std::move(error)) {}

  OperationOutcome outcome_;
  OperationTerminalReason reason_;
  std::unique_ptr<CommandError> error_;
};

enum class CommandState {
  IDLE,
  AUTHENTICATING,         // Unified auth initiation state
  AUTH_RESPONSE_WAITING,  // Unified auth response waiting state
  READY,
  WAITING_FOR_RESPONSE,
  COMPLETED,
  FAILED
};

// Forward declarations
class Vehicle;
struct Command;

struct Command {
  using OperationResultCallback = std::function<void(OperationResult)>;
  using OperationPhaseCallback = std::function<void(OperationPhase)>;

  UniversalMessage_Domain domain;
  std::string name;
  // Builder function: takes Client pointer, output buffer, output length pointer. Returns status code (0 for success).
  std::function<int(Client *, uint8_t *, size_t *)> builder;
  OperationResultCallback on_complete;
  OperationPhaseCallback on_phase_change;
  WakePolicy wake_policy = WakePolicy::WAKE_IF_NEEDED;

  CommandState state = CommandState::IDLE;
  OperationPhase phase = OperationPhase::QUEUED;
  OperationOutcome outcome = OperationOutcome::SUCCESS;
  OperationTerminalReason terminal_reason = OperationTerminalReason::NONE;
  std::chrono::steady_clock::time_point started_at;
  std::chrono::steady_clock::time_point phase_started_at;
  std::chrono::steady_clock::time_point last_tx_at;
  uint8_t retry_count = 0;

  // Error tracking for intelligent retry decisions
  std::unique_ptr<CommandError> last_error;

  // Exponential backoff retry timing
  std::chrono::milliseconds next_retry_delay = std::chrono::milliseconds(0);
  std::chrono::steady_clock::time_point next_retry_time;

  // Domain context for consolidated state handling
  UniversalMessage_Domain current_auth_domain;

  Command(UniversalMessage_Domain d, std::string n, std::function<int(Client *, uint8_t *, size_t *)> b,
          OperationResultCallback cb = nullptr, WakePolicy wake = WakePolicy::WAKE_IF_NEEDED,
          OperationPhaseCallback phase_cb = nullptr)
      : domain(d),
        name(std::move(n)),
        builder(std::move(b)),
        on_complete(std::move(cb)),
        on_phase_change(std::move(phase_cb)),
        wake_policy(wake),
        current_auth_domain(d) {
    started_at = std::chrono::steady_clock::now();
    phase_started_at = started_at;
    if (on_phase_change) {
      on_phase_change(phase);
    }
  }
};

class Vehicle {
 public:
  Vehicle(const std::shared_ptr<BleAdapter> &ble, const std::shared_ptr<StorageAdapter> &storage);

  void loop();

  void on_rx_data(const std::vector<uint8_t> &data);

  // Legacy overloads: bool requires_wake maps to WakePolicy::NO_WAKE_SKIP (false) or WakeIfNeeded (true).
  // The rich-error callback receives nullptr for both success and skipped outcomes; to distinguish
  // them use send_command_result() with OperationResultCallback instead.
  void send_command(UniversalMessage_Domain domain, const std::string &name,
                    std::function<int(Client *, uint8_t *, size_t *)> builder,
                    std::function<void(std::unique_ptr<CommandError>)> on_complete = nullptr,
                    bool requires_wake = true);
  void send_command(UniversalMessage_Domain domain, const std::string &name,
                    std::function<int(Client *, uint8_t *, size_t *)> builder,
                    std::function<void(std::unique_ptr<CommandError>)> on_complete, WakePolicy wake_policy);
  void send_command_bool(UniversalMessage_Domain domain, const std::string &name,
                         std::function<int(Client *, uint8_t *, size_t *)> builder,
                         const std::function<void(bool)> &on_complete = nullptr, bool requires_wake = true);
  void send_command_bool(UniversalMessage_Domain domain, const std::string &name,
                         std::function<int(Client *, uint8_t *, size_t *)> builder,
                         const std::function<void(bool)> &on_complete, WakePolicy wake_policy);
  // Primary API for richer phase and outcome semantics.
  void send_command_result(UniversalMessage_Domain domain, const std::string &name,
                           std::function<int(Client *, uint8_t *, size_t *)> builder,
                           Command::OperationResultCallback on_complete,
                           WakePolicy wake_policy = WakePolicy::WAKE_IF_NEEDED,
                           Command::OperationPhaseCallback on_phase_change = nullptr);

  void set_vehicle_status_callback(std::function<void(const VCSEC_VehicleStatus &)> cb) {
    vehicle_status_callback_ = std::move(cb);
  }
  void set_charge_state_callback(std::function<void(const CarServer_ChargeState &)> cb) {
    charge_state_callback_ = std::move(cb);
  }
  void set_climate_state_callback(std::function<void(const CarServer_ClimateState &)> cb) {
    climate_state_callback_ = std::move(cb);
  }
  void set_drive_state_callback(std::function<void(const CarServer_DriveState &)> cb) {
    drive_state_callback_ = std::move(cb);
  }
  void set_tire_pressure_state_callback(std::function<void(const CarServer_TirePressureState &)> cb) {
    tire_pressure_callback_ = std::move(cb);
  }
  void set_closures_state_callback(std::function<void(const CarServer_ClosuresState &)> cb) {
    closures_state_callback_ = std::move(cb);
  }

  void wake();
  void vcsec_poll();
  void infotainment_poll(bool force_wake = false);
  void infotainment_poll(WakePolicy wake_policy);
  void charge_state_poll(bool force_wake = false);
  void charge_state_poll(WakePolicy wake_policy);
  void climate_state_poll(bool force_wake = false);
  void climate_state_poll(WakePolicy wake_policy);
  void drive_state_poll(bool force_wake = false);
  void drive_state_poll(WakePolicy wake_policy);
  void closures_state_poll(bool force_wake = false);
  void closures_state_poll(WakePolicy wake_policy);
  void tire_pressure_poll(bool force_wake = false);
  void tire_pressure_poll(WakePolicy wake_policy);

  void set_charging_state(bool enable);
  void set_charging_amps(int amps);
  void set_charging_limit(int limit);
  void unlock_charge_port();

  // VCSEC closure controls
  void lock();
  void unlock();
  void open_trunk();
  void close_trunk();
  void open_frunk();
  void open_charge_port();
  void close_charge_port();
  void unlatch_driver_door();

  // HVAC controls (infotainment)
  void set_climate(bool enable);
  void set_climate_temp(float temp_celsius);
  void set_climate_keeper(int mode);  // 0=Off, 1=On, 2=Dog, 3=Camp
  void set_bioweapon_mode(bool enable);
  void set_preconditioning_max(bool enable);  // Defrost
  void set_steering_wheel_heat(bool enable);

  // Vehicle controls (infotainment)
  void flash_lights();
  void honk_horn();
  void set_sentry_mode(bool enable);
  void vent_windows();
  void close_windows();

  // Pairing & Auth
  void pair(Keys_Role role = Keys_Role_ROLE_OWNER);
  void regenerate_key();

  bool is_connected() const { return is_connected_; }
  void set_connected(bool connected);

  void set_awake(bool awake) { sleep_state_ = awake ? SleepState::AWAKE : SleepState::ASLEEP; }
  void set_sleep_state(SleepState state) { sleep_state_ = state; }
  SleepState sleep_state() const { return sleep_state_; }

  void set_vin(const std::string &vin);
  using MessageCallback = std::function<void(const UniversalMessage_RoutableMessage &)>;
  void set_message_callback(MessageCallback cb) { message_callback_ = std::move(cb); }
  using RawMessageCallback = std::function<void(const std::vector<uint8_t> &)>;
  void set_raw_message_callback(RawMessageCallback cb) { raw_message_callback_ = std::move(cb); }

  // Timeout constants
  static constexpr auto COMMAND_TIMEOUT = std::chrono::seconds(30);
  static constexpr auto AUTH_RESPONSE_TIMEOUT =
      std::chrono::seconds(25);  // Time to wait for auth responses (VCSEC/Infotainment)
  static constexpr auto CLOCK_SYNC_MAX_LATENCY =
      std::chrono::seconds(4);  // Max age for stale session info responses (from Go impl)
  static constexpr auto TRANSPORT_RETRY_INTERVAL =
      std::chrono::seconds(1);  // Transport-layer retry interval (from Go impl)

  // Retry configuration
  static constexpr uint8_t MAX_RETRIES = 5;
  static constexpr size_t MAX_COMMAND_QUEUE_SIZE = 32;

  // Exponential backoff configuration
  static constexpr auto INITIAL_RETRY_DELAY = std::chrono::milliseconds(250);
  static constexpr auto MAX_RETRY_DELAY = std::chrono::seconds(8);
  static constexpr double BACKOFF_MULTIPLIER = 2.0;

 private:
  std::shared_ptr<BleAdapter> ble_adapter_;
  std::shared_ptr<StorageAdapter> storage_adapter_;
  std::shared_ptr<Client> client_;

  std::queue<std::shared_ptr<Command>> command_queue_;
  MessageCallback message_callback_;
  RawMessageCallback raw_message_callback_;

  // Message processing for ordered session handling
  std::unique_ptr<MessageProcessor> message_processor_;

  std::function<void(const VCSEC_VehicleStatus &)> vehicle_status_callback_;
  std::function<void(const CarServer_ChargeState &)> charge_state_callback_;
  std::function<void(const CarServer_ClimateState &)> climate_state_callback_;
  std::function<void(const CarServer_DriveState &)> drive_state_callback_;
  std::function<void(const CarServer_TirePressureState &)> tire_pressure_callback_;
  std::function<void(const CarServer_ClosuresState &)> closures_state_callback_;

  bool is_connected_ = false;
  SleepState sleep_state_ = SleepState::UNKNOWN;
  bool recovery_attempted_ = false;

  static constexpr size_t FRAME_HEADER_SIZE = 2;
  static constexpr size_t MAX_MESSAGE_SIZE = 2048;
  std::shared_ptr<Command> peek_command_() const;
  void process_command_queue_();
  void handle_message_(const UniversalMessage_RoutableMessage &msg);
  void process_idle_command_(const std::shared_ptr<Command> &command);
  void process_authenticating_command_(const std::shared_ptr<Command> &command);
  void process_auth_response_waiting_command_(const std::shared_ptr<Command> &command);
  void process_ready_command_(const std::shared_ptr<Command> &command);
  void advance_infotainment_prerequisites_(const std::shared_ptr<Command> &command);
  void resume_command_after_prerequisite_(const std::shared_ptr<Command> &command);
  void initiate_vcsec_auth_(const std::shared_ptr<Command> &command);
  void initiate_infotainment_auth_(const std::shared_ptr<Command> &command);
  void initiate_wake_sequence_(const std::shared_ptr<Command> &command);
  void set_command_phase_(const std::shared_ptr<Command> &command, OperationPhase phase);
  void mark_command_failed_(const std::shared_ptr<Command> &command, std::unique_ptr<CommandError> error);
  void mark_command_failed_(const std::shared_ptr<Command> &command, std::unique_ptr<CommandError> error,
                            OperationTerminalReason reason);
  void mark_command_completed_(const std::shared_ptr<Command> &command);
  void mark_command_skipped_(const std::shared_ptr<Command> &command, OperationTerminalReason reason);
  void finalize_command_(const std::shared_ptr<Command> &command, OperationResult result);
  bool is_domain_authenticated_(UniversalMessage_Domain domain);
  void handle_authentication_response_(UniversalMessage_Domain domain, bool success);
  void load_session_from_storage_(UniversalMessage_Domain domain);
  void persist_session_(UniversalMessage_Domain domain,
                        const UniversalMessage_RoutableMessage_session_info_t &session_info);
  void clear_stored_session_(UniversalMessage_Domain domain);
  std::string get_session_key_(UniversalMessage_Domain domain);
  void reset_all_sessions_and_connection_();
  bool attempt_buffer_recovery_(int &msg_len);
  void log_timeout_message_(const std::string &message, const std::shared_ptr<Command> &command);
  void handle_vehicle_status_command_update_(const std::shared_ptr<Command> &cmd, const VCSEC_VehicleStatus &status);
  bool is_vehicle_observed_awake_() const;
  bool is_vehicle_observed_asleep_() const;

 public:
  void retry_command(const std::shared_ptr<Command> &command);
  bool is_message_complete();
  int get_expected_message_length();
  void process_complete_message();
  std::vector<uint8_t> rx_buffer_;
  void initialize_rx_buffer();

 private:
  void handle_vcsec_message_(const UniversalMessage_RoutableMessage &msg);
  void handle_carserver_message_(const UniversalMessage_RoutableMessage &msg);
  void handle_session_info_message_(const UniversalMessage_RoutableMessage &msg);
  void handle_auth_timeout_common_(const std::shared_ptr<Command> &command, const std::string &domain_name,
                                   CommandState retry_state);
  void handle_vcsec_auth_timeout_(const std::shared_ptr<Command> &command);
  void handle_infotainment_auth_timeout_(const std::shared_ptr<Command> &command);
  void handle_wake_response_timeout_(const std::shared_ptr<Command> &command);
  void handle_signed_message_error_(const UniversalMessage_RoutableMessage &msg, bool &has_session_error);
  void send_infotainment_poll_(const std::string &name, int32_t data_type, WakePolicy wake_policy);
  void initiate_auth_for_domain_(const std::shared_ptr<Command> &command, UniversalMessage_Domain domain,
                                 CommandState waiting_state, const std::string &domain_name);
  bool persist_private_key_();
  template<typename T> void send_infotainment_action_with_value_(const std::string &name, int32_t action_tag, T value) {
    send_command(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, name,
                 [action_tag, value](Client *client, uint8_t *buff, size_t *len) {
                   return client->build_car_server_vehicle_action_message(buff, len, action_tag, &value);
                 });
  }
  void send_infotainment_action_(const std::string &name, int32_t action_tag, int value) {
    send_infotainment_action_with_value_(name, action_tag, value);
  }
  void send_infotainment_action_(const std::string &name, int32_t action_tag, float value) {
    send_infotainment_action_with_value_(name, action_tag, value);
  }
  void send_infotainment_action_(const std::string &name, int32_t action_tag, bool value) {
    send_infotainment_action_with_value_(name, action_tag, value);
  }
  void send_infotainment_action_(const std::string &name, int32_t action_tag) {
    send_command(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, name,
                 [action_tag](Client *client, uint8_t *buff, size_t *len) {
                   return client->build_car_server_vehicle_action_message(buff, len, action_tag, nullptr);
                 });
  }

 public:
  // Testing helper to access command queue for verification
  const std::queue<std::shared_ptr<Command>> &get_command_queue_for_testing() const { return command_queue_; }
};

}  // namespace TeslaBLE
