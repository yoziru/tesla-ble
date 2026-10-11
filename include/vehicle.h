#pragma once

#include "adapters.h"
#include "client.h"
#include "universal_message.pb.h"
#include "message_processor.h"
#include "command_error.h"
#include "polling_policy.h"

#include <memory>
#include <functional>
#include <queue>
#include <vector>
#include <string>
#include <chrono>
#include <array>

#include "keys.pb.h"

namespace TeslaBLE {

class Client;

enum class SleepState {
  UNKNOWN,
  ASLEEP,
  AWAKE,
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

enum class SeatPosition {
  FRONT_LEFT = 7,
  FRONT_RIGHT = 8,
  REAR_LEFT = 9,
  REAR_LEFT_BACK = 10,
  REAR_CENTER = 11,
  REAR_RIGHT = 12,
  REAR_RIGHT_BACK = 13,
  THIRD_ROW_LEFT = 14,
  THIRD_ROW_RIGHT = 15
};

struct Command {
  enum class Kind { NORMAL, WAKE, PAIRING };
  enum class Refresh { VCSEC, CHARGE, CLIMATE, CLOSURES, SOFTWARE_UPDATE, COUNT };
  using Builder = std::function<int(Client *, uint8_t *, size_t *)>;
  using OperationResultCallback = std::function<void(OperationResult)>;
  using OperationPhaseCallback = std::function<void(OperationPhase)>;

  UniversalMessage_Domain domain;
  std::string name;
  Kind kind = Kind::NORMAL;
  Refresh refresh = Refresh::COUNT;
  // Builder function: takes Client pointer, output buffer, output length pointer. Returns status code (0 for success).
  // The output buffer capacity is passed in *output_length and must not be exceeded
  // (UniversalMessage_RoutableMessage_size + 2 bytes is always sufficient).
  Builder builder;
  std::vector<Builder> remaining_steps;
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
  // Small members of the two blocks below, kept here to avoid padding
  bool resend_encoded = false;
  bool request_accepted = false;
  uint8_t auth_resends = 0;
  UniversalMessage_Domain auth_request_domain = UniversalMessage_Domain_DOMAIN_BROADCAST;

  // The encoded request as last sent. A resend after a response timeout writes
  // these same bytes (as vehicle-command does): the car treats a repeat as a
  // duplicate instead of a new command, so a command that did arrive (only the
  // reply was lost) is not executed twice. Rebuilt only after a new session.
  // resend_encoded: the next send writes these bytes again.
  std::vector<uint8_t> encoded_request;

  // The pending session info request, resent unchanged every second while no
  // answer comes (as vehicle-command does). The infotainment of a car that is
  // just waking ignores a request sent the moment VCSEC reports it awake; with
  // a single request the command then waited the full auth timeout (25 s).
  // auth_request_domain: its domain; auth_resends: copies sent so far.
  std::vector<uint8_t> auth_request;
  std::chrono::steady_clock::time_point auth_resend_at;

  // Exponential backoff retry timing
  std::chrono::milliseconds next_retry_delay = std::chrono::milliseconds(0);
  std::chrono::steady_clock::time_point next_retry_time;

  // Domain context for consolidated state handling
  UniversalMessage_Domain current_auth_domain;

  bool awaiting_response() const {
    return state == CommandState::WAITING_FOR_RESPONSE || (state == CommandState::READY && resend_encoded);
  }

  Command(UniversalMessage_Domain d, std::string n, std::function<int(Client *, uint8_t *, size_t *)> b,
          OperationResultCallback cb = nullptr, WakePolicy wake = WakePolicy::WAKE_IF_NEEDED,
          OperationPhaseCallback phase_cb = nullptr, Kind command_kind = Kind::NORMAL,
          Refresh follow_up = Refresh::COUNT)
      : domain(d),
        name(std::move(n)),
        kind(command_kind),
        refresh(follow_up),
        builder(std::move(b)),
        on_complete(std::move(cb)),
        on_phase_change(std::move(phase_cb)),
        wake_policy(wake),
        current_auth_domain(d) {
    started_at = std::chrono::steady_clock::now();
    phase_started_at = started_at;
  }
};

class Vehicle {
 public:
  Vehicle(const std::shared_ptr<BleAdapter> &ble, const std::shared_ptr<StorageAdapter> &storage);

  void loop();

  void on_rx_data(const std::vector<uint8_t> &data);

  // Primary command API: queue a command built by `builder` and report its
  // outcome (success / skipped / failure with a rich CommandError) through
  // `on_complete`. High-level action methods below cover all standard
  // commands; use this directly only for custom frames.
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
  // Artist and title are not in the generated MediaState (unbounded strings); they come as MediaNowPlaying
  void set_media_state_callback(std::function<void(const CarServer_MediaState &, const MediaNowPlaying &)> cb) {
    media_state_callback_ = std::move(cb);
  }
  // Version is not in the generated SoftwareUpdateState (unbounded string); it
  // is extracted from the raw response alongside the struct.
  void set_software_update_state_callback(
      std::function<void(const CarServer_SoftwareUpdateState &, const std::string &)> cb) {
    software_update_callback_ = std::move(cb);
  }

  // Actions report their outcome through on_complete (success / skipped /
  // failure with a rich CommandError). Pass nullptr when the result is not
  // needed; the default wake policy matches the historical behavior
  // (WAKE_IF_NEEDED).
  void wake(Command::OperationResultCallback on_complete = nullptr);
  void vcsec_poll(WakePolicy wake_policy = WakePolicy::WAKE_IF_NEEDED,
                  Command::OperationResultCallback on_complete = nullptr);
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
  // Not part of infotainment_poll(): media state is only useful while someone listens
  void media_state_poll(bool force_wake = false);
  void media_state_poll(WakePolicy wake_policy);
  // Also included in every fifth infotainment_poll(); call directly for a manual refresh.
  void software_update_poll(bool force_wake = false);
  void software_update_poll(WakePolicy wake_policy);
  // Start (or schedule, offset_sec seconds from now) the installation of a
  // downloaded update. The car downloads firmware itself; this cannot fetch it.
  void schedule_software_update(int offset_sec, Command::OperationResultCallback on_complete = nullptr);
  void cancel_software_update(Command::OperationResultCallback on_complete = nullptr);

  void set_charging_state(bool enable, Command::OperationResultCallback on_complete = nullptr);
  void set_charging_amps(int amps, Command::OperationResultCallback on_complete = nullptr);
  void set_charging_limit(int limit, Command::OperationResultCallback on_complete = nullptr);
  void unlock_charge_port(Command::OperationResultCallback on_complete = nullptr);

  // VCSEC closure controls
  void lock(Command::OperationResultCallback on_complete = nullptr);
  void unlock(Command::OperationResultCallback on_complete = nullptr);
  void open_trunk(Command::OperationResultCallback on_complete = nullptr);
  void close_trunk(Command::OperationResultCallback on_complete = nullptr);
  void open_frunk(Command::OperationResultCallback on_complete = nullptr);
  void open_charge_port(Command::OperationResultCallback on_complete = nullptr);
  void close_charge_port(Command::OperationResultCallback on_complete = nullptr);
  void unlatch_driver_door(Command::OperationResultCallback on_complete = nullptr);

  // HVAC controls (infotainment)
  void set_climate(bool enable, Command::OperationResultCallback on_complete = nullptr);
  void set_climate_temp(float temp_celsius, Command::OperationResultCallback on_complete = nullptr);
  void set_climate_keeper(int mode,
                          Command::OperationResultCallback on_complete = nullptr);  // 0=Off, 1=On, 2=Dog, 3=Camp
  void set_bioweapon_mode(bool enable, Command::OperationResultCallback on_complete = nullptr);
  void set_preconditioning_max(bool enable, Command::OperationResultCallback on_complete = nullptr);  // Defrost
  void set_steering_wheel_heat(bool enable, Command::OperationResultCallback on_complete = nullptr);
  // Seat climate levels: 0 = off, 1-3 = Low/Medium/High. Cooling and Auto exist
  // only on seats that report them.
  void set_seat_heater(SeatPosition seat, int level, Command::OperationResultCallback on_complete = nullptr);
  void set_seat_climate(SeatPosition seat, int level, bool cooling, bool cooling_supported,
                        Command::OperationResultCallback on_complete = nullptr);
  void set_seat_cooler(SeatPosition seat, int level, Command::OperationResultCallback on_complete = nullptr);
  void set_auto_seat_climate(SeatPosition seat, bool enable, Command::OperationResultCallback on_complete = nullptr);
  // 0 = Off, 1 = On, 2 = Fan only
  void set_cabin_overheat_protection(int mode, Command::OperationResultCallback on_complete = nullptr);
  // 0-100 percent open
  void set_sunroof_position(int percent, Command::OperationResultCallback on_complete = nullptr);

  // Vehicle controls (infotainment)
  void flash_lights(Command::OperationResultCallback on_complete = nullptr);
  void honk_horn(Command::OperationResultCallback on_complete = nullptr);
  void set_sentry_mode(bool enable, Command::OperationResultCallback on_complete = nullptr);
  void set_low_power_mode(bool enable, Command::OperationResultCallback on_complete = nullptr);
  void set_keep_accessory_power_mode(bool enable, Command::OperationResultCallback on_complete = nullptr);
  void set_guest_mode(bool enable, Command::OperationResultCallback on_complete = nullptr);
  void set_cabin_overheat_protection_temp(int level,  // 1=Low, 2=Medium, 3=High
                                          Command::OperationResultCallback on_complete = nullptr);
  // Times in minutes after midnight; policies 0=Off, 1=All week, 2=Weekdays
  void set_scheduled_departure(bool enabled, int departure_minutes, int preconditioning_policy, int off_peak_policy,
                               int off_peak_end_minutes, Command::OperationResultCallback on_complete = nullptr);
  void vent_windows(Command::OperationResultCallback on_complete = nullptr);
  void close_windows(Command::OperationResultCallback on_complete = nullptr);

  // Media controls (infotainment)
  void media_toggle_playback(Command::OperationResultCallback on_complete = nullptr);
  void media_next_track(Command::OperationResultCallback on_complete = nullptr);
  void media_previous_track(Command::OperationResultCallback on_complete = nullptr);
  void media_next_favorite(Command::OperationResultCallback on_complete = nullptr);
  void media_previous_favorite(Command::OperationResultCallback on_complete = nullptr);
  void media_volume_up(Command::OperationResultCallback on_complete = nullptr);
  void media_volume_down(Command::OperationResultCallback on_complete = nullptr);
  void set_media_volume(float level,  // 0-10, as vehicle-command SetVolume
                        Command::OperationResultCallback on_complete = nullptr);

  // Pairing & Auth
  void pair(Keys_Role role = Keys_Role_ROLE_OWNER, Command::OperationResultCallback on_complete = nullptr);
  void regenerate_key(const Command::OperationResultCallback &on_complete = nullptr);

  bool is_connected() const { return is_connected_; }
  void set_connected(bool connected);

  // Whether a private key is loaded (from storage or created for pairing).
  // Key presence does not prove the vehicle has whitelisted it.
  bool has_private_key() const;

  // Pending commands, including the current command and deferred state refreshes.
  // Hosts can use this to avoid disconnecting while work is in flight.
  size_t pending_command_count() const;

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
  // Unanswered session info request: resent unchanged this many times, one
  // TRANSPORT_RETRY_INTERVAL apart, within AUTH_RESPONSE_TIMEOUT
  static constexpr uint8_t MAX_AUTH_RESENDS = 10;

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
  void enqueue_command_(const std::shared_ptr<Command> &cmd);
  uint32_t infotainment_cycles_ = 0;
  using Refresh = Command::Refresh;
  std::array<std::chrono::steady_clock::time_point, static_cast<size_t>(Refresh::COUNT)> follow_up_polls_{};
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
  std::function<void(const CarServer_MediaState &, const MediaNowPlaying &)> media_state_callback_;
  std::function<void(const CarServer_SoftwareUpdateState &, const std::string &)> software_update_callback_;

  bool is_connected_ = false;
  uint64_t connection_generation_ = 0;
  bool is_looping_ = false;
  SleepState sleep_state_ = SleepState::UNKNOWN;
  bool recovery_attempted_ = false;

  static constexpr size_t FRAME_HEADER_SIZE = 2;
  static constexpr size_t MAX_MESSAGE_SIZE = 2048;
  static constexpr size_t MAX_RX_BUFFER_SIZE = MAX_MESSAGE_SIZE * 2;
  std::vector<uint8_t> rx_buffer_;
  std::shared_ptr<Command> peek_command_() const;
  void process_command_queue_();
  void handle_message_(const UniversalMessage_RoutableMessage &msg);
  bool response_matches_request_(const UniversalMessage_RoutableMessage &msg, UniversalMessage_Domain &domain) const;
  void process_idle_command_(const std::shared_ptr<Command> &command);
  void process_authenticating_command_(const std::shared_ptr<Command> &command);
  void process_auth_response_waiting_command_(const std::shared_ptr<Command> &command);
  void process_ready_command_(const std::shared_ptr<Command> &command);
  void advance_infotainment_prerequisites_(const std::shared_ptr<Command> &command);
  void initiate_vcsec_auth_(const std::shared_ptr<Command> &command);
  void initiate_infotainment_auth_(const std::shared_ptr<Command> &command);
  void initiate_wake_sequence_(const std::shared_ptr<Command> &command);
  bool set_command_phase_(const std::shared_ptr<Command> &command, OperationPhase phase);
  void mark_command_failed_(const std::shared_ptr<Command> &command, std::unique_ptr<CommandError> error,
                            OperationTerminalReason reason = OperationTerminalReason::NONE);
  void mark_command_completed_(const std::shared_ptr<Command> &command);
  void mark_command_skipped_(const std::shared_ptr<Command> &command, OperationTerminalReason reason);
  void finalize_command_(const std::shared_ptr<Command> &command, OperationResult result);
  void schedule_follow_up_poll_(Refresh refresh);
  Refresh refresh_for_action_(int32_t action_tag) const;
  void process_follow_up_polls_();
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
  // Internal, public for tests and for hosts that implement their own framing
  // diagnostics.
  void retry_command(const std::shared_ptr<Command> &command);
  bool is_message_complete();
  int get_expected_message_length();
  void process_complete_message();
  void initialize_rx_buffer();

 private:
  void handle_vcsec_message_(const UniversalMessage_RoutableMessage &msg, bool matches_request);
  void handle_carserver_message_(const UniversalMessage_RoutableMessage &msg, bool matches_request);
  void handle_session_info_message_(const UniversalMessage_RoutableMessage &msg, UniversalMessage_Domain domain);
  void handle_auth_timeout_common_(const std::shared_ptr<Command> &command, const std::string &domain_name,
                                   CommandState retry_state);
  void handle_vcsec_auth_timeout_(const std::shared_ptr<Command> &command);
  void handle_infotainment_auth_timeout_(const std::shared_ptr<Command> &command);
  void handle_wake_response_timeout_(const std::shared_ptr<Command> &command);
  void handle_signed_message_error_(const UniversalMessage_RoutableMessage &msg, UniversalMessage_Domain domain,
                                    bool &has_session_error);
  void send_infotainment_poll_(const std::string &name, int32_t data_type, WakePolicy wake_policy);
  void initiate_auth_for_domain_(const std::shared_ptr<Command> &command, UniversalMessage_Domain domain,
                                 CommandState waiting_state, const std::string &domain_name);
  bool persist_private_key_();
  void send_vcsec_rke_(const std::string &name, VCSEC_RKEAction_E action,
                       Command::OperationResultCallback on_complete = nullptr);
  void send_vcsec_closure_(const std::string &name, const VCSEC_ClosureMoveRequest &request,
                           Command::OperationResultCallback on_complete = nullptr);
  template<typename T>
  void send_infotainment_action_(const std::string &name, int32_t action_tag, T value,
                                 Command::OperationResultCallback on_complete = nullptr) {
    enqueue_command_(std::make_shared<Command>(
        UniversalMessage_Domain_DOMAIN_INFOTAINMENT, name,
        [action_tag, value](Client *client, uint8_t *buff, size_t *len) {
          return client->build_car_server_vehicle_action_message(buff, len, action_tag, &value);
        },
        std::move(on_complete), WakePolicy::WAKE_IF_NEEDED, nullptr, Command::Kind::NORMAL,
        refresh_for_action_(action_tag)));
  }
  void send_infotainment_action_(const std::string &name, int32_t action_tag,
                                 Command::OperationResultCallback on_complete = nullptr) {
    enqueue_command_(std::make_shared<Command>(
        UniversalMessage_Domain_DOMAIN_INFOTAINMENT, name,
        [action_tag](Client *client, uint8_t *buff, size_t *len) {
          return client->build_car_server_vehicle_action_message(buff, len, action_tag, nullptr);
        },
        std::move(on_complete), WakePolicy::WAKE_IF_NEEDED, nullptr, Command::Kind::NORMAL,
        refresh_for_action_(action_tag)));
  }

 public:
  // Testing helpers to access (and manipulate) internal state.
  std::queue<std::shared_ptr<Command>> &get_command_queue_for_testing() { return command_queue_; }
  std::vector<uint8_t> &rx_buffer_for_testing() { return rx_buffer_; }
};

}  // namespace TeslaBLE
