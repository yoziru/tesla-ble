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
  UniversalMessage_Domain domain;
  std::string name;
  // Builder function: takes Client pointer, output buffer, output length pointer. Returns status code (0 for success).
  std::function<int(Client *, uint8_t *, size_t *)> builder;
  // Callback: rich error information instead of boolean
  std::function<void(std::unique_ptr<CommandError>)> on_complete;
  // Whether this command requires the vehicle to be awake (write commands = true, read/poll = false)
  bool requires_wake = true;

  CommandState state = CommandState::IDLE;
  std::chrono::steady_clock::time_point started_at;
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
          std::function<void(std::unique_ptr<CommandError>)> cb = nullptr, bool wake = true)
      : domain(d),
        name(std::move(n)),
        builder(std::move(b)),
        on_complete(std::move(cb)),
        requires_wake(wake),
        current_auth_domain(d) {
    started_at = std::chrono::steady_clock::now();
  }
};

class Vehicle {
 public:
  Vehicle(const std::shared_ptr<BleAdapter> &ble, const std::shared_ptr<StorageAdapter> &storage);

  void loop();

  void on_rx_data(const std::vector<uint8_t> &data);

  void send_command(UniversalMessage_Domain domain, const std::string &name,
                    std::function<int(Client *, uint8_t *, size_t *)> builder,
                    std::function<void(std::unique_ptr<CommandError>)> on_complete = nullptr,
                    bool requires_wake = true);
  void send_command_bool(UniversalMessage_Domain domain, const std::string &name,
                         std::function<int(Client *, uint8_t *, size_t *)> builder,
                         const std::function<void(bool)> &on_complete = nullptr, bool requires_wake = true);

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
  void charge_state_poll(bool force_wake = false);
  void climate_state_poll(bool force_wake = false);
  void drive_state_poll(bool force_wake = false);
  void closures_state_poll(bool force_wake = false);
  void tire_pressure_poll(bool force_wake = false);

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

  void set_awake(bool awake) { is_vehicle_awake_ = awake; }

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
      std::chrono::seconds(4);  // Max allowed clock sync error (from Go impl)
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
  bool is_vehicle_awake_ = false;  // From VCSEC sleep status (inverted: true unless explicitly ASLEEP)
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
  void initiate_vcsec_auth_(const std::shared_ptr<Command> &command);
  void initiate_infotainment_auth_(const std::shared_ptr<Command> &command);
  void initiate_wake_sequence_(const std::shared_ptr<Command> &command);
  void mark_command_failed_(const std::shared_ptr<Command> &command, std::unique_ptr<CommandError> error);
  void mark_command_completed_(const std::shared_ptr<Command> &command);
  void finalize_command_(const std::shared_ptr<Command> &command, std::unique_ptr<CommandError> error);
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
  void send_infotainment_poll_(const std::string &name, int32_t data_type, bool force_wake = false);
  void initiate_auth_for_domain_(const std::shared_ptr<Command> &command, UniversalMessage_Domain domain,
                                 CommandState waiting_state, const std::string &domain_name);
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
