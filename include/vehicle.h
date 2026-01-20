#pragma once

#include "adapters.h"
#include "client.h"
#include "universal_message.pb.h"

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
  WAITING_FOR_VCSEC_AUTH,
  WAITING_FOR_VCSEC_AUTH_RESPONSE,
  WAITING_FOR_INFOTAINMENT_AUTH,
  WAITING_FOR_INFOTAINMENT_AUTH_RESPONSE,
  WAITING_FOR_WAKE,
  WAITING_FOR_WAKE_RESPONSE,
  READY,
  WAITING_FOR_RESPONSE,
  COMPLETED,
  FAILED
};

struct Command {
  UniversalMessage_Domain domain;
  std::string name;
  // Builder function: takes Client pointer, output buffer, output length pointer. Returns status code (0 for success).
  std::function<int(Client *, uint8_t *, size_t *)> builder;
  // Callback: success state
  std::function<void(bool)> on_complete;
  // Whether this command requires the vehicle to be awake (write commands = true, read/poll = false)
  bool requires_wake = true;

  CommandState state = CommandState::IDLE;
  std::chrono::steady_clock::time_point started_at;
  std::chrono::steady_clock::time_point last_tx_at;
  uint8_t retry_count = 0;

  Command(UniversalMessage_Domain d, std::string n, std::function<int(Client *, uint8_t *, size_t *)> b,
          std::function<void(bool)> cb = nullptr, bool wake = true)
      : domain(d), name(std::move(n)), builder(std::move(b)), on_complete(std::move(cb)), requires_wake(wake) {
    started_at = std::chrono::steady_clock::now();
  }
};

class Vehicle {
 public:
  Vehicle(std::shared_ptr<BleAdapter> ble_adapter, std::shared_ptr<StorageAdapter> storage_adapter);

  // Main loop processing (handling timeouts, retries, etc.)
  void loop();

  // Data reception from Adapter
  void on_rx_data(const std::vector<uint8_t> &data);

  // Command Enqueueing
  void send_command(UniversalMessage_Domain domain, std::string name,
                    std::function<int(Client *, uint8_t *, size_t *)> builder,
                    std::function<void(bool)> on_complete = nullptr, bool requires_wake = true);

  // State Callbacks
  void set_vehicle_status_callback(std::function<void(const VCSEC_VehicleStatus &)> cb) {
    vehicle_status_callback_ = cb;
  }
  void set_charge_state_callback(std::function<void(const CarServer_ChargeState &)> cb) { charge_state_callback_ = cb; }
  void set_climate_state_callback(std::function<void(const CarServer_ClimateState &)> cb) {
    climate_state_callback_ = cb;
  }
  void set_drive_state_callback(std::function<void(const CarServer_DriveState &)> cb) { drive_state_callback_ = cb; }
  void set_tire_pressure_state_callback(std::function<void(const CarServer_TirePressureState &)> cb) {
    tire_pressure_callback_ = cb;
  }
  void set_closures_state_callback(std::function<void(const CarServer_ClosuresState &)> cb) {
    closures_state_callback_ = cb;
  }

  // Helpers for common commands (wrappers around send_command)
  void wake();
  void vcsec_poll();
  void infotainment_poll(bool force_wake = false);

  // Individual state polls (all use force_wake parameter like infotainment_poll)
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
  void authenticate_key_request();
  void pair(Keys_Role role = Keys_Role_ROLE_OWNER);
  void regenerate_key();

  bool is_connected() const { return is_connected_; }
  void set_connected(bool connected);

  // Configuration
  void set_vin(const std::string &vin);

  // Callbacks
  using MessageCallback = std::function<void(const UniversalMessage_RoutableMessage &)>;
  void set_message_callback(MessageCallback cb) { message_callback_ = cb; }

  using RawMessageCallback = std::function<void(const std::vector<uint8_t> &)>;
  void set_raw_message_callback(RawMessageCallback cb) { raw_message_callback_ = cb; }

 private:
  std::shared_ptr<BleAdapter> ble_adapter_;
  std::shared_ptr<StorageAdapter> storage_adapter_;
  std::shared_ptr<Client> client_;

  std::queue<std::shared_ptr<Command>> command_queue_;
  MessageCallback message_callback_;
  RawMessageCallback raw_message_callback_;

  std::function<void(const VCSEC_VehicleStatus &)> vehicle_status_callback_;
  std::function<void(const CarServer_ChargeState &)> charge_state_callback_;
  std::function<void(const CarServer_ClimateState &)> climate_state_callback_;
  std::function<void(const CarServer_DriveState &)> drive_state_callback_;
  std::function<void(const CarServer_TirePressureState &)> tire_pressure_callback_;
  std::function<void(const CarServer_ClosuresState &)> closures_state_callback_;

  bool is_connected_ = false;
  bool is_vcsec_authenticated_ = false;
  bool is_infotainment_authenticated_ = false;
  bool is_vehicle_awake_ = false;  // From VCSEC sleep status (inverted: true unless explicitly ASLEEP)

  // Constants
  static constexpr auto COMMAND_TIMEOUT = std::chrono::seconds(30);
  static constexpr auto MAX_LATENCY = std::chrono::seconds(4);
  static constexpr uint8_t MAX_RETRIES = 5;

  // Internal Helpers
  void process_command_queue();
  void handle_message(const UniversalMessage_RoutableMessage &msg);

  void process_idle_command(const std::shared_ptr<Command> &command);
  void process_auth_waiting_command(const std::shared_ptr<Command> &command);
  void process_ready_command(const std::shared_ptr<Command> &command);

  void initiate_vcsec_auth(const std::shared_ptr<Command> &command);
  void initiate_infotainment_auth(const std::shared_ptr<Command> &command);
  void initiate_wake_sequence(const std::shared_ptr<Command> &command);
  void retry_command(const std::shared_ptr<Command> &command);
  void mark_command_failed(const std::shared_ptr<Command> &command, const std::string &reason);
  void mark_command_completed(const std::shared_ptr<Command> &command);

  bool is_domain_authenticated(UniversalMessage_Domain domain);
  void handle_authentication_response(UniversalMessage_Domain domain, bool success);

  // Session persistence
  void load_session_from_storage(UniversalMessage_Domain domain);

 protected:
  // Message Reassembly
  bool is_message_complete();
  int get_expected_message_length();
  void process_complete_message();

  // Reassembly buffer
  std::vector<uint8_t> rx_buffer_;

 private:
  // Message Handlers
  void handle_vcsec_message(const UniversalMessage_RoutableMessage &msg);
  void handle_carserver_message(const UniversalMessage_RoutableMessage &msg);
  void handle_session_info_message(const UniversalMessage_RoutableMessage &msg);
};

}  // namespace TeslaBLE
