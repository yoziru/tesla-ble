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
    std::function<int(Client*, uint8_t*, size_t*)> builder;
    // Callback: success state
    std::function<void(bool)> on_complete;

    CommandState state = CommandState::IDLE;
    std::chrono::steady_clock::time_point started_at;
    std::chrono::steady_clock::time_point last_tx_at;
    uint8_t retry_count = 0;

    Command(UniversalMessage_Domain d, std::string n, std::function<int(Client*, uint8_t*, size_t*)> b, std::function<void(bool)> cb = nullptr)
        : domain(d), name(std::move(n)), builder(std::move(b)), on_complete(std::move(cb)) {
            started_at = std::chrono::steady_clock::now();
    }
};

class Vehicle {
public:
    Vehicle(std::shared_ptr<BleAdapter> ble_adapter, std::shared_ptr<StorageAdapter> storage_adapter);

    // Main loop processing (handling timeouts, retries, etc.)
    void loop();

    // Data reception from Adapter
    void on_rx_data(const std::vector<uint8_t>& data);
    
    // Command Enqueueing
    void send_command(UniversalMessage_Domain domain, std::string name, std::function<int(Client*, uint8_t*, size_t*)> builder, std::function<void(bool)> on_complete = nullptr);
    
    // State Callbacks
    void set_vehicle_status_callback(std::function<void(const VCSEC_VehicleStatus&)> cb) { vehicle_status_callback_ = cb; }
    void set_charge_state_callback(std::function<void(const CarServer_ChargeState&)> cb) { charge_state_callback_ = cb; }
    void set_climate_state_callback(std::function<void(const CarServer_ClimateState&)> cb) { climate_state_callback_ = cb; }
    void set_drive_state_callback(std::function<void(const CarServer_DriveState&)> cb) { drive_state_callback_ = cb; }
    void set_tire_pressure_callback(std::function<void(const CarServer_TirePressureState&)> cb) { tire_pressure_callback_ = cb; }
    
    // Helpers for common commands (wrappers around send_command)
    void wake();
    void vcsec_poll();
    void infotainment_poll();
    void set_charging_state(bool enable);
    void set_charging_amps(int amps);
    void set_charging_limit(int limit);
    void unlock_charge_port();
    

    
    // Pairing & Auth
    void authenticate_key_request();
    void pair(Keys_Role role = Keys_Role_ROLE_OWNER);
    void regenerate_key();
    
    bool is_connected() const { return is_connected_; }
    void set_connected(bool connected);
    
    // Configuration
    void set_vin(const std::string& vin);
    
    // Callbacks
    using MessageCallback = std::function<void(const UniversalMessage_RoutableMessage&)>;
    void set_message_callback(MessageCallback cb) { message_callback_ = cb; }
    
    using RawMessageCallback = std::function<void(const std::vector<uint8_t>&)>;
    void set_raw_message_callback(RawMessageCallback cb) { raw_message_callback_ = cb; }

private:
    std::shared_ptr<BleAdapter> ble_adapter_;
    std::shared_ptr<StorageAdapter> storage_adapter_;
    std::shared_ptr<Client> client_;
    
    std::queue<std::shared_ptr<Command>> command_queue_;
    MessageCallback message_callback_;
    RawMessageCallback raw_message_callback_;
    
    std::function<void(const VCSEC_VehicleStatus&)> vehicle_status_callback_;
    std::function<void(const CarServer_ChargeState&)> charge_state_callback_;
    std::function<void(const CarServer_ClimateState&)> climate_state_callback_;
    std::function<void(const CarServer_DriveState&)> drive_state_callback_;
    std::function<void(const CarServer_TirePressureState&)> tire_pressure_callback_;

    bool is_connected_ = false;
    bool is_vcsec_authenticated_ = false;
    bool is_infotainment_authenticated_ = false;
    


    // Constants
    static constexpr auto COMMAND_TIMEOUT = std::chrono::seconds(30);
    static constexpr auto MAX_LATENCY = std::chrono::seconds(4);
    static constexpr uint8_t MAX_RETRIES = 5;

    // Internal Helpers
    void process_command_queue();
    void handle_message(const UniversalMessage_RoutableMessage& msg);
    
    void process_idle_command(std::shared_ptr<Command> command);
    void process_auth_waiting_command(std::shared_ptr<Command> command);
    void process_ready_command(std::shared_ptr<Command> command);
    
    void initiate_vcsec_auth(std::shared_ptr<Command> command);
    void initiate_infotainment_auth(std::shared_ptr<Command> command);
    void initiate_wake_sequence(std::shared_ptr<Command> command);
    void retry_command(std::shared_ptr<Command> command);
    void mark_command_failed(std::shared_ptr<Command> command, const std::string& reason);
    void mark_command_completed(std::shared_ptr<Command> command);
    
    bool is_domain_authenticated(UniversalMessage_Domain domain);
    void handle_authentication_response(UniversalMessage_Domain domain, bool success);

protected:
    // Message Reassembly
    bool is_message_complete();
    int get_expected_message_length();
    void process_complete_message();
    
    // Reassembly buffer
    std::vector<uint8_t> rx_buffer_;

private:
    // Message Handlers
    void handle_vcsec_message(const UniversalMessage_RoutableMessage& msg);
    void handle_carserver_message(const UniversalMessage_RoutableMessage& msg);
    void handle_session_info_message(const UniversalMessage_RoutableMessage& msg);
};

} // namespace TeslaBLE
