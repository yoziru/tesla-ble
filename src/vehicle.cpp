#ifndef TESLA_LOG_TAG
#define TESLA_LOG_TAG "TeslaBLE::Vehicle"
#endif

#include "vehicle.h"

#include "defs.h"
#include "tb_logging.h"
#include "tb_utils.h"

#include <pb_decode.h>
#include <pb_encode.h>

#include <cstring>
#include <inttypes.h>
#include <vector>

namespace TeslaBLE {

Vehicle::Vehicle(std::shared_ptr<BleAdapter> ble, std::shared_ptr<StorageAdapter> storage)
    : ble_adapter_(ble), storage_adapter_(storage), client_(std::make_shared<Client>())
{
    // Load existing keys and sessions from storage
    
    // 1. Load private key
    std::vector<uint8_t> key_buffer;
    if (storage_adapter_->load("private_key", key_buffer)) {
         if (client_->loadPrivateKey(key_buffer.data(), key_buffer.size()) == 0) {
             LOG_INFO("Loaded private key from storage");
         } else {
             LOG_ERROR("Failed to load private key from storage");
         }
    } else {
        LOG_INFO("No private key found in storage");
    }
    
    // 2. Load VCSEC session
    load_session_from_storage(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
    
    // 3. Load Infotainment session
    load_session_from_storage(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
}

void Vehicle::set_vin(const std::string& vin) {
    if (client_) {
        client_->setVIN(vin);
    }
}

void Vehicle::set_connected(bool connected) {
    is_connected_ = connected;
    if (!connected) {
        LOG_INFO("Disconnected from vehicle");
        // Clear auth states?
        // Usually session persists, but connection state is used for something?
    } else {
        LOG_INFO("Connected to vehicle");
    }
}

void Vehicle::loop() {
    process_command_queue();
}

void Vehicle::send_command(UniversalMessage_Domain domain, 
                           std::string name, 
                           std::function<int(Client*, uint8_t*, size_t*)> builder,
                           std::function<void(bool)> on_complete,
                           bool requires_wake) {
    
    // TODO: Max queue size check?
    
    auto cmd = std::make_shared<Command>(domain, std::move(name), std::move(builder), std::move(on_complete), requires_wake);
    command_queue_.push(cmd);
    
    LOG_DEBUG("Enqueued command: %s (domain: %s, requires_wake: %s)", cmd->name.c_str(), domain_to_string(domain), requires_wake ? "true" : "false");
}

void Vehicle::process_command_queue() {
    if (command_queue_.empty()) return;

    auto current_command = command_queue_.front();
    auto now = std::chrono::steady_clock::now();

    // Overall timeout
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - current_command->started_at);
    if (duration > COMMAND_TIMEOUT) {
        LOG_WARNING("Command timeout: %s", current_command->name.c_str());
        mark_command_failed(current_command, "Timeout");
        return;
    }

    switch (current_command->state) {
        case CommandState::IDLE:
            process_idle_command(current_command);
            break;
            
        case CommandState::WAITING_FOR_VCSEC_AUTH:
        case CommandState::WAITING_FOR_VCSEC_AUTH_RESPONSE:
        case CommandState::WAITING_FOR_INFOTAINMENT_AUTH:
        case CommandState::WAITING_FOR_INFOTAINMENT_AUTH_RESPONSE:
        case CommandState::WAITING_FOR_WAKE:
        case CommandState::WAITING_FOR_WAKE_RESPONSE:
            process_auth_waiting_command(current_command);
            break;
            
        case CommandState::READY:
            process_ready_command(current_command);
            break;
            
        case CommandState::WAITING_FOR_RESPONSE:
            {
                auto tx_duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - current_command->last_tx_at);
                if (tx_duration > MAX_LATENCY) {
                    LOG_WARNING("Response timeout for command: %s (attempt %d/%d)", current_command->name.c_str(), current_command->retry_count, MAX_RETRIES + 1);
                    retry_command(current_command);
                }
            }
            break;
            
        default:
            break;
    }
}

void Vehicle::process_idle_command(std::shared_ptr<Command> command) {
    command->started_at = std::chrono::steady_clock::now();
    
    switch (command->domain) {
        case UniversalMessage_Domain_DOMAIN_BROADCAST:
            command->state = CommandState::READY;
            break;
            
        case UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY:
            initiate_vcsec_auth(command);
            break;
            
        case UniversalMessage_Domain_DOMAIN_INFOTAINMENT:
            initiate_infotainment_auth(command);
            break;
            
        default:
            LOG_ERROR("Unknown domain for command: %s", command->name.c_str());
            mark_command_failed(command, "Unknown domain");
            break;
    }
}

void Vehicle::process_auth_waiting_command(std::shared_ptr<Command> command) {
    auto now = std::chrono::steady_clock::now();
    auto tx_duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->last_tx_at);
    
    if (tx_duration > MAX_LATENCY) {
        switch (command->state) {
            case CommandState::WAITING_FOR_VCSEC_AUTH_RESPONSE:
                 LOG_WARNING("VCSEC auth response timeout (attempt %d/%d)", command->retry_count + 1, MAX_RETRIES + 1);
                 command->state = CommandState::WAITING_FOR_VCSEC_AUTH; // Retry initiation
                 break;
            case CommandState::WAITING_FOR_INFOTAINMENT_AUTH_RESPONSE:
                 LOG_WARNING("Infotainment auth response timeout (attempt %d/%d)", command->retry_count + 1, MAX_RETRIES + 1);
                 command->state = CommandState::WAITING_FOR_INFOTAINMENT_AUTH;
                 break;
            case CommandState::WAITING_FOR_WAKE_RESPONSE:
                 // Check if vehicle woke up (we may have received status update even without wake response)
                 if (is_vehicle_awake_) {
                     LOG_INFO("Wake response timeout but vehicle is awake - proceeding");
                     if (command->domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT) {
                         command->state = CommandState::WAITING_FOR_INFOTAINMENT_AUTH;
                         command->last_tx_at = std::chrono::steady_clock::time_point();  // Trigger immediate auth
                     } else {
                         mark_command_completed(command);
                     }
                 } else {
                     LOG_WARNING("Wake response timeout - vehicle still asleep (attempt %d/%d)", command->retry_count + 1, MAX_RETRIES + 1);
                     retry_command(command);
                 }
                 break;
            case CommandState::WAITING_FOR_VCSEC_AUTH:
                 initiate_vcsec_auth(command);
                 break;
            case CommandState::WAITING_FOR_INFOTAINMENT_AUTH:
                 initiate_infotainment_auth(command);
                 break;
            case CommandState::WAITING_FOR_WAKE:
                 initiate_wake_sequence(command);
                 break;
            default:
                 break;
        }
    }
}

void Vehicle::initiate_vcsec_auth(std::shared_ptr<Command> command) {
    if (is_domain_authenticated(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY)) {
        if (command->domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY) {
            command->state = CommandState::READY;
        } else {
             // Chain to infotainment
             command->state = CommandState::WAITING_FOR_INFOTAINMENT_AUTH;
        }
    } else {
        // Build Session Info Request
        uint8_t buffer[256];
        size_t len = 256;
        if (client_->buildSessionInfoRequestMessage(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, buffer, &len) == 0) {
            std::vector<uint8_t> data(buffer, buffer + len);
            if (ble_adapter_->write(data)) {
                 command->state = CommandState::WAITING_FOR_VCSEC_AUTH_RESPONSE;
                 command->last_tx_at = std::chrono::steady_clock::now();
                 LOG_INFO("Sent VCSEC Session Info Request");
            } else {
                 LOG_ERROR("Failed to write VCSEC Session Info Request");
            }
        } else {
            LOG_ERROR("Failed to build VCSEC Session Info Request");
            mark_command_failed(command, "Build failed");
        }
    }
}

void Vehicle::initiate_infotainment_auth(std::shared_ptr<Command> command) {
    // FIRST: If vehicle is asleep and command doesn't require wake, skip immediately
    // This avoids unnecessary auth attempts for optional polls when vehicle is sleeping
    if (!is_vehicle_awake_ && !command->requires_wake) {
        LOG_DEBUG("Vehicle is asleep and command doesn't require wake, skipping: %s", command->name.c_str());
        mark_command_completed(command);  // Mark as completed (no-op when asleep)
        return;
    }
    
    // Check if VCSEC is authenticated (prerequisite for both wake and infotainment)
    if (!is_domain_authenticated(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY)) {
        LOG_DEBUG("VCSEC auth required before Infotainment auth");
        // Directly initiate VCSEC auth instead of just setting state, to avoid extra loop iteration
        initiate_vcsec_auth(command);
        return;
    }
    
    // Check if vehicle is asleep and command requires wake - if so, transition to wake state
    if (!is_vehicle_awake_ && command->requires_wake) {
        LOG_DEBUG("Vehicle is asleep and command requires wake, transitioning to wake state");
        command->state = CommandState::WAITING_FOR_WAKE;
        command->last_tx_at = std::chrono::steady_clock::time_point();  // Trigger immediate wake sequence
        return;
    }
    
    if (is_domain_authenticated(UniversalMessage_Domain_DOMAIN_INFOTAINMENT)) {
        command->state = CommandState::READY;
    } else {
        uint8_t buffer[256];
        size_t len = 256;
        if (client_->buildSessionInfoRequestMessage(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, buffer, &len) == 0) {
            std::vector<uint8_t> data(buffer, buffer + len);
            if (ble_adapter_->write(data)) {
                 command->state = CommandState::WAITING_FOR_INFOTAINMENT_AUTH_RESPONSE;
                 command->last_tx_at = std::chrono::steady_clock::now();
                 LOG_INFO("Sent Infotainment Session Info Request");
            } else {
                 LOG_ERROR("Failed to write Infotainment Session Info Request");
            }
        } else {
            LOG_ERROR("Failed to build Infotainment Session Info Request");
            mark_command_failed(command, "Build failed");
        }
    }
}

void Vehicle::initiate_wake_sequence(std::shared_ptr<Command> command) {
    // Send Wake command (RKE Action)
    uint8_t buffer[256];
    size_t len = 256;
    if (client_->buildVCSECActionMessage(VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, buffer, &len) == 0) {
         std::vector<uint8_t> data(buffer, buffer + len);
         if (ble_adapter_->write(data)) {
             command->state = CommandState::WAITING_FOR_WAKE_RESPONSE;
             command->last_tx_at = std::chrono::steady_clock::now();
             LOG_INFO("Sent Wake Command");
         } else {
             LOG_ERROR("Failed to write Wake Command");
         }
    } else {
         LOG_ERROR("Failed to build Wake Command");
         mark_command_failed(command, "Build failed");
    }
}

void Vehicle::process_ready_command(std::shared_ptr<Command> command) {
    uint8_t buffer[1024]; // Assuming max message size
    size_t len = 1024;
    
    int result = command->builder(client_.get(), buffer, &len);
    if (result == 0) {
        std::vector<uint8_t> data(buffer, buffer + len);
        if (ble_adapter_->write(data)) {
            command->state = CommandState::WAITING_FOR_RESPONSE;
            command->last_tx_at = std::chrono::steady_clock::now();
            command->retry_count++;
            LOG_INFO("Sent command: %s (attempt %d/%d)", command->name.c_str(), command->retry_count, MAX_RETRIES + 1);
        } else {
            LOG_ERROR("Failed to write command: %s", command->name.c_str());
            retry_command(command);
        }
    } else {
        LOG_ERROR("Failed to build command: %s (error %d)", command->name.c_str(), result);
        mark_command_failed(command, "Build failed");
    }
}

void Vehicle::retry_command(std::shared_ptr<Command> command) {
    if (command->retry_count >= MAX_RETRIES) {
        LOG_ERROR("Max retries exceeded for command: %s", command->name.c_str());
        mark_command_failed(command, "Max retries exceeded");
        return;
    }
    
    LOG_DEBUG("Retrying command: %s", command->name.c_str());
    // Use last_tx_at to delay? Or just reset state.
    // Logic from CommandManager: reset to appropriate state.
    
    // Simplification: if waiting for response, go back to ready.
    if (command->state == CommandState::WAITING_FOR_RESPONSE) {
        command->state = CommandState::READY;
    }
    // If auth failed, go back to IDLE to re-verify auth?
    else if (command->state == CommandState::WAITING_FOR_VCSEC_AUTH_RESPONSE || 
             command->state == CommandState::WAITING_FOR_INFOTAINMENT_AUTH_RESPONSE) {
        command->state = CommandState::IDLE;
    }
    // Wake retry
    else if (command->state == CommandState::WAITING_FOR_WAKE_RESPONSE) {
        command->state = CommandState::WAITING_FOR_WAKE;
    }
    else {
        command->state = CommandState::IDLE;
    }
}

void Vehicle::mark_command_failed(std::shared_ptr<Command> command, const std::string& reason) {
    command->state = CommandState::FAILED;
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->started_at);
    LOG_ERROR("[%s] Command failed after %lld ms: %s", command->name.c_str(), (long long)duration.count(), reason.c_str());
    
    if (command->on_complete) {
        command->on_complete(false);
    }
    
    // Remove from queue if it's the front
    if (!command_queue_.empty() && command_queue_.front() == command) {
        command_queue_.pop();
    }
}

void Vehicle::mark_command_completed(std::shared_ptr<Command> command) {
    command->state = CommandState::COMPLETED;
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->started_at);
    LOG_INFO("[%s] Command completed successfully in %lld ms", command->name.c_str(), (long long)duration.count());
    
    if (command->on_complete) {
        command->on_complete(true);
    }
    
    if (!command_queue_.empty() && command_queue_.front() == command) {
        command_queue_.pop();
    }
}

bool Vehicle::is_domain_authenticated(UniversalMessage_Domain domain) {
    auto peer = client_->getPeer(domain);
    return peer && peer->isValid();
}

void Vehicle::on_rx_data(const std::vector<uint8_t>& data) {
    rx_buffer_.insert(rx_buffer_.end(), data.begin(), data.end());
    
    // Reassembly logic
    while (is_message_complete()) {
        process_complete_message();
    }
}

bool Vehicle::is_message_complete() {
    if (rx_buffer_.size() < 2) return false;
    
    int msg_len = get_expected_message_length();
    return rx_buffer_.size() >= (size_t)msg_len;
}

int Vehicle::get_expected_message_length() {
    if (rx_buffer_.size() < 2) return 0;
    // Length bytes usually indicate the payload length following the header
    return (int)((rx_buffer_[0] << 8) | rx_buffer_[1]) + 2;
}

void Vehicle::process_complete_message() {
    int msg_len = get_expected_message_length();
    if (msg_len <= 0 || msg_len > 2048) { // Sanity check
        LOG_ERROR("Invalid message length %d, clearing buffer", msg_len);
        rx_buffer_.clear();
        return;
    }
    
    std::vector<uint8_t> full_msg(rx_buffer_.begin(), rx_buffer_.begin() + msg_len);
    if (raw_message_callback_) {
        raw_message_callback_(full_msg);
    }
    
    std::vector<uint8_t> msg_data(rx_buffer_.begin() + 2, rx_buffer_.begin() + msg_len);
    
    // Parse
    UniversalMessage_RoutableMessage msg = UniversalMessage_RoutableMessage_init_default;
    if (client_->parseUniversalMessage(msg_data.data(), msg_data.size(), &msg) == 0) {
        LOG_DEBUG("Successfully parsed universal message");
        log_routable_message(TESLA_LOG_TAG, &msg);
        handle_message(msg);
    } else {
        LOG_ERROR("Failed to parse Universal Message");
    }
    
    // Remove processed data
    rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + msg_len);
}

void Vehicle::handle_message(const UniversalMessage_RoutableMessage& msg) {
    // Notify callback (for sensors)
    if (message_callback_) {
        message_callback_(msg);
    }
    
    // Handle session info updates first (can come from any domain)
    if (msg.which_payload == UniversalMessage_RoutableMessage_session_info_tag) {
        handle_session_info_message(msg);
        return;
    }
    
    // Handle Signed Message Status (errors)
    if (msg.has_signedMessageStatus) {
        if (msg.signedMessageStatus.operation_status == UniversalMessage_OperationStatus_E_OPERATIONSTATUS_ERROR) {
             UniversalMessage_Domain domain = msg.from_destination.sub_destination.domain;
             auto fault = msg.signedMessageStatus.signed_message_fault;
             LOG_ERROR("Signed message error from %s: %s", domain_to_string(domain), message_fault_to_string(fault));
             
             // Check for session-related errors that require re-authentication
             bool session_error = (
                 fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_TIME_EXPIRED ||
                 fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER ||
                 fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INVALID_SIGNATURE
             );
             
             if (session_error) {
                 // Invalidate the session for this domain
                 auto peer = client_->getPeer(domain);
                 if (peer) {
                     LOG_INFO("Invalidating session for %s due to session error, will re-authenticate", domain_to_string(domain));
                     peer->setIsValid(false);
                     
                     // Mark the domain as unauthenticated so next command will re-auth
                     if (domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY) {
                         is_vcsec_authenticated_ = false;
                     } else if (domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT) {
                         is_infotainment_authenticated_ = false;
                     }
                 }
             }
             
             // Handle command failure and retry
             if (!command_queue_.empty()) {
                 auto cmd = command_queue_.front();
                 if (cmd->state == CommandState::WAITING_FOR_RESPONSE) {
                     if (session_error) {
                         // For session errors, retry the command (it will re-authenticate)
                         LOG_INFO("Retrying command after session error");
                         cmd->state = CommandState::IDLE;
                         cmd->retry_count++; // Count this as a retry
                         if (cmd->retry_count > MAX_RETRIES) {
                             mark_command_failed(cmd, "Session error after max retries");
                         }
                     } else {
                         mark_command_failed(cmd, "Signed Message Error");
                     }
                 }
             }
             return;
        }
    }

    // Route based on domain
    if (msg.from_destination.which_sub_destination == UniversalMessage_Destination_domain_tag) {
        switch (msg.from_destination.sub_destination.domain) {
            case UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY:
                handle_vcsec_message(msg);
                break;
            case UniversalMessage_Domain_DOMAIN_INFOTAINMENT:
                handle_carserver_message(msg);
                break;
            default:
                LOG_DEBUG("Message from unknown domain: %d", msg.from_destination.sub_destination.domain);
                break;
        }
    }
}

void Vehicle::handle_session_info_message(const UniversalMessage_RoutableMessage& msg) {
    UniversalMessage_Domain domain = msg.from_destination.sub_destination.domain;
    
    // Infer domain if missing (common in some responses?)
    if (!msg.has_from_destination || msg.from_destination.which_sub_destination != UniversalMessage_Destination_domain_tag) {
         if (!command_queue_.empty()) {
             auto cmd = command_queue_.front();
             if (cmd->state == CommandState::WAITING_FOR_INFOTAINMENT_AUTH_RESPONSE) domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;
             else if (cmd->state == CommandState::WAITING_FOR_VCSEC_AUTH_RESPONSE) domain = UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY;
         }
    }
    
    Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
    int result = client_->parsePayloadSessionInfo(const_cast<UniversalMessage_RoutableMessage_session_info_t*>(&msg.payload.session_info), &session_info);
    
    if (result != 0) {
        LOG_ERROR("Failed to parse session info: %d", result);
        handle_authentication_response(domain, false);
        return;
    }
    LOG_DEBUG("Parsed session info successfully");
    
    log_session_info(TESLA_LOG_TAG, &session_info);
    
    if (session_info.status != Signatures_Session_Info_Status_SESSION_INFO_STATUS_OK) {
        LOG_ERROR("Session info invalid status: %d", session_info.status);
        handle_authentication_response(domain, false);
        return;
    }
    
    auto peer = client_->getPeer(domain);
    if (peer) {
        int update_result = peer->updateSession(&session_info);
        if (update_result == 0) {
            LOG_INFO("Session updated for %s", domain_to_string(domain));
            
            // Persist session
            std::vector<uint8_t> sess_data(msg.payload.session_info.bytes, msg.payload.session_info.bytes + msg.payload.session_info.size);
            std::string key = (domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY) ? "session_vcsec" : "session_infotainment";
            storage_adapter_->save(key, sess_data);
            
            handle_authentication_response(domain, true);
        } else if (update_result == TeslaBLE_Status_E_ERROR_COUNTER_REPLAY) {
            // Counter went backwards - the vehicle's session is authoritative
            // This can happen after ERROR_TIME_EXPIRED when the vehicle sends new session info
            LOG_INFO("Counter anti-replay detected for %s, force updating with vehicle's authoritative session", domain_to_string(domain));
            
            if (peer->forceUpdateSession(&session_info) == 0) {
                LOG_INFO("Session force-updated for %s", domain_to_string(domain));
                
                // Persist the new session
                std::vector<uint8_t> sess_data(msg.payload.session_info.bytes, msg.payload.session_info.bytes + msg.payload.session_info.size);
                std::string key = (domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY) ? "session_vcsec" : "session_infotainment";
                storage_adapter_->save(key, sess_data);
                
                handle_authentication_response(domain, true);
            } else {
                LOG_ERROR("Failed to force update peer session for %s", domain_to_string(domain));
                handle_authentication_response(domain, false);
            }
        } else {
            LOG_ERROR("Failed to update peer session for %s: %d", domain_to_string(domain), update_result);
            handle_authentication_response(domain, false);
        }
    }
}

void Vehicle::handle_vcsec_message(const UniversalMessage_RoutableMessage& msg) {
    LOG_DEBUG("Processing VCSEC message");
    VCSEC_FromVCSECMessage vcsec_msg = VCSEC_FromVCSECMessage_init_default;
    int result = client_->parseFromVCSECMessage(const_cast<UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t*>(&msg.payload.protobuf_message_as_bytes), &vcsec_msg);
    
    if (result != 0) {
        LOG_ERROR("Failed to parse VCSEC message: %d", result);
        return;
    }
    
    LOG_DEBUG("Parsed VCSEC message successfully");
    
    switch (vcsec_msg.which_sub_message) {
        case VCSEC_FromVCSECMessage_commandStatus_tag:
            log_vcsec_command_status(TESLA_LOG_TAG, &vcsec_msg.sub_message.commandStatus);
            // Check if this matches pending command
            if (!command_queue_.empty()) {
                auto cmd = command_queue_.front();
                if (cmd->domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY) {
                    if (cmd->state == CommandState::WAITING_FOR_RESPONSE || 
                        cmd->state == CommandState::WAITING_FOR_WAKE_RESPONSE) {
                        mark_command_completed(cmd);
                    }
                }
            }
            break;
        
        case VCSEC_FromVCSECMessage_vehicleStatus_tag:
            LOG_DEBUG("Received vehicle status");
            log_vehicle_status(TESLA_LOG_TAG, &vcsec_msg.sub_message.vehicleStatus);
            
            // Track vehicle sleep state for command state machine
            is_vehicle_awake_ = (vcsec_msg.sub_message.vehicleStatus.vehicleSleepStatus == VCSEC_VehicleSleepStatus_E_VEHICLE_SLEEP_STATUS_AWAKE);
            
            if (vehicle_status_callback_) vehicle_status_callback_(vcsec_msg.sub_message.vehicleStatus);
            
            // If we are waiting for wake response or VCSEC poll, check status
            if (!command_queue_.empty()) {
                auto cmd = command_queue_.front();
                if (cmd->state == CommandState::WAITING_FOR_WAKE_RESPONSE) {
                    if (is_vehicle_awake_ || vcsec_msg.sub_message.vehicleStatus.has_closureStatuses) {
                        LOG_INFO("Vehicle is awake");
                        // If this was an infotainment command waiting for wake, transition to infotainment auth
                        if (cmd->domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT) {
                            LOG_DEBUG("Transitioning infotainment command to auth state after wake");
                            cmd->state = CommandState::WAITING_FOR_INFOTAINMENT_AUTH;
                        } else {
                            // For wake commands or VCSEC commands, mark as completed
                            mark_command_completed(cmd);
                        }
                    }
                } else if (cmd->domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY && 
                           cmd->state == CommandState::WAITING_FOR_RESPONSE) {
                    // Start Polling (or specific VCSEC poll) expects VehicleStatus
                    // Mark as completed since we got a status update
                    mark_command_completed(cmd);
                }
            }
            break;
            
        case VCSEC_FromVCSECMessage_whitelistInfo_tag:
             // Pairing info?
             break;
             
        case VCSEC_FromVCSECMessage_nominalError_tag:
             LOG_ERROR("VCSEC Nominal Error: %s", generic_error_to_string(vcsec_msg.sub_message.nominalError.genericError));
             if (!command_queue_.empty()) {
                 mark_command_failed(command_queue_.front(), "VCSEC Error");
             }
             break;
             
        default: 
             break;
    }
}

void Vehicle::handle_carserver_message(const UniversalMessage_RoutableMessage& msg) {
    LOG_DEBUG("Processing CarServer message");
    const Signatures_SignatureData* sig_data = nullptr;
    if (msg.which_sub_sigData == UniversalMessage_RoutableMessage_signature_data_tag) {
        sig_data = &msg.sub_sigData.signature_data;
    }
    
    UniversalMessage_MessageFault_E fault = UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE;
    if (msg.has_signedMessageStatus) {
        fault = msg.signedMessageStatus.signed_message_fault;
    }

    CarServer_Response response = CarServer_Response_init_default;
    int result = client_->parsePayloadCarServerResponse(
        const_cast<UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t*>(&msg.payload.protobuf_message_as_bytes), 
        const_cast<Signatures_SignatureData*>(sig_data), 
        msg.which_sub_sigData, 
        fault, 
        &response
    );
    
    if (result != 0) {
        LOG_ERROR("Failed to parse CarServer response: %d", result);
        return;
    }
    
    LOG_DEBUG("Parsed CarServer.Response successfully");
    log_carserver_response(TESLA_LOG_TAG, &response);
    
    // Trigger callbacks based on response content
    if (response.which_response_msg == CarServer_Response_vehicleData_tag) {
         if (response.response_msg.vehicleData.has_charge_state && charge_state_callback_) {
             charge_state_callback_(response.response_msg.vehicleData.charge_state);
         }
         if (response.response_msg.vehicleData.has_climate_state && climate_state_callback_) {
             climate_state_callback_(response.response_msg.vehicleData.climate_state);
         }
         if (response.response_msg.vehicleData.has_drive_state && drive_state_callback_) {
             drive_state_callback_(response.response_msg.vehicleData.drive_state);
         }
         if (response.response_msg.vehicleData.has_tire_pressure_state && tire_pressure_callback_) {
             tire_pressure_callback_(response.response_msg.vehicleData.tire_pressure_state);
         }
    }
    
    // Check command completion
    if (!command_queue_.empty()) {
        auto cmd = command_queue_.front();
        if (cmd->domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT && cmd->state == CommandState::WAITING_FOR_RESPONSE) {
            if (response.has_actionStatus) {
                if (response.actionStatus.result == CarServer_OperationStatus_E_OPERATIONSTATUS_OK) {
                    mark_command_completed(cmd);
                } else {
                    LOG_ERROR("CarServer Action Failed");
                    mark_command_failed(cmd, "Action Failed");
                }
            } else {
                // If it's a data response (vehicleData), assume success
                if (response.which_response_msg == CarServer_Response_vehicleData_tag) {
                    mark_command_completed(cmd);
                }
            }
        }
    }
}

void Vehicle::handle_authentication_response(UniversalMessage_Domain domain, bool success) {
    if (!command_queue_.empty()) {
        auto cmd = command_queue_.front();
        if ((cmd->state == CommandState::WAITING_FOR_VCSEC_AUTH_RESPONSE && domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY) ||
            (cmd->state == CommandState::WAITING_FOR_INFOTAINMENT_AUTH_RESPONSE && domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT)) {
            
            if (success) {
                // If VCSEC, might need to transition to Infotainment or Ready
                if (domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY) {
                    if (cmd->domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT) {
                        cmd->state = CommandState::WAITING_FOR_INFOTAINMENT_AUTH;
                    } else {
                        cmd->state = CommandState::READY;
                    }
                } else {
                    cmd->state = CommandState::READY;
                }
            } else {
                mark_command_failed(cmd, "Auth failed");
            }
        }
    }
}

void Vehicle::load_session_from_storage(UniversalMessage_Domain domain) {
    std::string key = (domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY) ? "session_vcsec" : "session_infotainment";
    
    std::vector<uint8_t> session_data;
    if (!storage_adapter_->load(key, session_data)) {
        LOG_DEBUG("No stored session found for %s", domain_to_string(domain));
        return;
    }
    
    if (session_data.empty()) {
        LOG_DEBUG("Empty session data for %s", domain_to_string(domain));
        return;
    }
    
    // Create a session_info_t structure for parsing
    UniversalMessage_RoutableMessage_session_info_t session_info_buffer;
    if (session_data.size() > sizeof(session_info_buffer.bytes)) {
        LOG_ERROR("Session data too large for %s: %zu bytes", domain_to_string(domain), session_data.size());
        return;
    }
    
    memcpy(session_info_buffer.bytes, session_data.data(), session_data.size());
    session_info_buffer.size = session_data.size();
    
    // Parse the session info
    Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
    int result = client_->parsePayloadSessionInfo(&session_info_buffer, &session_info);
    if (result != 0) {
        LOG_ERROR("Failed to parse stored session info for %s: %d", domain_to_string(domain), result);
        return;
    }
    
    // Validate session status
    if (session_info.status != Signatures_Session_Info_Status_SESSION_INFO_STATUS_OK) {
        LOG_WARNING("Stored session for %s has invalid status: %d", domain_to_string(domain), session_info.status);
        return;
    }
    
    // Update the peer with the loaded session
    auto peer = client_->getPeer(domain);
    if (peer) {
        // Use forceUpdateSession since we're loading from storage (no anti-replay check needed)
        if (peer->forceUpdateSession(&session_info) == 0) {
            LOG_INFO("Loaded session from storage for %s (counter: %u)", domain_to_string(domain), session_info.counter);
        } else {
            LOG_ERROR("Failed to apply stored session for %s", domain_to_string(domain));
        }
    }
}

void Vehicle::wake() {
    send_command(
        UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
        "Wake",
        [](Client* client, uint8_t* buff, size_t* len) {
             return client->buildVCSECActionMessage(VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, buff, len);
        }
    );
}

void Vehicle::vcsec_poll() {
    send_command(
        UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
        "VCSEC Poll",
        [](Client* client, uint8_t* buff, size_t* len) {
             return client->buildVCSECInformationRequestMessage(VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS, buff, len);
        }
    );
}

void Vehicle::infotainment_poll(bool force_wake) {
    send_command(
        UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
        "Infotainment Poll",
        [](Client* client, uint8_t* buff, size_t* len) {
             return client->buildCarServerGetVehicleDataMessage(buff, len, CarServer_GetVehicleData_getChargeState_tag);
        },
        nullptr,     // no callback
        force_wake   // requires_wake - if true, will wake vehicle; if false, skip when asleep
    );
}

void Vehicle::set_charging_state(bool enable) {
    send_command(
        UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
        enable ? "Start Charging" : "Stop Charging",
        [enable](Client* client, uint8_t* buff, size_t* len) {
             int32_t action = enable ? 1 : 0;
             return client->buildCarServerVehicleActionMessage(buff, len, CarServer_VehicleAction_chargingStartStopAction_tag, &action);
        }
    );
}

void Vehicle::set_charging_amps(int amps) {
    send_command(
        UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
        "Set Charging Amps",
        [amps](Client* client, uint8_t* buff, size_t* len) {
             int32_t val = amps;
             return client->buildCarServerVehicleActionMessage(buff, len, CarServer_VehicleAction_setChargingAmpsAction_tag, &val);
        }
    );
}

void Vehicle::set_charging_limit(int limit) {
    send_command(
        UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
        "Set Charging Limit",
        [limit](Client* client, uint8_t* buff, size_t* len) {
             int32_t val = limit;
             return client->buildCarServerVehicleActionMessage(buff, len, CarServer_VehicleAction_chargingSetLimitAction_tag, &val);
        }
    );
}

void Vehicle::unlock_charge_port() {
    send_command(
        UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
        "Unlock Charge Port",
        [](Client* client, uint8_t* buff, size_t* len) {
             return client->buildCarServerVehicleActionMessage(buff, len, CarServer_VehicleAction_chargePortDoorOpen_tag, nullptr);
        }
    );
}


void Vehicle::authenticate_key_request() {
     // Trigger VCSEC auth manually if needed, though usually automatic
     send_command(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Key Auth Request",
        [](Client* client, uint8_t* buf, size_t* len) {
             // Just triggering auth logic if needed, usually we just send whitelist query or ephemeral key exchange
             return client->buildVCSECInformationRequestMessage(VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS, buf, len);
        });
}

void Vehicle::pair(Keys_Role role) {
    LOG_INFO("Initiating pairing sequence...");
    
    // Ensure we have a key first
    if (client_->createPrivateKey() != 0) {
        LOG_WARNING("Could not check/create private key, proceeding anyway");
    }

    send_command(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Whitelist Add Key",
        [role](Client* client, uint8_t* buf, size_t* len) {
            return client->buildWhiteListMessage(role, VCSEC_KeyFormFactor_KEY_FORM_FACTOR_NFC_CARD, buf, len);
        });
}

void Vehicle::regenerate_key() {
    LOG_INFO("Regenerating private key...");
    if (client_->createPrivateKey() == 0) {
        // Get and save new key
        uint8_t key_buf[MBEDTLS_ECP_MAX_PT_LEN];
        size_t key_len = 0;
        size_t buf_len = sizeof(key_buf); 
        
        if (client_->getPrivateKey(key_buf, buf_len, &key_len) == 0) {
            std::vector<uint8_t> key_vec(key_buf, key_buf + key_len);
            if (storage_adapter_->save("private_key", key_vec)) {
                LOG_INFO("New private key saved to storage");
            } else {
                 LOG_ERROR("Failed to save new private key");
            }
        }
    } else {
        LOG_ERROR("Failed to create private key");
    }
}

} // namespace TeslaBLE
