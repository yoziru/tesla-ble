#ifndef TESLA_LOG_TAG
#define TESLA_LOG_TAG "TeslaBLE::Vehicle"
#endif

#include "vehicle.h"

#include "command_error.h"
#include "defs.h"

#include "tb_logging.h"
#include "tb_utils.h"

#include <pb_decode.h>
#include <pb_encode.h>

#include <algorithm>
#include <cinttypes>
#include <vector>
#include <array>
#include <cstdlib>  // for rand()
#include <utility>  // for std::cmp_greater, std::cmp_less_equal

namespace TeslaBLE {

Vehicle::Vehicle(const std::shared_ptr<BleAdapter> &ble, const std::shared_ptr<StorageAdapter> &storage)
    : ble_adapter_(ble),
      storage_adapter_(storage),
      client_(std::make_shared<Client>()),
      message_processor_(std::make_unique<MessageProcessor>(
          [this](const UniversalMessage_RoutableMessage &msg) { handle_message_(msg); })) {
  std::vector<uint8_t> key_buffer;
  if (storage_adapter_->load("private_key", key_buffer)) {
    if (client_->load_private_key(key_buffer.data(), key_buffer.size()) == 0) {
      LOG_INFO("Loaded private key from storage");
    } else {
      LOG_ERROR("Failed to load private key from storage");
    }
  } else {
    LOG_INFO("No private key found in storage");
  }

  load_session_from_storage_(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  load_session_from_storage_(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
  initialize_rx_buffer();
}

void TeslaBLE::Vehicle::initialize_rx_buffer() { rx_buffer_.reserve(MAX_MESSAGE_SIZE); }

void TeslaBLE::Vehicle::set_vin(const std::string &vin) {
  if (client_) {
    client_->set_vin(vin);
  }
}

void TeslaBLE::Vehicle::set_connected(bool connected) {
  is_connected_ = connected;
  if (!connected) {
    LOG_INFO("Disconnected from vehicle");

    auto *vcsec_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
    auto *info_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
    if (vcsec_peer) {
      vcsec_peer->reset();
    }
    if (info_peer) {
      info_peer->reset();
    }

    is_vehicle_awake_ = false;

    while (!command_queue_.empty()) {
      auto cmd = command_queue_.front();
      if (cmd->on_complete) {
        cmd->on_complete(CommandError::connection_lost());  // Notify failure
      }
      command_queue_.pop();
    }

    rx_buffer_.clear();
  } else {
    LOG_INFO("Connected to vehicle");
  }
}

void TeslaBLE::Vehicle::loop() {
  message_processor_->process_messages();
  if (is_connected_) {
    process_command_queue_();
  }
}

void TeslaBLE::Vehicle::send_command(UniversalMessage_Domain domain, const std::string &name,
                                     std::function<int(Client *, uint8_t *, size_t *)> builder,
                                     std::function<void(std::unique_ptr<CommandError>)> on_complete,
                                     bool requires_wake) {
  if (!is_connected_) {
    LOG_DEBUG("Not connected - rejecting command: %s", name.c_str());
    if (on_complete) {
      on_complete(CommandError::connection_lost());
    }
    return;
  }

  if (command_queue_.size() >= MAX_COMMAND_QUEUE_SIZE) {
    LOG_WARNING("Command queue full, rejecting command: %s", name.c_str());
    if (on_complete) {
      on_complete(CommandError::build_failed("queue full"));
    }
    return;
  }

  auto cmd = std::make_shared<Command>(domain, name, std::move(builder), std::move(on_complete), requires_wake);
  command_queue_.push(cmd);
  LOG_DEBUG("Enqueued command: %s (domain: %s, requires_wake: %s)", cmd->name.c_str(), domain_to_string(domain),
            requires_wake ? "true" : "false");
}

void TeslaBLE::Vehicle::send_command_bool(UniversalMessage_Domain domain, const std::string &name,
                                          std::function<int(Client *, uint8_t *, size_t *)> builder,
                                          const std::function<void(bool)> &on_complete, bool requires_wake) {
  auto rich_callback = on_complete ? [on_complete](std::unique_ptr<CommandError> error) { on_complete(!error); }
                                   : std::function<void(std::unique_ptr<CommandError>)>(nullptr);
  send_command(domain, name, std::move(builder), std::move(rich_callback), requires_wake);
}

void TeslaBLE::Vehicle::process_command_queue_() {
  if (command_queue_.empty()) {
    return;
  }

  auto command = command_queue_.front();
  auto now = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->started_at);
  if (duration > COMMAND_TIMEOUT) {
    if (is_connected_) {
      LOG_WARNING("Command timeout while connected: %s", command->name.c_str());
    } else {
      LOG_DEBUG("Command timeout while disconnected: %s", command->name.c_str());
    }
    mark_command_failed_(command, CommandError::timeout("Command"));
    return;
  }

  switch (command->state) {
    case CommandState::IDLE:
      process_idle_command_(command);
      break;
    case CommandState::AUTHENTICATING:
      process_authenticating_command_(command);
      break;
    case CommandState::AUTH_RESPONSE_WAITING:
      process_auth_response_waiting_command_(command);
      break;
    case CommandState::READY:
      process_ready_command_(command);
      break;
    case CommandState::WAITING_FOR_RESPONSE: {
      auto tx_duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->last_tx_at);
      if (tx_duration > CLOCK_SYNC_MAX_LATENCY) {
        if (command->name == "Wake" && is_vehicle_awake_) {
          LOG_INFO("Wake response timeout but vehicle is awake - proceeding");
          mark_command_completed_(command);
          break;
        }
        LOG_DEBUG("Response timeout for command: %s (attempt %d/%d)", command->name.c_str(), command->retry_count,
                  MAX_RETRIES + 1);
        retry_command(command);
      }
    } break;
    default:
      break;
  }
}

std::shared_ptr<TeslaBLE::Command> TeslaBLE::Vehicle::peek_command_() const {
  if (command_queue_.empty()) {
    return nullptr;
  }
  return command_queue_.front();
}

void TeslaBLE::Vehicle::process_idle_command_(const std::shared_ptr<Command> &command) {
  command->started_at = std::chrono::steady_clock::now();
  switch (command->domain) {
    case UniversalMessage_Domain_DOMAIN_BROADCAST:
      command->state = CommandState::READY;
      break;
    case UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY:
      initiate_vcsec_auth_(command);
      break;
    case UniversalMessage_Domain_DOMAIN_INFOTAINMENT:
      initiate_infotainment_auth_(command);
      break;
    default:
      LOG_ERROR("Unknown domain for command: %s", command->name.c_str());
      mark_command_failed_(command, CommandError::build_failed("unknown domain"));
      break;
  }
}

void TeslaBLE::Vehicle::process_authenticating_command_(const std::shared_ptr<Command> &command) {
  LOG_DEBUG("Processing auth for %s (%s)", command->name.c_str(), domain_to_string(command->current_auth_domain));

  switch (command->current_auth_domain) {
    case UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY:
      initiate_auth_for_domain_(command, UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
                                CommandState::AUTH_RESPONSE_WAITING, "VCSEC");
      break;
    case UniversalMessage_Domain_DOMAIN_INFOTAINMENT:
      if (!is_domain_authenticated_(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY)) {
        LOG_DEBUG("VCSEC auth required before Infotainment auth");
        command->current_auth_domain = UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY;
        initiate_auth_for_domain_(command, UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
                                  CommandState::AUTH_RESPONSE_WAITING, "VCSEC");
      } else {
        initiate_auth_for_domain_(command, UniversalMessage_Domain_DOMAIN_INFOTAINMENT,
                                  CommandState::AUTH_RESPONSE_WAITING, "Infotainment");
      }
      break;
    case UniversalMessage_Domain_DOMAIN_BROADCAST:
      initiate_wake_sequence_(command);
      break;
    default:
      LOG_ERROR("Unknown authentication domain for command: %s", command->name.c_str());
      mark_command_failed_(command, CommandError::build_failed("unknown auth domain"));
      break;
  }
}

void TeslaBLE::Vehicle::process_auth_response_waiting_command_(const std::shared_ptr<Command> &command) {
  auto now = std::chrono::steady_clock::now();
  auto tx_duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->last_tx_at);
  if (tx_duration > AUTH_RESPONSE_TIMEOUT) {
    switch (command->current_auth_domain) {
      case UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY:
        handle_vcsec_auth_timeout_(command);
        break;
      case UniversalMessage_Domain_DOMAIN_INFOTAINMENT:
        handle_infotainment_auth_timeout_(command);
        break;
      case UniversalMessage_Domain_DOMAIN_BROADCAST:
        handle_wake_response_timeout_(command);
        break;
      default:
        LOG_ERROR("Unknown auth domain for timeout handling: %s", command->name.c_str());
        mark_command_failed_(command, CommandError::timeout("Unknown auth"));
        break;
    }
  }
}

void TeslaBLE::Vehicle::handle_auth_timeout_common_(const std::shared_ptr<Command> &command,
                                                    const std::string &domain_name, CommandState retry_state) {
  log_timeout_message_(domain_name + " auth response timeout", command);
  auto now = std::chrono::steady_clock::now();
  auto total_duration = std::chrono::duration_cast<std::chrono::seconds>(now - command->started_at);
  int attempt_level = std::min(command->retry_count / 2, 3);
  static constexpr std::array<int, 4> TIMEOUT_THRESHOLDS = {30, 60, 120, 300};
  if (total_duration > std::chrono::seconds(TIMEOUT_THRESHOLDS[attempt_level])) {
    LOG_ERROR("Connection validation failed: %s auth stuck for %lld seconds (level %d, retry %d)", domain_name.c_str(),
              (long long) total_duration.count(), attempt_level, command->retry_count);
    reset_all_sessions_and_connection_();
    mark_command_failed_(command, CommandError::session_stale("connection"));
    return;
  }
  command->state = retry_state;
}

void TeslaBLE::Vehicle::handle_vcsec_auth_timeout_(const std::shared_ptr<Command> &command) {
  handle_auth_timeout_common_(command, "VCSEC", CommandState::AUTHENTICATING);
}

void TeslaBLE::Vehicle::handle_infotainment_auth_timeout_(const std::shared_ptr<Command> &command) {
  handle_auth_timeout_common_(command, "Infotainment", CommandState::AUTHENTICATING);
}

void TeslaBLE::Vehicle::handle_wake_response_timeout_(const std::shared_ptr<Command> &command) {
  // Check if vehicle woke up (we may have received status update even without wake response)
  if (is_vehicle_awake_) {
    LOG_INFO("Wake response timeout but vehicle is awake - proceeding");
    if (command->domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT) {
      command->current_auth_domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;
      command->state = CommandState::AUTHENTICATING;
      command->last_tx_at = std::chrono::steady_clock::time_point();  // Trigger immediate auth
    } else {
      mark_command_completed_(command);
    }
  } else {
    log_timeout_message_("Wake response timeout - vehicle still asleep", command);
    retry_command(command);
  }
}

void TeslaBLE::Vehicle::initiate_auth_for_domain_(const std::shared_ptr<Command> &command,
                                                  UniversalMessage_Domain domain, CommandState waiting_state,
                                                  const std::string &domain_name) {
  if (is_domain_authenticated_(domain)) {
    if (command->domain == domain) {
      command->state = CommandState::READY;
    } else if (domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY) {
      command->state = CommandState::AUTHENTICATING;
    }
  } else {
    uint8_t buffer[256];
    size_t len = 256;
    if (client_->build_session_info_request_message(domain, buffer, &len) == 0) {
      std::vector<uint8_t> data(buffer, buffer + len);
      if (ble_adapter_->write(data)) {
        command->state = waiting_state;
        command->last_tx_at = std::chrono::steady_clock::now();
        LOG_INFO("Sent %s Session Info Request", domain_name.c_str());
      } else {
        LOG_ERROR("Failed to write %s Session Info Request", domain_name.c_str());
      }
    } else {
      LOG_ERROR("Failed to build %s Session Info Request", domain_name.c_str());
      mark_command_failed_(command, CommandError::build_failed(domain_name + " Session Info Request"));
    }
  }
}

void TeslaBLE::Vehicle::initiate_vcsec_auth_(const std::shared_ptr<Command> &command) {
  command->current_auth_domain = UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY;
  initiate_auth_for_domain_(command, UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
                            CommandState::AUTH_RESPONSE_WAITING, "VCSEC");
}

void TeslaBLE::Vehicle::initiate_infotainment_auth_(const std::shared_ptr<Command> &command) {
  if (!is_vehicle_awake_ && !command->requires_wake) {
    LOG_DEBUG("Vehicle asleep, skipping optional command: %s", command->name.c_str());
    mark_command_completed_(command);
    return;
  }
  if (!is_domain_authenticated_(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY)) {
    LOG_DEBUG("VCSEC auth required before Infotainment auth");
    initiate_vcsec_auth_(command);
    return;
  }
  if (!is_vehicle_awake_ && command->requires_wake) {
    LOG_DEBUG("Vehicle is asleep and command requires wake, initiating wake sequence");
    command->current_auth_domain = UniversalMessage_Domain_DOMAIN_BROADCAST;
    command->state = CommandState::AUTHENTICATING;
    command->last_tx_at = std::chrono::steady_clock::time_point();
    return;
  }
  initiate_auth_for_domain_(command, UniversalMessage_Domain_DOMAIN_INFOTAINMENT, CommandState::AUTH_RESPONSE_WAITING,
                            "Infotainment");
}

void TeslaBLE::Vehicle::initiate_wake_sequence_(const std::shared_ptr<Command> &command) {
  uint8_t buffer[256];
  size_t len = 256;
  if (client_->build_vcsec_action_message(VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, buffer, &len) == 0) {
    std::vector<uint8_t> data(buffer, buffer + len);
    if (ble_adapter_->write(data)) {
      command->state = CommandState::AUTH_RESPONSE_WAITING;
      command->last_tx_at = std::chrono::steady_clock::now();
      LOG_INFO("Sent Wake Command");
    } else {
      LOG_ERROR("Failed to write Wake Command");
      mark_command_failed_(command, CommandError::build_failed("Wake write"));
    }
  } else {
    LOG_ERROR("Failed to build Wake Command");
    mark_command_failed_(command, CommandError::build_failed("Wake Command"));
  }
}

void TeslaBLE::Vehicle::retry_command(const std::shared_ptr<Command> &command) {
  if (command->retry_count >= MAX_RETRIES) {
    LOG_ERROR("Max retries exceeded for command: %s", command->name.c_str());
    mark_command_failed_(command, CommandError::max_retries_exceeded(command->name));
    return;
  }

  bool should_retry = true;
  if (command->last_error) {
    should_retry = command->last_error->is_temporary();
    if (!should_retry) {
      LOG_INFO("Not retrying %s: error is permanent", command->name.c_str());
      mark_command_failed_(command, std::move(command->last_error));
      return;
    }
  }

  command->retry_count++;
  LOG_DEBUG("Retrying command: %s (attempt %d/%d)", command->name.c_str(), command->retry_count, MAX_RETRIES + 1);

  std::chrono::milliseconds backoff_delay;
  if (command->retry_count == 1) {
    backoff_delay = INITIAL_RETRY_DELAY;
  } else {
    auto current_delay = command->next_retry_delay;
    auto calculated_delay = std::chrono::milliseconds(static_cast<int64_t>(current_delay.count() * BACKOFF_MULTIPLIER));
    backoff_delay = calculated_delay > MAX_RETRY_DELAY ? MAX_RETRY_DELAY : calculated_delay;
    auto jitter = std::chrono::milliseconds(arc4random() % 101);
    backoff_delay += jitter;
  }

  command->next_retry_delay = backoff_delay;
  command->next_retry_time = std::chrono::steady_clock::now() + backoff_delay;
  LOG_DEBUG("Exponential backoff: retry %d, delay %lldms for command: %s", static_cast<int>(command->retry_count + 1),
            static_cast<long long>(backoff_delay.count()), command->name.c_str());
  command->last_tx_at = std::chrono::steady_clock::now() - backoff_delay + std::chrono::milliseconds(100);

  switch (command->state) {
    case CommandState::WAITING_FOR_RESPONSE:
      command->state = CommandState::READY;
      break;
    case CommandState::AUTH_RESPONSE_WAITING:
    default:
      command->state = CommandState::IDLE;
      break;
  }
}

void TeslaBLE::Vehicle::process_ready_command_(const std::shared_ptr<Command> &command) {
  uint8_t buffer[256];
  size_t len = 256;
  if (command->builder(client_.get(), buffer, &len) == 0) {
    std::vector<uint8_t> data(buffer, buffer + len);
    if (ble_adapter_->write(data)) {
      LOG_DEBUG("Sent command: %s (%zu bytes)", command->name.c_str(), data.size());
      command->state = CommandState::WAITING_FOR_RESPONSE;
      command->last_tx_at = std::chrono::steady_clock::now();
    } else {
      LOG_ERROR("Failed to write command data: %s", command->name.c_str());
      mark_command_failed_(command, CommandError::build_failed("BLE write failed"));
    }
  } else {
    LOG_ERROR("Failed to build command: %s", command->name.c_str());
    mark_command_failed_(command, CommandError::build_failed(command->name));
  }
}

void TeslaBLE::Vehicle::mark_command_failed_(const std::shared_ptr<Command> &command,
                                             std::unique_ptr<CommandError> error) {
  command->state = CommandState::FAILED;
  command->last_error = std::move(error);
  auto now = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->started_at);
  LOG_ERROR("[%s] Command failed after %lld ms: %s", command->name.c_str(), (long long) duration.count(),
            command->last_error->message().c_str());
  finalize_command_(command, std::move(command->last_error));
}

void TeslaBLE::Vehicle::mark_command_completed_(const std::shared_ptr<Command> &command) {
  command->state = CommandState::COMPLETED;
  auto now = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->started_at);
  LOG_INFO("[%s] Command completed successfully in %lld ms", command->name.c_str(), (long long) duration.count());
  finalize_command_(command, nullptr);
}

void TeslaBLE::Vehicle::finalize_command_(const std::shared_ptr<Command> &command,
                                          std::unique_ptr<CommandError> error) {
  if (command->on_complete) {
    command->on_complete(std::move(error));
  }
  if (!command_queue_.empty() && command_queue_.front() == command) {
    command_queue_.pop();
  }
}

bool Vehicle::is_domain_authenticated_(UniversalMessage_Domain domain) {
  auto *peer = client_->get_peer(domain);
  return peer && peer->is_valid();
}

void TeslaBLE::Vehicle::on_rx_data(const std::vector<uint8_t> &data) {
  rx_buffer_.insert(rx_buffer_.end(), data.begin(), data.end());
  recovery_attempted_ = false;
  while (is_message_complete()) {
    process_complete_message();
  }
}

bool Vehicle::is_message_complete() {
  if (rx_buffer_.size() < FRAME_HEADER_SIZE)
    return false;
  int msg_len = get_expected_message_length();
  if (msg_len <= 0 || std::cmp_greater(msg_len, MAX_MESSAGE_SIZE)) {
    return true;
  }
  return rx_buffer_.size() >= static_cast<size_t>(msg_len);
}

int Vehicle::get_expected_message_length() {
  if (rx_buffer_.size() < FRAME_HEADER_SIZE)
    return 0;
  return static_cast<int>((rx_buffer_[0] << 8) | rx_buffer_[1]) + FRAME_HEADER_SIZE;
}

void TeslaBLE::Vehicle::process_complete_message() {
  int msg_len = get_expected_message_length();
  if (msg_len <= 0 || std::cmp_greater(msg_len, MAX_MESSAGE_SIZE)) {
    LOG_ERROR("Invalid message length %d, attempting buffer recovery", msg_len);
    bool severe_corruption = msg_len > 0xF000;
    if (!attempt_buffer_recovery_(msg_len)) {
      if (severe_corruption) {
        LOG_ERROR("Severe buffer corruption detected (length: %d), clearing buffer", msg_len);
      } else {
        LOG_WARNING("Buffer recovery failed, clearing all data");
      }
      rx_buffer_.clear();
      return;
    }
    recovery_attempted_ = true;
  }

  if (msg_len <= 0 || std::cmp_greater(msg_len, MAX_MESSAGE_SIZE)) {
    LOG_WARNING("Buffer recovery produced invalid length %d, clearing buffer", msg_len);
    rx_buffer_.clear();
    recovery_attempted_ = false;
    return;
  }

  if (rx_buffer_.size() < static_cast<size_t>(msg_len)) {
    return;
  }

  std::vector<uint8_t> full_msg(rx_buffer_.begin(), rx_buffer_.begin() + msg_len);
  if (raw_message_callback_) {
    raw_message_callback_(full_msg);
  }
  std::vector<uint8_t> msg_data(rx_buffer_.begin() + FRAME_HEADER_SIZE, rx_buffer_.begin() + msg_len);
  UniversalMessage_RoutableMessage msg = UniversalMessage_RoutableMessage_init_default;
  if (client_->parse_universal_message(msg_data.data(), msg_data.size(), &msg) == 0) {
    LOG_DEBUG("Successfully parsed universal message");
    log_routable_message(TESLA_LOG_TAG, &msg);
    message_processor_->queue_message(msg);
    rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + msg_len);
    recovery_attempted_ = false;
  } else {
    LOG_ERROR("Failed to parse Universal Message (buffer size: %zu) - attempting buffer recovery", rx_buffer_.size());
    if (recovery_attempted_ || !attempt_buffer_recovery_(msg_len)) {
      LOG_WARNING("Buffer recovery failed after parse error, clearing all data");
      rx_buffer_.clear();
      recovery_attempted_ = false;
    } else {
      recovery_attempted_ = true;
    }
  }
}

void TeslaBLE::Vehicle::handle_message_(const UniversalMessage_RoutableMessage &msg) {
  if (message_callback_) {
    message_callback_(msg);
  }
  bool has_session_error = false;
  if (msg.has_signedMessageStatus) {
    handle_signed_message_error_(msg, has_session_error);
  }
  if (msg.which_payload == UniversalMessage_RoutableMessage_session_info_tag) {
    handle_session_info_message_(msg);
    auto cmd = peek_command_();
    if (has_session_error && cmd &&
        (cmd->state == CommandState::WAITING_FOR_RESPONSE || cmd->state == CommandState::AUTH_RESPONSE_WAITING)) {
      LOG_INFO("Retrying command after session recovery");
      cmd->state = CommandState::IDLE;
      cmd->retry_count++;
      if (cmd->retry_count > MAX_RETRIES) {
        mark_command_failed_(cmd, CommandError::session_expired("session recovery"));
      }
    }
    return;
  }
  auto cmd = peek_command_();
  if (has_session_error && cmd &&
      (cmd->state == CommandState::WAITING_FOR_RESPONSE || cmd->state == CommandState::AUTH_RESPONSE_WAITING)) {
    LOG_INFO("Transitioning to IDLE to trigger manual session recovery");
    cmd->state = CommandState::IDLE;
  }
  if (msg.from_destination.which_sub_destination == UniversalMessage_Destination_domain_tag) {
    switch (msg.from_destination.sub_destination.domain) {
      case UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY:
        handle_vcsec_message_(msg);
        break;
      case UniversalMessage_Domain_DOMAIN_INFOTAINMENT:
        handle_carserver_message_(msg);
        break;
      default:
        LOG_DEBUG("Message from unknown domain: %d", msg.from_destination.sub_destination.domain);
        break;
    }
  }
}

void TeslaBLE::Vehicle::handle_session_info_message_(const UniversalMessage_RoutableMessage &msg) {
  UniversalMessage_Domain domain = UniversalMessage_Domain_DOMAIN_BROADCAST;
  if (msg.has_from_destination &&
      msg.from_destination.which_sub_destination == UniversalMessage_Destination_domain_tag) {
    domain = msg.from_destination.sub_destination.domain;
  } else if (!command_queue_.empty()) {
    domain = command_queue_.front()->domain;
  }
  if (domain != UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY &&
      domain != UniversalMessage_Domain_DOMAIN_INFOTAINMENT) {
    LOG_ERROR("Could not determine valid domain for session info update");
    return;
  }

  auto fail_auth = [&](const char *format, auto... args) {
    LOG_ERROR(format, args...);
    handle_authentication_response_(domain, false);
  };

  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  int result = client_->parse_payload_session_info(
      const_cast<UniversalMessage_RoutableMessage_session_info_t *>(&msg.payload.session_info), &session_info);
  if (result != 0 || session_info.status != Signatures_Session_Info_Status_SESSION_INFO_STATUS_OK) {
    fail_auth("Failed to parse valid session info (result=%d, status=%d)", result, session_info.status);
    return;
  }

  if (msg.which_sub_sigData != UniversalMessage_RoutableMessage_signature_data_tag ||
      msg.sub_sigData.signature_data.which_sig_type != Signatures_SignatureData_session_info_tag_tag) {
    fail_auth("Missing session info HMAC tag for %s", domain_to_string(domain));
    return;
  }

  const auto &tag = msg.sub_sigData.signature_data.sig_type.session_info_tag.tag;
  if (tag.size == 0) {
    fail_auth("Empty session info HMAC tag for %s", domain_to_string(domain));
    return;
  }

  pb_byte_t request_uuid[16] = {0};
  size_t request_uuid_length = sizeof(request_uuid);
  if (!client_->get_last_request_uuid(domain, request_uuid, &request_uuid_length)) {
    fail_auth("Missing request UUID for session info verification (%s)", domain_to_string(domain));
    return;
  }

  if (!client_->verify_session_info_tag(session_info, msg.payload.session_info.bytes, msg.payload.session_info.size,
                                        request_uuid, request_uuid_length, tag.bytes, tag.size)) {
    fail_auth("Session info HMAC verification failed for %s", domain_to_string(domain));
    return;
  }

  LOG_DEBUG("Parsed session info successfully for %s", domain_to_string(domain));
  log_session_info(TESLA_LOG_TAG, &session_info);
  auto *peer = client_->get_peer(domain);
  if (peer && peer->update_session(&session_info) == 0) {
    LOG_INFO("Session updated for %s", domain_to_string(domain));
    persist_session_(domain, msg.payload.session_info);
    handle_authentication_response_(domain, true);
  } else {
    LOG_ERROR("Failed to update peer session for %s", domain_to_string(domain));
    handle_authentication_response_(domain, false);
  }
}

void TeslaBLE::Vehicle::handle_vcsec_message_(const UniversalMessage_RoutableMessage &msg) {
  LOG_DEBUG("Processing VCSEC message");
  if (msg.which_payload != UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag) {
    LOG_ERROR("VCSEC message missing protobuf payload");
    return;
  }

  const Signatures_SignatureData *sig_data = nullptr;
  if (msg.which_sub_sigData == UniversalMessage_RoutableMessage_signature_data_tag) {
    sig_data = &msg.sub_sigData.signature_data;
  }

  UniversalMessage_MessageFault_E fault = UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE;
  if (msg.has_signedMessageStatus) {
    fault = msg.signedMessageStatus.signed_message_fault;
  }

  const UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *payload = &msg.payload.protobuf_message_as_bytes;
  UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t decrypt_buffer;
  if (sig_data && sig_data->which_sig_type == Signatures_SignatureData_AES_GCM_Response_data_tag) {
    LOG_DEBUG("AES_GCM_Response_data found in VCSEC signature_data");
    auto *session = client_->get_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
    if (!session->is_initialized()) {
      LOG_ERROR("VCSEC session not initialized for response decrypt");
      return;
    }

    size_t request_hash_length = 0;
    const pb_byte_t *request_hash = client_->get_last_request_hash(&request_hash_length);
    if (!request_hash || request_hash_length == 0) {
      LOG_ERROR("Missing request hash for VCSEC response decrypt");
      return;
    }

    size_t decrypt_length = 0;
    int return_code = session->decrypt_response(
        payload->bytes, payload->size, sig_data->sig_type.AES_GCM_Response_data.nonce,
        sig_data->sig_type.AES_GCM_Response_data.tag, request_hash, request_hash_length, msg.flags, fault,
        decrypt_buffer.bytes, sizeof(decrypt_buffer.bytes), &decrypt_length);
    if (return_code != 0) {
      LOG_ERROR("Failed to decrypt VCSEC response: %d", return_code);
      return;
    }

    decrypt_buffer.size = decrypt_length;
    payload = &decrypt_buffer;
  } else if (sig_data) {
    LOG_DEBUG("No AES_GCM_Response_data found in VCSEC signature_data");
  }

  VCSEC_FromVCSECMessage vcsec_msg = VCSEC_FromVCSECMessage_init_default;
  int result = client_->parse_from_vcsec_message(
      const_cast<UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *>(payload), &vcsec_msg);
  if (result != 0) {
    LOG_ERROR("Failed to parse VCSEC message: %d", result);
    return;
  }
  LOG_DEBUG("Parsed VCSEC message successfully");
  switch (vcsec_msg.which_sub_message) {
    case VCSEC_FromVCSECMessage_commandStatus_tag:
      log_vcsec_command_status(TESLA_LOG_TAG, &vcsec_msg.sub_message.commandStatus);
      if (auto cmd = peek_command_()) {
        if (cmd->domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY &&
            (cmd->state == CommandState::WAITING_FOR_RESPONSE || cmd->state == CommandState::AUTH_RESPONSE_WAITING)) {
          mark_command_completed_(cmd);
        }
      }
      break;
    case VCSEC_FromVCSECMessage_vehicleStatus_tag:
      LOG_DEBUG("Received vehicle status");
      log_vehicle_status(TESLA_LOG_TAG, &vcsec_msg.sub_message.vehicleStatus);
      is_vehicle_awake_ = vcsec_msg.sub_message.vehicleStatus.vehicleSleepStatus !=
                          VCSEC_VehicleSleepStatus_E_VEHICLE_SLEEP_STATUS_ASLEEP;
      if (vehicle_status_callback_) {
        vehicle_status_callback_(vcsec_msg.sub_message.vehicleStatus);
      }
      if (auto cmd = peek_command_()) {
        handle_vehicle_status_command_update_(cmd, vcsec_msg.sub_message.vehicleStatus);
      }
      break;
    case VCSEC_FromVCSECMessage_whitelistInfo_tag:
      break;
    case VCSEC_FromVCSECMessage_nominalError_tag:
      LOG_ERROR("VCSEC Nominal Error: %s", generic_error_to_string(vcsec_msg.sub_message.nominalError.genericError));
      if (auto cmd = peek_command_()) {
        mark_command_failed_(cmd, CommandError::authentication_failed("VCSEC"));
      }
      break;
    default:
      break;
  }
}

void TeslaBLE::Vehicle::handle_carserver_message_(const UniversalMessage_RoutableMessage &msg) {
  LOG_DEBUG("Processing CarServer message");
  const Signatures_SignatureData *sig_data = nullptr;
  if (msg.which_sub_sigData == UniversalMessage_RoutableMessage_signature_data_tag) {
    sig_data = &msg.sub_sigData.signature_data;
  }
  UniversalMessage_MessageFault_E fault = UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE;
  if (msg.has_signedMessageStatus) {
    fault = msg.signedMessageStatus.signed_message_fault;
  }
  CarServer_Response response = CarServer_Response_init_default;
  uint32_t response_counter = 0;
  int result = client_->parse_payload_car_server_response(
      const_cast<UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *>(
          &msg.payload.protobuf_message_as_bytes),
      const_cast<Signatures_SignatureData *>(sig_data), msg.which_sub_sigData, fault, msg.flags, &response,
      &response_counter);
  if (result != 0) {
    LOG_ERROR("Failed to parse CarServer response: %d", result);
    return;
  }
  LOG_DEBUG("Parsed CarServer.Response successfully");
  log_carserver_response(TESLA_LOG_TAG, &response);
  auto *peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
  if (peer && response_counter > 0 && !peer->validate_response_counter(response_counter)) {
    LOG_WARNING("Duplicate response counter detected: %u", response_counter);
  }
  if (response.which_response_msg == CarServer_Response_vehicleData_tag) {
    auto &vd = response.response_msg.vehicleData;
    auto emit_if = [&](bool has_value, auto &callback, const auto &value) {
      if (has_value && callback) {
        callback(value);
      }
    };
    emit_if(vd.has_charge_state, charge_state_callback_, vd.charge_state);
    emit_if(vd.has_climate_state, climate_state_callback_, vd.climate_state);
    emit_if(vd.has_drive_state, drive_state_callback_, vd.drive_state);
    emit_if(vd.has_tire_pressure_state, tire_pressure_callback_, vd.tire_pressure_state);
    emit_if(vd.has_closures_state, closures_state_callback_, vd.closures_state);
  }
  auto cmd = peek_command_();
  if (cmd && cmd->domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT &&
      cmd->state == CommandState::WAITING_FOR_RESPONSE) {
    if (response.has_actionStatus) {
      if (response.actionStatus.result == CarServer_OperationStatus_E_OPERATIONSTATUS_OK) {
        mark_command_completed_(cmd);
      } else {
        LOG_ERROR("CarServer Action Failed");
        mark_command_failed_(cmd, CommandError::authentication_failed("Infotainment action"));
      }
    } else if (response.which_response_msg == CarServer_Response_vehicleData_tag) {
      mark_command_completed_(cmd);
    }
  }
}

void TeslaBLE::Vehicle::handle_authentication_response_(UniversalMessage_Domain domain, bool success) {
  auto cmd = peek_command_();
  if (!cmd || cmd->state != CommandState::AUTH_RESPONSE_WAITING) {
    return;
  }

  if (success) {
    if (domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY &&
        cmd->domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT) {
      cmd->current_auth_domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;
      cmd->state = CommandState::AUTHENTICATING;
      return;
    }
    cmd->state = CommandState::READY;
    return;
  }

  mark_command_failed_(cmd, CommandError::authentication_failed("auth response", true));
}

std::string Vehicle::get_session_key_(UniversalMessage_Domain domain) {
  return (domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY) ? "session_vcsec" : "session_infotainment";
}

void TeslaBLE::Vehicle::persist_session_(UniversalMessage_Domain domain,
                                         const UniversalMessage_RoutableMessage_session_info_t &session_info) {
  std::string key = get_session_key_(domain);
  std::vector<uint8_t> sess_data(session_info.bytes, session_info.bytes + session_info.size);
  storage_adapter_->save(key, sess_data);
}

void TeslaBLE::Vehicle::reset_all_sessions_and_connection_() {
  if (auto *vcsec_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY)) {
    vcsec_peer->reset();
  }
  if (auto *info_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT)) {
    info_peer->reset();
  }
  clear_stored_session_(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  clear_stored_session_(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
  set_connected(false);
}

void TeslaBLE::Vehicle::log_timeout_message_(const std::string &message, const std::shared_ptr<Command> &command) {
  if (is_connected_) {
    LOG_WARNING("%s (attempt %d/%d)", message.c_str(), command->retry_count + 1, MAX_RETRIES + 1);
  } else {
    LOG_DEBUG("%s while disconnected (attempt %d/%d)", message.c_str(), command->retry_count + 1, MAX_RETRIES + 1);
  }
}

bool Vehicle::attempt_buffer_recovery_(int &msg_len) {
  if (rx_buffer_.size() <= FRAME_HEADER_SIZE) {
    return false;
  }

  LOG_INFO("Attempting to recover buffer from %zu bytes", rx_buffer_.size());

  // Search for potential next valid message start
  for (size_t i = 1; i < rx_buffer_.size() - FRAME_HEADER_SIZE; i++) {
    uint16_t potential_len = (rx_buffer_[i] << 8) | rx_buffer_[i + 1];

    // Valid length check: reasonable size and fits in buffer
    // Also check for corrupted length values (near max uint16)
    if (potential_len > 0 && potential_len <= MAX_MESSAGE_SIZE &&
        potential_len < 0xF000 &&  // Filter out obviously corrupted lengths
        i + FRAME_HEADER_SIZE + potential_len <= rx_buffer_.size()) {
      LOG_INFO("Found potential valid message at offset %zu, length %d", i, potential_len);

      // Remove corrupted prefix, keep valid suffix
      rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + i);
      LOG_DEBUG("Buffer recovered to %zu bytes", rx_buffer_.size());

      // Retry processing with recovered buffer
      msg_len = get_expected_message_length();
      if (msg_len > 0 && std::cmp_less_equal(msg_len, MAX_MESSAGE_SIZE)) {
        LOG_INFO("Successfully recovered valid message, continuing processing");
        return true;
      }
    }
  }

  return false;
}

void TeslaBLE::Vehicle::handle_vehicle_status_command_update_(const std::shared_ptr<Command> &cmd,
                                                              const VCSEC_VehicleStatus &status) {
  switch (cmd->state) {
    case CommandState::AUTH_RESPONSE_WAITING:
      if (is_vehicle_awake_ || status.has_closureStatuses) {
        LOG_INFO("Vehicle is awake");
        if (cmd->domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT) {
          LOG_DEBUG("Transitioning infotainment command to auth state after wake");
          cmd->current_auth_domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;
          cmd->state = CommandState::AUTHENTICATING;
        } else {
          mark_command_completed_(cmd);
        }
      }
      break;
    case CommandState::WAITING_FOR_RESPONSE:
      if (cmd->domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY) {
        mark_command_completed_(cmd);
      }
      break;
    default:
      break;
  }
}

void TeslaBLE::Vehicle::clear_stored_session_(UniversalMessage_Domain domain) {
  std::string key = get_session_key_(domain);
  if (storage_adapter_->remove(key)) {
    LOG_INFO("Cleared stored session for %s", domain_to_string(domain));
  } else {
    LOG_WARNING("Failed to clear stored session for %s (may not exist)", domain_to_string(domain));
  }
}

void TeslaBLE::Vehicle::load_session_from_storage_(UniversalMessage_Domain domain) {
  std::string key = get_session_key_(domain);

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

  std::copy_n(session_data.data(), session_data.size(), session_info_buffer.bytes);
  session_info_buffer.size = session_data.size();

  // Parse the session info
  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  int result = client_->parse_payload_session_info(&session_info_buffer, &session_info);
  if (result != 0) {
    LOG_ERROR("Failed to parse stored session info for %s: %d", domain_to_string(domain), result);
    return;
  }

  // Validate session status
  if (session_info.status != Signatures_Session_Info_Status_SESSION_INFO_STATUS_OK) {
    LOG_WARNING("Stored session for %s has invalid status: %d", domain_to_string(domain), session_info.status);
    return;
  }

  // Validate session age - reject sessions older than 1 hour to prevent INVALID_SIGNATURE errors
  // Stale sessions cause crypto failures when vehicle's internal state changes
  uint32_t current_time = static_cast<uint32_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
  uint32_t session_time = session_info.clock_time;
  uint32_t session_age_seconds = current_time - session_time;

  // If session has no clock_time, check if it's from a previous run (be very conservative)
  if (session_time == 0) {
    LOG_WARNING("Stored session for %s has no timestamp - rejecting to prevent crypto errors",
                domain_to_string(domain));
    return;
  }

  // Reject sessions older than 1 hour (3600 seconds)
  if (session_age_seconds > 3600) {
    LOG_WARNING("Stored session for %s is too old (%u seconds) - rejecting to prevent crypto errors",
                domain_to_string(domain), session_age_seconds);
    return;
  }

  LOG_DEBUG("Session age validation passed for %s: %u seconds old", domain_to_string(domain), session_age_seconds);

  // Update the peer with the loaded session
  auto *peer = client_->get_peer(domain);
  if (peer) {
    // Use update_session - it will handle counter correctly (preserve higher value)
    if (peer->update_session(&session_info) == 0) {
      LOG_INFO("Loaded session from storage for %s (counter: %u)", domain_to_string(domain), session_info.counter);
    } else {
      LOG_ERROR("Failed to apply stored session for %s", domain_to_string(domain));
    }
  }
}

void TeslaBLE::Vehicle::wake() {
  if (is_vehicle_awake_) {
    LOG_DEBUG("Vehicle is already awake, skipping redundant wake action");
    return;
  }
  send_command(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Wake", [](Client *client, uint8_t *buff, size_t *len) {
    return client->build_vcsec_action_message(VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, buff, len);
  });
}

void TeslaBLE::Vehicle::vcsec_poll() {
  send_command(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "VCSEC Poll",
               [](Client *client, uint8_t *buff, size_t *len) {
                 return client->build_vcsec_information_request_message(
                     VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS, buff, len);
               });
}

void TeslaBLE::Vehicle::infotainment_poll(bool force_wake) {
  charge_state_poll(force_wake);
  climate_state_poll(force_wake);
  drive_state_poll(force_wake);
  closures_state_poll(force_wake);
  tire_pressure_poll(force_wake);
}

void TeslaBLE::Vehicle::send_infotainment_poll_(const std::string &name, int32_t data_type, bool force_wake) {
  send_command(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, name,
      [data_type](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len, data_type);
      },
      nullptr, force_wake);
}

void TeslaBLE::Vehicle::charge_state_poll(bool force_wake) {
  send_infotainment_poll_("Charge State Poll", CarServer_GetVehicleData_getChargeState_tag, force_wake);
}

void TeslaBLE::Vehicle::climate_state_poll(bool force_wake) {
  send_infotainment_poll_("Climate State Poll", CarServer_GetVehicleData_getClimateState_tag, force_wake);
}

void TeslaBLE::Vehicle::drive_state_poll(bool force_wake) {
  send_infotainment_poll_("Drive State Poll", CarServer_GetVehicleData_getDriveState_tag, force_wake);
}

void TeslaBLE::Vehicle::closures_state_poll(bool force_wake) {
  send_infotainment_poll_("Closures State Poll", CarServer_GetVehicleData_getClosuresState_tag, force_wake);
}

void TeslaBLE::Vehicle::tire_pressure_poll(bool force_wake) {
  send_infotainment_poll_("Tire Pressure Poll", CarServer_GetVehicleData_getTirePressureState_tag, force_wake);
}

void TeslaBLE::Vehicle::set_charging_state(bool enable) {
  send_infotainment_action_(enable ? "Start Charging" : "Stop Charging",
                            CarServer_VehicleAction_chargingStartStopAction_tag, enable);
}

void TeslaBLE::Vehicle::set_charging_amps(int amps) {
  if (!ParameterValidator::is_valid_charging_amps(amps)) {
    LOG_ERROR("Invalid charging amps value: %d (must be 0-80)", amps);
    return;
  }
  LOG_DEBUG("set_charging_amps called with: %d", amps);
  send_infotainment_action_("Set Charging Amps", CarServer_VehicleAction_setChargingAmpsAction_tag, amps);
}

void TeslaBLE::Vehicle::set_charging_limit(int limit) {
  send_infotainment_action_("Set Charging Limit", CarServer_VehicleAction_chargingSetLimitAction_tag, limit);
}

void TeslaBLE::Vehicle::unlock_charge_port() {
  send_infotainment_action_("Unlock Charge Port", CarServer_VehicleAction_chargePortDoorOpen_tag);
}

// =============================================================================
// VCSEC Closure Controls
// =============================================================================

void TeslaBLE::Vehicle::lock() {
  send_command(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Lock", [](Client *client, uint8_t *buff, size_t *len) {
    return client->build_vcsec_action_message(VCSEC_RKEAction_E_RKE_ACTION_LOCK, buff, len);
  });
}

void TeslaBLE::Vehicle::unlock() {
  send_command(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Unlock",
               [](Client *client, uint8_t *buff, size_t *len) {
                 return client->build_vcsec_action_message(VCSEC_RKEAction_E_RKE_ACTION_UNLOCK, buff, len);
               });
}

void TeslaBLE::Vehicle::open_trunk() {
  send_command(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Open Trunk",
               [](Client *client, uint8_t *buff, size_t *len) {
                 VCSEC_ClosureMoveRequest request = VCSEC_ClosureMoveRequest_init_zero;
                 request.rearTrunk = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_OPEN;
                 return client->build_vcsec_closure_message(&request, buff, len);
               });
}

void TeslaBLE::Vehicle::close_trunk() {
  send_command(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Close Trunk",
               [](Client *client, uint8_t *buff, size_t *len) {
                 VCSEC_ClosureMoveRequest request = VCSEC_ClosureMoveRequest_init_zero;
                 request.rearTrunk = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_CLOSE;
                 return client->build_vcsec_closure_message(&request, buff, len);
               });
}

void TeslaBLE::Vehicle::open_frunk() {
  send_command(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Open Frunk",
               [](Client *client, uint8_t *buff, size_t *len) {
                 VCSEC_ClosureMoveRequest request = VCSEC_ClosureMoveRequest_init_zero;
                 request.frontTrunk = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_OPEN;
                 return client->build_vcsec_closure_message(&request, buff, len);
               });
}

void TeslaBLE::Vehicle::open_charge_port() {
  send_command(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Open Charge Port",
               [](Client *client, uint8_t *buff, size_t *len) {
                 VCSEC_ClosureMoveRequest request = VCSEC_ClosureMoveRequest_init_zero;
                 request.chargePort = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_OPEN;
                 return client->build_vcsec_closure_message(&request, buff, len);
               });
}

void TeslaBLE::Vehicle::close_charge_port() {
  send_command(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Close Charge Port",
               [](Client *client, uint8_t *buff, size_t *len) {
                 VCSEC_ClosureMoveRequest request = VCSEC_ClosureMoveRequest_init_zero;
                 request.chargePort = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_CLOSE;
                 return client->build_vcsec_closure_message(&request, buff, len);
               });
}

void TeslaBLE::Vehicle::unlatch_driver_door() {
  send_command(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Unlatch Driver Door",
               [](Client *client, uint8_t *buff, size_t *len) {
                 VCSEC_ClosureMoveRequest request = VCSEC_ClosureMoveRequest_init_zero;
                 request.frontDriverDoor = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_OPEN;
                 return client->build_vcsec_closure_message(&request, buff, len);
               });
}

// =============================================================================
// HVAC Controls (Infotainment)
// =============================================================================

void TeslaBLE::Vehicle::set_climate(bool enable) {
  send_infotainment_action_(enable ? "Climate On" : "Climate Off", CarServer_VehicleAction_hvacAutoAction_tag, enable);
}

void TeslaBLE::Vehicle::set_climate_temp(float temp_celsius) {
  send_infotainment_action_("Set Climate Temp", CarServer_VehicleAction_hvacTemperatureAdjustmentAction_tag,
                            temp_celsius);
}

void TeslaBLE::Vehicle::set_climate_keeper(int mode) {
  const char *modes[] = {"Off", "On", "Dog", "Camp"};
  std::string name = std::string("Climate Keeper ") + (mode >= 0 && mode <= 3 ? modes[mode] : "Unknown");
  send_infotainment_action_(name, CarServer_VehicleAction_hvacClimateKeeperAction_tag, mode);
}

void TeslaBLE::Vehicle::set_bioweapon_mode(bool enable) {
  send_infotainment_action_(enable ? "Bioweapon On" : "Bioweapon Off",
                            CarServer_VehicleAction_hvacBioweaponModeAction_tag, enable);
}

void TeslaBLE::Vehicle::set_preconditioning_max(bool enable) {
  send_infotainment_action_(enable ? "Defrost On" : "Defrost Off",
                            CarServer_VehicleAction_hvacSetPreconditioningMaxAction_tag, enable);
}

void TeslaBLE::Vehicle::set_steering_wheel_heat(bool enable) {
  send_infotainment_action_(enable ? "Steering Heat On" : "Steering Heat Off",
                            CarServer_VehicleAction_hvacSteeringWheelHeaterAction_tag, enable);
}

// =============================================================================
// Vehicle Controls (Infotainment)
// =============================================================================

void TeslaBLE::Vehicle::flash_lights() {
  send_infotainment_action_("Flash Lights", CarServer_VehicleAction_vehicleControlFlashLightsAction_tag);
}

void TeslaBLE::Vehicle::honk_horn() {
  send_infotainment_action_("Honk Horn", CarServer_VehicleAction_vehicleControlHonkHornAction_tag);
}

void TeslaBLE::Vehicle::set_sentry_mode(bool enable) {
  send_infotainment_action_(enable ? "Sentry On" : "Sentry Off",
                            CarServer_VehicleAction_vehicleControlSetSentryModeAction_tag, enable);
}

void TeslaBLE::Vehicle::vent_windows() {
  send_infotainment_action_("Vent Windows", CarServer_VehicleAction_vehicleControlWindowAction_tag, 0);
}

void TeslaBLE::Vehicle::close_windows() {
  send_infotainment_action_("Close Windows", CarServer_VehicleAction_vehicleControlWindowAction_tag, 1);
}

// =============================================================================
// Pairing and Key Management
// =============================================================================

void TeslaBLE::Vehicle::pair(Keys_Role role) {
  LOG_INFO("Initiating pairing sequence...");
  if (client_->create_private_key() != 0) {
    LOG_WARNING("Could not check/create private key, proceeding anyway");
  }
  send_command(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Whitelist Add Key",
               [role_copy = role](Client *client, uint8_t *buf, size_t *len) {
                 return client->build_white_list_message(role_copy, VCSEC_KeyFormFactor_KEY_FORM_FACTOR_NFC_CARD, buf,
                                                         len);
               });
}

void TeslaBLE::Vehicle::regenerate_key() {
  LOG_INFO("Regenerating private key...");
  if (client_->create_private_key() == 0) {
    // NOLINTNEXTLINE(readability-math-missing-parentheses) - macro from external library
    uint8_t key_buf[MBEDTLS_ECP_MAX_PT_LEN];
    size_t key_len = 0;
    size_t buf_len = sizeof(key_buf);
    if (client_->get_private_key(key_buf, buf_len, &key_len) == 0) {
      std::vector<uint8_t> key_vec(key_buf, key_buf + key_len);
      if (storage_adapter_->save("private_key", key_vec)) {
        LOG_INFO("New private key saved to storage");
      } else {
        LOG_ERROR("Failed to save new private key");
      }
    } else {
      LOG_ERROR("Failed to create private key");
    }
  }
}  // namespace TeslaBLE

void TeslaBLE::Vehicle::handle_signed_message_error_(const UniversalMessage_RoutableMessage &msg,
                                                     bool &has_session_error) {
  if (msg.signedMessageStatus.operation_status != UniversalMessage_OperationStatus_E_OPERATIONSTATUS_ERROR) {
    return;
  }

  UniversalMessage_Domain domain = UniversalMessage_Domain_DOMAIN_BROADCAST;
  if (msg.has_from_destination &&
      msg.from_destination.which_sub_destination == UniversalMessage_Destination_domain_tag) {
    domain = msg.from_destination.sub_destination.domain;
  } else if (auto cmd = peek_command_()) {
    domain = cmd->domain;
  }

  auto fault = msg.signedMessageStatus.signed_message_fault;
  LOG_ERROR("Signed message error from %s: %s", domain_to_string(domain), message_fault_to_string(fault));

  auto *peer = client_->get_peer(domain);
  if (peer) {
    switch (fault) {
      case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_TIME_EXPIRED:
      case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INCORRECT_EPOCH:
      case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER:
        LOG_INFO("Session sync required for %s (%s)", domain_to_string(domain), message_fault_to_string(fault));
        has_session_error = true;
        break;
      case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INVALID_SIGNATURE:
        LOG_INFO("INVALID_SIGNATURE for %s: resetting session and clearing stored data", domain_to_string(domain));
        peer->reset();
        // Clear stored session to prevent repeated INVALID_SIGNATURE errors
        clear_stored_session_(domain);
        has_session_error = true;
        break;
      default:
        break;
    }
  }

  auto cmd = peek_command_();
  if (!has_session_error && cmd && cmd->state == CommandState::WAITING_FOR_RESPONSE) {
    mark_command_failed_(cmd, CommandError::authentication_failed("signed message"));
  }
}

}  // namespace TeslaBLE
