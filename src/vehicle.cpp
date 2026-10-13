#ifndef TESLA_LOG_TAG
#define TESLA_LOG_TAG "TeslaBLE::Vehicle"
#endif

#include "vehicle.h"

#include "command_error.h"
#include "defs.h"
#include "state_text.h"

#include "tb_logging.h"
#include "tb_utils.h"

#include <pb_decode.h>
#include <pb_encode.h>

#include <algorithm>
#include <cinttypes>
#include <cmath>
#include <vector>
#include <array>
#include <cstdlib>  // for rand()
#include <string_view>
#include <utility>  // for std::cmp_greater, std::cmp_less_equal

namespace TeslaBLE {

namespace {

WakePolicy wake_policy_from_bool(bool requires_wake) {
  return requires_wake ? WakePolicy::WAKE_IF_NEEDED : WakePolicy::NO_WAKE_SKIP;
}

std::unique_ptr<CommandError> build_carserver_action_error(const CarServer_ActionStatus &status) {
  std::string message = "Infotainment action failed";
  if (status.has_result_reason && status.result_reason.which_reason == CarServer_ResultReason_plain_text_tag) {
    message += ": ";
    message += status.result_reason.reason.plain_text;
  }

  return std::make_unique<CommandError>(std::move(message), CommandError::Severity::PERMANENT,
                                        CommandError::Outcome::DEFINITELY_FAILED);
}

// The cooler and Auto-climate actions only accept the two front seats; both
// protocol enums number FrontLeft = 1, FrontRight = 2.
int front_seat_tag(SeatPosition seat) {
  return seat == SeatPosition::FRONT_LEFT ? 1 : seat == SeatPosition::FRONT_RIGHT ? 2 : 0;
}

}  // namespace

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
    ++connection_generation_;
    clear_requests_();
    LOG_INFO("Disconnected from vehicle");

    auto *vcsec_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
    auto *info_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
    if (vcsec_peer) {
      vcsec_peer->reset();
    }
    if (info_peer) {
      info_peer->reset();
    }

    sleep_state_ = SleepState::UNKNOWN;

    rx_buffer_.clear();
    message_processor_->clear();
    follow_up_polls_.fill({});
    std::queue<std::shared_ptr<Command>> cancelled;
    cancelled.swap(command_queue_);
    while (!cancelled.empty()) {
      auto cmd = cancelled.front();
      cancelled.pop();
      cmd->state = CommandState::FAILED;
      auto on_complete = std::move(cmd->on_complete);
      set_command_phase_(cmd, OperationPhase::TERMINAL);
      if (on_complete) {
        on_complete(OperationResult::failure(CommandError::connection_lost()));
      }
    }
  } else {
    LOG_INFO("Connected to vehicle");
  }
}

void TeslaBLE::Vehicle::loop() {
  if (is_looping_) {
    return;
  }
  is_looping_ = true;
  struct LoopGuard {
    bool &active;
    ~LoopGuard() { active = false; }
  } guard{is_looping_};
  message_processor_->process_messages();
  if (is_connected_) {
    process_follow_up_polls_();
    process_command_queue_();
  }
}

void TeslaBLE::Vehicle::send_command_result(UniversalMessage_Domain domain, const std::string &name,
                                            std::function<int(Client *, uint8_t *, size_t *)> builder,
                                            Command::OperationResultCallback on_complete, WakePolicy wake_policy,
                                            Command::OperationPhaseCallback on_phase_change) {
  enqueue_command_(std::make_shared<Command>(domain, name, std::move(builder), std::move(on_complete), wake_policy,
                                             std::move(on_phase_change)));
}

void TeslaBLE::Vehicle::enqueue_command_(const std::shared_ptr<Command> &cmd) {
  if (!is_connected_) {
    LOG_DEBUG("Not connected - rejecting command: %s", cmd->name.c_str());
    if (cmd->on_complete) {
      cmd->on_complete(OperationResult::failure(CommandError::connection_lost()));
    }
    return;
  }

  if (command_queue_.size() >= MAX_COMMAND_QUEUE_SIZE) {
    LOG_WARNING("Command queue full, rejecting command: %s", cmd->name.c_str());
    if (cmd->on_complete) {
      cmd->on_complete(OperationResult::failure(CommandError::build_failed("queue full")));
    }
    return;
  }

  command_queue_.push(cmd);
  LOG_DEBUG("Enqueued command: %s (domain: %s, wake_policy: %d)", cmd->name.c_str(), domain_to_string(cmd->domain),
            static_cast<int>(cmd->wake_policy));
  if (cmd->on_phase_change) {
    cmd->on_phase_change(OperationPhase::QUEUED);
  }
}

void TeslaBLE::Vehicle::process_command_queue_() {
  if (command_queue_.empty()) {
    return;
  }

  auto command = command_queue_.front();
  auto now = std::chrono::steady_clock::now();
  auto phase_duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->phase_started_at);
  if (phase_duration > AUTH_RESPONSE_TIMEOUT && command->state != CommandState::WAITING_FOR_RESPONSE &&
      command->state != CommandState::READY && command->state != CommandState::AUTH_RESPONSE_WAITING) {
    if (is_connected_) {
      LOG_WARNING("Command step timeout while connected: %s (phase: %d)", command->name.c_str(),
                  static_cast<int>(command->phase));
    } else {
      LOG_DEBUG("Command step timeout while disconnected: %s (phase: %d)", command->name.c_str(),
                static_cast<int>(command->phase));
    }
    mark_command_failed_(command, CommandError::timeout("Command step"));
    return;
  }

  if ((command->state == CommandState::IDLE || command->state == CommandState::READY) &&
      now < command->next_retry_time) {
    return;
  }

  const bool waiting_for_wake = command->state == CommandState::AUTH_RESPONSE_WAITING &&
                                command->current_auth_domain == UniversalMessage_Domain_DOMAIN_BROADCAST;
  if (waiting_for_wake && now - command->wake_poll_at >= TRANSPORT_RETRY_INTERVAL) {
    command->wake_poll_at = now;
    if (wake_probe_request_.empty()) {
      std::array<uint8_t, UniversalMessage_RoutableMessage_size + FRAME_HEADER_SIZE> buffer{};
      size_t length = buffer.size();
      client_->generate_connection_id();
      if (client_->build_vcsec_information_request_message(
              VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS, buffer.data(), &length) != 0) {
        LOG_WARNING("Failed to build wake status probe");
        return;
      }
      wake_probe_request_.assign(buffer.begin(), buffer.begin() + length);
      capture_request_(wake_probe_request_, wake_probe_);
    }
    if (!ble_adapter_->write(wake_probe_request_)) {
      LOG_WARNING("Failed to poll vehicle status while waiting for wake");
    }
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
      const auto timeout = (command->kind == Command::Kind::PAIRING) ? COMMAND_TIMEOUT : TRANSPORT_RETRY_INTERVAL;
      if (tx_duration > timeout) {
        if (command->kind == Command::Kind::WAKE && is_vehicle_observed_awake_()) {
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

  // Pairing starts with an untrusted key, so VCSEC session auth will return
  // KEY_NOT_ON_WHITELIST. This command must be sent without prior session auth.
  if (command->kind == Command::Kind::PAIRING) {
    LOG_INFO("Bypassing session auth for Whitelist Add Key");
    command->state = CommandState::READY;
    return;
  }

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
        if (!set_command_phase_(command, OperationPhase::ENSURING_VCSEC_SESSION))
          return;
        command->current_auth_domain = UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY;
        initiate_auth_for_domain_(command, UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
                                  CommandState::AUTH_RESPONSE_WAITING, "VCSEC");
      } else {
        if (!set_command_phase_(command, OperationPhase::ENSURING_INFOTAINMENT_SESSION))
          return;
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
  // Resend fresh session challenges unchanged; renew expired challenges without extending the overall wait.
  if (command->current_auth_domain == command->auth_request_domain &&
      command->current_auth_domain != UniversalMessage_Domain_DOMAIN_BROADCAST && !command->auth_request.empty() &&
      command->auth_resends < MAX_AUTH_RESENDS && now - command->auth_resend_at >= TRANSPORT_RETRY_INTERVAL) {
    if (now - request_.sent_at >= CLOCK_SYNC_MAX_LATENCY) {
      std::array<uint8_t, UniversalMessage_RoutableMessage_size + FRAME_HEADER_SIZE> buffer{};
      size_t length = buffer.size();
      client_->generate_connection_id();
      if (client_->build_session_info_request_message(command->current_auth_domain, buffer.data(), &length) != 0) {
        mark_command_failed_(command, CommandError::build_failed("Session Info Request"));
        return;
      }
      command->auth_request.assign(buffer.begin(), buffer.begin() + length);
      capture_request_(command->auth_request, request_);
    }
    if (ble_adapter_->write(command->auth_request)) {
      command->auth_resends++;
      LOG_DEBUG("Resent %s Session Info Request (%d/%d)", domain_to_string(command->current_auth_domain),
                command->auth_resends, MAX_AUTH_RESENDS);
    }
    command->auth_resend_at = now;
  }
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
  command->retry_count++;
  int attempt_level = std::min(command->retry_count / 2, 3);
  static constexpr std::array<int, 4> TIMEOUT_THRESHOLDS = {30, 60, 120, 300};
  if (total_duration > std::chrono::seconds(TIMEOUT_THRESHOLDS.at(attempt_level))) {
    LOG_ERROR("Connection validation failed: %s auth stuck for %lld seconds (level %d, retry %d)", domain_name.c_str(),
              (long long) total_duration.count(), attempt_level, command->retry_count);
    mark_command_failed_(command, CommandError::session_stale("connection"));
    reset_all_sessions_and_connection_();
    return;
  }
  rx_buffer_.clear();
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
  if (is_vehicle_observed_awake_()) {
    LOG_INFO("Wake response timeout but vehicle is awake - proceeding");
    handle_vehicle_status_command_update_(command);
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
      if (!set_command_phase_(command, OperationPhase::SENDING_REQUEST))
        return;
      command->state = CommandState::READY;
    } else if (domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY &&
               command->domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT) {
      advance_infotainment_prerequisites_(command);
    }
  } else {
    // A new session means a new counter: the request must be built again
    command->resend_encoded = false;
    std::array<uint8_t, UniversalMessage_RoutableMessage_size + FRAME_HEADER_SIZE> buffer{};
    size_t len = buffer.size();
    client_->generate_connection_id();
    if (client_->build_session_info_request_message(domain, buffer.data(), &len) == 0) {
      std::vector<uint8_t> data(buffer.begin(), buffer.begin() + len);
      capture_request_(data, request_);
      if (ble_adapter_->write(data)) {
        command->current_auth_domain = domain;
        command->state = waiting_state;
        command->last_tx_at = std::chrono::steady_clock::now();
        command->auth_request = std::move(data);
        command->auth_request_domain = domain;
        command->auth_resend_at = command->last_tx_at;
        command->auth_resends = 0;
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
  if (!set_command_phase_(command, OperationPhase::ENSURING_VCSEC_SESSION))
    return;
  initiate_auth_for_domain_(command, UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY,
                            CommandState::AUTH_RESPONSE_WAITING, "VCSEC");
}

void TeslaBLE::Vehicle::initiate_infotainment_auth_(const std::shared_ptr<Command> &command) {
  if (!set_command_phase_(command, OperationPhase::QUEUED))
    return;

  switch (command->wake_policy) {
    case WakePolicy::NO_WAKE_SKIP:
      if (is_vehicle_observed_asleep_()) {
        LOG_DEBUG("Vehicle asleep, skipping command with NoWakeSkip: %s", command->name.c_str());
        mark_command_skipped_(command, OperationTerminalReason::VEHICLE_ASLEEP);
        return;
      }
      break;
    case WakePolicy::NO_WAKE_FAIL:
      if (is_vehicle_observed_asleep_()) {
        LOG_DEBUG("Vehicle asleep, failing command with NoWakeFail: %s", command->name.c_str());
        mark_command_failed_(command, CommandError::build_failed("vehicle asleep"),
                             OperationTerminalReason::VEHICLE_ASLEEP);
        return;
      }
      break;
    case WakePolicy::WAKE_IF_NEEDED:
      break;
  }

  advance_infotainment_prerequisites_(command);
}

void TeslaBLE::Vehicle::advance_infotainment_prerequisites_(const std::shared_ptr<Command> &command) {
  if (!is_domain_authenticated_(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY)) {
    LOG_DEBUG("VCSEC auth required before Infotainment auth");
    if (!set_command_phase_(command, OperationPhase::ENSURING_VCSEC_SESSION))
      return;
    initiate_vcsec_auth_(command);
    return;
  }

  if (!is_vehicle_observed_awake_() && command->wake_policy == WakePolicy::WAKE_IF_NEEDED) {
    LOG_DEBUG("Vehicle is not awake and wake policy requires wake, initiating wake sequence");
    if (!set_command_phase_(command, OperationPhase::ENSURING_AWAKE))
      return;
    command->current_auth_domain = UniversalMessage_Domain_DOMAIN_BROADCAST;
    command->state = CommandState::AUTHENTICATING;
    command->last_tx_at = std::chrono::steady_clock::time_point();
    return;
  }

  if (!set_command_phase_(command, OperationPhase::ENSURING_INFOTAINMENT_SESSION))
    return;
  initiate_auth_for_domain_(command, UniversalMessage_Domain_DOMAIN_INFOTAINMENT, CommandState::AUTH_RESPONSE_WAITING,
                            "Infotainment");
}

void TeslaBLE::Vehicle::initiate_wake_sequence_(const std::shared_ptr<Command> &command) {
  if (!set_command_phase_(command, OperationPhase::ENSURING_AWAKE))
    return;
  command->resend_encoded = false;
  std::array<uint8_t, UniversalMessage_RoutableMessage_size + FRAME_HEADER_SIZE> buffer{};
  size_t len = buffer.size();
  client_->generate_connection_id();
  if (client_->build_vcsec_action_message(VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, buffer.data(), &len) == 0) {
    std::vector<uint8_t> data(buffer.begin(), buffer.begin() + len);
    capture_request_(data, request_);
    if (ble_adapter_->write(data)) {
      command->state = CommandState::AUTH_RESPONSE_WAITING;
      command->last_tx_at = std::chrono::steady_clock::now();
      command->wake_poll_at = command->last_tx_at;
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
    mark_command_failed_(command, CommandError::max_retries_exceeded(command->name, command->request_accepted));
    return;
  }

  rx_buffer_.clear();
  command->retry_count++;
  LOG_DEBUG("Retrying command: %s (attempt %d/%d)", command->name.c_str(), command->retry_count, MAX_RETRIES + 1);

  std::chrono::milliseconds backoff_delay;
  if (command->retry_count == 1) {
    backoff_delay = INITIAL_RETRY_DELAY;
  } else {
    auto current_delay = command->next_retry_delay;
    auto calculated_delay = std::chrono::milliseconds(static_cast<int64_t>(current_delay.count() * BACKOFF_MULTIPLIER));
    backoff_delay = calculated_delay > MAX_RETRY_DELAY ? MAX_RETRY_DELAY : calculated_delay;
    // Jitter from the high-resolution clock; retries are seconds apart, so the
    // sub-millisecond variation spreads retries without needing a PRNG.
    auto jitter = std::chrono::milliseconds(
        static_cast<int64_t>(std::chrono::steady_clock::now().time_since_epoch().count()) % 101);
    backoff_delay += jitter;
  }

  command->next_retry_delay = backoff_delay;
  command->next_retry_time = std::chrono::steady_clock::now() + backoff_delay;
  LOG_DEBUG("Exponential backoff: retry %d, delay %lldms for command: %s", static_cast<int>(command->retry_count + 1),
            static_cast<long long>(backoff_delay.count()), command->name.c_str());

  if (!set_command_phase_(command, OperationPhase::QUEUED))
    return;
  switch (command->state) {
    case CommandState::WAITING_FOR_RESPONSE:
      // No reply in time, session unchanged: send the same message again
      command->state = CommandState::READY;
      command->resend_encoded = true;
      break;
    case CommandState::AUTH_RESPONSE_WAITING:
    default:
      command->state = CommandState::IDLE;
      command->resend_encoded = false;
      break;
  }
}

void TeslaBLE::Vehicle::process_ready_command_(const std::shared_ptr<Command> &command) {
  if (!set_command_phase_(command, OperationPhase::SENDING_REQUEST))
    return;
  const bool resend = command->resend_encoded && !command->encoded_request.empty();
  command->resend_encoded = false;
  if (!resend) {
    std::array<uint8_t, UniversalMessage_RoutableMessage_size + FRAME_HEADER_SIZE> buffer{};
    size_t len = buffer.size();
    client_->generate_connection_id();
    if (command->builder(client_.get(), buffer.data(), &len) != 0) {
      LOG_ERROR("Failed to build command: %s", command->name.c_str());
      mark_command_failed_(command, CommandError::build_failed(command->name));
      return;
    }
    command->encoded_request.assign(buffer.begin(), buffer.begin() + len);
    capture_request_(command->encoded_request, request_);
  }
  if (ble_adapter_->write(command->encoded_request)) {
    command->request_accepted = true;
    LOG_DEBUG("%s command: %s (%zu bytes)", resend ? "Resent" : "Sent", command->name.c_str(),
              command->encoded_request.size());
    command->state = CommandState::WAITING_FOR_RESPONSE;
    if (command->kind == Command::Kind::WAKE) {
      command->current_auth_domain = UniversalMessage_Domain_DOMAIN_BROADCAST;
      command->state = CommandState::AUTH_RESPONSE_WAITING;
    }
    if (!set_command_phase_(command, command->kind == Command::Kind::WAKE ? OperationPhase::ENSURING_AWAKE
                                                                          : OperationPhase::AWAITING_RESPONSE))
      return;
    command->last_tx_at = std::chrono::steady_clock::now();
    if (command->kind == Command::Kind::WAKE) {
      command->wake_poll_at = command->last_tx_at;
    }
  } else {
    LOG_ERROR("Failed to write command data: %s", command->name.c_str());
    mark_command_failed_(command, CommandError::write_failed(command->request_accepted));
  }
}

void TeslaBLE::Vehicle::mark_command_failed_(const std::shared_ptr<Command> &command,
                                             std::unique_ptr<CommandError> error, OperationTerminalReason reason) {
  const bool key_not_paired = error->is_key_not_paired();
  command->state = CommandState::FAILED;
  auto now = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->started_at);
  LOG_ERROR("[%s] Command failed after %lld ms: %s (reason: %d)", command->name.c_str(), (long long) duration.count(),
            error->message().c_str(), static_cast<int>(reason));
  finalize_command_(command, OperationResult::failure(std::move(error), reason));
  auto callback = key_not_paired_callback_;
  if (key_not_paired && callback) {
    callback();
  }
}

void TeslaBLE::Vehicle::mark_command_completed_(const std::shared_ptr<Command> &command) {
  command->state = CommandState::COMPLETED;
  auto now = std::chrono::steady_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - command->started_at);
  LOG_INFO("[%s] Command completed successfully in %lld ms", command->name.c_str(), (long long) duration.count());
  finalize_command_(command, OperationResult::success());
}

void TeslaBLE::Vehicle::mark_command_skipped_(const std::shared_ptr<Command> &command, OperationTerminalReason reason) {
  command->state = CommandState::COMPLETED;
  LOG_INFO("[%s] Command skipped (reason: %d)", command->name.c_str(), static_cast<int>(reason));
  finalize_command_(command, OperationResult::skipped(reason));
}

bool TeslaBLE::Vehicle::set_command_phase_(const std::shared_ptr<Command> &command, OperationPhase phase) {
  if (command->phase == phase)
    return is_connected_ && peek_command_() == command;
  command->phase = phase;
  command->phase_started_at = std::chrono::steady_clock::now();
  if (command->on_phase_change) {
    command->on_phase_change(phase);
  }
  return is_connected_ && peek_command_() == command;
}

void TeslaBLE::Vehicle::finalize_command_(const std::shared_ptr<Command> &command, OperationResult result) {
  if (peek_command_() != command) {
    return;
  }
  clear_requests_();
  if (result.is_success()) {
    schedule_follow_up_poll_(command->refresh);
    if (!command->remaining_steps.empty()) {
      auto next = std::make_shared<Command>(command->domain, command->name, std::move(command->remaining_steps.front()),
                                            std::move(command->on_complete), command->wake_policy,
                                            std::move(command->on_phase_change), command->kind, command->refresh);
      command->remaining_steps.erase(command->remaining_steps.begin());
      next->remaining_steps = std::move(command->remaining_steps);
      command_queue_.front() = std::move(next);
      return;
    }
  }
  auto completed = std::move(command_queue_.front());
  command_queue_.pop();
  auto on_complete = std::move(completed->on_complete);
  set_command_phase_(completed, OperationPhase::TERMINAL);
  if (on_complete) {
    on_complete(std::move(result));
  }
}

void TeslaBLE::Vehicle::schedule_follow_up_poll_(Refresh refresh) {
  if (refresh != Refresh::COUNT) {
    follow_up_polls_[static_cast<size_t>(refresh)] = std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
  }
}

TeslaBLE::Vehicle::Refresh TeslaBLE::Vehicle::refresh_for_action_(int32_t action_tag) const {
  switch (action_tag) {
    case CarServer_VehicleAction_chargingStartStopAction_tag:
    case CarServer_VehicleAction_setChargingAmpsAction_tag:
    case CarServer_VehicleAction_chargingSetLimitAction_tag:
    case CarServer_VehicleAction_chargePortDoorOpen_tag:
      return Refresh::CHARGE;
    case CarServer_VehicleAction_hvacAutoAction_tag:
    case CarServer_VehicleAction_hvacTemperatureAdjustmentAction_tag:
    case CarServer_VehicleAction_hvacClimateKeeperAction_tag:
    case CarServer_VehicleAction_hvacBioweaponModeAction_tag:
    case CarServer_VehicleAction_hvacSetPreconditioningMaxAction_tag:
    case CarServer_VehicleAction_hvacSteeringWheelHeaterAction_tag:
    case CarServer_VehicleAction_hvacSeatHeaterActions_tag:
    case CarServer_VehicleAction_autoSeatClimateAction_tag:
    case CarServer_VehicleAction_hvacSeatCoolerActions_tag:
    case CarServer_VehicleAction_setCabinOverheatProtectionAction_tag:
    case CarServer_VehicleAction_setCopTempAction_tag:
      return Refresh::CLIMATE;
    case CarServer_VehicleAction_vehicleControlSetSentryModeAction_tag:
    case CarServer_VehicleAction_vehicleControlWindowAction_tag:
    case CarServer_VehicleAction_vehicleControlSunroofOpenCloseAction_tag:
      return Refresh::CLOSURES;
    case CarServer_VehicleAction_vehicleControlScheduleSoftwareUpdateAction_tag:
    case CarServer_VehicleAction_vehicleControlCancelSoftwareUpdateAction_tag:
      return Refresh::SOFTWARE_UPDATE;
    default:
      return Refresh::COUNT;
  }
}

void TeslaBLE::Vehicle::process_follow_up_polls_() {
  const auto now = std::chrono::steady_clock::now();
  for (size_t i = 0; i < follow_up_polls_.size(); ++i) {
    auto &due = follow_up_polls_[i];
    if (due == std::chrono::steady_clock::time_point{} || now < due ||
        command_queue_.size() >= MAX_COMMAND_QUEUE_SIZE) {
      continue;
    }
    due = {};
    switch (static_cast<Refresh>(i)) {
      case Refresh::VCSEC:
        vcsec_poll(WakePolicy::NO_WAKE_SKIP);
        break;
      case Refresh::CHARGE:
        charge_state_poll(WakePolicy::NO_WAKE_SKIP);
        break;
      case Refresh::CLIMATE:
        climate_state_poll(WakePolicy::NO_WAKE_SKIP);
        break;
      case Refresh::CLOSURES:
        closures_state_poll(WakePolicy::NO_WAKE_SKIP);
        break;
      case Refresh::SOFTWARE_UPDATE:
        software_update_poll(WakePolicy::NO_WAKE_SKIP);
        break;
      case Refresh::COUNT:
        break;
    }
  }
}

size_t TeslaBLE::Vehicle::pending_command_count() const {
  return command_queue_.size() + std::count_if(follow_up_polls_.begin(), follow_up_polls_.end(), [](const auto &due) {
           return due != std::chrono::steady_clock::time_point{};
         });
}

bool TeslaBLE::Vehicle::has_private_key() const { return client_ != nullptr && client_->has_private_key(); }

bool Vehicle::is_vehicle_observed_awake_() const { return sleep_state_ == SleepState::AWAKE; }

bool Vehicle::is_vehicle_observed_asleep_() const { return sleep_state_ == SleepState::ASLEEP; }

bool Vehicle::is_domain_authenticated_(UniversalMessage_Domain domain) {
  auto *peer = client_->get_peer(domain);
  return peer && peer->is_valid();
}

void TeslaBLE::Vehicle::on_rx_data(const std::vector<uint8_t> &data) {
  if (data.empty()) {
    return;
  }
  if (data.size() >= MAX_RX_BUFFER_SIZE) {
    rx_buffer_.assign(data.end() - MAX_RX_BUFFER_SIZE, data.end());
  } else {
    const size_t required = rx_buffer_.size() + data.size();
    if (required > MAX_RX_BUFFER_SIZE) {
      rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + (required - MAX_RX_BUFFER_SIZE));
    }
    rx_buffer_.insert(rx_buffer_.end(), data.begin(), data.end());
  }
  recovery_attempted_ = false;
  while (is_message_complete()) {
    process_complete_message();
  }
}

bool Vehicle::is_message_complete() {
  if (rx_buffer_.size() < FRAME_HEADER_SIZE)
    return false;
  if (recovery_attempted_)
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
  return static_cast<int>((rx_buffer_.at(0) << 8) | rx_buffer_.at(1)) + FRAME_HEADER_SIZE;
}

void TeslaBLE::Vehicle::process_complete_message() {
  int msg_len = get_expected_message_length();
  if (msg_len <= 0 || std::cmp_greater(msg_len, MAX_MESSAGE_SIZE)) {
    LOG_ERROR("Invalid message length %d, attempting buffer recovery", msg_len);
    if (!attempt_buffer_recovery_(msg_len)) {
      LOG_WARNING("Buffer recovery found no complete frame, retaining data for fragmented recovery");
      if (rx_buffer_.size() > MAX_RX_BUFFER_SIZE) {
        rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.end() - MAX_RX_BUFFER_SIZE);
      }
      recovery_attempted_ = true;
      return;
    }
    recovery_attempted_ = false;
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
      LOG_WARNING("Buffer recovery failed after parse error, retaining data for fragmented recovery");
      if (rx_buffer_.size() > MAX_RX_BUFFER_SIZE) {
        rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.end() - MAX_RX_BUFFER_SIZE);
      }
      recovery_attempted_ = true;
    } else {
      recovery_attempted_ = false;
    }
  }
  auto callback = raw_message_callback_;
  if (callback) {
    callback(full_msg);
  }
}

void TeslaBLE::Vehicle::clear_requests_() {
  request_ = {};
  wake_probe_ = {};
  wake_probe_request_.clear();
}

void TeslaBLE::Vehicle::capture_request_(const std::vector<uint8_t> &frame, RequestContext &context) {
  if (&context == &request_) {
    clear_requests_();
  }
  context = {};
  UniversalMessage_RoutableMessage message = UniversalMessage_RoutableMessage_init_default;
  if (frame.size() <= FRAME_HEADER_SIZE ||
      client_->parse_universal_message(const_cast<pb_byte_t *>(frame.data()) + FRAME_HEADER_SIZE,
                                       frame.size() - FRAME_HEADER_SIZE, &message) != TeslaBLE_Status_E_OK ||
      !message.has_to_destination ||
      message.to_destination.which_sub_destination != UniversalMessage_Destination_domain_tag ||
      !message.has_from_destination ||
      message.from_destination.which_sub_destination != UniversalMessage_Destination_routing_address_tag ||
      message.from_destination.sub_destination.routing_address.size != context.routing_address.size() ||
      message.uuid.size != context.uuid.size()) {
    return;
  }
  context.domain = message.to_destination.sub_destination.domain;
  std::copy_n(message.uuid.bytes, context.uuid.size(), context.uuid.begin());
  std::copy_n(message.from_destination.sub_destination.routing_address.bytes, context.routing_address.size(),
              context.routing_address.begin());
  if (message.which_sub_sigData == UniversalMessage_RoutableMessage_signature_data_tag &&
      message.sub_sigData.signature_data.which_sig_type == Signatures_SignatureData_AES_GCM_Personalized_data_tag) {
    context.hash[0] = Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED;
    std::copy_n(message.sub_sigData.signature_data.sig_type.AES_GCM_Personalized_data.tag, 16,
                context.hash.begin() + 1);
    context.hash_length = context.hash.size();
  }
  context.sent_at = std::chrono::steady_clock::now();
  context.active = true;
}

TeslaBLE::Vehicle::RequestContext *TeslaBLE::Vehicle::response_context_(const UniversalMessage_RoutableMessage &msg) {
  const auto cmd = peek_command_();
  if (!cmd || (msg.request_uuid.size != 0 && msg.request_uuid.size != request_.uuid.size())) {
    return nullptr;
  }
  auto expected_domain = cmd->state == CommandState::AUTH_RESPONSE_WAITING || cmd->state == CommandState::AUTHENTICATING
                             ? cmd->current_auth_domain
                             : cmd->domain;
  if (expected_domain == UniversalMessage_Domain_DOMAIN_BROADCAST) {
    expected_domain = UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY;
  }
  if (msg.has_from_destination &&
      (msg.from_destination.which_sub_destination != UniversalMessage_Destination_domain_tag ||
       msg.from_destination.sub_destination.domain != expected_domain)) {
    return nullptr;
  }
  for (auto *context : {&request_, &wake_probe_}) {
    if (!context->active || context->domain != expected_domain ||
        std::chrono::steady_clock::now() - context->sent_at > COMMAND_TIMEOUT) {
      continue;
    }
    const bool uuid_matches = msg.request_uuid.size == context->uuid.size() &&
                              std::equal(context->uuid.begin(), context->uuid.end(), msg.request_uuid.bytes);
    if (msg.has_to_destination) {
      if (msg.to_destination.which_sub_destination != UniversalMessage_Destination_routing_address_tag) {
        continue;
      }
      const auto &address = msg.to_destination.sub_destination.routing_address;
      if (address.size != context->routing_address.size() ||
          !std::equal(context->routing_address.begin(), context->routing_address.end(), address.bytes)) {
        continue;
      }
      if (context->domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY || uuid_matches) {
        return context;
      }
    } else if (uuid_matches) {
      return context;
    }
  }
  return nullptr;
}

void TeslaBLE::Vehicle::handle_message_(UniversalMessage_RoutableMessage msg) {
  const auto generation = connection_generation_;
  if (message_callback_) {
    message_callback_(msg);
  }
  if (generation != connection_generation_) {
    return;
  }
  auto *context = response_context_(msg);
  const auto domain = context ? context->domain
                              : (msg.has_from_destination && msg.from_destination.which_sub_destination ==
                                                                 UniversalMessage_Destination_domain_tag
                                     ? msg.from_destination.sub_destination.domain
                                     : UniversalMessage_Domain_DOMAIN_BROADCAST);
  auto cmd = peek_command_();
  const bool legacy_pairing = cmd && cmd->kind == Command::Kind::PAIRING && !request_.active &&
                              domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY && msg.request_uuid.size == 0;
  const bool matches_request = context == &request_ || legacy_pairing;
  if (msg.which_payload == UniversalMessage_RoutableMessage_session_info_tag) {
    if (!context) {
      return;
    }
    const bool pending = cmd && (cmd->awaiting_response() || cmd->state == CommandState::AUTH_RESPONSE_WAITING);
    if (!handle_session_info_message_(msg, *context) || generation != connection_generation_) {
      return;
    }
    bool has_session_error = false;
    if (matches_request && msg.has_signedMessageStatus) {
      handle_signed_message_error_(msg, domain, has_session_error, true);
    }
    if (has_session_error && pending && peek_command_() == cmd) {
      LOG_INFO("Retrying command after session recovery");
      clear_requests_();
      cmd->state = CommandState::IDLE;
      cmd->resend_encoded = false;
      cmd->retry_count++;
      if (cmd->retry_count > MAX_RETRIES) {
        mark_command_failed_(cmd, CommandError::session_expired("session recovery"));
      }
    }
    return;
  }
  if (msg.which_sub_sigData == UniversalMessage_RoutableMessage_signature_data_tag &&
      msg.sub_sigData.signature_data.which_sig_type == Signatures_SignatureData_AES_GCM_Response_data_tag) {
    auto *peer = context ? client_->get_peer(context->domain) : nullptr;
    if (!peer || !peer->is_initialized() || context->hash_length == 0 ||
        msg.which_payload != UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag) {
      return;
    }
    const auto &signature = msg.sub_sigData.signature_data.sig_type.AES_GCM_Response_data;
    UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t plaintext{};
    size_t length = 0;
    const auto fault = msg.has_signedMessageStatus ? msg.signedMessageStatus.signed_message_fault
                                                   : UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE;
    if (peer->decrypt_response(msg.payload.protobuf_message_as_bytes.bytes, msg.payload.protobuf_message_as_bytes.size,
                               signature.nonce, signature.tag, context->hash.data(), context->hash_length, msg.flags,
                               fault, signature.counter, plaintext.bytes, sizeof(plaintext.bytes),
                               &length) != TeslaBLE_Status_E_OK ||
        !context->responses.add(signature.counter)) {
      return;
    }
    plaintext.size = length;
    msg.payload.protobuf_message_as_bytes = plaintext;
    msg.which_sub_sigData = 0;
  }
  if (matches_request && msg.has_signedMessageStatus) {
    bool has_session_error = false;
    handle_signed_message_error_(msg, domain, has_session_error);
    if (has_session_error && cmd && peek_command_() == cmd &&
        (cmd->awaiting_response() || cmd->state == CommandState::AUTH_RESPONSE_WAITING)) {
      clear_requests_();
      cmd->state = CommandState::IDLE;
      cmd->resend_encoded = false;
      if (++cmd->retry_count > MAX_RETRIES) {
        mark_command_failed_(cmd, CommandError::session_expired("session recovery"));
      }
    }
    if (generation != connection_generation_ ||
        msg.signedMessageStatus.operation_status == UniversalMessage_OperationStatus_E_OPERATIONSTATUS_ERROR) {
      return;
    }
  } else if (msg.has_signedMessageStatus &&
             msg.signedMessageStatus.operation_status == UniversalMessage_OperationStatus_E_OPERATIONSTATUS_ERROR) {
    return;
  }
  if (msg.has_from_destination &&
      msg.from_destination.which_sub_destination == UniversalMessage_Destination_domain_tag) {
    switch (domain) {
      case UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY:
        handle_vcsec_message_(msg, context, matches_request);
        break;
      case UniversalMessage_Domain_DOMAIN_INFOTAINMENT:
        if (context || msg.request_uuid.size == 0) {
          handle_carserver_message_(msg, context);
        }
        break;
      default:
        LOG_DEBUG("Message from unknown domain: %d", static_cast<int>(msg.from_destination.sub_destination.domain));
        break;
    }
  }
}

bool TeslaBLE::Vehicle::handle_session_info_message_(const UniversalMessage_RoutableMessage &msg,
                                                     RequestContext &context) {
  const auto domain = context.domain;
  if (msg.request_uuid.size != context.uuid.size() ||
      !std::equal(context.uuid.begin(), context.uuid.end(), msg.request_uuid.bytes) ||
      std::chrono::steady_clock::now() - context.sent_at > CLOCK_SYNC_MAX_LATENCY) {
    return false;
  }
  if (domain != UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY &&
      domain != UniversalMessage_Domain_DOMAIN_INFOTAINMENT) {
    LOG_ERROR("Could not determine valid domain for session info update");
    return false;
  }

  auto fail_auth = [&](const char *format, auto... args) {
    LOG_ERROR(format, args...);
    if (&context == &request_) {
      handle_authentication_response_(domain, false);
    }
  };

  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  int result = client_->parse_payload_session_info(
      const_cast<UniversalMessage_RoutableMessage_session_info_t *>(&msg.payload.session_info), &session_info);
  if (result != 0) {
    fail_auth("Failed to parse session info (result=%d)", result);
    return false;
  }

  if (msg.which_sub_sigData != UniversalMessage_RoutableMessage_signature_data_tag ||
      msg.sub_sigData.signature_data.which_sig_type != Signatures_SignatureData_session_info_tag_tag) {
    fail_auth("Missing session info HMAC tag for %s", domain_to_string(domain));
    return false;
  }

  const auto &tag = msg.sub_sigData.signature_data.sig_type.session_info_tag.tag;
  if (tag.size == 0) {
    fail_auth("Empty session info HMAC tag for %s", domain_to_string(domain));
    return false;
  }

  if (!client_->verify_session_info_tag(session_info, msg.payload.session_info.bytes, msg.payload.session_info.size,
                                        context.uuid.data(), context.uuid.size(), tag.bytes, tag.size)) {
    fail_auth("Session info HMAC verification failed for %s", domain_to_string(domain));
    return false;
  }

  LOG_DEBUG("Parsed session info successfully for %s", domain_to_string(domain));
  log_session_info(TESLA_LOG_TAG, &session_info);

  if (session_info.status != Signatures_Session_Info_Status_SESSION_INFO_STATUS_OK) {
    LOG_WARNING("Session info status not OK for %s: %d", domain_to_string(domain),
                static_cast<int>(session_info.status));
    auto cmd = peek_command_();
    if (cmd && &context == &request_) {
      mark_command_failed_(
          cmd, session_info.status == Signatures_Session_Info_Status_SESSION_INFO_STATUS_KEY_NOT_ON_WHITELIST
                   ? CommandError::key_not_paired(domain_to_string(domain))
                   : CommandError::authentication_failed(domain_to_string(domain), false));
    }
    return false;
  }

  auto *peer = client_->get_peer(domain);
  int update_result = peer ? peer->update_session(&session_info) : TeslaBLE_Status_E_ERROR_INVALID_SESSION;
  if (peer && update_result == TeslaBLE_Status_E_ERROR_COUNTER_REPLAY) {
    // The vehicle reports a counter below ours (it lost counter state).
    // Upstream signer.go always applies such updates, keeping
    // max(local, reported); hard-rejecting strands the session with a counter
    // the vehicle no longer acks. Resync to the vehicle's truth.
    LOG_WARNING("Counter replay for %s - forcing session resync to vehicle counter", domain_to_string(domain));
    update_result = peer->force_update_session(&session_info);
  }
  if (peer && update_result == TeslaBLE_Status_E_OK) {
    LOG_INFO("Session updated for %s", domain_to_string(domain));
    persist_session_(domain, msg.payload.session_info);
    if (&context == &request_ &&
        (!msg.has_signedMessageStatus ||
         msg.signedMessageStatus.operation_status != UniversalMessage_OperationStatus_E_OPERATIONSTATUS_ERROR)) {
      handle_authentication_response_(domain, true);
    }
    return true;
  } else {
    LOG_ERROR("Failed to update peer session for %s", domain_to_string(domain));
    fail_auth("Session update failed for %s", domain_to_string(domain));
    return false;
  }
}

void TeslaBLE::Vehicle::handle_vcsec_message_(const UniversalMessage_RoutableMessage &msg, RequestContext *context,
                                              bool matches_request) {
  const auto generation = connection_generation_;
  LOG_DEBUG("Processing VCSEC message");
  if (msg.which_payload != UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag) {
    LOG_ERROR("VCSEC message missing protobuf payload");
    return;
  }

  const UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *payload = &msg.payload.protobuf_message_as_bytes;

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
        if (matches_request && cmd->domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY &&
            (cmd->awaiting_response() || cmd->state == CommandState::AUTH_RESPONSE_WAITING)) {
          const auto &status = vcsec_msg.sub_message.commandStatus;
          const bool has_whitelist = status.which_sub_message == VCSEC_CommandStatus_whitelistOperationStatus_tag;
          const bool has_signed = status.which_sub_message == VCSEC_CommandStatus_signedMessageStatus_tag;
          const auto whitelist_code = has_whitelist
                                          ? status.sub_message.whitelistOperationStatus.whitelistOperationInformation
                                          : VCSEC_WhitelistOperation_information_E_WHITELISTOPERATION_INFORMATION_NONE;
          const auto signed_code = has_signed ? status.sub_message.signedMessageStatus.signedMessageInformation
                                              : VCSEC_SignedMessage_information_E_SIGNEDMESSAGE_INFORMATION_NONE;
          if (status.operationStatus == VCSEC_OperationStatus_E_OPERATIONSTATUS_ERROR ||
              (has_whitelist && status.sub_message.whitelistOperationStatus.operationStatus ==
                                    VCSEC_OperationStatus_E_OPERATIONSTATUS_ERROR) ||
              whitelist_code != VCSEC_WhitelistOperation_information_E_WHITELISTOPERATION_INFORMATION_NONE ||
              signed_code != VCSEC_SignedMessage_information_E_SIGNEDMESSAGE_INFORMATION_NONE) {
            auto error =
                signed_code == VCSEC_SignedMessage_information_E_SIGNEDMESSAGE_INFORMATION_FAULT_NOT_ON_WHITELIST
                    ? CommandError::key_not_paired("VCSEC")
                    : std::make_unique<CommandError>(
                          "VCSEC command rejected (whitelist=" + std::to_string(whitelist_code) +
                              ", signed=" + std::to_string(signed_code) + ")",
                          CommandError::Severity::PERMANENT, CommandError::Outcome::DEFINITELY_FAILED);
            mark_command_failed_(cmd, std::move(error));
          } else if (cmd->awaiting_response() && status.operationStatus == VCSEC_OperationStatus_E_OPERATIONSTATUS_OK &&
                     (!has_whitelist || status.sub_message.whitelistOperationStatus.operationStatus ==
                                            VCSEC_OperationStatus_E_OPERATIONSTATUS_OK) &&
                     (cmd->kind != Command::Kind::PAIRING || has_whitelist)) {
            mark_command_completed_(cmd);
          }
        }
      }
      break;
    case VCSEC_FromVCSECMessage_vehicleStatus_tag:
      LOG_DEBUG("Received vehicle status");
      log_vehicle_status(TESLA_LOG_TAG, &vcsec_msg.sub_message.vehicleStatus);
      if (auto asleep = state_text::sleep_status(vcsec_msg.sub_message.vehicleStatus.vehicleSleepStatus)) {
        sleep_state_ = *asleep ? SleepState::ASLEEP : SleepState::AWAKE;
      } else {
        sleep_state_ = SleepState::UNKNOWN;
      }
      if (vehicle_status_callback_) {
        vehicle_status_callback_(vcsec_msg.sub_message.vehicleStatus);
      }
      if (generation != connection_generation_) {
        return;
      }
      if (auto cmd = peek_command_();
          cmd &&
          (matches_request || ((context == &wake_probe_ || (!msg.has_to_destination && msg.request_uuid.size == 0)) &&
                               cmd->state == CommandState::AUTH_RESPONSE_WAITING &&
                               cmd->current_auth_domain == UniversalMessage_Domain_DOMAIN_BROADCAST))) {
        handle_vehicle_status_command_update_(cmd);
      }
      break;
    case VCSEC_FromVCSECMessage_whitelistInfo_tag:
      break;
    case VCSEC_FromVCSECMessage_nominalError_tag:
      LOG_ERROR("VCSEC Nominal Error: %s", generic_error_to_string(vcsec_msg.sub_message.nominalError.genericError));
      if (auto cmd = peek_command_(); cmd && matches_request) {
        mark_command_failed_(cmd, CommandError::authentication_failed("VCSEC"));
      }
      break;
    default:
      break;
  }
}

void TeslaBLE::Vehicle::handle_carserver_message_(const UniversalMessage_RoutableMessage &msg,
                                                  RequestContext *context) {
  const auto generation = connection_generation_;
  LOG_DEBUG("Processing CarServer message");
  CarServer_Response response = CarServer_Response_init_default;
  MediaNowPlaying now_playing;
  std::string update_version;
  int result = client_->parse_payload_car_server_response(
      const_cast<UniversalMessage_RoutableMessage_protobuf_message_as_bytes_t *>(
          &msg.payload.protobuf_message_as_bytes),
      nullptr, 0, UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE, msg.flags, &response, nullptr,
      media_state_callback_ ? &now_playing : nullptr, software_update_callback_ ? &update_version : nullptr);
  if (result != 0) {
    LOG_ERROR("Failed to parse CarServer response: %d", result);
    return;
  }
  LOG_DEBUG("Parsed CarServer.Response successfully");
  log_carserver_response(TESLA_LOG_TAG, &response);
  if (response.which_response_msg == CarServer_Response_vehicleData_tag) {
    auto &vd = response.response_msg.vehicleData;
    auto emit_if = [&](bool has_value, auto &callback, const auto &value) {
      if (generation == connection_generation_ && has_value && callback) {
        callback(value);
      }
    };
    emit_if(vd.has_charge_state, charge_state_callback_, vd.charge_state);
    emit_if(vd.has_climate_state, climate_state_callback_, vd.climate_state);
    emit_if(vd.has_drive_state, drive_state_callback_, vd.drive_state);
    emit_if(vd.has_tire_pressure_state, tire_pressure_callback_, vd.tire_pressure_state);
    emit_if(vd.has_closures_state, closures_state_callback_, vd.closures_state);
    if (generation == connection_generation_ && vd.has_media_state && media_state_callback_) {
      media_state_callback_(vd.media_state, now_playing);
    }
    if (generation == connection_generation_ && vd.has_software_update_state && software_update_callback_) {
      software_update_callback_(vd.software_update_state, update_version);
    }
  }
  if (generation != connection_generation_) {
    return;
  }
  auto cmd = peek_command_();
  if (context == &request_ && cmd && cmd->domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT &&
      cmd->awaiting_response()) {
    if (response.has_actionStatus) {
      bool already_set = response.actionStatus.has_result_reason &&
                         response.actionStatus.result_reason.which_reason == CarServer_ResultReason_plain_text_tag &&
                         std::string_view(response.actionStatus.result_reason.reason.plain_text) == "already_set";
      if (response.actionStatus.result == CarServer_OperationStatus_E_OPERATIONSTATUS_OK || already_set) {
        mark_command_completed_(cmd);
      } else {
        LOG_ERROR("CarServer Action Failed");
        mark_command_failed_(cmd, build_carserver_action_error(response.actionStatus));
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
      advance_infotainment_prerequisites_(cmd);
      return;
    }
    if (!set_command_phase_(cmd, OperationPhase::SENDING_REQUEST))
      return;
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
  rx_buffer_.clear();
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

  // Resync only to a complete candidate that also decodes as a UniversalMessage.
  for (size_t i = 1; i + FRAME_HEADER_SIZE <= rx_buffer_.size(); i++) {
    uint16_t potential_len = (rx_buffer_.at(i) << 8) | rx_buffer_.at(i + 1);
    size_t potential_total = static_cast<size_t>(potential_len) + FRAME_HEADER_SIZE;

    if (potential_len == 0 || potential_total > MAX_MESSAGE_SIZE || i + potential_total > rx_buffer_.size()) {
      continue;
    }

    UniversalMessage_RoutableMessage candidate = UniversalMessage_RoutableMessage_init_default;
    if (client_->parse_universal_message(rx_buffer_.data() + i + FRAME_HEADER_SIZE, potential_len, &candidate) != 0) {
      continue;
    }
    bool valid_from_destination =
        candidate.has_from_destination &&
        candidate.from_destination.which_sub_destination == UniversalMessage_Destination_domain_tag &&
        (candidate.from_destination.sub_destination.domain == UniversalMessage_Domain_DOMAIN_BROADCAST ||
         candidate.from_destination.sub_destination.domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY ||
         candidate.from_destination.sub_destination.domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
    if (!valid_from_destination || (candidate.which_payload == 0 && !candidate.has_signedMessageStatus)) {
      continue;
    }

    LOG_INFO("Found valid message at offset %zu, length %d", i, potential_len);

    // Remove corrupted prefix, keep valid suffix.
    rx_buffer_.erase(rx_buffer_.begin(), rx_buffer_.begin() + i);
    LOG_DEBUG("Buffer recovered to %zu bytes", rx_buffer_.size());

    msg_len = get_expected_message_length();
    LOG_INFO("Successfully recovered valid message, continuing processing");
    return true;
  }

  return false;
}

void TeslaBLE::Vehicle::handle_vehicle_status_command_update_(const std::shared_ptr<Command> &cmd) {
  if (cmd->kind == Command::Kind::PAIRING) {
    return;
  }
  if (cmd->domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY && cmd->awaiting_response()) {
    mark_command_completed_(cmd);
    return;
  }
  switch (cmd->state) {
    case CommandState::AUTH_RESPONSE_WAITING:
      // An infotainment command reacts only while it waits for the wake. A
      // waking car sends a burst of status updates; once the infotainment
      // session request is out, each of them used to restart the auth and send
      // another session request (5 in 0.6 s seen on a car), all queued behind
      // each other.
      if (cmd->current_auth_domain != UniversalMessage_Domain_DOMAIN_BROADCAST) {
        break;
      }
      if (is_vehicle_observed_awake_()) {
        LOG_INFO("Vehicle is awake");
        clear_requests_();
        if (cmd->domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT) {
          LOG_DEBUG("Transitioning infotainment command to auth state after wake");
          // Restart the step timeout budget now that wake succeeded and infotainment auth can begin.
          if (!set_command_phase_(cmd, OperationPhase::ENSURING_INFOTAINMENT_SESSION))
            return;
          cmd->current_auth_domain = UniversalMessage_Domain_DOMAIN_INFOTAINMENT;
          cmd->state = CommandState::AUTHENTICATING;
        } else {
          mark_command_completed_(cmd);
        }
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
    LOG_WARNING("Stored session for %s has invalid status: %d", domain_to_string(domain),
                static_cast<int>(session_info.status));
    return;
  }

  // Validate session age - reject sessions older than 1 hour to prevent INVALID_SIGNATURE errors
  // Stale sessions cause crypto failures when vehicle's internal state changes
  uint32_t current_time = static_cast<uint32_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
  uint32_t session_time = session_info.clock_time;
  int64_t session_age_seconds = static_cast<int64_t>(current_time) - static_cast<int64_t>(session_time);

  // If session has no clock_time, check if it's from a previous run (be very conservative)
  if (session_time == 0) {
    LOG_WARNING("Stored session for %s has no timestamp - rejecting to prevent crypto errors",
                domain_to_string(domain));
    return;
  }

  // The local clock can sit behind the recorded session time after a reboot
  // before the time source resyncs. That says nothing about staleness, so
  // accept instead of letting unsigned subtraction underflow to a huge age.
  if (session_age_seconds < 0) {
    LOG_DEBUG("Session time for %s is ahead of the local clock - accepting", domain_to_string(domain));
  } else if (session_age_seconds > 3600) {
    LOG_WARNING("Stored session for %s is too old (%lld seconds) - rejecting to prevent crypto errors",
                domain_to_string(domain), static_cast<long long>(session_age_seconds));
    return;
  } else {
    LOG_DEBUG("Session age validation passed for %s: %lld seconds old", domain_to_string(domain),
              static_cast<long long>(session_age_seconds));
  }

  // Update the peer with the loaded session
  auto *peer = client_->get_peer(domain);
  if (peer) {
    // Use update_session - it will handle counter correctly (preserve higher value)
    if (peer->update_session(&session_info) == 0) {
      LOG_INFO("Loaded session from storage for %s (counter: %" PRIu32 ")", domain_to_string(domain),
               session_info.counter);
    } else {
      LOG_ERROR("Failed to apply stored session for %s", domain_to_string(domain));
    }
  }
}

void TeslaBLE::Vehicle::send_vcsec_rke_(const std::string &name, VCSEC_RKEAction_E action,
                                        Command::OperationResultCallback on_complete) {
  const bool wake = action == VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE;
  enqueue_command_(std::make_shared<Command>(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, name,
      [action](Client *client, uint8_t *buff, size_t *len) {
        return client->build_vcsec_action_message(action, buff, len);
      },
      std::move(on_complete), WakePolicy::WAKE_IF_NEEDED, nullptr, wake ? Command::Kind::WAKE : Command::Kind::NORMAL,
      wake ? Refresh::COUNT : Refresh::VCSEC));
}

void TeslaBLE::Vehicle::send_vcsec_closure_(const std::string &name, const VCSEC_ClosureMoveRequest &request,
                                            Command::OperationResultCallback on_complete) {
  enqueue_command_(std::make_shared<Command>(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, name,
      [request](Client *client, uint8_t *buff, size_t *len) {
        return client->build_vcsec_closure_message(&request, buff, len);
      },
      std::move(on_complete), WakePolicy::WAKE_IF_NEEDED, nullptr, Command::Kind::NORMAL, Refresh::VCSEC));
}

void TeslaBLE::Vehicle::wake(Command::OperationResultCallback on_complete) {
  if (is_vehicle_observed_awake_()) {
    LOG_DEBUG("Vehicle is already awake, skipping redundant wake action");
    if (on_complete) {
      on_complete(OperationResult::skipped(OperationTerminalReason::NONE));
    }
    return;
  }
  send_vcsec_rke_("Wake", VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE, std::move(on_complete));
}

void TeslaBLE::Vehicle::vcsec_poll(WakePolicy wake_policy, Command::OperationResultCallback on_complete) {
  send_command_result(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "VCSEC Poll",
      [](Client *client, uint8_t *buff, size_t *len) {
        return client->build_vcsec_information_request_message(
            VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS, buff, len);
      },
      std::move(on_complete), wake_policy);
}

void TeslaBLE::Vehicle::infotainment_poll(bool force_wake) { infotainment_poll(wake_policy_from_bool(force_wake)); }

void TeslaBLE::Vehicle::infotainment_poll(WakePolicy wake_policy) {
  charge_state_poll(wake_policy);
  climate_state_poll(wake_policy);
  drive_state_poll(wake_policy);
  closures_state_poll(wake_policy);
  tire_pressure_poll(wake_policy);
  if (is_connected_ && ++infotainment_cycles_ % 5 == 0) {
    software_update_poll(wake_policy);
  }
}

void TeslaBLE::Vehicle::send_infotainment_poll_(const std::string &name, int32_t data_type, WakePolicy wake_policy) {
  send_command_result(
      UniversalMessage_Domain_DOMAIN_INFOTAINMENT, name,
      [data_type](Client *client, uint8_t *buff, size_t *len) {
        return client->build_car_server_get_vehicle_data_message(buff, len, data_type);
      },
      nullptr, wake_policy);
}

void TeslaBLE::Vehicle::charge_state_poll(bool force_wake) { charge_state_poll(wake_policy_from_bool(force_wake)); }

void TeslaBLE::Vehicle::charge_state_poll(WakePolicy wake_policy) {
  send_infotainment_poll_("Charge State Poll", CarServer_GetVehicleData_getChargeState_tag, wake_policy);
}

void TeslaBLE::Vehicle::climate_state_poll(bool force_wake) { climate_state_poll(wake_policy_from_bool(force_wake)); }

void TeslaBLE::Vehicle::climate_state_poll(WakePolicy wake_policy) {
  send_infotainment_poll_("Climate State Poll", CarServer_GetVehicleData_getClimateState_tag, wake_policy);
}

void TeslaBLE::Vehicle::drive_state_poll(bool force_wake) { drive_state_poll(wake_policy_from_bool(force_wake)); }

void TeslaBLE::Vehicle::drive_state_poll(WakePolicy wake_policy) {
  send_infotainment_poll_("Drive State Poll", CarServer_GetVehicleData_getDriveState_tag, wake_policy);
}

void TeslaBLE::Vehicle::closures_state_poll(bool force_wake) { closures_state_poll(wake_policy_from_bool(force_wake)); }

void TeslaBLE::Vehicle::closures_state_poll(WakePolicy wake_policy) {
  send_infotainment_poll_("Closures State Poll", CarServer_GetVehicleData_getClosuresState_tag, wake_policy);
}

void TeslaBLE::Vehicle::tire_pressure_poll(bool force_wake) { tire_pressure_poll(wake_policy_from_bool(force_wake)); }

void TeslaBLE::Vehicle::tire_pressure_poll(WakePolicy wake_policy) {
  send_infotainment_poll_("Tire Pressure Poll", CarServer_GetVehicleData_getTirePressureState_tag, wake_policy);
}

void TeslaBLE::Vehicle::media_state_poll(bool force_wake) { media_state_poll(wake_policy_from_bool(force_wake)); }

void TeslaBLE::Vehicle::media_state_poll(WakePolicy wake_policy) {
  send_infotainment_poll_("Media State Poll", CarServer_GetVehicleData_getMediaState_tag, wake_policy);
}

void TeslaBLE::Vehicle::software_update_poll(bool force_wake) {
  software_update_poll(wake_policy_from_bool(force_wake));
}

void TeslaBLE::Vehicle::software_update_poll(WakePolicy wake_policy) {
  send_infotainment_poll_("Software Update Poll", CarServer_GetVehicleData_getSoftwareUpdateState_tag, wake_policy);
}

void TeslaBLE::Vehicle::schedule_software_update(int offset_sec, Command::OperationResultCallback on_complete) {
  if (offset_sec < 0) {
    LOG_ERROR("Invalid software update offset: %d (must be >= 0 seconds)", offset_sec);
    if (on_complete) {
      on_complete(OperationResult::failure(CommandError::build_failed("Schedule Software Update")));
    }
    return;
  }
  send_infotainment_action_("Schedule Software Update",
                            CarServer_VehicleAction_vehicleControlScheduleSoftwareUpdateAction_tag, offset_sec,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::cancel_software_update(Command::OperationResultCallback on_complete) {
  send_infotainment_action_("Cancel Software Update",
                            CarServer_VehicleAction_vehicleControlCancelSoftwareUpdateAction_tag,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::set_charging_state(bool enable, Command::OperationResultCallback on_complete) {
  send_infotainment_action_(enable ? "Start Charging" : "Stop Charging",
                            CarServer_VehicleAction_chargingStartStopAction_tag, enable, std::move(on_complete));
}

void TeslaBLE::Vehicle::set_charging_amps(int amps, Command::OperationResultCallback on_complete) {
  if (!ParameterValidator::is_valid_charging_amps(amps)) {
    LOG_ERROR("Invalid charging amps value: %d (must be 0-80)", amps);
    if (on_complete) {
      on_complete(OperationResult::failure(CommandError::build_failed("Set Charging Amps")));
    }
    return;
  }
  LOG_DEBUG("set_charging_amps called with: %d", amps);
  send_infotainment_action_("Set Charging Amps", CarServer_VehicleAction_setChargingAmpsAction_tag, amps,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::set_charging_limit(int limit, Command::OperationResultCallback on_complete) {
  send_infotainment_action_("Set Charging Limit", CarServer_VehicleAction_chargingSetLimitAction_tag, limit,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::unlock_charge_port(Command::OperationResultCallback on_complete) {
  send_infotainment_action_("Unlock Charge Port", CarServer_VehicleAction_chargePortDoorOpen_tag,
                            std::move(on_complete));
}

// =============================================================================
// VCSEC Closure Controls
// =============================================================================

void TeslaBLE::Vehicle::lock(Command::OperationResultCallback on_complete) {
  send_vcsec_rke_("Lock", VCSEC_RKEAction_E_RKE_ACTION_LOCK, std::move(on_complete));
}

void TeslaBLE::Vehicle::unlock(Command::OperationResultCallback on_complete) {
  send_vcsec_rke_("Unlock", VCSEC_RKEAction_E_RKE_ACTION_UNLOCK, std::move(on_complete));
}

void TeslaBLE::Vehicle::open_trunk(Command::OperationResultCallback on_complete) {
  VCSEC_ClosureMoveRequest request = VCSEC_ClosureMoveRequest_init_zero;
  request.rearTrunk = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_OPEN;
  send_vcsec_closure_("Open Trunk", request, std::move(on_complete));
}

void TeslaBLE::Vehicle::close_trunk(Command::OperationResultCallback on_complete) {
  VCSEC_ClosureMoveRequest request = VCSEC_ClosureMoveRequest_init_zero;
  request.rearTrunk = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_CLOSE;
  send_vcsec_closure_("Close Trunk", request, std::move(on_complete));
}

void TeslaBLE::Vehicle::open_frunk(Command::OperationResultCallback on_complete) {
  VCSEC_ClosureMoveRequest request = VCSEC_ClosureMoveRequest_init_zero;
  request.frontTrunk = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_OPEN;
  send_vcsec_closure_("Open Frunk", request, std::move(on_complete));
}

void TeslaBLE::Vehicle::open_charge_port(Command::OperationResultCallback on_complete) {
  VCSEC_ClosureMoveRequest request = VCSEC_ClosureMoveRequest_init_zero;
  request.chargePort = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_OPEN;
  send_vcsec_closure_("Open Charge Port", request, std::move(on_complete));
}

void TeslaBLE::Vehicle::close_charge_port(Command::OperationResultCallback on_complete) {
  VCSEC_ClosureMoveRequest request = VCSEC_ClosureMoveRequest_init_zero;
  request.chargePort = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_CLOSE;
  send_vcsec_closure_("Close Charge Port", request, std::move(on_complete));
}

void TeslaBLE::Vehicle::unlatch_driver_door(Command::OperationResultCallback on_complete) {
  VCSEC_ClosureMoveRequest request = VCSEC_ClosureMoveRequest_init_zero;
  request.frontDriverDoor = VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_OPEN;
  send_vcsec_closure_("Unlatch Driver Door", request, std::move(on_complete));
}

// =============================================================================
// HVAC Controls (Infotainment)
// =============================================================================

void TeslaBLE::Vehicle::set_climate(bool enable, Command::OperationResultCallback on_complete) {
  send_infotainment_action_(enable ? "Climate On" : "Climate Off", CarServer_VehicleAction_hvacAutoAction_tag, enable,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::set_climate_temp(float temp_celsius, Command::OperationResultCallback on_complete) {
  send_infotainment_action_("Set Climate Temp", CarServer_VehicleAction_hvacTemperatureAdjustmentAction_tag,
                            temp_celsius, std::move(on_complete));
}

void TeslaBLE::Vehicle::set_climate_keeper(int mode, Command::OperationResultCallback on_complete) {
  const char *modes[] = {"Off", "On", "Dog", "Camp"};
  std::string name = std::string("Climate Keeper ") + (mode >= 0 && mode <= 3 ? modes[mode] : "Unknown");
  send_infotainment_action_(name, CarServer_VehicleAction_hvacClimateKeeperAction_tag, mode, std::move(on_complete));
}

void TeslaBLE::Vehicle::set_bioweapon_mode(bool enable, Command::OperationResultCallback on_complete) {
  send_infotainment_action_(enable ? "Bioweapon On" : "Bioweapon Off",
                            CarServer_VehicleAction_hvacBioweaponModeAction_tag, enable, std::move(on_complete));
}

void TeslaBLE::Vehicle::set_preconditioning_max(bool enable, Command::OperationResultCallback on_complete) {
  send_infotainment_action_(enable ? "Defrost On" : "Defrost Off",
                            CarServer_VehicleAction_hvacSetPreconditioningMaxAction_tag, enable,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::set_steering_wheel_heat(bool enable, Command::OperationResultCallback on_complete) {
  send_infotainment_action_(enable ? "Steering Heat On" : "Steering Heat Off",
                            CarServer_VehicleAction_hvacSteeringWheelHeaterAction_tag, enable, std::move(on_complete));
}

void TeslaBLE::Vehicle::set_seat_heater(SeatPosition seat, int level, Command::OperationResultCallback on_complete) {
  CarServer_HvacSeatHeaterActions action = CarServer_HvacSeatHeaterActions_init_default;
  action.hvacSeatHeaterAction_count = 1;
  action.hvacSeatHeaterAction[0].which_seat_position = static_cast<pb_size_t>(seat);
  action.hvacSeatHeaterAction[0].which_seat_heater_level = level >= 0 && level <= 3 ? level + 2 : 0;
  send_infotainment_action_("Set Seat Heater", CarServer_VehicleAction_hvacSeatHeaterActions_tag, action,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::set_seat_climate(SeatPosition seat, int level, bool cooling, bool cooling_supported,
                                         Command::OperationResultCallback on_complete) {
  const int position = static_cast<int>(seat);
  if (position < 7 || position > 15 || level < 0 || level > 3 || (cooling && !cooling_supported) ||
      (cooling_supported && front_seat_tag(seat) == 0)) {
    if (on_complete) {
      on_complete(OperationResult::failure(CommandError::build_failed("Set Seat Climate")));
    }
    return;
  }
  std::vector<Command::Builder> steps;
  auto append = [&steps](int32_t tag, auto value) {
    steps.emplace_back([tag, value](Client *client, uint8_t *buffer, size_t *length) {
      return client->build_car_server_vehicle_action_message(buffer, length, tag, &value);
    });
  };
  auto heat = [&](int value) {
    CarServer_HvacSeatHeaterActions action = CarServer_HvacSeatHeaterActions_init_default;
    action.hvacSeatHeaterAction_count = 1;
    action.hvacSeatHeaterAction[0].which_seat_position = static_cast<pb_size_t>(seat);
    action.hvacSeatHeaterAction[0].which_seat_heater_level = value + 2;
    append(CarServer_VehicleAction_hvacSeatHeaterActions_tag, action);
  };
  auto cool = [&](int value) {
    CarServer_HvacSeatCoolerActions action = CarServer_HvacSeatCoolerActions_init_default;
    action.hvacSeatCoolerAction_count = 1;
    action.hvacSeatCoolerAction[0].seat_position =
        static_cast<CarServer_HvacSeatCoolerActions_HvacSeatCoolerPosition_E>(front_seat_tag(seat));
    action.hvacSeatCoolerAction[0].seat_cooler_level =
        static_cast<CarServer_HvacSeatCoolerActions_HvacSeatCoolerLevel_E>(value + 1);
    append(CarServer_VehicleAction_hvacSeatCoolerActions_tag, action);
  };
  if (cooling && level > 0) {
    cool(level);
  } else {
    if (level == 0 && cooling_supported) {
      cool(0);
    }
    heat(level);
  }
  auto command = std::make_shared<Command>(UniversalMessage_Domain_DOMAIN_INFOTAINMENT, "Set Seat Climate",
                                           std::move(steps.front()), std::move(on_complete), WakePolicy::WAKE_IF_NEEDED,
                                           nullptr, Command::Kind::NORMAL, Refresh::CLIMATE);
  steps.erase(steps.begin());
  command->remaining_steps = std::move(steps);
  enqueue_command_(command);
}

void TeslaBLE::Vehicle::set_seat_cooler(SeatPosition seat, int level, Command::OperationResultCallback on_complete) {
  CarServer_HvacSeatCoolerActions action = CarServer_HvacSeatCoolerActions_init_default;
  action.hvacSeatCoolerAction_count = 1;
  auto &value = action.hvacSeatCoolerAction[0];
  value.seat_position = static_cast<CarServer_HvacSeatCoolerActions_HvacSeatCoolerPosition_E>(front_seat_tag(seat));
  value.seat_cooler_level =
      static_cast<CarServer_HvacSeatCoolerActions_HvacSeatCoolerLevel_E>(level >= 0 && level <= 3 ? level + 1 : 0);
  send_infotainment_action_("Set Seat Cooler", CarServer_VehicleAction_hvacSeatCoolerActions_tag, action,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::set_auto_seat_climate(SeatPosition seat, bool enable,
                                              Command::OperationResultCallback on_complete) {
  CarServer_AutoSeatClimateAction action = CarServer_AutoSeatClimateAction_init_default;
  action.carseat_count = 1;
  action.carseat[0].on = enable;
  action.carseat[0].seat_position =
      static_cast<CarServer_AutoSeatClimateAction_AutoSeatPosition_E>(front_seat_tag(seat));
  send_infotainment_action_("Set Auto Seat Climate", CarServer_VehicleAction_autoSeatClimateAction_tag, action,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::set_cabin_overheat_protection(int mode, Command::OperationResultCallback on_complete) {
  if (mode < 0 || mode > 2) {
    if (on_complete) {
      on_complete(OperationResult::failure(CommandError::build_failed("Cabin Overheat Protection")));
    }
    return;
  }
  CarServer_SetCabinOverheatProtectionAction action = CarServer_SetCabinOverheatProtectionAction_init_default;
  action.on = mode != 0;
  action.fan_only = mode == 2;
  send_infotainment_action_("Cabin Overheat Protection", CarServer_VehicleAction_setCabinOverheatProtectionAction_tag,
                            action, std::move(on_complete));
}

void TeslaBLE::Vehicle::set_sunroof_position(int percent, Command::OperationResultCallback on_complete) {
  CarServer_VehicleControlSunroofOpenCloseAction action = CarServer_VehicleControlSunroofOpenCloseAction_init_default;
  action.which_sunroof_level = CarServer_VehicleControlSunroofOpenCloseAction_absolute_level_tag;
  action.sunroof_level.absolute_level = percent;
  send_infotainment_action_("Set Sunroof Position", CarServer_VehicleAction_vehicleControlSunroofOpenCloseAction_tag,
                            action, std::move(on_complete));
}

// =============================================================================
// Vehicle Controls (Infotainment)
// =============================================================================

void TeslaBLE::Vehicle::flash_lights(Command::OperationResultCallback on_complete) {
  send_infotainment_action_("Flash Lights", CarServer_VehicleAction_vehicleControlFlashLightsAction_tag,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::honk_horn(Command::OperationResultCallback on_complete) {
  send_infotainment_action_("Honk Horn", CarServer_VehicleAction_vehicleControlHonkHornAction_tag,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::set_sentry_mode(bool enable, Command::OperationResultCallback on_complete) {
  send_infotainment_action_(enable ? "Sentry On" : "Sentry Off",
                            CarServer_VehicleAction_vehicleControlSetSentryModeAction_tag, enable,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::set_low_power_mode(bool enable, Command::OperationResultCallback on_complete) {
  send_infotainment_action_(enable ? "Low Power Mode On" : "Low Power Mode Off",
                            CarServer_VehicleAction_setLowPowerModeAction_tag, enable, std::move(on_complete));
}

void TeslaBLE::Vehicle::set_keep_accessory_power_mode(bool enable, Command::OperationResultCallback on_complete) {
  send_infotainment_action_(enable ? "Keep Accessory Power On" : "Keep Accessory Power Off",
                            CarServer_VehicleAction_setKeepAccessoryPowerModeAction_tag, enable,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::set_guest_mode(bool enable, Command::OperationResultCallback on_complete) {
  send_infotainment_action_(enable ? "Guest Mode On" : "Guest Mode Off", CarServer_VehicleAction_guestModeAction_tag,
                            enable, std::move(on_complete));
}

void TeslaBLE::Vehicle::set_cabin_overheat_protection_temp(int level, Command::OperationResultCallback on_complete) {
  static const char *const NAMES[] = {"", "Low", "Medium", "High"};
  if (level < 1 || level > 3) {
    LOG_ERROR("Invalid cabin overheat protection temperature level: %d", level);
    if (on_complete) {
      on_complete(OperationResult::failure(CommandError::build_failed("Cabin Overheat Temp")));
    }
    return;
  }
  send_infotainment_action_(std::string("Cabin Overheat Temp ") + NAMES[level],
                            CarServer_VehicleAction_setCopTempAction_tag, static_cast<int32_t>(level),
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::set_scheduled_departure(bool enabled, int departure_minutes, int preconditioning_policy,
                                                int off_peak_policy, int off_peak_end_minutes,
                                                Command::OperationResultCallback on_complete) {
  CarServer_ScheduledDepartureAction departure = CarServer_ScheduledDepartureAction_init_default;
  departure.enabled = enabled;
  if (enabled) {
    departure.departure_time = departure_minutes;
    departure.off_peak_hours_end_time = off_peak_end_minutes;
    if (preconditioning_policy == 1 || preconditioning_policy == 2) {
      departure.has_preconditioning_times = true;
      departure.preconditioning_times.which_times = preconditioning_policy == 1
                                                        ? CarServer_PreconditioningTimes_all_week_tag
                                                        : CarServer_PreconditioningTimes_weekdays_tag;
    }
    if (off_peak_policy == 1 || off_peak_policy == 2) {
      departure.has_off_peak_charging_times = true;
      departure.off_peak_charging_times.which_times = off_peak_policy == 1
                                                          ? CarServer_OffPeakChargingTimes_all_week_tag
                                                          : CarServer_OffPeakChargingTimes_weekdays_tag;
    }
  }
  send_infotainment_action_(enabled ? "Scheduled Departure On" : "Scheduled Departure Off",
                            CarServer_VehicleAction_scheduledDepartureAction_tag, departure, std::move(on_complete));
}

void TeslaBLE::Vehicle::vent_windows(Command::OperationResultCallback on_complete) {
  send_infotainment_action_("Vent Windows", CarServer_VehicleAction_vehicleControlWindowAction_tag, 0,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::close_windows(Command::OperationResultCallback on_complete) {
  send_infotainment_action_("Close Windows", CarServer_VehicleAction_vehicleControlWindowAction_tag, 1,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::media_toggle_playback(Command::OperationResultCallback on_complete) {
  send_infotainment_action_("Media Toggle Playback", CarServer_VehicleAction_mediaPlayAction_tag,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::media_next_track(Command::OperationResultCallback on_complete) {
  send_infotainment_action_("Media Next Track", CarServer_VehicleAction_mediaNextTrack_tag, std::move(on_complete));
}

void TeslaBLE::Vehicle::media_previous_track(Command::OperationResultCallback on_complete) {
  send_infotainment_action_("Media Previous Track", CarServer_VehicleAction_mediaPreviousTrack_tag,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::media_next_favorite(Command::OperationResultCallback on_complete) {
  send_infotainment_action_("Media Next Favorite", CarServer_VehicleAction_mediaNextFavorite_tag,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::media_previous_favorite(Command::OperationResultCallback on_complete) {
  send_infotainment_action_("Media Previous Favorite", CarServer_VehicleAction_mediaPreviousFavorite_tag,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::media_volume_up(Command::OperationResultCallback on_complete) {
  CarServer_MediaUpdateVolume volume = CarServer_MediaUpdateVolume_init_default;
  volume.which_media_volume = CarServer_MediaUpdateVolume_volume_delta_tag;
  volume.media_volume.volume_delta = 1;
  send_infotainment_action_("Media Volume Up", CarServer_VehicleAction_mediaUpdateVolume_tag, volume,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::media_volume_down(Command::OperationResultCallback on_complete) {
  CarServer_MediaUpdateVolume volume = CarServer_MediaUpdateVolume_init_default;
  volume.which_media_volume = CarServer_MediaUpdateVolume_volume_delta_tag;
  volume.media_volume.volume_delta = -1;
  send_infotainment_action_("Media Volume Down", CarServer_VehicleAction_mediaUpdateVolume_tag, volume,
                            std::move(on_complete));
}

void TeslaBLE::Vehicle::set_media_volume(float level, Command::OperationResultCallback on_complete) {
  if (!std::isfinite(level) || level < 0.0f || level > 10.0f) {
    LOG_ERROR("Invalid media volume: %.2f (must be 0-10)", static_cast<double>(level));
    if (on_complete) {
      on_complete(OperationResult::failure(CommandError::build_failed("Set Media Volume")));
    }
    return;
  }
  CarServer_MediaUpdateVolume volume = CarServer_MediaUpdateVolume_init_default;
  volume.which_media_volume = CarServer_MediaUpdateVolume_volume_absolute_float_tag;
  volume.media_volume.volume_absolute_float = level;
  send_infotainment_action_("Set Media Volume", CarServer_VehicleAction_mediaUpdateVolume_tag, volume,
                            std::move(on_complete));
}

// =============================================================================
// Pairing and Key Management
// =============================================================================

bool TeslaBLE::Vehicle::persist_private_key_() {
  if (!client_ || !storage_adapter_) {
    LOG_ERROR("Client or storage adapter unavailable");
    return false;
  }

  std::array<uint8_t, 2048> key_buf{};
  size_t key_len = 0;
  if (client_->get_private_key(key_buf.data(), key_buf.size(), &key_len) != 0) {
    LOG_ERROR("Failed to export private key");
    return false;
  }

  if (key_len == 0 || key_len > key_buf.size()) {
    LOG_ERROR("Invalid private key length: %zu", key_len);
    return false;
  }

  std::vector<uint8_t> key_vec(key_buf.begin(), key_buf.begin() + key_len);
  if (!storage_adapter_->save("private_key", key_vec)) {
    LOG_ERROR("Failed to save private key to storage");
    return false;
  }

  return true;
}

void TeslaBLE::Vehicle::pair(Keys_Role role, Command::OperationResultCallback on_complete) {
  LOG_INFO("Initiating pairing sequence...");
  if (!client_->has_private_key()) {
    LOG_INFO("No private key loaded, creating a new one");
    if (client_->create_private_key() != 0) {
      LOG_ERROR("Failed to create private key for pairing");
      if (on_complete) {
        on_complete(OperationResult::failure(CommandError::build_failed("Pairing")));
      }
      return;
    }
  }

  if (!persist_private_key_()) {
    LOG_ERROR("Cannot start pairing without persisted private key");
    if (on_complete) {
      on_complete(OperationResult::failure(CommandError::build_failed("Pairing")));
    }
    return;
  }

  enqueue_command_(std::make_shared<Command>(
      UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY, "Whitelist Add Key",
      [role_copy = role](Client *client, uint8_t *buf, size_t *len) {
        return client->build_white_list_message(role_copy, VCSEC_KeyFormFactor_KEY_FORM_FACTOR_NFC_CARD, buf, len);
      },
      std::move(on_complete), WakePolicy::WAKE_IF_NEEDED, nullptr, Command::Kind::PAIRING, Refresh::VCSEC));
}

void TeslaBLE::Vehicle::regenerate_key(const Command::OperationResultCallback &on_complete) {
  LOG_INFO("Regenerating private key...");
  if (client_->create_private_key() != 0) {
    LOG_ERROR("Failed to create private key");
    if (on_complete) {
      on_complete(OperationResult::failure(CommandError::build_failed("Regenerate Key")));
    }
    return;
  }
  clear_requests_();

  // Existing sessions were derived from the old key and the vehicle only
  // knows the new key's public part, so drop both sessions and stored
  // credentials to force a clean re-authentication.
  if (auto *vcsec_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY)) {
    vcsec_peer->reset();
  }
  if (auto *info_peer = client_->get_peer(UniversalMessage_Domain_DOMAIN_INFOTAINMENT)) {
    info_peer->reset();
  }
  clear_stored_session_(UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  clear_stored_session_(UniversalMessage_Domain_DOMAIN_INFOTAINMENT);

  bool saved = persist_private_key_();
  if (saved) {
    LOG_INFO("New private key saved to storage");
  } else {
    LOG_ERROR("Failed to save new private key");
  }
  if (on_complete) {
    if (saved) {
      on_complete(OperationResult::success());
    } else {
      on_complete(OperationResult::failure(CommandError::build_failed("Regenerate Key")));
    }
  }
}

void TeslaBLE::Vehicle::handle_signed_message_error_(const UniversalMessage_RoutableMessage &msg,
                                                     UniversalMessage_Domain domain, bool &has_session_error,
                                                     bool session_updated) {
  if (msg.signedMessageStatus.operation_status != UniversalMessage_OperationStatus_E_OPERATIONSTATUS_ERROR) {
    return;
  }

  auto fault = msg.signedMessageStatus.signed_message_fault;
  LOG_ERROR("Signed message error from %s: %s", domain_to_string(domain), message_fault_to_string(fault));

  auto *peer = client_->get_peer(domain);
  if (peer) {
    switch (fault) {
      case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_TIME_EXPIRED:
      case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INCORRECT_EPOCH:
      case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER:
        LOG_INFO("Session sync required for %s (%s) - resetting session", domain_to_string(domain),
                 message_fault_to_string(fault));
        if (!session_updated) {
          peer->reset();
        }
        has_session_error = true;
        break;
      case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INVALID_SIGNATURE:
        LOG_INFO("INVALID_SIGNATURE for %s: resetting session and clearing stored data", domain_to_string(domain));
        if (!session_updated) {
          peer->reset();
        }
        // Clear stored session to prevent repeated INVALID_SIGNATURE errors
        if (!session_updated) {
          clear_stored_session_(domain);
        }
        has_session_error = true;
        break;
      default:
        break;
    }
  }

  auto cmd = peek_command_();
  if (!has_session_error && cmd && (cmd->awaiting_response() || cmd->state == CommandState::AUTH_RESPONSE_WAITING)) {
    mark_command_failed_(cmd, fault == UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_UNKNOWN_KEY_ID
                                  ? CommandError::key_not_paired(domain_to_string(domain))
                                  : CommandError::authentication_failed("signed message"));
  }
}

}  // namespace TeslaBLE
