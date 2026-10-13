#pragma once

#include <cassert>
#include <string>
#include <memory>

namespace TeslaBLE {

/**
 * Rich error interface inspired by Go, but using C++ idioms.
 * Provides semantic information about errors for intelligent retry and handling decisions.
 */
class CommandError {
 public:
  enum class Severity {
    TEMPORARY,  // Error might be transient - safe to retry
    PERMANENT,  // Error is permanent - should not retry
    UNKNOWN     // Cannot determine severity
  };

  enum class Outcome {
    MAY_HAVE_SUCCEEDED,  // Command might have executed despite error
    DEFINITELY_FAILED,   // Command definitely failed
    UNKNOWN              // Cannot determine outcome
  };

  CommandError(std::string message, Severity severity, Outcome outcome)
      : message_(std::move(message)), severity_(severity), outcome_(outcome) {}

  // Go-inspired semantic methods
  bool is_temporary() const { return severity_ == Severity::TEMPORARY; }
  bool may_have_succeeded() const { return outcome_ == Outcome::MAY_HAVE_SUCCEEDED; }
  bool is_key_not_paired() const { return key_not_paired_; }

  // Accessors
  const std::string &message() const { return message_; }
  Severity severity() const { return severity_; }
  Outcome outcome() const { return outcome_; }

  // Factory methods for common Tesla BLE errors
  static std::unique_ptr<CommandError> timeout(const std::string &context) {
    return std::make_unique<CommandError>(context + " timeout", Severity::TEMPORARY, Outcome::DEFINITELY_FAILED);
  }

  static std::unique_ptr<CommandError> authentication_failed(const std::string &domain, bool temporary = true) {
    return std::make_unique<CommandError>(domain + " authentication failed",
                                          temporary ? Severity::TEMPORARY : Severity::PERMANENT,
                                          Outcome::DEFINITELY_FAILED);
  }

  static std::unique_ptr<CommandError> connection_lost() {
    return std::make_unique<CommandError>("Connection lost", Severity::TEMPORARY, Outcome::MAY_HAVE_SUCCEEDED);
  }

  static std::unique_ptr<CommandError> build_failed(const std::string &command) {
    return std::make_unique<CommandError>("Failed to build " + command + " command", Severity::PERMANENT,
                                          Outcome::DEFINITELY_FAILED);
  }

  static std::unique_ptr<CommandError> max_retries_exceeded(const std::string &command, bool request_accepted = false) {
    return std::make_unique<CommandError>("Max retries exceeded for " + command, Severity::PERMANENT,
                                          request_accepted ? Outcome::MAY_HAVE_SUCCEEDED : Outcome::DEFINITELY_FAILED);
  }

  static std::unique_ptr<CommandError> write_failed(bool request_accepted) {
    return std::make_unique<CommandError>("BLE write failed", Severity::PERMANENT,
                                          request_accepted ? Outcome::MAY_HAVE_SUCCEEDED : Outcome::DEFINITELY_FAILED);
  }

  static std::unique_ptr<CommandError> session_expired(const std::string &domain) {
    return std::make_unique<CommandError>(domain + " session expired", Severity::TEMPORARY, Outcome::DEFINITELY_FAILED);
  }

  static std::unique_ptr<CommandError> session_stale(const std::string &domain) {
    return std::make_unique<CommandError>(domain + " session stale - connection reset", Severity::TEMPORARY,
                                          Outcome::MAY_HAVE_SUCCEEDED);
  }

  static std::unique_ptr<CommandError> key_not_paired(const std::string &domain) {
    auto error = std::make_unique<CommandError>(domain + " key not on whitelist - pairing required",
                                                Severity::PERMANENT, Outcome::DEFINITELY_FAILED);
    error->key_not_paired_ = true;
    return error;
  }

 private:
  std::string message_;
  Severity severity_;
  Outcome outcome_;
  bool key_not_paired_{false};
};

}  // namespace TeslaBLE
