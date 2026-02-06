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

  // Accessors
  const std::string &message() const { return message_; }
  Severity severity() const { return severity_; }
  Outcome outcome() const { return outcome_; }

  // Factory methods for common Tesla BLE errors
  static std::unique_ptr<CommandError> timeout(const std::string &context, bool may_succeed = false) {
    return std::make_unique<CommandError>(context + " timeout", Severity::TEMPORARY,
                                          may_succeed ? Outcome::MAY_HAVE_SUCCEEDED : Outcome::DEFINITELY_FAILED);
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

  static std::unique_ptr<CommandError> max_retries_exceeded(const std::string &command) {
    return std::make_unique<CommandError>("Max retries exceeded for " + command, Severity::PERMANENT,
                                          Outcome::DEFINITELY_FAILED);
  }

  static std::unique_ptr<CommandError> session_expired(const std::string &domain) {
    return std::make_unique<CommandError>(domain + " session expired", Severity::TEMPORARY, Outcome::DEFINITELY_FAILED);
  }

  static std::unique_ptr<CommandError> session_stale(const std::string &domain) {
    return std::make_unique<CommandError>(domain + " session stale - connection reset", Severity::TEMPORARY,
                                          Outcome::MAY_HAVE_SUCCEEDED);
  }

  static std::unique_ptr<CommandError> buffer_corruption() {
    return std::make_unique<CommandError>("Buffer corruption detected", Severity::TEMPORARY,
                                          Outcome::DEFINITELY_FAILED);
  }

  static std::unique_ptr<CommandError> circuit_breaker_tripped(const std::string &reason) {
    return std::make_unique<CommandError>("Circuit breaker: " + reason, Severity::TEMPORARY,
                                          Outcome::MAY_HAVE_SUCCEEDED);
  }

  static std::unique_ptr<CommandError> invalid_signature(const std::string &domain) {
    return std::make_unique<CommandError>(domain + " invalid signature", Severity::TEMPORARY,
                                          Outcome::DEFINITELY_FAILED);
  }

  // Builder pattern for more flexible error creation
  class Builder {
   public:
    Builder() = default;

    Builder &with_message(const std::string &message) {
      message_ = message;
      return *this;
    }

    Builder &with_severity(Severity severity) {
      severity_ = severity;
      return *this;
    }

    Builder &with_outcome(Outcome outcome) {
      outcome_ = outcome;
      return *this;
    }

    Builder &may_have_succeeded(bool may_succeed = true) {
      outcome_ = may_succeed ? Outcome::MAY_HAVE_SUCCEEDED : Outcome::DEFINITELY_FAILED;
      return *this;
    }

    Builder &is_temporary(bool temporary = true) {
      severity_ = temporary ? Severity::TEMPORARY : Severity::PERMANENT;
      return *this;
    }

    std::unique_ptr<CommandError> build() { return std::make_unique<CommandError>(message_, severity_, outcome_); }

   private:
    std::string message_;
    Severity severity_ = Severity::TEMPORARY;
    Outcome outcome_ = Outcome::DEFINITELY_FAILED;
  };

  static Builder create() { return Builder(); }

 private:
  std::string message_;
  Severity severity_;
  Outcome outcome_;
};

// Result type for commands that can return success or rich error
template<typename T = void> class CommandResult {
 public:
  static CommandResult success(T value = T{}) { return CommandResult(std::move(value)); }

  static CommandResult error(std::unique_ptr<CommandError> error) { return CommandResult(std::move(error)); }

  bool is_success() const { return error_ == nullptr; }
  bool is_error() const { return error_ != nullptr; }

  const T &value() const {
    assert(is_success() && "Cannot get value from error result");
    return value_;
  }

  T &value() {
    assert(is_success() && "Cannot get value from error result");
    return value_;
  }

  const CommandError &error() const {
    assert(is_error() && "Cannot get error from success result");
    return *error_;
  }

  std::unique_ptr<CommandError> release_error() { return std::move(error_); }

 private:
  CommandResult(T value) : value_(std::move(value)), error_(nullptr) {}
  CommandResult(std::unique_ptr<CommandError> error) : error_(std::move(error)) {}

  T value_;
  std::unique_ptr<CommandError> error_;
};

// Specialization for void results
template<> class CommandResult<void> {
 public:
  static CommandResult success() { return CommandResult(); }

  static CommandResult error(std::unique_ptr<CommandError> error) { return CommandResult(std::move(error)); }

  bool is_success() const { return error_ == nullptr; }
  bool is_error() const { return error_ != nullptr; }

  const CommandError &error() const {
    assert(is_error() && "Cannot get error from success result");
    return *error_;
  }

  std::unique_ptr<CommandError> release_error() { return std::move(error_); }

 private:
  CommandResult() : error_(nullptr) {}
  CommandResult(std::unique_ptr<CommandError> error) : error_(std::move(error)) {}

  std::unique_ptr<CommandError> error_;
};

}  // namespace TeslaBLE