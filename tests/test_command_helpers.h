#pragma once

// Test helpers mirroring the legacy send_command/send_command_bool overloads
// that 6.0.0 removed in favor of the single send_command_result() API.
// Tests keep their historical call shapes through these wrappers.

#include <functional>
#include <memory>
#include <string>

#include "command_error.h"
#include "vehicle.h"

namespace TeslaBLE {
namespace TestHelpers {

inline void send_command_bool(Vehicle &vehicle, UniversalMessage_Domain domain, const std::string &name,
                              std::function<int(Client *, uint8_t *, size_t *)> builder,
                              const std::function<void(bool)> &callback, WakePolicy wake_policy) {
  vehicle.send_command_result(
      domain, name, std::move(builder),
      [callback](OperationResult result) {
        if (callback) {
          callback(result.compatible_success());
        }
      },
      wake_policy);
}

inline void send_command_bool(Vehicle &vehicle, UniversalMessage_Domain domain, const std::string &name,
                              std::function<int(Client *, uint8_t *, size_t *)> builder,
                              const std::function<void(bool)> &callback, bool requires_wake = true) {
  send_command_bool(vehicle, domain, name, std::move(builder), callback,
                    requires_wake ? WakePolicy::WAKE_IF_NEEDED : WakePolicy::NO_WAKE_SKIP);
}

inline void send_command_error_callback(Vehicle &vehicle, UniversalMessage_Domain domain, const std::string &name,
                                        std::function<int(Client *, uint8_t *, size_t *)> builder,
                                        std::function<void(std::unique_ptr<CommandError>)> callback,
                                        bool requires_wake = true) {
  vehicle.send_command_result(
      domain, name, std::move(builder),
      [callback = std::move(callback)](OperationResult result) {
        if (callback) {
          callback(result.release_error());
        }
      },
      requires_wake ? WakePolicy::WAKE_IF_NEEDED : WakePolicy::NO_WAKE_SKIP);
}

}  // namespace TestHelpers
}  // namespace TeslaBLE
