// Python bindings for TeslaBLE.
//
// Exposes the Vehicle state machine (with Python-implemented BleAdapter and
// StorageAdapter), state callbacks delivered as plain dicts, the log bridge,
// VIN helpers and a SimulatedVehicle test double.

#include <pybind11/functional.h>
#include <pybind11/native_enum.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <cstdarg>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "adapters.h"
#include "client.h"
#include "command_error.h"
#include "defs.h"
#include "polling_policy.h"
#include "simulated_vehicle.h"
#include "state_dicts.h"
#include "state_text.h"
#include "tb_utils.h"
#include "vehicle.h"
#include "vin_utils.h"

using TeslaBLE::TeslaBLE_Status_E_OK;

namespace py = pybind11;

namespace tesla_ble_python {

namespace {

constexpr const char *CALLBACK_ERROR_CONTEXT = "tesla_ble callback";

// ---------------------------------------------------------------------------
// Trampolines
// ---------------------------------------------------------------------------

class PyBleAdapter : public TeslaBLE::BleAdapter {
 public:
  using TeslaBLE::BleAdapter::BleAdapter;

  void connect(const std::string &address) override { PYBIND11_OVERRIDE(void, TeslaBLE::BleAdapter, connect, address); }

  void disconnect() override { PYBIND11_OVERRIDE(void, TeslaBLE::BleAdapter, disconnect); }

  bool write(const std::vector<uint8_t> &data) override {
    py::gil_scoped_acquire gil;
    py::function override = py::get_override(static_cast<const TeslaBLE::BleAdapter *>(this), "write");
    if (!override) {
      throw std::runtime_error("BleAdapter.write is not implemented");
    }
    return override(py::bytes(reinterpret_cast<const char *>(data.data()), data.size())).cast<bool>();
  }
};

class PyStorageAdapter : public TeslaBLE::StorageAdapter {
 public:
  using TeslaBLE::StorageAdapter::StorageAdapter;

  bool load(const std::string &key, std::vector<uint8_t> &buffer) override {
    py::gil_scoped_acquire gil;
    py::function override = py::get_override(static_cast<const TeslaBLE::StorageAdapter *>(this), "load");
    if (!override) {
      throw std::runtime_error("StorageAdapter.load is not implemented");
    }
    py::object result = override(py::str(key));
    if (result.is_none()) {
      return false;
    }
    py::bytes as_bytes = py::reinterpret_steal<py::bytes>(PyBytes_FromObject(result.ptr()));
    if (!as_bytes) {
      throw py::error_already_set();
    }
    std::string data = as_bytes.cast<std::string>();
    buffer.assign(data.begin(), data.end());
    return true;
  }

  bool save(const std::string &key, const std::vector<uint8_t> &data) override {
    py::gil_scoped_acquire gil;
    py::function override = py::get_override(static_cast<const TeslaBLE::StorageAdapter *>(this), "save");
    if (!override) {
      throw std::runtime_error("StorageAdapter.save is not implemented");
    }
    try {
      return override(py::str(key), py::bytes(reinterpret_cast<const char *>(data.data()), data.size())).cast<bool>();
    } catch (py::error_already_set &e) {
      e.discard_as_unraisable("tesla_ble StorageAdapter.save");
      return false;
    }
  }

  bool remove(const std::string &key) override {
    py::gil_scoped_acquire gil;
    py::function override = py::get_override(static_cast<const TeslaBLE::StorageAdapter *>(this), "remove");
    if (!override) {
      throw std::runtime_error("StorageAdapter.remove is not implemented");
    }
    try {
      return override(py::str(key)).cast<bool>();
    } catch (py::error_already_set &e) {
      e.discard_as_unraisable("tesla_ble StorageAdapter.remove");
      return false;
    }
  }
};

// ---------------------------------------------------------------------------
// Callback helpers
// ---------------------------------------------------------------------------

std::shared_ptr<py::function> to_python_function(const py::object &callback) {
  if (callback.is_none()) {
    return nullptr;
  }
  return std::make_shared<py::function>(callback.cast<py::function>());
}

// NOLINTNEXTLINE(performance-unnecessary-value-param) - retain callbacks that unregister themselves
void invoke_guarded(std::shared_ptr<py::function> fn, const py::object &arg) {
  py::gil_scoped_acquire gil;
  try {
    (*fn)(arg);
  } catch (py::error_already_set &e) {
    e.discard_as_unraisable(CALLBACK_ERROR_CONTEXT);
  }
}

std::string outcome_text(TeslaBLE::OperationOutcome outcome) {
  switch (outcome) {
    case TeslaBLE::OperationOutcome::SUCCESS:
      return "success";
    case TeslaBLE::OperationOutcome::SKIPPED:
      return "skipped";
    case TeslaBLE::OperationOutcome::FAILED:
      return "failed";
  }
  return "unknown";
}

std::string terminal_reason_text(TeslaBLE::OperationTerminalReason reason) {
  switch (reason) {
    case TeslaBLE::OperationTerminalReason::VEHICLE_ASLEEP:
      return "vehicle_asleep";
    default:
      return "none";
  }
}

std::string severity_text(TeslaBLE::CommandError::Severity severity) {
  switch (severity) {
    case TeslaBLE::CommandError::Severity::TEMPORARY:
      return "temporary";
    case TeslaBLE::CommandError::Severity::PERMANENT:
      return "permanent";
    default:
      return "unknown";
  }
}

std::string error_outcome_text(TeslaBLE::CommandError::Outcome outcome) {
  switch (outcome) {
    case TeslaBLE::CommandError::Outcome::MAY_HAVE_SUCCEEDED:
      return "may_have_succeeded";
    case TeslaBLE::CommandError::Outcome::DEFINITELY_FAILED:
      return "definitely_failed";
    default:
      return "unknown";
  }
}

// Copyable, Python-friendly view of OperationResult (which is move-only).
struct PyCommandResult {
  bool success = false;
  bool skipped = false;
  bool failure = false;
  bool compatible_success = false;
  bool may_have_succeeded = false;
  std::string outcome;
  std::string terminal_reason;
  py::object error_message = py::none();
  py::object error_severity = py::none();
  py::object error_outcome = py::none();
};

PyCommandResult make_py_result(const TeslaBLE::OperationResult &result) {
  PyCommandResult out;
  out.success = result.is_success();
  out.skipped = result.is_skipped();
  out.failure = result.is_failure();
  out.compatible_success = result.compatible_success();
  out.outcome = outcome_text(result.outcome());
  out.terminal_reason = terminal_reason_text(result.reason());
  if (const TeslaBLE::CommandError *error = result.error()) {
    out.error_message = py::str(error->message());
    out.error_severity = py::str(severity_text(error->severity()));
    out.error_outcome = py::str(error_outcome_text(error->outcome()));
    out.may_have_succeeded = error->may_have_succeeded();
  }
  return out;
}

TeslaBLE::Command::OperationResultCallback wrap_result_callback(const py::object &callback) {
  auto fn = to_python_function(callback);
  if (!fn) {
    return nullptr;
  }
  return [fn](TeslaBLE::OperationResult result) {
    py::gil_scoped_acquire gil;
    try {
      (*fn)(make_py_result(result));
    } catch (py::error_already_set &e) {
      e.discard_as_unraisable(CALLBACK_ERROR_CONTEXT);
    }
  };
}

template<typename PbType> using StateConverter = py::dict (*)(const PbType &);

template<typename PbType, StateConverter<PbType> Converter>
std::function<void(const PbType &)> wrap_state_callback(const py::object &callback) {
  auto fn = to_python_function(callback);
  if (!fn) {
    return nullptr;
  }
  return [fn](const PbType &state) {
    py::gil_scoped_acquire gil;
    invoke_guarded(fn, Converter(state));
  };
}

// ---------------------------------------------------------------------------
// Log bridge: C function pointer -> Python callable
// ---------------------------------------------------------------------------

void log_bridge(TeslaBLE::LogLevel level, const char *tag, int line, const char *format, va_list args) {
  if (!Py_IsInitialized() || Py_IsFinalizing()) {
    return;
  }
  char buffer[1024];
  std::vsnprintf(buffer, sizeof(buffer), format, args);
  py::gil_scoped_acquire gil;
  try {
    py::object callback = py::module_::import("tesla_ble._tesla_ble").attr("_log_callback");
    if (!callback.is_none()) {
      callback(static_cast<int>(level), std::string(buffer), std::string(tag), line);
    }
  } catch (py::error_already_set &e) {
    e.discard_as_unraisable("tesla_ble log callback");
  }
}

void set_log_callback_binding(const py::object &callback) {
  py::object fn = callback;
  if (!callback.is_none()) {
    fn = callback.cast<py::function>();
  }
  py::module_::import("tesla_ble._tesla_ble").attr("_log_callback") = fn;
  if (callback.is_none()) {
    TeslaBLE::set_log_callback(nullptr);
    return;
  }
  TeslaBLE::set_log_callback(log_bridge);
}

// ---------------------------------------------------------------------------
// Frame inspection helper
// ---------------------------------------------------------------------------

py::dict parse_frame_info(const std::vector<uint8_t> &data) {
  py::dict info;
  if (data.size() <= 2) {
    info["valid"] = false;
    return info;
  }
  TeslaBLE::Client parser;
  UniversalMessage_RoutableMessage message = UniversalMessage_RoutableMessage_init_default;
  auto status = parser.parse_universal_message_ble(const_cast<pb_byte_t *>(data.data()), data.size(), &message);
  if (status != TeslaBLE_Status_E_OK) {
    info["valid"] = false;
    return info;
  }
  info["valid"] = true;
  info["flags"] = message.flags;
  if (message.uuid.size > 0) {
    info["uuid"] = py::bytes(reinterpret_cast<const char *>(message.uuid.bytes), message.uuid.size);
  }
  if (message.has_from_destination &&
      message.from_destination.which_sub_destination == UniversalMessage_Destination_domain_tag) {
    info["from_domain"] = static_cast<int>(message.from_destination.sub_destination.domain);
  }
  if (message.has_to_destination &&
      message.to_destination.which_sub_destination == UniversalMessage_Destination_domain_tag) {
    info["to_domain"] = static_cast<int>(message.to_destination.sub_destination.domain);
  }
  switch (message.which_payload) {
    case UniversalMessage_RoutableMessage_session_info_request_tag:
      info["payload"] = "session_info_request";
      break;
    case UniversalMessage_RoutableMessage_session_info_tag:
      info["payload"] = "session_info";
      break;
    case UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag:
      info["payload"] = "message";
      info["payload_size"] = message.payload.protobuf_message_as_bytes.size;
      break;
    default:
      info["payload"] = "other";
      break;
  }
  return info;
}

}  // namespace

}  // namespace tesla_ble_python

using namespace tesla_ble_python;  // NOLINT(google-build-using-namespace) - local module file

PYBIND11_MODULE(_tesla_ble, m) {
  m.doc() = "Python bindings for the TeslaBLE C++ library";
  m.attr("_log_callback") = py::none();
  m.attr("__version__") = TESLA_BLE_VERSION;

  // -------------------------------------------------------------------------
  // Enums (native Python enums, pybind11 3.x)
  // -------------------------------------------------------------------------
  py::native_enum<TeslaBLE::LogLevel>(m, "LogLevel", "enum.Enum")
      .value("ERROR", TeslaBLE::LogLevel::ERROR)
      .value("WARN", TeslaBLE::LogLevel::WARN)
      .value("INFO", TeslaBLE::LogLevel::INFO)
      .value("DEBUG", TeslaBLE::LogLevel::DEBUG)
      .value("VERBOSE", TeslaBLE::LogLevel::VERBOSE)
      .finalize();

  py::native_enum<TeslaBLE::SleepState>(m, "SleepState", "enum.Enum")
      .value("UNKNOWN", TeslaBLE::SleepState::UNKNOWN)
      .value("ASLEEP", TeslaBLE::SleepState::ASLEEP)
      .value("AWAKE", TeslaBLE::SleepState::AWAKE)
      .finalize();

  py::native_enum<TeslaBLE::SeatPosition>(m, "SeatPosition", "enum.Enum")
      .value("FRONT_LEFT", TeslaBLE::SeatPosition::FRONT_LEFT)
      .value("FRONT_RIGHT", TeslaBLE::SeatPosition::FRONT_RIGHT)
      .value("REAR_LEFT", TeslaBLE::SeatPosition::REAR_LEFT)
      .value("REAR_LEFT_BACK", TeslaBLE::SeatPosition::REAR_LEFT_BACK)
      .value("REAR_CENTER", TeslaBLE::SeatPosition::REAR_CENTER)
      .value("REAR_RIGHT", TeslaBLE::SeatPosition::REAR_RIGHT)
      .value("REAR_RIGHT_BACK", TeslaBLE::SeatPosition::REAR_RIGHT_BACK)
      .value("THIRD_ROW_LEFT", TeslaBLE::SeatPosition::THIRD_ROW_LEFT)
      .value("THIRD_ROW_RIGHT", TeslaBLE::SeatPosition::THIRD_ROW_RIGHT)
      .finalize();

  py::native_enum<TeslaBLE::WakePolicy>(m, "WakePolicy", "enum.Enum")
      .value("NO_WAKE_SKIP", TeslaBLE::WakePolicy::NO_WAKE_SKIP)
      .value("NO_WAKE_FAIL", TeslaBLE::WakePolicy::NO_WAKE_FAIL)
      .value("WAKE_IF_NEEDED", TeslaBLE::WakePolicy::WAKE_IF_NEEDED)
      .finalize();

  py::native_enum<TeslaBLE::OperationOutcome>(m, "OperationOutcome", "enum.Enum")
      .value("SUCCESS", TeslaBLE::OperationOutcome::SUCCESS)
      .value("SKIPPED", TeslaBLE::OperationOutcome::SKIPPED)
      .value("FAILED", TeslaBLE::OperationOutcome::FAILED)
      .finalize();

  py::native_enum<Keys_Role>(m, "KeysRole", "enum.Enum")
      .value("NONE", Keys_Role_ROLE_NONE)
      .value("SERVICE", Keys_Role_ROLE_SERVICE)
      .value("OWNER", Keys_Role_ROLE_OWNER)
      .value("DRIVER", Keys_Role_ROLE_DRIVER)
      .value("FM", Keys_Role_ROLE_FM)
      .value("VEHICLE_MONITOR", Keys_Role_ROLE_VEHICLE_MONITOR)
      .value("CHARGING_MANAGER", Keys_Role_ROLE_CHARGING_MANAGER)
      .value("GUEST", Keys_Role_ROLE_GUEST)
      .finalize();

  py::native_enum<UniversalMessage_Domain>(m, "Domain", "enum.Enum")
      .value("BROADCAST", UniversalMessage_Domain_DOMAIN_BROADCAST)
      .value("VEHICLE_SECURITY", UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY)
      .value("INFOTAINMENT", UniversalMessage_Domain_DOMAIN_INFOTAINMENT)
      .finalize();

  // -------------------------------------------------------------------------
  // Adapters
  // -------------------------------------------------------------------------
  py::class_<TeslaBLE::BleAdapter, PyBleAdapter, std::shared_ptr<TeslaBLE::BleAdapter>>(m, "BleAdapter",
                                                                                        R"doc(
Abstract BLE transport. Subclass and implement:

  connect(address: str) -> None
  disconnect() -> None
  write(data: bytes) -> bool   # True when the data was accepted for sending
)doc")
      .def(py::init<>())
      .def("connect", &TeslaBLE::BleAdapter::connect)
      .def("disconnect", &TeslaBLE::BleAdapter::disconnect)
      .def("write", &TeslaBLE::BleAdapter::write);

  py::class_<TeslaBLE::StorageAdapter, PyStorageAdapter, std::shared_ptr<TeslaBLE::StorageAdapter>>(m, "StorageAdapter",
                                                                                                    R"doc(
Persistent storage for keys and sessions. Subclass and implement:

  load(key: str) -> bytes | None
  save(key: str, data: bytes) -> bool
  remove(key: str) -> bool
)doc")
      .def(py::init<>())
      .def("load",
           [](TeslaBLE::StorageAdapter &self, const std::string &key) -> py::object {
             std::vector<uint8_t> buffer;
             if (!self.load(key, buffer)) {
               return py::none();
             }
             return py::bytes(reinterpret_cast<const char *>(buffer.data()), buffer.size());
           })
      .def("save", [](TeslaBLE::StorageAdapter &self, const std::string &key,
                      const std::vector<uint8_t> &data) { return self.save(key, data); })
      .def("remove", &TeslaBLE::StorageAdapter::remove);

  // -------------------------------------------------------------------------
  // Command result
  // -------------------------------------------------------------------------
  py::class_<PyCommandResult>(m, "CommandResult", "Outcome of a Vehicle action")
      .def_readonly("success", &PyCommandResult::success)
      .def_readonly("skipped", &PyCommandResult::skipped)
      .def_readonly("failure", &PyCommandResult::failure)
      .def_readonly("compatible_success", &PyCommandResult::compatible_success)
      .def_readonly("may_have_succeeded", &PyCommandResult::may_have_succeeded)
      .def_readonly("outcome", &PyCommandResult::outcome)
      .def_readonly("terminal_reason", &PyCommandResult::terminal_reason)
      .def_readonly("error_message", &PyCommandResult::error_message)
      .def_readonly("error_severity", &PyCommandResult::error_severity)
      .def_readonly("error_outcome", &PyCommandResult::error_outcome)
      .def("__repr__", [](const PyCommandResult &self) {
        std::string text = "<CommandResult " + self.outcome;
        if (!self.error_message.is_none()) {
          text += " " + self.error_message.cast<std::string>();
        }
        return text + ">";
      });

  // -------------------------------------------------------------------------
  // Vehicle
  // -------------------------------------------------------------------------
  py::class_<TeslaBLE::Vehicle>(m, "Vehicle", "Tesla vehicle session and command state machine")
      .def(py::init([](const std::shared_ptr<TeslaBLE::BleAdapter> &ble,
                       const std::shared_ptr<TeslaBLE::StorageAdapter> &storage) {
             if (!ble || !storage) {
               throw py::value_error("BLE and storage adapters must not be None");
             }
             return std::make_unique<TeslaBLE::Vehicle>(ble, storage);
           }),
           py::arg("ble_adapter"), py::arg("storage_adapter"), py::keep_alive<1, 2>(), py::keep_alive<1, 3>())
      .def("set_vin", &TeslaBLE::Vehicle::set_vin)
      .def("loop", &TeslaBLE::Vehicle::loop, "Process queued messages and drive the command queue")
      .def(
          "on_rx_data",
          [](TeslaBLE::Vehicle &self, const py::bytes &data) {
            std::string raw = data;
            self.on_rx_data(std::vector<uint8_t>(raw.begin(), raw.end()));
          },
          py::arg("data"), "Feed a BLE notification frame")
      .def("set_connected", &TeslaBLE::Vehicle::set_connected)
      .def("set_key_not_paired_callback",
           [](TeslaBLE::Vehicle &self, const py::object &callback) {
             if (callback.is_none()) {
               self.set_key_not_paired_callback(nullptr);
               return;
             }
             auto fn = std::make_shared<py::object>(callback);
             self.set_key_not_paired_callback([fn]() {
               py::gil_scoped_acquire gil;
               (*fn)();
             });
           })
      .def_property_readonly("is_connected", &TeslaBLE::Vehicle::is_connected)
      .def_property_readonly("has_private_key", &TeslaBLE::Vehicle::has_private_key)
      .def_property_readonly("pending_command_count", &TeslaBLE::Vehicle::pending_command_count)
      .def("set_awake", &TeslaBLE::Vehicle::set_awake)
      .def("set_sleep_state", &TeslaBLE::Vehicle::set_sleep_state)
      .def_property_readonly("sleep_state", &TeslaBLE::Vehicle::sleep_state)
      .def(
          "clear_callbacks",
          [](TeslaBLE::Vehicle &self) {
            self.set_vehicle_status_callback(nullptr);
            self.set_charge_state_callback(nullptr);
            self.set_climate_state_callback(nullptr);
            self.set_drive_state_callback(nullptr);
            self.set_tire_pressure_state_callback(nullptr);
            self.set_closures_state_callback(nullptr);
            self.set_media_state_callback(nullptr);
            self.set_software_update_state_callback(nullptr);
            self.set_raw_message_callback(nullptr);
            self.set_key_not_paired_callback(nullptr);
          },
          "Remove all state and raw-message callbacks; disconnect first to finish pending actions")
      // Polls
      .def(
          "wake",
          [](TeslaBLE::Vehicle &self, const py::object &callback) { self.wake(wrap_result_callback(callback)); },
          py::arg("on_complete") = py::none())
      .def(
          "vcsec_poll", [](TeslaBLE::Vehicle &self, TeslaBLE::WakePolicy policy) { self.vcsec_poll(policy); },
          py::arg("wake_policy") = TeslaBLE::WakePolicy::WAKE_IF_NEEDED)
      .def(
          "infotainment_poll",
          [](TeslaBLE::Vehicle &self, TeslaBLE::WakePolicy policy) { self.infotainment_poll(policy); },
          py::arg("wake_policy") = TeslaBLE::WakePolicy::WAKE_IF_NEEDED)
      .def(
          "charge_state_poll",
          [](TeslaBLE::Vehicle &self, TeslaBLE::WakePolicy policy) { self.charge_state_poll(policy); },
          py::arg("wake_policy") = TeslaBLE::WakePolicy::WAKE_IF_NEEDED)
      .def(
          "climate_state_poll",
          [](TeslaBLE::Vehicle &self, TeslaBLE::WakePolicy policy) { self.climate_state_poll(policy); },
          py::arg("wake_policy") = TeslaBLE::WakePolicy::WAKE_IF_NEEDED)
      .def(
          "drive_state_poll",
          [](TeslaBLE::Vehicle &self, TeslaBLE::WakePolicy policy) { self.drive_state_poll(policy); },
          py::arg("wake_policy") = TeslaBLE::WakePolicy::WAKE_IF_NEEDED)
      .def(
          "closures_state_poll",
          [](TeslaBLE::Vehicle &self, TeslaBLE::WakePolicy policy) { self.closures_state_poll(policy); },
          py::arg("wake_policy") = TeslaBLE::WakePolicy::WAKE_IF_NEEDED)
      .def(
          "tire_pressure_poll",
          [](TeslaBLE::Vehicle &self, TeslaBLE::WakePolicy policy) { self.tire_pressure_poll(policy); },
          py::arg("wake_policy") = TeslaBLE::WakePolicy::WAKE_IF_NEEDED)
      .def(
          "media_state_poll",
          [](TeslaBLE::Vehicle &self, TeslaBLE::WakePolicy policy) { self.media_state_poll(policy); },
          py::arg("wake_policy") = TeslaBLE::WakePolicy::WAKE_IF_NEEDED)
      .def(
          "software_update_poll",
          [](TeslaBLE::Vehicle &self, TeslaBLE::WakePolicy policy) { self.software_update_poll(policy); },
          py::arg("wake_policy") = TeslaBLE::WakePolicy::WAKE_IF_NEEDED)
      // Charging
      .def(
          "set_charging_state",
          [](TeslaBLE::Vehicle &self, bool enable, const py::object &callback) {
            self.set_charging_state(enable, wrap_result_callback(callback));
          },
          py::arg("enable"), py::arg("on_complete") = py::none())
      .def(
          "set_charging_amps",
          [](TeslaBLE::Vehicle &self, int amps, const py::object &callback) {
            self.set_charging_amps(amps, wrap_result_callback(callback));
          },
          py::arg("amps"), py::arg("on_complete") = py::none())
      .def(
          "set_charging_limit",
          [](TeslaBLE::Vehicle &self, int limit, const py::object &callback) {
            self.set_charging_limit(limit, wrap_result_callback(callback));
          },
          py::arg("limit"), py::arg("on_complete") = py::none())
      .def(
          "unlock_charge_port",
          [](TeslaBLE::Vehicle &self, const py::object &callback) {
            self.unlock_charge_port(wrap_result_callback(callback));
          },
          py::arg("on_complete") = py::none())
      .def(
          "schedule_software_update",
          [](TeslaBLE::Vehicle &self, int offset_sec, const py::object &callback) {
            self.schedule_software_update(offset_sec, wrap_result_callback(callback));
          },
          py::arg("offset_sec"), py::arg("on_complete") = py::none())
      .def(
          "cancel_software_update",
          [](TeslaBLE::Vehicle &self, const py::object &callback) {
            self.cancel_software_update(wrap_result_callback(callback));
          },
          py::arg("on_complete") = py::none())
      // VCSEC closures
      .def(
          "lock",
          [](TeslaBLE::Vehicle &self, const py::object &callback) { self.lock(wrap_result_callback(callback)); },
          py::arg("on_complete") = py::none())
      .def(
          "unlock",
          [](TeslaBLE::Vehicle &self, const py::object &callback) { self.unlock(wrap_result_callback(callback)); },
          py::arg("on_complete") = py::none())
      .def(
          "open_trunk",
          [](TeslaBLE::Vehicle &self, const py::object &callback) { self.open_trunk(wrap_result_callback(callback)); },
          py::arg("on_complete") = py::none())
      .def(
          "close_trunk",
          [](TeslaBLE::Vehicle &self, const py::object &callback) { self.close_trunk(wrap_result_callback(callback)); },
          py::arg("on_complete") = py::none())
      .def(
          "open_frunk",
          [](TeslaBLE::Vehicle &self, const py::object &callback) { self.open_frunk(wrap_result_callback(callback)); },
          py::arg("on_complete") = py::none())
      .def(
          "open_charge_port",
          [](TeslaBLE::Vehicle &self, const py::object &callback) {
            self.open_charge_port(wrap_result_callback(callback));
          },
          py::arg("on_complete") = py::none())
      .def(
          "close_charge_port",
          [](TeslaBLE::Vehicle &self, const py::object &callback) {
            self.close_charge_port(wrap_result_callback(callback));
          },
          py::arg("on_complete") = py::none())
      .def(
          "unlatch_driver_door",
          [](TeslaBLE::Vehicle &self, const py::object &callback) {
            self.unlatch_driver_door(wrap_result_callback(callback));
          },
          py::arg("on_complete") = py::none())
      // HVAC
      .def(
          "set_climate",
          [](TeslaBLE::Vehicle &self, bool enable, const py::object &callback) {
            self.set_climate(enable, wrap_result_callback(callback));
          },
          py::arg("enable"), py::arg("on_complete") = py::none())
      .def(
          "set_climate_temp",
          [](TeslaBLE::Vehicle &self, float temp_celsius, const py::object &callback) {
            self.set_climate_temp(temp_celsius, wrap_result_callback(callback));
          },
          py::arg("temp_celsius"), py::arg("on_complete") = py::none())
      .def(
          "set_climate_keeper",
          [](TeslaBLE::Vehicle &self, int mode, const py::object &callback) {
            self.set_climate_keeper(mode, wrap_result_callback(callback));
          },
          py::arg("mode"), py::arg("on_complete") = py::none())
      .def(
          "set_bioweapon_mode",
          [](TeslaBLE::Vehicle &self, bool enable, const py::object &callback) {
            self.set_bioweapon_mode(enable, wrap_result_callback(callback));
          },
          py::arg("enable"), py::arg("on_complete") = py::none())
      .def(
          "set_preconditioning_max",
          [](TeslaBLE::Vehicle &self, bool enable, const py::object &callback) {
            self.set_preconditioning_max(enable, wrap_result_callback(callback));
          },
          py::arg("enable"), py::arg("on_complete") = py::none())
      .def(
          "set_steering_wheel_heat",
          [](TeslaBLE::Vehicle &self, bool enable, const py::object &callback) {
            self.set_steering_wheel_heat(enable, wrap_result_callback(callback));
          },
          py::arg("enable"), py::arg("on_complete") = py::none())
      // Vehicle controls
      .def(
          "set_seat_heater",
          [](TeslaBLE::Vehicle &self, TeslaBLE::SeatPosition seat, int level, const py::object &callback) {
            self.set_seat_heater(seat, level, wrap_result_callback(callback));
          },
          py::arg("seat"), py::arg("level"), py::arg("on_complete") = py::none())
      .def(
          "set_seat_climate",
          [](TeslaBLE::Vehicle &self, TeslaBLE::SeatPosition seat, int level, bool cooling, bool cooling_supported,
             const py::object &callback) {
            self.set_seat_climate(seat, level, cooling, cooling_supported, wrap_result_callback(callback));
          },
          py::arg("seat"), py::arg("level"), py::arg("cooling"), py::arg("cooling_supported"),
          py::arg("on_complete") = py::none())
      .def(
          "set_seat_cooler",
          [](TeslaBLE::Vehicle &self, TeslaBLE::SeatPosition seat, int level, const py::object &callback) {
            self.set_seat_cooler(seat, level, wrap_result_callback(callback));
          },
          py::arg("seat"), py::arg("level"), py::arg("on_complete") = py::none())
      .def(
          "set_auto_seat_climate",
          [](TeslaBLE::Vehicle &self, TeslaBLE::SeatPosition seat, bool enable, const py::object &callback) {
            self.set_auto_seat_climate(seat, enable, wrap_result_callback(callback));
          },
          py::arg("seat"), py::arg("enable"), py::arg("on_complete") = py::none())
      .def(
          "set_cabin_overheat_protection",
          [](TeslaBLE::Vehicle &self, int mode, const py::object &callback) {
            self.set_cabin_overheat_protection(mode, wrap_result_callback(callback));
          },
          py::arg("mode"), py::arg("on_complete") = py::none())
      .def(
          "set_sunroof_position",
          [](TeslaBLE::Vehicle &self, int percent, const py::object &callback) {
            self.set_sunroof_position(percent, wrap_result_callback(callback));
          },
          py::arg("percent"), py::arg("on_complete") = py::none())
      .def(
          "flash_lights",
          [](TeslaBLE::Vehicle &self, const py::object &callback) {
            self.flash_lights(wrap_result_callback(callback));
          },
          py::arg("on_complete") = py::none())
      .def(
          "honk_horn",
          [](TeslaBLE::Vehicle &self, const py::object &callback) { self.honk_horn(wrap_result_callback(callback)); },
          py::arg("on_complete") = py::none())
      .def(
          "set_sentry_mode",
          [](TeslaBLE::Vehicle &self, bool enable, const py::object &callback) {
            self.set_sentry_mode(enable, wrap_result_callback(callback));
          },
          py::arg("enable"), py::arg("on_complete") = py::none())
      .def(
          "set_low_power_mode",
          [](TeslaBLE::Vehicle &self, bool enable, const py::object &callback) {
            self.set_low_power_mode(enable, wrap_result_callback(callback));
          },
          py::arg("enable"), py::arg("on_complete") = py::none())
      .def(
          "set_keep_accessory_power_mode",
          [](TeslaBLE::Vehicle &self, bool enable, const py::object &callback) {
            self.set_keep_accessory_power_mode(enable, wrap_result_callback(callback));
          },
          py::arg("enable"), py::arg("on_complete") = py::none())
      .def(
          "set_guest_mode",
          [](TeslaBLE::Vehicle &self, bool enable, const py::object &callback) {
            self.set_guest_mode(enable, wrap_result_callback(callback));
          },
          py::arg("enable"), py::arg("on_complete") = py::none())
      .def(
          "set_cabin_overheat_protection_temp",
          [](TeslaBLE::Vehicle &self, int level, const py::object &callback) {
            self.set_cabin_overheat_protection_temp(level, wrap_result_callback(callback));
          },
          py::arg("level"), py::arg("on_complete") = py::none())
      .def(
          "set_scheduled_departure",
          [](TeslaBLE::Vehicle &self, bool enabled, int departure_minutes, int preconditioning_policy,
             int off_peak_policy, int off_peak_end_minutes, const py::object &callback) {
            self.set_scheduled_departure(enabled, departure_minutes, preconditioning_policy, off_peak_policy,
                                         off_peak_end_minutes, wrap_result_callback(callback));
          },
          py::arg("enabled"), py::arg("departure_minutes"), py::arg("preconditioning_policy"),
          py::arg("off_peak_policy"), py::arg("off_peak_end_minutes"), py::arg("on_complete") = py::none())
      .def(
          "vent_windows",
          [](TeslaBLE::Vehicle &self, const py::object &callback) {
            self.vent_windows(wrap_result_callback(callback));
          },
          py::arg("on_complete") = py::none())
      .def(
          "close_windows",
          [](TeslaBLE::Vehicle &self, const py::object &callback) {
            self.close_windows(wrap_result_callback(callback));
          },
          py::arg("on_complete") = py::none())
      // Media
      .def(
          "media_toggle_playback",
          [](TeslaBLE::Vehicle &self, const py::object &callback) {
            self.media_toggle_playback(wrap_result_callback(callback));
          },
          py::arg("on_complete") = py::none())
      .def(
          "media_next_track",
          [](TeslaBLE::Vehicle &self, const py::object &callback) {
            self.media_next_track(wrap_result_callback(callback));
          },
          py::arg("on_complete") = py::none())
      .def(
          "media_previous_track",
          [](TeslaBLE::Vehicle &self, const py::object &callback) {
            self.media_previous_track(wrap_result_callback(callback));
          },
          py::arg("on_complete") = py::none())
      .def(
          "media_next_favorite",
          [](TeslaBLE::Vehicle &self, const py::object &callback) {
            self.media_next_favorite(wrap_result_callback(callback));
          },
          py::arg("on_complete") = py::none())
      .def(
          "media_previous_favorite",
          [](TeslaBLE::Vehicle &self, const py::object &callback) {
            self.media_previous_favorite(wrap_result_callback(callback));
          },
          py::arg("on_complete") = py::none())
      .def(
          "media_volume_up",
          [](TeslaBLE::Vehicle &self, const py::object &callback) {
            self.media_volume_up(wrap_result_callback(callback));
          },
          py::arg("on_complete") = py::none())
      .def(
          "media_volume_down",
          [](TeslaBLE::Vehicle &self,
             const py::object &callback) { self.media_volume_down(wrap_result_callback(callback)); },
          py::arg("on_complete") = py::none())
      .def(
          "set_media_volume",
          [](TeslaBLE::Vehicle &self, float level,
             const py::object &callback) { self.set_media_volume(level, wrap_result_callback(callback)); },
          py::arg("level"), py::arg("on_complete") = py::none())
      // Pairing
      .def(
          "pair",
          [](TeslaBLE::Vehicle &self, Keys_Role role,
             const py::object &callback) { self.pair(role, wrap_result_callback(callback)); },
          py::arg("role") = Keys_Role_ROLE_OWNER, py::arg("on_complete") = py::none())
      .def(
          "regenerate_key",
          [](TeslaBLE::Vehicle &self,
             const py::object &callback) { self.regenerate_key(wrap_result_callback(callback)); },
          py::arg("on_complete") = py::none())
      // Callbacks
      .def("set_vehicle_status_callback",
           [](TeslaBLE::Vehicle &self, const py::object &callback) {
             self.set_vehicle_status_callback(
                 wrap_state_callback<VCSEC_VehicleStatus, vehicle_status_to_dict>(callback));
           })
      .def("set_charge_state_callback",
           [](TeslaBLE::Vehicle &self, const py::object &callback) {
             self.set_charge_state_callback(wrap_state_callback<CarServer_ChargeState, charge_state_to_dict>(callback));
           })
      .def("set_climate_state_callback",
           [](TeslaBLE::Vehicle &self, const py::object &callback) {
             self.set_climate_state_callback(
                 wrap_state_callback<CarServer_ClimateState, climate_state_to_dict>(callback));
           })
      .def("set_drive_state_callback",
           [](TeslaBLE::Vehicle &self, const py::object &callback) {
             self.set_drive_state_callback(wrap_state_callback<CarServer_DriveState, drive_state_to_dict>(callback));
           })
      .def("set_tire_pressure_state_callback",
           [](TeslaBLE::Vehicle &self, const py::object &callback) {
             self.set_tire_pressure_state_callback(
                 wrap_state_callback<CarServer_TirePressureState, tire_pressure_state_to_dict>(callback));
           })
      .def("set_closures_state_callback",
           [](TeslaBLE::Vehicle &self, const py::object &callback) {
             self.set_closures_state_callback(
                 wrap_state_callback<CarServer_ClosuresState, closures_state_to_dict>(callback));
           })
      .def("set_media_state_callback",
           [](TeslaBLE::Vehicle &self, const py::object &callback) {
             auto fn = to_python_function(callback);
             if (!fn) {
               self.set_media_state_callback(nullptr);
               return;
             }
             self.set_media_state_callback(
                 [fn](const CarServer_MediaState &state, const TeslaBLE::MediaNowPlaying &now_playing) {
                   py::gil_scoped_acquire gil;
                   try {
                     py::dict d = media_state_to_dict(state, now_playing);
                     invoke_guarded(fn, d);
                   } catch (py::error_already_set &e) {
                     e.discard_as_unraisable(CALLBACK_ERROR_CONTEXT);
                   }
                 });
           })
      .def("set_software_update_state_callback",
           [](TeslaBLE::Vehicle &self, const py::object &callback) {
             auto fn = to_python_function(callback);
             if (!fn) {
               self.set_software_update_state_callback(nullptr);
               return;
             }
             self.set_software_update_state_callback(
                 [fn](const CarServer_SoftwareUpdateState &state, const std::string &version) {
                   py::gil_scoped_acquire gil;
                   try {
                     py::dict d = software_update_state_to_dict(state, version);
                     invoke_guarded(fn, d);
                   } catch (py::error_already_set &e) {
                     e.discard_as_unraisable(CALLBACK_ERROR_CONTEXT);
                   }
                 });
           })
      .def("set_raw_message_callback", [](TeslaBLE::Vehicle &self, const py::object &callback) {
        auto fn = to_python_function(callback);
        if (!fn) {
          self.set_raw_message_callback(nullptr);
          return;
        }
        self.set_raw_message_callback([fn](const std::vector<uint8_t> &data) {
          py::gil_scoped_acquire gil;
          invoke_guarded(fn, py::bytes(reinterpret_cast<const char *>(data.data()), data.size()));
        });
      });

  // -------------------------------------------------------------------------
  // Polling policy
  // -------------------------------------------------------------------------
  py::class_<TeslaBLE::InfotainmentPollPolicy>(m, "InfotainmentPollPolicy",
                                               "Decides infotainment poll cadence and wake policy from vehicle state")
      .def(py::init<>())
      .def("set_awake_interval_ms", &TeslaBLE::InfotainmentPollPolicy::set_awake_interval_ms)
      .def("set_active_interval_ms", &TeslaBLE::InfotainmentPollPolicy::set_active_interval_ms)
      .def("set_sleep_timeout_ms", &TeslaBLE::InfotainmentPollPolicy::set_sleep_timeout_ms)
      .def_property_readonly("awake_interval_ms", &TeslaBLE::InfotainmentPollPolicy::awake_interval_ms)
      .def_property_readonly("active_interval_ms", &TeslaBLE::InfotainmentPollPolicy::active_interval_ms)
      .def_property_readonly("sleep_timeout_ms", &TeslaBLE::InfotainmentPollPolicy::sleep_timeout_ms)
      .def("reset", &TeslaBLE::InfotainmentPollPolicy::reset)
      .def("should_poll", &TeslaBLE::InfotainmentPollPolicy::should_poll, py::arg("now_ms"), py::arg("interval_ms"))
      .def("on_poll", &TeslaBLE::InfotainmentPollPolicy::on_poll, py::arg("now_ms"))
      .def(
          "update",
          [](TeslaBLE::InfotainmentPollPolicy &self, uint32_t now_ms, bool is_asleep, bool is_charging,
             bool is_sentry_mode) {
            auto decision = self.update(now_ms, is_asleep, is_charging, is_sentry_mode);
            py::dict result;
            result["interval_ms"] = decision.interval_ms;
            result["wake_policy"] = decision.wake_policy;
            return result;
          },
          py::arg("now_ms"), py::arg("is_asleep"), py::arg("is_charging"), py::arg("is_sentry_mode"));

  // -------------------------------------------------------------------------
  // Simulated vehicle
  // -------------------------------------------------------------------------
  py::class_<SimulatedVehicle>(m, "SimulatedVehicle", "Protocol-valid Tesla vehicle test double (offline tests only)")
      .def(py::init<std::string>(), py::arg("vin") = "5YJ30123456789ABC")
      .def(
          "on_client_frame",
          [](SimulatedVehicle &self, const py::bytes &frame) {
            std::string data = frame;
            std::vector<uint8_t> bytes(data.begin(), data.end());
            py::list responses;
            for (auto &response : self.on_client_frame(bytes)) {
              responses.append(py::bytes(reinterpret_cast<const char *>(response.data()), response.size()));
            }
            return responses;
          },
          py::arg("frame"), "Feed a framed client message; returns the list of framed replies")
      .def("set_paired", &SimulatedVehicle::set_paired)
      .def("set_locked", &SimulatedVehicle::set_locked)
      .def("set_sleeping", &SimulatedVehicle::set_sleeping)
      .def("set_user_present", &SimulatedVehicle::set_user_present)
      .def("set_battery_level", &SimulatedVehicle::set_battery_level)
      .def("set_battery_range", &SimulatedVehicle::set_battery_range)
      .def("set_charging_state", &SimulatedVehicle::set_charging_state)
      .def("set_scheduled_charging_mode", &SimulatedVehicle::set_scheduled_charging_mode)
      .def("set_charge_limit", &SimulatedVehicle::set_charge_limit)
      .def("set_charging_amps", &SimulatedVehicle::set_charging_amps)
      .def("set_charger_power", &SimulatedVehicle::set_charger_power)
      .def("set_charger_voltage", &SimulatedVehicle::set_charger_voltage)
      .def("set_charger_actual_current", &SimulatedVehicle::set_charger_actual_current)
      .def("set_charger_pilot_current", &SimulatedVehicle::set_charger_pilot_current)
      .def("set_charger_phases", &SimulatedVehicle::set_charger_phases)
      .def("set_charge_port_door_open", &SimulatedVehicle::set_charge_port_door_open)
      .def("set_charge_port_latch", &SimulatedVehicle::set_charge_port_latch)
      .def("set_inside_temp", &SimulatedVehicle::set_inside_temp)
      .def("set_outside_temp", &SimulatedVehicle::set_outside_temp)
      .def("set_climate_on", &SimulatedVehicle::set_climate_on)
      .def("set_climate_keeper_mode", &SimulatedVehicle::set_climate_keeper_mode)
      .def("set_cabin_overheat_protection", &SimulatedVehicle::set_cabin_overheat_protection)
      .def("set_seat_heater", &SimulatedVehicle::set_seat_heater)
      .def("set_seat_cooler", &SimulatedVehicle::set_seat_cooler)
      .def("set_auto_seat_climate", &SimulatedVehicle::set_auto_seat_climate)
      .def("set_steering_wheel_heat", &SimulatedVehicle::set_steering_wheel_heat)
      .def("set_cabin_overheat_protection_temp", &SimulatedVehicle::set_cabin_overheat_protection_temp)
      .def("set_bioweapon_mode", &SimulatedVehicle::set_bioweapon_mode)
      .def("set_shift_state", &SimulatedVehicle::set_shift_state)
      .def("set_odometer_miles", &SimulatedVehicle::set_odometer_miles)
      .def("set_door_open", &SimulatedVehicle::set_door_open)
      .def("set_window_open", &SimulatedVehicle::set_window_open)
      .def("set_tpms", &SimulatedVehicle::set_tpms)
      .def("set_sentry_mode", &SimulatedVehicle::set_sentry_mode)
      .def("set_sentry_mode_state", &SimulatedVehicle::set_sentry_mode_state)
      .def("set_software_update_state", &SimulatedVehicle::set_software_update_state)
      .def("set_sunroof_percent", &SimulatedVehicle::set_sunroof_percent)
      .def_property_readonly("vin", &SimulatedVehicle::vin)
      .def_property_readonly("frames_received", &SimulatedVehicle::frames_received);

  // -------------------------------------------------------------------------
  // Module functions
  // -------------------------------------------------------------------------
  m.def("set_log_callback", &set_log_callback_binding, py::arg("callback"),
        "Install a Python log callback: callback(level: int, message: str, tag: str, line: int). "
        "Pass None to disable.");
  m.def("get_vin_advertisement_name", [](const std::string &vin) { return TeslaBLE::get_vin_advertisement_name(vin); });
  m.def("is_tesla_vehicle_name", [](const std::string &name) { return TeslaBLE::is_tesla_vehicle_name(name); });
  m.def("matches_vin",
        [](const std::string &name, const std::string &vin) { return TeslaBLE::matches_vin(name, vin); });
  m.def("format_hex", [](const py::bytes &data) {
    std::string raw = data;
    return TeslaBLE::format_hex(reinterpret_cast<const uint8_t *>(raw.data()), raw.size());
  });
  m.def(
      "parse_frame_info",
      [](const py::bytes &data) {
        std::string raw = data;
        return parse_frame_info(std::vector<uint8_t>(raw.begin(), raw.end()));
      },
      py::arg("data"), "Parse a framed BLE message for diagnostics");

  // state_text helpers
  m.def("charging_state_text", &TeslaBLE::state_text::charging_state, py::arg("tag"));
  m.def("iec61851_state_text", &TeslaBLE::state_text::iec61851_state, py::arg("tag"));
  m.def("software_update_status_text", &TeslaBLE::state_text::software_update_status, py::arg("tag"));
  m.def("shift_state_text", &TeslaBLE::state_text::shift_state, py::arg("tag"));
  m.def("charge_limit_reason_text", &TeslaBLE::state_text::charge_limit_reason, py::arg("reason"));
  m.def("is_charging_tag", &TeslaBLE::state_text::is_charging, py::arg("tag"));
  m.def("is_parked_tag", &TeslaBLE::state_text::is_parked, py::arg("tag"));
  m.def("charger_connected_tag", &TeslaBLE::state_text::charger_connected, py::arg("tag"));
  m.def("closure_state_text", &TeslaBLE::state_text::closure_state_text, py::arg("state"));
  m.def("closure_is_open", &TeslaBLE::state_text::closure_is_open, py::arg("state"));
  m.def("sentry_mode_active", &TeslaBLE::state_text::sentry_mode_active, py::arg("state"));

  m.def(
      "charging_state_tag",
      [](const std::string &text) -> int {
        const int tags[] = {
            CarServer_ChargeState_ChargingState_Unknown_tag,  CarServer_ChargeState_ChargingState_Disconnected_tag,
            CarServer_ChargeState_ChargingState_NoPower_tag,  CarServer_ChargeState_ChargingState_Starting_tag,
            CarServer_ChargeState_ChargingState_Charging_tag, CarServer_ChargeState_ChargingState_Complete_tag,
            CarServer_ChargeState_ChargingState_Stopped_tag,  CarServer_ChargeState_ChargingState_Calibrating_tag,
        };
        for (int tag : tags) {
          if (TeslaBLE::state_text::charging_state(tag) == text) {
            return tag;
          }
        }
        return 0;
      },
      py::arg("text"), "Reverse of charging_state_text; 0 when unknown");
  m.def(
      "shift_state_tag",
      [](const std::string &text) -> int {
        const int tags[] = {
            CarServer_ShiftState_Invalid_tag, CarServer_ShiftState_P_tag, CarServer_ShiftState_R_tag,
            CarServer_ShiftState_N_tag,       CarServer_ShiftState_D_tag, CarServer_ShiftState_SNA_tag,
        };
        for (int tag : tags) {
          if (TeslaBLE::state_text::shift_state(tag) == text) {
            return tag;
          }
        }
        return 0;
      },
      py::arg("text"), "Reverse of shift_state_text; 0 when unknown");
}
