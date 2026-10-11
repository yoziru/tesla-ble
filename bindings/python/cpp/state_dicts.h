#pragma once

#include <pybind11/pybind11.h>

#include "client.h"
#include "vcsec.pb.h"
#include "vehicle.pb.h"

namespace py = pybind11;

namespace tesla_ble_python {

py::dict vehicle_status_to_dict(const VCSEC_VehicleStatus &s);
py::dict charge_state_to_dict(const CarServer_ChargeState &s);
py::dict climate_state_to_dict(const CarServer_ClimateState &s);
py::dict drive_state_to_dict(const CarServer_DriveState &s);
py::dict tire_pressure_state_to_dict(const CarServer_TirePressureState &s);
py::dict closures_state_to_dict(const CarServer_ClosuresState &s);
py::dict media_state_to_dict(const CarServer_MediaState &s, const TeslaBLE::MediaNowPlaying &now_playing);
py::dict software_update_state_to_dict(const CarServer_SoftwareUpdateState &s, const std::string &version);

}  // namespace tesla_ble_python
