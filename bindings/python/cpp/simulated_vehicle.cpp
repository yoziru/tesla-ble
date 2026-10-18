#include "simulated_vehicle.h"

#include <algorithm>
#include <cstring>
#include <cmath>

#include <mbedtls/gcm.h>
#include <mbedtls/sha256.h>
#include <pb_decode.h>

#include "defs.h"
#include "signatures.pb.h"
#include "tb_utils.h"

using TeslaBLE::TeslaBLE_Status_E_OK;

namespace tesla_ble_python {

namespace {

constexpr size_t ENCODE_BUFFER_SIZE = 4096;

template<typename T> bool decode(const std::vector<pb_byte_t> &payload, const pb_msgdesc_t *fields, T &message) {
  pb_istream_t stream = pb_istream_from_buffer(payload.data(), payload.size());
  return pb_decode(&stream, fields, &message);
}

std::vector<uint8_t> frame_message(const UniversalMessage_RoutableMessage &message) {
  std::vector<pb_byte_t> encoded(UniversalMessage_RoutableMessage_size);
  size_t encoded_length = encoded.size();
  if (TeslaBLE::pb_encode_fields(encoded.data(), &encoded_length, UniversalMessage_RoutableMessage_fields, &message) !=
      TeslaBLE_Status_E_OK) {
    return {};
  }
  std::vector<uint8_t> framed(encoded_length + 2);
  framed[0] = static_cast<uint8_t>((encoded_length >> 8) & 0xFF);
  framed[1] = static_cast<uint8_t>(encoded_length & 0xFF);
  std::copy_n(encoded.begin(), encoded_length, framed.begin() + 2);
  return framed;
}

void set_from_domain(UniversalMessage_RoutableMessage &msg, UniversalMessage_Domain domain) {
  msg.has_from_destination = true;
  msg.from_destination.which_sub_destination = UniversalMessage_Destination_domain_tag;
  msg.from_destination.sub_destination.domain = domain;
}

void echo_routing(const UniversalMessage_RoutableMessage &request, UniversalMessage_RoutableMessage &response) {
  response.has_to_destination = true;
  response.to_destination.which_sub_destination = UniversalMessage_Destination_routing_address_tag;
  if (request.has_from_destination &&
      request.from_destination.which_sub_destination == UniversalMessage_Destination_routing_address_tag) {
    std::copy_n(request.from_destination.sub_destination.routing_address.bytes,
                request.from_destination.sub_destination.routing_address.size,
                response.to_destination.sub_destination.routing_address.bytes);
    response.to_destination.sub_destination.routing_address.size =
        request.from_destination.sub_destination.routing_address.size;
  }
  if (request.uuid.size > 0) {
    std::copy_n(request.uuid.bytes, request.uuid.size, response.request_uuid.bytes);
    response.request_uuid.size = request.uuid.size;
  }
}

std::vector<uint8_t> vcsec_response(const VCSEC_FromVCSECMessage &message,
                                    const UniversalMessage_RoutableMessage &request) {
  std::vector<pb_byte_t> encoded(ENCODE_BUFFER_SIZE);
  size_t length = encoded.size();
  if (TeslaBLE::pb_encode_fields(encoded.data(), &length, VCSEC_FromVCSECMessage_fields, &message) !=
      TeslaBLE_Status_E_OK) {
    return {};
  }
  UniversalMessage_RoutableMessage response = UniversalMessage_RoutableMessage_init_default;
  set_from_domain(response, UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY);
  echo_routing(request, response);
  response.which_payload = UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag;
  std::copy_n(encoded.begin(), length, response.payload.protobuf_message_as_bytes.bytes);
  response.payload.protobuf_message_as_bytes.size = static_cast<pb_size_t>(length);
  return frame_message(response);
}

}  // namespace

SimulatedVehicle::SimulatedVehicle(std::string vin) : vin_(std::move(vin)) {
  charge_state_ = CarServer_ChargeState_init_default;
  climate_state_ = CarServer_ClimateState_init_default;
  drive_state_ = CarServer_DriveState_init_default;
  tire_state_ = CarServer_TirePressureState_init_default;
  closures_state_ = CarServer_ClosuresState_init_default;
  media_state_ = CarServer_MediaState_init_default;

  if (crypto_.create_private_key() != TeslaBLE_Status_E_OK) {
    return;
  }
  size_t key_length = public_key_.size();
  if (crypto_.generate_public_key(public_key_.data(), &key_length) != TeslaBLE_Status_E_OK) {
    return;
  }
  public_key_size_ = key_length;
  crypto_.generate_random_bytes(epoch_.data(), epoch_.size());

  set_locked(true);
  set_sleeping(false);
  set_battery_level(60);
  set_battery_range(180.0f);
  set_charging_state(CarServer_ChargeState_ChargingState_Disconnected_tag);
  set_charge_limit(80);
  set_charging_amps(16);
  set_charge_port_latch(CarServer_ChargePortLatchState_Disengaged_tag);
  set_shift_state(CarServer_ShiftState_P_tag);
  set_odometer_miles(1000.0f);
  set_sentry_mode(false);
}

std::vector<std::vector<uint8_t>> SimulatedVehicle::on_client_frame(const std::vector<uint8_t> &frame) {
  std::vector<std::vector<uint8_t>> responses;
  if (frame.size() <= 2) {
    return responses;
  }
  frames_received_++;
  if ((static_cast<size_t>(frame[0]) << 8 | frame[1]) != frame.size() - 2) {
    return responses;
  }

  std::vector<pb_byte_t> raw(frame.begin() + 2, frame.end());
  VCSEC_ToVCSECMessage pairing = VCSEC_ToVCSECMessage_init_default;
  if (decode(raw, VCSEC_ToVCSECMessage_fields, pairing) && pairing.has_signedMessage &&
      pairing.signedMessage.signatureType == VCSEC_SignatureType_SIGNATURE_TYPE_PRESENT_KEY) {
    const auto &bytes = pairing.signedMessage.protobufMessageAsBytes;
    VCSEC_UnsignedMessage action = VCSEC_UnsignedMessage_init_default;
    std::vector<pb_byte_t> payload(bytes.bytes, bytes.bytes + bytes.size);
    if (!decode(payload, VCSEC_UnsignedMessage_fields, action) ||
        action.which_sub_message != VCSEC_UnsignedMessage_WhitelistOperation_tag ||
        action.sub_message.WhitelistOperation.which_sub_message !=
            VCSEC_WhitelistOperation_addKeyToWhitelistAndAddPermissions_tag) {
      return responses;
    }
    const auto &permission = action.sub_message.WhitelistOperation.sub_message.addKeyToWhitelistAndAddPermissions;
    if (!permission.has_key || permission.key.PublicKeyRaw.size != 65 || permission.keyRole < Keys_Role_ROLE_SERVICE ||
        permission.keyRole > Keys_Role_ROLE_GUEST) {
      return responses;
    }
    paired_ = true;
    UniversalMessage_RoutableMessage request = UniversalMessage_RoutableMessage_init_default;
    VCSEC_FromVCSECMessage response = VCSEC_FromVCSECMessage_init_default;
    response.which_sub_message = VCSEC_FromVCSECMessage_commandStatus_tag;
    response.sub_message.commandStatus.operationStatus = VCSEC_OperationStatus_E_OPERATIONSTATUS_OK;
    response.sub_message.commandStatus.which_sub_message = VCSEC_CommandStatus_whitelistOperationStatus_tag;
    response.sub_message.commandStatus.sub_message.whitelistOperationStatus.operationStatus =
        VCSEC_OperationStatus_E_OPERATIONSTATUS_OK;
    responses.push_back(vcsec_response(response, request));
    return responses;
  }

  TeslaBLE::Client parser;
  UniversalMessage_RoutableMessage request = UniversalMessage_RoutableMessage_init_default;
  if (parser.parse_universal_message_ble(const_cast<pb_byte_t *>(frame.data()), frame.size(), &request) !=
      TeslaBLE_Status_E_OK) {
    return responses;
  }

  if (request.which_payload == UniversalMessage_RoutableMessage_session_info_request_tag) {
    auto response = respond_to_session_info_request_(request);
    if (!response.empty()) {
      responses.push_back(std::move(response));
    }
    return responses;
  }

  if (!request.has_to_destination ||
      request.to_destination.which_sub_destination != UniversalMessage_Destination_domain_tag) {
    return responses;
  }
  UniversalMessage_Domain domain = request.to_destination.sub_destination.domain;
  std::vector<pb_byte_t> payload;
  if (!decode_payload_(request, domain, payload)) {
    return responses;
  }

  if (domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY) {
    if (!apply_vcsec_action_(payload)) {
      return responses;
    }
    auto response = respond_to_vcsec_(request);
    if (!response.empty()) {
      responses.push_back(std::move(response));
    }
  } else if (domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT) {
    CarServer_Action action = CarServer_Action_init_default;
    if (!decode(payload, CarServer_Action_fields, action) || !apply_carserver_action_(action)) {
      return responses;
    }
    const auto &vehicle = action.action_msg.vehicleAction;
    return respond_to_carserver_(request, vehicle.which_vehicle_action_msg == CarServer_VehicleAction_getVehicleData_tag
                                              ? &vehicle.vehicle_action_msg.getVehicleData
                                              : nullptr);
  }
  return responses;
}

bool SimulatedVehicle::decode_payload_(const UniversalMessage_RoutableMessage &request, UniversalMessage_Domain domain,
                                       std::vector<pb_byte_t> &payload) {
  if (request.which_payload != UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag ||
      (domain != UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY &&
       domain != UniversalMessage_Domain_DOMAIN_INFOTAINMENT)) {
    return false;
  }
  const auto &bytes = request.payload.protobuf_message_as_bytes;
  if (request.which_sub_sigData == 0) {
    payload.assign(bytes.bytes, bytes.bytes + bytes.size);
    VCSEC_UnsignedMessage action = VCSEC_UnsignedMessage_init_default;
    return domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY &&
           decode(payload, VCSEC_UnsignedMessage_fields, action) &&
           action.which_sub_message == VCSEC_UnsignedMessage_InformationRequest_tag &&
           action.sub_message.InformationRequest.informationRequestType ==
               VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS;
  }
  const auto &signature = request.sub_sigData.signature_data;
  if (!paired_ || request.which_sub_sigData != UniversalMessage_RoutableMessage_signature_data_tag ||
      signature.which_sig_type != Signatures_SignatureData_AES_GCM_Personalized_data_tag ||
      !signature.has_signer_identity ||
      signature.signer_identity.which_identity_type != Signatures_KeyIdentity_public_key_tag) {
    return false;
  }
  const auto &data = signature.sig_type.AES_GCM_Personalized_data;
  size_t index = domain == UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY ? 0 : 1;
  if (!std::equal(epoch_.begin(), epoch_.end(), data.epoch) || data.expires_at < clock_time_ ||
      data.counter <= request_counters_[index]) {
    return false;
  }
  std::vector<pb_byte_t> aad;
  auto append = [&](uint8_t tag, const uint8_t *value, size_t length) {
    aad.push_back(tag);
    aad.push_back(static_cast<uint8_t>(length));
    aad.insert(aad.end(), value, value + length);
  };
  auto append_number = [&](uint8_t tag, uint32_t value) {
    uint8_t bytes_be[] = {static_cast<uint8_t>(value >> 24), static_cast<uint8_t>(value >> 16),
                          static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value)};
    append(tag, bytes_be, sizeof(bytes_be));
  };
  uint8_t type = Signatures_SignatureType_SIGNATURE_TYPE_AES_GCM_PERSONALIZED;
  uint8_t domain_byte = static_cast<uint8_t>(domain);
  append(Signatures_Tag_TAG_SIGNATURE_TYPE, &type, 1);
  append(Signatures_Tag_TAG_DOMAIN, &domain_byte, 1);
  append(Signatures_Tag_TAG_PERSONALIZATION, reinterpret_cast<const uint8_t *>(vin_.data()),
         std::min<size_t>(vin_.size(), 17));
  append(Signatures_Tag_TAG_EPOCH, data.epoch, sizeof(data.epoch));
  append_number(Signatures_Tag_TAG_EXPIRES_AT, data.expires_at);
  append_number(Signatures_Tag_TAG_COUNTER, data.counter);
  if (request.flags) {
    append_number(Signatures_Tag_TAG_FLAGS, request.flags);
  }
  aad.push_back(Signatures_Tag_TAG_END);
  uint8_t hash[32];
  uint8_t key[TeslaBLE::Peer::SHARED_KEY_SIZE_BYTES] = {};
  const auto &public_key = signature.signer_identity.identity_type.public_key;
  if (mbedtls_sha256(aad.data(), aad.size(), hash, 0) != 0 ||
      crypto_.perform_tesla_ecdh(public_key.bytes, public_key.size, key) != TeslaBLE_Status_E_OK) {
    TeslaBLE::CryptoUtils::clear_sensitive_memory(key, sizeof(key));
    return false;
  }
  mbedtls_gcm_context context;
  mbedtls_gcm_init(&context);
  int status = mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key, 128);
  TeslaBLE::CryptoUtils::clear_sensitive_memory(key, sizeof(key));
  payload.resize(bytes.size);
  if (status == 0) {
    status = mbedtls_gcm_auth_decrypt(&context, bytes.size, data.nonce, sizeof(data.nonce), hash, sizeof(hash),
                                      data.tag, sizeof(data.tag), bytes.bytes, payload.data());
  }
  mbedtls_gcm_free(&context);
  if (status != 0) {
    payload.clear();
    return false;
  }
  request_counters_[index] = data.counter;
  return true;
}

bool SimulatedVehicle::apply_vcsec_action_(const std::vector<pb_byte_t> &payload) {
  VCSEC_UnsignedMessage action = VCSEC_UnsignedMessage_init_default;
  if (!decode(payload, VCSEC_UnsignedMessage_fields, action)) {
    return false;
  }
  switch (action.which_sub_message) {
    case VCSEC_UnsignedMessage_InformationRequest_tag:
      return action.sub_message.InformationRequest.informationRequestType ==
             VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS;
    case VCSEC_UnsignedMessage_RKEAction_tag:
      switch (action.sub_message.RKEAction) {
        case VCSEC_RKEAction_E_RKE_ACTION_UNLOCK:
          locked_ = false;
          return true;
        case VCSEC_RKEAction_E_RKE_ACTION_LOCK:
          locked_ = true;
          return true;
        case VCSEC_RKEAction_E_RKE_ACTION_WAKE_VEHICLE:
          asleep_ = false;
          return true;
        default:
          return false;
      }
    case VCSEC_UnsignedMessage_closureMoveRequest_tag: {
      const auto &closure = action.sub_message.closureMoveRequest;
      auto valid = [](VCSEC_ClosureMoveType_E move) {
        return move == VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_NONE ||
               move == VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_OPEN ||
               move == VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_CLOSE ||
               move == VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_MOVE;
      };
      if (!valid(closure.frontDriverDoor) || !valid(closure.frontTrunk) || !valid(closure.rearTrunk) ||
          !valid(closure.chargePort) || closure.frontPassengerDoor || closure.rearDriverDoor ||
          closure.rearPassengerDoor || closure.tonneau) {
        return false;
      }
      auto apply = [](VCSEC_ClosureMoveType_E move, bool &open) {
        if (move != VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_NONE) {
          open = move != VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_CLOSE;
        }
      };
      if (closure.frontDriverDoor) {
        set_door_open("driver_front", closure.frontDriverDoor != VCSEC_ClosureMoveType_E_CLOSURE_MOVE_TYPE_CLOSE);
      }
      apply(closure.frontTrunk, front_trunk_open_);
      apply(closure.rearTrunk, rear_trunk_open_);
      bool charge_port = charge_port_open_;
      apply(closure.chargePort, charge_port);
      set_charge_port_door_open(charge_port);
      return closure.frontDriverDoor || closure.frontTrunk || closure.rearTrunk || closure.chargePort;
    }
    default:
      return false;
  }
}

bool SimulatedVehicle::apply_carserver_action_(const CarServer_Action &action) {
  if (action.which_action_msg != CarServer_Action_vehicleAction_tag) {
    return false;
  }
  const auto &vehicle = action.action_msg.vehicleAction;
  const auto &value = vehicle.vehicle_action_msg;
  switch (vehicle.which_vehicle_action_msg) {
    case CarServer_VehicleAction_getVehicleData_tag: {
      const auto &poll = value.getVehicleData;
      return (poll.has_getChargeState || poll.has_getClimateState || poll.has_getDriveState ||
              poll.has_getClosuresState || poll.has_getTirePressureState || poll.has_getMediaState ||
              poll.has_getMediaDetailState || poll.has_getSoftwareUpdateState) &&
             !poll.has_getLocationState && !poll.has_getChargeScheduleState &&
             !poll.has_getPreconditioningScheduleState && !poll.has_getParentalControlsState;
    }
    case CarServer_VehicleAction_chargingStartStopAction_tag:
      if (value.chargingStartStopAction.which_charging_action != CarServer_ChargingStartStopAction_start_tag &&
          value.chargingStartStopAction.which_charging_action != CarServer_ChargingStartStopAction_stop_tag)
        return false;
      set_charging_state(value.chargingStartStopAction.which_charging_action ==
                                 CarServer_ChargingStartStopAction_start_tag
                             ? CarServer_ChargeState_ChargingState_Charging_tag
                             : CarServer_ChargeState_ChargingState_Stopped_tag);
      return true;
    case CarServer_VehicleAction_chargingSetLimitAction_tag:
      if (value.chargingSetLimitAction.percent < 0 || value.chargingSetLimitAction.percent > 100)
        return false;
      set_charge_limit(value.chargingSetLimitAction.percent);
      return true;
    case CarServer_VehicleAction_setChargingAmpsAction_tag:
      if (value.setChargingAmpsAction.charging_amps < 0 || value.setChargingAmpsAction.charging_amps > 48)
        return false;
      set_charging_amps(value.setChargingAmpsAction.charging_amps);
      return true;
    case CarServer_VehicleAction_hvacAutoAction_tag:
      set_climate_on(value.hvacAutoAction.power_on);
      return true;
    case CarServer_VehicleAction_hvacTemperatureAdjustmentAction_tag:
      if (!std::isfinite(value.hvacTemperatureAdjustmentAction.driver_temp_celsius) ||
          !std::isfinite(value.hvacTemperatureAdjustmentAction.passenger_temp_celsius))
        return false;
      climate_state_.which_optional_driver_temp_setting = CarServer_ClimateState_driver_temp_setting_tag;
      climate_state_.optional_driver_temp_setting.driver_temp_setting =
          value.hvacTemperatureAdjustmentAction.driver_temp_celsius;
      climate_state_.which_optional_passenger_temp_setting = CarServer_ClimateState_passenger_temp_setting_tag;
      climate_state_.optional_passenger_temp_setting.passenger_temp_setting =
          value.hvacTemperatureAdjustmentAction.passenger_temp_celsius;
      return true;
    case CarServer_VehicleAction_hvacClimateKeeperAction_tag:
      if (value.hvacClimateKeeperAction.ClimateKeeperAction < 0 ||
          value.hvacClimateKeeperAction.ClimateKeeperAction > 3)
        return false;
      set_climate_keeper_mode(static_cast<int>(value.hvacClimateKeeperAction.ClimateKeeperAction) + 2);
      return true;
    case CarServer_VehicleAction_hvacSetPreconditioningMaxAction_tag:
      climate_state_.has_defrost_mode = true;
      climate_state_.defrost_mode.which_type = value.hvacSetPreconditioningMaxAction.on
                                                   ? CarServer_ClimateState_DefrostMode_Max_tag
                                                   : CarServer_ClimateState_DefrostMode_Off_tag;
      return true;
    case CarServer_VehicleAction_hvacBioweaponModeAction_tag:
      set_bioweapon_mode(value.hvacBioweaponModeAction.on);
      return true;
    case CarServer_VehicleAction_hvacSteeringWheelHeaterAction_tag:
      set_steering_wheel_heat(value.hvacSteeringWheelHeaterAction.power_on);
      return true;
    case CarServer_VehicleAction_hvacSeatHeaterActions_tag: {
      if (value.hvacSeatHeaterActions.hvacSeatHeaterAction_count != 1)
        return false;
      const auto &seat = value.hvacSeatHeaterActions.hvacSeatHeaterAction[0];
      if (seat.which_seat_position < 7 || seat.which_seat_position > 15 || seat.which_seat_heater_level < 2 ||
          seat.which_seat_heater_level > 5)
        return false;
      const auto position = static_cast<TeslaBLE::SeatPosition>(seat.which_seat_position);
      set_seat_heater(position, seat.which_seat_heater_level - 2);
      if ((position == TeslaBLE::SeatPosition::FRONT_LEFT && climate_state_.which_optional_auto_seat_climate_left) ||
          (position == TeslaBLE::SeatPosition::FRONT_RIGHT && climate_state_.which_optional_auto_seat_climate_right))
        set_auto_seat_climate(position, false);
      if (seat.which_seat_heater_level > 2 &&
          ((position == TeslaBLE::SeatPosition::FRONT_LEFT && climate_state_.which_optional_seat_fan_front_left) ||
           (position == TeslaBLE::SeatPosition::FRONT_RIGHT && climate_state_.which_optional_seat_fan_front_right)))
        set_seat_cooler(position, 0);
      return true;
    }
    case CarServer_VehicleAction_hvacSeatCoolerActions_tag: {
      if (value.hvacSeatCoolerActions.hvacSeatCoolerAction_count != 1)
        return false;
      const auto &seat = value.hvacSeatCoolerActions.hvacSeatCoolerAction[0];
      if (seat.seat_position < 1 || seat.seat_position > 2 || seat.seat_cooler_level < 1 || seat.seat_cooler_level > 4)
        return false;
      const auto position = static_cast<TeslaBLE::SeatPosition>(static_cast<int>(seat.seat_position) + 6);
      set_seat_cooler(position, static_cast<int>(seat.seat_cooler_level) - 1);
      if ((position == TeslaBLE::SeatPosition::FRONT_LEFT && climate_state_.which_optional_auto_seat_climate_left) ||
          (position == TeslaBLE::SeatPosition::FRONT_RIGHT && climate_state_.which_optional_auto_seat_climate_right))
        set_auto_seat_climate(position, false);
      if (seat.seat_cooler_level > 1)
        set_seat_heater(position, 0);
      return true;
    }
    case CarServer_VehicleAction_autoSeatClimateAction_tag: {
      if (value.autoSeatClimateAction.carseat_count != 1)
        return false;
      const auto &seat = value.autoSeatClimateAction.carseat[0];
      if (seat.seat_position < 1 || seat.seat_position > 2)
        return false;
      set_auto_seat_climate(static_cast<TeslaBLE::SeatPosition>(static_cast<int>(seat.seat_position) + 6), seat.on);
      return true;
    }
    case CarServer_VehicleAction_setCabinOverheatProtectionAction_tag:
      set_cabin_overheat_protection(!value.setCabinOverheatProtectionAction.on        ? 0
                                    : value.setCabinOverheatProtectionAction.fan_only ? 2
                                                                                      : 1);
      return true;
    case CarServer_VehicleAction_setCopTempAction_tag:
      if (value.setCopTempAction.copActivationTemp < 1 || value.setCopTempAction.copActivationTemp > 3)
        return false;
      set_cabin_overheat_protection_temp(value.setCopTempAction.copActivationTemp);
      return true;
    case CarServer_VehicleAction_vehicleControlSunroofOpenCloseAction_tag: {
      const auto &roof = value.vehicleControlSunroofOpenCloseAction;
      if (roof.which_sunroof_level != CarServer_VehicleControlSunroofOpenCloseAction_absolute_level_tag ||
          roof.sunroof_level.absolute_level < 0 || roof.sunroof_level.absolute_level > 100)
        return false;
      set_sunroof_percent(roof.sunroof_level.absolute_level);
      return true;
    }
    case CarServer_VehicleAction_vehicleControlSetSentryModeAction_tag:
      set_sentry_mode(value.vehicleControlSetSentryModeAction.on);
      return true;
    case CarServer_VehicleAction_vehicleControlFlashLightsAction_tag:
    case CarServer_VehicleAction_vehicleControlHonkHornAction_tag:
      return true;
    case CarServer_VehicleAction_vehicleControlScheduleSoftwareUpdateAction_tag:
      if (value.vehicleControlScheduleSoftwareUpdateAction.offset_sec < 0)
        return false;
      set_software_update_state(CarServer_SoftwareUpdateState_SoftwareUpdateStatus_Scheduled_tag);
      return true;
    case CarServer_VehicleAction_vehicleControlCancelSoftwareUpdateAction_tag:
      if (software_update_state_.has_status && software_update_state_.status.which_type ==
                                                   CarServer_SoftwareUpdateState_SoftwareUpdateStatus_Scheduled_tag) {
        set_software_update_state(CarServer_SoftwareUpdateState_SoftwareUpdateStatus_Available_tag);
      }
      return true;
    default:
      return false;
  }
}

std::vector<uint8_t> SimulatedVehicle::respond_to_session_info_request_(
    const UniversalMessage_RoutableMessage &request) {
  if (public_key_size_ == 0 || request.uuid.size == 0) {
    return {};
  }

  UniversalMessage_Domain domain = UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY;
  if (request.has_to_destination &&
      request.to_destination.which_sub_destination == UniversalMessage_Destination_domain_tag) {
    domain = request.to_destination.sub_destination.domain;
  }

  const auto &client_public_key = request.payload.session_info_request.public_key;
  if (client_public_key.size == 0) {
    return {};
  }

  Signatures_SessionInfo session_info = Signatures_SessionInfo_init_default;
  session_info.counter = request_counters_[domain == UniversalMessage_Domain_DOMAIN_INFOTAINMENT ? 1 : 0];
  std::copy_n(public_key_.begin(), public_key_size_, session_info.publicKey.bytes);
  session_info.publicKey.size = static_cast<pb_size_t>(public_key_size_);
  std::ranges::copy(epoch_, session_info.epoch);
  session_info.clock_time = clock_time_;
  session_info.status = paired_ ? Signatures_Session_Info_Status_SESSION_INFO_STATUS_OK
                                : Signatures_Session_Info_Status_SESSION_INFO_STATUS_KEY_NOT_ON_WHITELIST;

  pb_byte_t session_info_buffer[Signatures_SessionInfo_size];
  size_t session_info_length = sizeof(session_info_buffer);
  if (TeslaBLE::pb_encode_fields(session_info_buffer, &session_info_length, Signatures_SessionInfo_fields,
                                 &session_info) != TeslaBLE_Status_E_OK) {
    return {};
  }

  UniversalMessage_RoutableMessage response = UniversalMessage_RoutableMessage_init_default;
  set_from_domain(response, domain);
  echo_routing(request, response);
  response.which_payload = UniversalMessage_RoutableMessage_session_info_tag;
  std::copy_n(session_info_buffer, session_info_length, response.payload.session_info.bytes);
  response.payload.session_info.size = static_cast<pb_size_t>(session_info_length);
  if (!paired_) {
    return frame_message(response);
  }

  // HMAC input: metadata (signature type, personalization = VIN, challenge =
  // request UUID) followed by the session info bytes.
  std::vector<pb_byte_t> hmac_input;
  hmac_input.push_back(Signatures_Tag_TAG_SIGNATURE_TYPE);
  hmac_input.push_back(0x01);
  hmac_input.push_back(Signatures_SignatureType_SIGNATURE_TYPE_HMAC);
  hmac_input.push_back(Signatures_Tag_TAG_PERSONALIZATION);
  hmac_input.push_back(static_cast<pb_byte_t>(vin_.size()));
  hmac_input.insert(hmac_input.end(), vin_.begin(), vin_.end());
  hmac_input.push_back(Signatures_Tag_TAG_CHALLENGE);
  hmac_input.push_back(request.uuid.size);
  hmac_input.insert(hmac_input.end(), request.uuid.bytes, request.uuid.bytes + request.uuid.size);
  hmac_input.push_back(Signatures_Tag_TAG_END);
  hmac_input.insert(hmac_input.end(), session_info_buffer, session_info_buffer + session_info_length);

  uint8_t session_key[TeslaBLE::Peer::SHARED_KEY_SIZE_BYTES] = {0};
  if (crypto_.perform_tesla_ecdh(client_public_key.bytes, client_public_key.size, session_key) !=
      TeslaBLE_Status_E_OK) {
    return {};
  }
  uint8_t session_info_key[32] = {0};
  auto kdf_status = TeslaBLE::CryptoUtils::derive_session_info_key(session_key, sizeof(session_key), session_info_key,
                                                                   sizeof(session_info_key));
  TeslaBLE::CryptoUtils::clear_sensitive_memory(session_key, sizeof(session_key));
  if (kdf_status != TeslaBLE_Status_E_OK) {
    return {};
  }
  uint8_t tag[32] = {0};
  auto hmac_status = TeslaBLE::CryptoUtils::hmac_sha256(session_info_key, sizeof(session_info_key), hmac_input.data(),
                                                        hmac_input.size(), tag, sizeof(tag));
  TeslaBLE::CryptoUtils::clear_sensitive_memory(session_info_key, sizeof(session_info_key));
  if (hmac_status != TeslaBLE_Status_E_OK) {
    return {};
  }

  response.which_sub_sigData = UniversalMessage_RoutableMessage_signature_data_tag;
  response.sub_sigData.signature_data.which_sig_type = Signatures_SignatureData_session_info_tag_tag;
  std::copy_n(tag, sizeof(tag), response.sub_sigData.signature_data.sig_type.session_info_tag.tag.bytes);
  response.sub_sigData.signature_data.sig_type.session_info_tag.tag.size = sizeof(tag);

  return frame_message(response);
}

std::vector<uint8_t> SimulatedVehicle::respond_to_vcsec_(const UniversalMessage_RoutableMessage &request) {
  VCSEC_FromVCSECMessage vcsec_message = VCSEC_FromVCSECMessage_init_default;
  vcsec_message.which_sub_message = VCSEC_FromVCSECMessage_vehicleStatus_tag;
  auto &status = vcsec_message.sub_message.vehicleStatus;
  status.has_closureStatuses = true;
  status.closureStatuses.frontDriverDoor =
      doors_open_[0] ? VCSEC_ClosureState_E_CLOSURESTATE_OPEN : VCSEC_ClosureState_E_CLOSURESTATE_CLOSED;
  status.closureStatuses.frontPassengerDoor =
      doors_open_[1] ? VCSEC_ClosureState_E_CLOSURESTATE_OPEN : VCSEC_ClosureState_E_CLOSURESTATE_CLOSED;
  status.closureStatuses.rearDriverDoor =
      doors_open_[2] ? VCSEC_ClosureState_E_CLOSURESTATE_OPEN : VCSEC_ClosureState_E_CLOSURESTATE_CLOSED;
  status.closureStatuses.rearPassengerDoor =
      doors_open_[3] ? VCSEC_ClosureState_E_CLOSURESTATE_OPEN : VCSEC_ClosureState_E_CLOSURESTATE_CLOSED;
  status.closureStatuses.chargePort =
      charge_port_open_ ? VCSEC_ClosureState_E_CLOSURESTATE_OPEN : VCSEC_ClosureState_E_CLOSURESTATE_CLOSED;
  status.closureStatuses.frontTrunk =
      front_trunk_open_ ? VCSEC_ClosureState_E_CLOSURESTATE_OPEN : VCSEC_ClosureState_E_CLOSURESTATE_CLOSED;
  status.closureStatuses.rearTrunk =
      rear_trunk_open_ ? VCSEC_ClosureState_E_CLOSURESTATE_OPEN : VCSEC_ClosureState_E_CLOSURESTATE_CLOSED;
  status.vehicleLockState =
      locked_ ? VCSEC_VehicleLockState_E_VEHICLELOCKSTATE_LOCKED : VCSEC_VehicleLockState_E_VEHICLELOCKSTATE_UNLOCKED;
  status.vehicleSleepStatus = asleep_ ? VCSEC_VehicleSleepStatus_E_VEHICLE_SLEEP_STATUS_ASLEEP
                                      : VCSEC_VehicleSleepStatus_E_VEHICLE_SLEEP_STATUS_AWAKE;
  status.userPresence = user_present_ ? VCSEC_UserPresence_E_VEHICLE_USER_PRESENCE_PRESENT
                                      : VCSEC_UserPresence_E_VEHICLE_USER_PRESENCE_NOT_PRESENT;

  return vcsec_response(vcsec_message, request);
}

std::vector<std::vector<uint8_t>> SimulatedVehicle::respond_to_carserver_(
    const UniversalMessage_RoutableMessage &request, const CarServer_GetVehicleData *poll) {
  std::vector<std::vector<uint8_t>> responses;

  auto encode_response = [&](const CarServer_Response &car_response) -> std::vector<uint8_t> {
    std::vector<pb_byte_t> encoded(ENCODE_BUFFER_SIZE);
    size_t encoded_length = encoded.size();
    if (TeslaBLE::pb_encode_fields(encoded.data(), &encoded_length, CarServer_Response_fields, &car_response) !=
        TeslaBLE_Status_E_OK) {
      return {};
    }
    UniversalMessage_RoutableMessage response = UniversalMessage_RoutableMessage_init_default;
    set_from_domain(response, UniversalMessage_Domain_DOMAIN_INFOTAINMENT);
    echo_routing(request, response);
    response.which_payload = UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag;
    std::copy_n(encoded.begin(), encoded_length, response.payload.protobuf_message_as_bytes.bytes);
    response.payload.protobuf_message_as_bytes.size = static_cast<pb_size_t>(encoded_length);
    return frame_message(response);
  };

  if (poll == nullptr) {
    CarServer_Response action_response = CarServer_Response_init_default;
    action_response.has_actionStatus = true;
    action_response.actionStatus.result = CarServer_OperationStatus_E_OPERATIONSTATUS_OK;
    if (auto frame = encode_response(action_response); !frame.empty()) {
      responses.push_back(std::move(frame));
    }
    return responses;
  }

  CarServer_Response state_response = CarServer_Response_init_default;
  state_response.has_actionStatus = true;
  state_response.actionStatus.result = CarServer_OperationStatus_E_OPERATIONSTATUS_OK;
  state_response.which_response_msg = CarServer_Response_vehicleData_tag;
  closures_state_.which_optional_locked = CarServer_ClosuresState_locked_tag;
  closures_state_.optional_locked.locked = locked_;
  closures_state_.which_optional_is_user_present = CarServer_ClosuresState_is_user_present_tag;
  closures_state_.optional_is_user_present.is_user_present = user_present_;
  auto &vehicle_data = state_response.response_msg.vehicleData;
  vehicle_data.has_charge_state = poll->has_getChargeState;
  vehicle_data.charge_state = charge_state_;
  vehicle_data.has_climate_state = poll->has_getClimateState;
  vehicle_data.climate_state = climate_state_;
  vehicle_data.has_drive_state = poll->has_getDriveState;
  vehicle_data.drive_state = drive_state_;
  vehicle_data.has_closures_state = poll->has_getClosuresState;
  vehicle_data.closures_state = closures_state_;
  vehicle_data.has_tire_pressure_state = poll->has_getTirePressureState;
  vehicle_data.tire_pressure_state = tire_state_;
  vehicle_data.has_media_state = poll->has_getMediaState || poll->has_getMediaDetailState;
  vehicle_data.media_state = media_state_;
  vehicle_data.has_software_update_state = poll->has_getSoftwareUpdateState;
  vehicle_data.software_update_state = software_update_state_;
  if (auto frame = encode_response(state_response); !frame.empty()) {
    responses.push_back(std::move(frame));
  }

  return responses;
}

void SimulatedVehicle::set_battery_level(int level) {
  charge_state_.which_optional_battery_level = CarServer_ChargeState_battery_level_tag;
  charge_state_.optional_battery_level.battery_level = level;
}

void SimulatedVehicle::set_battery_range(float range) {
  charge_state_.which_optional_battery_range = CarServer_ChargeState_battery_range_tag;
  charge_state_.optional_battery_range.battery_range = range;
}

void SimulatedVehicle::set_charging_state(int tag) {
  if (tag == 0) {
    charge_state_.has_charging_state = false;
    return;
  }
  charge_state_.has_charging_state = true;
  charge_state_.charging_state.which_type = tag;
}

void SimulatedVehicle::set_scheduled_charging_mode(int mode) {
  charge_state_.which_optional_scheduled_charging_mode = CarServer_ChargeState_scheduled_charging_mode_tag;
  charge_state_.optional_scheduled_charging_mode.scheduled_charging_mode =
      static_cast<CarServer_ChargeState_ScheduledChargingMode>(mode);
}

void SimulatedVehicle::set_charge_limit(int soc) {
  charge_state_.which_optional_charge_limit_soc = CarServer_ChargeState_charge_limit_soc_tag;
  charge_state_.optional_charge_limit_soc.charge_limit_soc = soc;
}

void SimulatedVehicle::set_charging_amps(int amps) {
  charge_state_.which_optional_charging_amps = CarServer_ChargeState_charging_amps_tag;
  charge_state_.optional_charging_amps.charging_amps = amps;
}

void SimulatedVehicle::set_charger_power(float kw) {
  charge_state_.which_optional_charger_power = CarServer_ChargeState_charger_power_tag;
  charge_state_.optional_charger_power.charger_power = static_cast<int32_t>(kw);
}

void SimulatedVehicle::set_fast_charger_present(bool present) {
  charge_state_.which_optional_fast_charger_present = CarServer_ChargeState_fast_charger_present_tag;
  charge_state_.optional_fast_charger_present.fast_charger_present = present;
}

void SimulatedVehicle::set_charger_voltage(int volts) {
  charge_state_.which_optional_charger_voltage = CarServer_ChargeState_charger_voltage_tag;
  charge_state_.optional_charger_voltage.charger_voltage = volts;
}

void SimulatedVehicle::set_charger_actual_current(int amps) {
  charge_state_.which_optional_charger_actual_current = CarServer_ChargeState_charger_actual_current_tag;
  charge_state_.optional_charger_actual_current.charger_actual_current = amps;
}

void SimulatedVehicle::set_charger_pilot_current(int amps) {
  charge_state_.which_optional_charger_pilot_current = CarServer_ChargeState_charger_pilot_current_tag;
  charge_state_.optional_charger_pilot_current.charger_pilot_current = amps;
}

void SimulatedVehicle::set_charger_phases(int phases) {
  charge_state_.which_optional_charger_phases = CarServer_ChargeState_charger_phases_tag;
  charge_state_.optional_charger_phases.charger_phases = phases;
}

void SimulatedVehicle::set_charge_port_door_open(bool open) {
  charge_port_open_ = open;
  charge_state_.which_optional_charge_port_door_open = CarServer_ChargeState_charge_port_door_open_tag;
  charge_state_.optional_charge_port_door_open.charge_port_door_open = open;
}

void SimulatedVehicle::set_charge_port_latch(int state) {
  charge_state_.has_charge_port_latch = true;
  charge_state_.charge_port_latch.which_type = static_cast<pb_size_t>(state);
}

void SimulatedVehicle::set_inside_temp(float celsius) {
  climate_state_.which_optional_inside_temp_celsius = CarServer_ClimateState_inside_temp_celsius_tag;
  climate_state_.optional_inside_temp_celsius.inside_temp_celsius = celsius;
}

void SimulatedVehicle::set_outside_temp(float celsius) {
  climate_state_.which_optional_outside_temp_celsius = CarServer_ClimateState_outside_temp_celsius_tag;
  climate_state_.optional_outside_temp_celsius.outside_temp_celsius = celsius;
}

void SimulatedVehicle::set_climate_on(bool on) {
  climate_state_.which_optional_is_climate_on = CarServer_ClimateState_is_climate_on_tag;
  climate_state_.optional_is_climate_on.is_climate_on = on;
}

void SimulatedVehicle::set_climate_keeper_mode(int mode) {
  climate_state_.has_climate_keeper_mode = true;
  climate_state_.climate_keeper_mode.which_type = static_cast<pb_size_t>(mode);
}

void SimulatedVehicle::set_cabin_overheat_protection(int mode) {
  climate_state_.which_optional_cabin_overheat_protection = CarServer_ClimateState_cabin_overheat_protection_tag;
  climate_state_.optional_cabin_overheat_protection.cabin_overheat_protection =
      static_cast<CarServer_ClimateState_CabinOverheatProtection_E>(mode);
}

void SimulatedVehicle::set_bioweapon_mode(bool enable) {
  climate_state_.which_optional_bioweapon_mode_on = CarServer_ClimateState_bioweapon_mode_on_tag;
  climate_state_.optional_bioweapon_mode_on.bioweapon_mode_on = enable;
}

void SimulatedVehicle::set_seat_heater(TeslaBLE::SeatPosition seat, int level) {
  switch (seat) {
#define SET_SEAT(position, field) \
  case TeslaBLE::SeatPosition::position: \
    climate_state_.which_optional_##field = CarServer_ClimateState_##field##_tag; \
    climate_state_.optional_##field.field = level; \
    break;
    SET_SEAT(FRONT_LEFT, seat_heater_left)
    SET_SEAT(FRONT_RIGHT, seat_heater_right)
    SET_SEAT(REAR_LEFT, seat_heater_rear_left)
    SET_SEAT(REAR_LEFT_BACK, seat_heater_rear_left_back)
    SET_SEAT(REAR_CENTER, seat_heater_rear_center)
    SET_SEAT(REAR_RIGHT, seat_heater_rear_right)
    SET_SEAT(REAR_RIGHT_BACK, seat_heater_rear_right_back)
    SET_SEAT(THIRD_ROW_LEFT, seat_heater_third_row_left)
    SET_SEAT(THIRD_ROW_RIGHT, seat_heater_third_row_right)
#undef SET_SEAT
  }
}

void SimulatedVehicle::set_seat_cooler(TeslaBLE::SeatPosition seat, int level) {
  if (seat == TeslaBLE::SeatPosition::FRONT_LEFT) {
    climate_state_.which_optional_seat_fan_front_left = CarServer_ClimateState_seat_fan_front_left_tag;
    climate_state_.optional_seat_fan_front_left.seat_fan_front_left = level;
  } else if (seat == TeslaBLE::SeatPosition::FRONT_RIGHT) {
    climate_state_.which_optional_seat_fan_front_right = CarServer_ClimateState_seat_fan_front_right_tag;
    climate_state_.optional_seat_fan_front_right.seat_fan_front_right = level;
  }
}

void SimulatedVehicle::set_auto_seat_climate(TeslaBLE::SeatPosition seat, bool enabled) {
  if (seat == TeslaBLE::SeatPosition::FRONT_LEFT) {
    climate_state_.which_optional_auto_seat_climate_left = CarServer_ClimateState_auto_seat_climate_left_tag;
    climate_state_.optional_auto_seat_climate_left.auto_seat_climate_left = enabled;
  } else if (seat == TeslaBLE::SeatPosition::FRONT_RIGHT) {
    climate_state_.which_optional_auto_seat_climate_right = CarServer_ClimateState_auto_seat_climate_right_tag;
    climate_state_.optional_auto_seat_climate_right.auto_seat_climate_right = enabled;
  }
}

void SimulatedVehicle::set_steering_wheel_heat(bool enabled) {
  climate_state_.which_optional_steering_wheel_heater = CarServer_ClimateState_steering_wheel_heater_tag;
  climate_state_.optional_steering_wheel_heater.steering_wheel_heater = enabled;
}

void SimulatedVehicle::set_cabin_overheat_protection_temp(int level) {
  climate_state_.which_optional_cop_activation_temperature = CarServer_ClimateState_cop_activation_temperature_tag;
  climate_state_.optional_cop_activation_temperature.cop_activation_temperature =
      static_cast<CarServer_ClimateState_CopActivationTemp>(level);
}

void SimulatedVehicle::set_shift_state(int tag) {
  drive_state_.has_shift_state = true;
  drive_state_.shift_state.which_type = tag;
}

void SimulatedVehicle::set_odometer_miles(float miles) {
  drive_state_.which_optional_odometer_in_hundredths_of_a_mile =
      CarServer_DriveState_odometer_in_hundredths_of_a_mile_tag;
  drive_state_.optional_odometer_in_hundredths_of_a_mile.odometer_in_hundredths_of_a_mile =
      static_cast<int32_t>(miles * 100.0f);
}

void SimulatedVehicle::set_door_open(const std::string &door, bool open) {
  int index = -1;
  if (door == "driver_front") {
    index = 0;
  } else if (door == "passenger_front") {
    index = 1;
  } else if (door == "driver_rear") {
    index = 2;
  } else if (door == "passenger_rear") {
    index = 3;
  }
  if (index < 0) {
    return;
  }
  doors_open_[index] = open;
  switch (index) {
    case 0:
      closures_state_.which_optional_door_open_driver_front = CarServer_ClosuresState_door_open_driver_front_tag;
      closures_state_.optional_door_open_driver_front.door_open_driver_front = open;
      break;
    case 1:
      closures_state_.which_optional_door_open_passenger_front = CarServer_ClosuresState_door_open_passenger_front_tag;
      closures_state_.optional_door_open_passenger_front.door_open_passenger_front = open;
      break;
    case 2:
      closures_state_.which_optional_door_open_driver_rear = CarServer_ClosuresState_door_open_driver_rear_tag;
      closures_state_.optional_door_open_driver_rear.door_open_driver_rear = open;
      break;
    default:
      closures_state_.which_optional_door_open_passenger_rear = CarServer_ClosuresState_door_open_passenger_rear_tag;
      closures_state_.optional_door_open_passenger_rear.door_open_passenger_rear = open;
      break;
  }
}

void SimulatedVehicle::set_window_open(const std::string &window, bool open) {
  int index = -1;
  if (window == "driver_front") {
    index = 0;
  } else if (window == "passenger_front") {
    index = 1;
  } else if (window == "driver_rear") {
    index = 2;
  } else if (window == "passenger_rear") {
    index = 3;
  }
  if (index < 0) {
    return;
  }
  switch (index) {
    case 0:
      closures_state_.which_optional_window_open_driver_front = CarServer_ClosuresState_window_open_driver_front_tag;
      closures_state_.optional_window_open_driver_front.window_open_driver_front = open;
      break;
    case 1:
      closures_state_.which_optional_window_open_passenger_front =
          CarServer_ClosuresState_window_open_passenger_front_tag;
      closures_state_.optional_window_open_passenger_front.window_open_passenger_front = open;
      break;
    case 2:
      closures_state_.which_optional_window_open_driver_rear = CarServer_ClosuresState_window_open_driver_rear_tag;
      closures_state_.optional_window_open_driver_rear.window_open_driver_rear = open;
      break;
    default:
      closures_state_.which_optional_window_open_passenger_rear =
          CarServer_ClosuresState_window_open_passenger_rear_tag;
      closures_state_.optional_window_open_passenger_rear.window_open_passenger_rear = open;
      break;
  }
}

void SimulatedVehicle::set_tpms(int wheel, float bar) {
  switch (wheel) {
    case 0:
      tire_state_.which_optional_tpms_pressure_fl = CarServer_TirePressureState_tpms_pressure_fl_tag;
      tire_state_.optional_tpms_pressure_fl.tpms_pressure_fl = bar;
      break;
    case 1:
      tire_state_.which_optional_tpms_pressure_fr = CarServer_TirePressureState_tpms_pressure_fr_tag;
      tire_state_.optional_tpms_pressure_fr.tpms_pressure_fr = bar;
      break;
    case 2:
      tire_state_.which_optional_tpms_pressure_rl = CarServer_TirePressureState_tpms_pressure_rl_tag;
      tire_state_.optional_tpms_pressure_rl.tpms_pressure_rl = bar;
      break;
    case 3:
      tire_state_.which_optional_tpms_pressure_rr = CarServer_TirePressureState_tpms_pressure_rr_tag;
      tire_state_.optional_tpms_pressure_rr.tpms_pressure_rr = bar;
      break;
    default:
      break;
  }
}

void SimulatedVehicle::set_software_update_state(int status) {
  software_update_state_.has_status = true;
  software_update_state_.status.which_type = static_cast<pb_size_t>(status);
}

void SimulatedVehicle::set_sentry_mode_state(int tag) {
  closures_state_.has_sentry_mode_state = true;
  closures_state_.sentry_mode_state.which_type = static_cast<pb_size_t>(tag);
}

void SimulatedVehicle::set_sunroof_percent(int percent) {
  closures_state_.which_optional_sun_roof_percent_open = CarServer_ClosuresState_sun_roof_percent_open_tag;
  closures_state_.optional_sun_roof_percent_open.sun_roof_percent_open = percent;
}

void SimulatedVehicle::set_sentry_mode(bool enabled) {
  set_sentry_mode_state(enabled ? CarServer_ClosuresState_SentryModeState_Armed_tag
                                : CarServer_ClosuresState_SentryModeState_Off_tag);
  closures_state_.which_optional_sentry_mode_available = CarServer_ClosuresState_sentry_mode_available_tag;
  closures_state_.optional_sentry_mode_available.sentry_mode_available = true;
}

}  // namespace tesla_ble_python
