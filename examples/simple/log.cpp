#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <signatures.pb.h>
#include <universal_message.pb.h>
#include <vcsec.pb.h>

// Helper function to convert UniversalMessage_OperationStatus_E enum to string
static const char *operation_status_to_string(UniversalMessage_OperationStatus_E status)
{
  switch (status)
  {
  case UniversalMessage_OperationStatus_E_OPERATIONSTATUS_OK:
    return "OK";
  case UniversalMessage_OperationStatus_E_OPERATIONSTATUS_WAIT:
    return "WAIT";
  case UniversalMessage_OperationStatus_E_OPERATIONSTATUS_ERROR:
    return "ERROR";
  default:
    return "UNKNOWN_STATUS";
  }
}

static const char *information_request_type_to_string(VCSEC_InformationRequestType request_type)
{
  switch (request_type)
  {
  case VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_STATUS:
    return "GET_STATUS";
  case VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_WHITELIST_INFO:
    return "GET_WHITELIST_INFO";
  case VCSEC_InformationRequestType_INFORMATION_REQUEST_TYPE_GET_WHITELIST_ENTRY_INFO:
    return "GET_WHITELIST_ENTRY_INFO";
  default:
    return "UNKNOWN_REQUEST_TYPE";
  }
}

// Helper function to convert UniversalMessage_MessageFault_E enum to string
static const char *message_fault_to_string(UniversalMessage_MessageFault_E fault)
{
  switch (fault)
  {
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NONE:
    return "ERROR_NONE";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_BUSY:
    return "ERROR_BUSY";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_TIMEOUT:
    return "ERROR_TIMEOUT";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_UNKNOWN_KEY_ID:
    return "ERROR_UNKNOWN_KEY_ID";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INACTIVE_KEY:
    return "ERROR_INACTIVE_KEY";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INVALID_SIGNATURE:
    return "ERROR_INVALID_SIGNATURE";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER:
    return "ERROR_INVALID_TOKEN_OR_COUNTER";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INSUFFICIENT_PRIVILEGES:
    return "ERROR_INSUFFICIENT_PRIVILEGES";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INVALID_DOMAINS:
    return "ERROR_INVALID_DOMAINS";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INVALID_COMMAND:
    return "ERROR_INVALID_COMMAND";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_DECODING:
    return "ERROR_DECODING";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INTERNAL:
    return "ERROR_INTERNAL";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_WRONG_PERSONALIZATION:
    return "ERROR_WRONG_PERSONALIZATION";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_BAD_PARAMETER:
    return "ERROR_BAD_PARAMETER";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_KEYCHAIN_IS_FULL:
    return "ERROR_KEYCHAIN_IS_FULL";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_INCORRECT_EPOCH:
    return "ERROR_INCORRECT_EPOCH";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_IV_INCORRECT_LENGTH:
    return "ERROR_IV_INCORRECT_LENGTH";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_TIME_EXPIRED:
    return "ERROR_TIME_EXPIRED";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_NOT_PROVISIONED_WITH_IDENTITY:
    return "ERROR_NOT_PROVISIONED_WITH_IDENTITY";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_COULD_NOT_HASH_METADATA:
    return "ERROR_COULD_NOT_HASH_METADATA";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_TIME_TO_LIVE_TOO_LONG:
    return "ERROR_TIME_TO_LIVE_TOO_LONG";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_REMOTE_ACCESS_DISABLED:
    return "ERROR_REMOTE_ACCESS_DISABLED";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_REMOTE_SERVICE_ACCESS_DISABLED:
    return "ERROR_REMOTE_SERVICE_ACCESS_DISABLED";
  case UniversalMessage_MessageFault_E_MESSAGEFAULT_ERROR_COMMAND_REQUIRES_ACCOUNT_CREDENTIALS:
    return "ERROR_COMMAND_REQUIRES_ACCOUNT_CREDENTIALS";
  default:
    return "UNKNOWN_FAULT";
  }
}

// Function to log UniversalMessage_MessageStatus
static void log_message_status(const UniversalMessage_MessageStatus *status)
{
  printf("  MessageStatus:\n");
  printf("    operation_status: %s\n", operation_status_to_string(status->operation_status));
  printf("    signed_message_fault: %s\n", message_fault_to_string(status->signed_message_fault));
}

// Function to convert UniversalMessage_Domain enum to string
static const char *domain_to_string(UniversalMessage_Domain domain)
{
  switch (domain)
  {
  case UniversalMessage_Domain_DOMAIN_BROADCAST:
    return "DOMAIN_BROADCAST";
  case UniversalMessage_Domain_DOMAIN_VEHICLE_SECURITY:
    return "DOMAIN_VEHICLE_SECURITY";
  case UniversalMessage_Domain_DOMAIN_INFOTAINMENT:
    return "DOMAIN_INFOTAINMENT";
  default:
    return "UNKNOWN_DOMAIN";
  }
}

static void log_destination(const char *direction,
                     const UniversalMessage_Destination *dest)
{
  printf("Destination: %s\n", direction);
  printf("  which_sub_destination: %d\n", dest->which_sub_destination);
  switch (dest->which_sub_destination)
  {
  case UniversalMessage_Destination_domain_tag:
    printf("  domain: %s\n", domain_to_string(dest->sub_destination.domain));
    break;
  case UniversalMessage_Destination_routing_address_tag:
    // dest->sub_destination.routing_address
    // print routing_address as hex
    printf("  routing_address: ");
    for (int i = 0; i < sizeof(dest->sub_destination.routing_address); i++)
    {
      printf("%02X", dest->sub_destination.routing_address[i]);
    }
    printf("\n");
    break;
  default:
    printf("  unknown sub_destination\n");
  }
}

static void log_session_info_request(const UniversalMessage_SessionInfoRequest *req)
{
  printf("  SessionInfoRequest:");
  printf("    public_key: %s\n", req->public_key.bytes);
  printf("    challenge: %s\n", req->challenge.bytes);
}

static void log_session_info(const Signatures_SessionInfo *req)
{
  printf("  SessionInfo:\n");
  printf("    counter: %" PRIu32, req->counter);
  printf("\n");
  printf("    publicKey: \n");
  for (int i = 0; i < req->publicKey.size; i++)
  {
    printf("%02X", req->publicKey.bytes[i]);
  }
  printf("\n");

  printf("    epoch: ");
  for (int i = 0; i < sizeof(req->epoch); i++)
  {
    printf("%02X", req->epoch[i]);
  }
  printf("\n");
  // convert uint32_t to int32_t
  printf("    clock_time: %" PRIu32, req->clock_time);
  printf("\n");
  // int32_t *clock_time_converted = (int32_t *)&req->clock_time;
  // printf("    clock_time converted: %" PRIu32, *clock_time_converted);
  // printf("\n");
  printf("    status: %d\n", req->status);
}

static void log_aes_gcm_personalized_signature_data(const Signatures_AES_GCM_Personalized_Signature_Data *data)
{
  printf("    AES_GCM_Personalized_Signature_Data:");
  // printf("      epoch: %s\n", data->epoch);
  // printf("      nonce: %s\n", data->nonce);
  printf("      counter: %" PRIu32, data->counter);
  printf("      expires_at: %" PRIu32, data->expires_at);
  // printf("      tag: %s\n", data->tag);
}

static void log_signature_data(const Signatures_SignatureData *sig)
{
  printf("  SignatureData:");
  printf("    has_signer_identity: %s\n", sig->has_signer_identity ? "true" : "false");
  if (sig->has_signer_identity)
  {
    printf("    signer_identity: (implement logging for Signatures_KeyIdentity)");
  }
  printf("    which_sig_type: %d\n", sig->which_sig_type);
  switch (sig->which_sig_type)
  {
  case Signatures_SignatureData_AES_GCM_Personalized_data_tag:
    log_aes_gcm_personalized_signature_data(&sig->sig_type.AES_GCM_Personalized_data);
    break;
  case Signatures_SignatureData_session_info_tag_tag:
    printf("    session_info_tag: (implement logging for Signatures_HMAC_Signature_Data)");
    break;
  case Signatures_SignatureData_HMAC_Personalized_data_tag:
    printf("    HMAC_Personalized_data: (implement logging for Signatures_HMAC_Personalized_Signature_Data)");
    break;
  default:
    printf("    unknown sig_type");
  }
}

static void log_information_request(const VCSEC_InformationRequest *msg)
{
  printf("VCSEC_InformationRequest:");
  printf("  which_request: %d\n", msg->which_key);

  printf("  informationRequestType: %s\n", information_request_type_to_string(msg->informationRequestType));
  printf("  publicKeySHA1: %s\n", msg->key.keyId.publicKeySHA1.bytes);
  printf("  publicKey");
  // ESP_LOG_BUFFER_HEX_LEVEL(msg->key.publicKey.bytes, msg->key.publicKey.size, ESP_LOG_DEBUG);
  printf("  publicKeySHA1: %" PRIu32, msg->key.slot);
}

static void log_routable_message(const UniversalMessage_RoutableMessage *msg)
{
  printf("UniversalMessage_RoutableMessage:\n");
  printf("  has_to_destination: %s\n", msg->has_to_destination ? "true" : "false");
  // if (msg->has_to_destination)
  // {
  log_destination("to_destination", &msg->to_destination);
  // }

  printf("  has_from_destination: %s\n", msg->has_from_destination ? "true" : "false");
  if (msg->has_from_destination)
  {
    log_destination("from_destination", &msg->from_destination);
  }

  printf("  which_payload: %d\n", msg->which_payload);
  switch (msg->which_payload)
  {
  case UniversalMessage_RoutableMessage_protobuf_message_as_bytes_tag:
  case UniversalMessage_RoutableMessage_session_info_tag:
    printf("  payload: protobuf_message_as_bytes\n");
    // print bytes as hex
    // printf("    payload: %s\n", msg->payload.protobuf_message_as_bytes.bytes);
    printf("    payload: ");
    for (int i = 0; i < msg->payload.protobuf_message_as_bytes.size; i++)
    {
      printf("%02X", msg->payload.protobuf_message_as_bytes.bytes[i]);
    }
    printf("\n");
    break;
  case UniversalMessage_RoutableMessage_session_info_request_tag:
    printf("  payload: session_info_request\n");
    log_session_info_request(&msg->payload.session_info_request);
    break;
  default:
    printf("  payload: unknown\n");
  }

  printf("  has_signedMessageStatus: %s\n", msg->has_signedMessageStatus ? "true" : "false");
  if (msg->has_signedMessageStatus)
  {
    log_message_status(&msg->signedMessageStatus);
  }

  printf("  which_sub_sigData: %d\n", msg->which_sub_sigData);
  if (msg->which_sub_sigData == UniversalMessage_RoutableMessage_signature_data_tag)
  {
    log_signature_data(&msg->sub_sigData.signature_data);
  }

  // print uuid
  printf("  uuid: ");
  for (int i = 0; i < sizeof(msg->uuid); i++)
  {
    printf("%02X", msg->uuid[i]);
  }
  printf("\n");
  printf("  flags: %" PRIu32, msg->flags);
  printf("\n");
}
