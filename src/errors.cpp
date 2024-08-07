#include "errors.h"

namespace TeslaBLE
{
    // add helper functions to convert error codes to strings
    const char *TeslaBLE_Status_to_string(int status)
    {
        TeslaBLE_Status_E status_enum = static_cast<TeslaBLE_Status_E>(status);
        switch (status_enum)
        {
        case TeslaBLE_Status_E_OK:
            return "OK";
        case TeslaBLE_Status_E_ERROR_INTERNAL:
            return "ERROR_INTERNAL";
        case TeslaBLE_Status_E_ERROR_PB_ENCODING:
            return "ERROR_PB_ENCODING";
        case TeslaBLE_Status_E_ERROR_PB_DECODING:
            return "ERROR_PB_DECODING";
        case TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED:
            return "ERROR_PRIVATE_KEY_NOT_INITIALIZED";
        case TeslaBLE_Status_E_ERROR_INVALID_SESSION:
            return "ERROR_INVALID_SESSION";
        case TeslaBLE_Status_E_ERROR_ENCRYPT:
            return "ERROR_ENCRYPT";
        default:
            return "ERROR_UNKNOWN";
        }
    }
}
