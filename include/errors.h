#ifndef TESLA_BLE_ERRORS_H
#define TESLA_BLE_ERRORS_H

namespace TeslaBLE
{

    typedef enum _TeslaBLE_Status_E
    {
        TeslaBLE_Status_E_OK = 0,                /* Request succeeded. */
        TeslaBLE_Status_E_ERROR_INTERNAL = 1,    /* Something went wrong. */
        TeslaBLE_Status_E_ERROR_PB_ENCODING = 2, /* Error encoding protobuf payload to vehicle. */
        TeslaBLE_Status_E_ERROR_PB_DECODING = 3, /* Error decoding protobuf payload from vehicle. */

        TeslaBLE_Status_E_ERROR_PRIVATE_KEY_NOT_INITIALIZED = 4, /* Private key not initialized. */
        TeslaBLE_Status_E_ERROR_INVALID_SESSION = 5,         /* Invalid session from vehicle. */
        TeslaBLE_Status_E_ERROR_ENCRYPT = 6,         /* Error encrypting payload. */
        TeslaBLE_Status_E_ERROR_DECRYPT = 7,         /* Error decrypting response payload. */
        TeslaBLE_Status_E_ERROR_INVALID_PARAMS = 8,  /* Invalid input parameters. */
        TeslaBLE_Status_E_ERROR_CRYPTO = 9,          /* Cryptographic operation failed. */
    } TeslaBLE_Status_E;

    // add helper functions to convert error codes to strings
    const char *TeslaBLE_Status_to_string(int status);
} // namespace TeslaBLE
#endif // TESLA_BLE_ERRORS_H
