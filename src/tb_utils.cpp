#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <pb_encode.h>
#include <pb.h>
#include <sstream>

#include "errors.h"

namespace TeslaBLE
{
  int pb_encode_fields(
      pb_byte_t *output_buffer,
      size_t *output_length,
      const pb_msgdesc_t *fields,
      const void *src_struct)
  {
    // Validate input parameters
    if (!output_buffer || !output_length || !fields || !src_struct)
    {
      printf("[E][pb_encode] Invalid parameters: output_buffer=%p, output_length=%p, fields=%p, src_struct=%p\n",
             output_buffer, output_length, fields, src_struct);
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }

    pb_ostream_t unsigned_message_size_stream = {nullptr, 0, 0, 0, nullptr};
    bool status_encode_length = pb_encode(&unsigned_message_size_stream, fields, src_struct);
    if (!status_encode_length)
    {
      printf("[E][pb_encode] Failed to get encoded message size (err: %s)\n",
             PB_GET_ERROR(&unsigned_message_size_stream));
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }
    // printf("Bytes written: %zu\n", unsigned_message_size_stream.bytes_written);
    if (unsigned_message_size_stream.bytes_written == 0)
    {
      printf("[E][pb_encode] No bytes written\n");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }
    *output_length = unsigned_message_size_stream.bytes_written;
    // printf("Message size: %hhu\n", *output_length);

    // now encode proper
    // printf("Encoding message\n");
    pb_ostream_t unsigned_message_stream = pb_ostream_from_buffer(output_buffer, *output_length);
    bool status_encode_bytes = pb_encode(&unsigned_message_stream, fields, src_struct);
    if (!status_encode_bytes)
    {
      printf("[E][pb_encode] Failed to encode message (err: %s)\n",
             PB_GET_ERROR(&unsigned_message_stream));
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }
    return 0;
  }
} // namespace TeslaBLE
// #endif // MBEDTLS_CONFIG_FILE
