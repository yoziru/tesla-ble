#include "tb_utils.h"

#include "defs.h"
#include "errors.h"

#include <pb.h>
#include <pb_encode.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace TeslaBLE
{
  std::string format_hex(const uint8_t* data, size_t length)
  {
      if (data == nullptr || length == 0) return "";
      std::string hex;
      hex.reserve(length * 2);
      char buf[3];
      for (size_t i = 0; i < length; ++i) {
          snprintf(buf, sizeof(buf), "%02x", data[i]);
          hex.append(buf);
      }
      return hex;
  }

  int pb_encode_fields(
      pb_byte_t *output_buffer,
      size_t *output_length,
      const pb_msgdesc_t *fields,
      const void *src_struct)
  {
    // Validate input parameters
    if (!output_buffer || !output_length || !fields || !src_struct)
    {
      LOG_ERROR("pb_encode: Invalid parameters (buffer=%p, length=%p, fields=%p, struct=%p)",
                output_buffer, output_length, fields, src_struct);
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }

    pb_ostream_t unsigned_message_size_stream = {nullptr, 0, 0, 0, nullptr};
    bool status_encode_length = pb_encode(&unsigned_message_size_stream, fields, src_struct);
    if (!status_encode_length)
    {
      LOG_ERROR("pb_encode: Failed to get encoded message size (err: %s)",
                PB_GET_ERROR(&unsigned_message_size_stream));
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }
    if (unsigned_message_size_stream.bytes_written == 0)
    {
      LOG_ERROR("pb_encode: No bytes written");
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }
    *output_length = unsigned_message_size_stream.bytes_written;

    // now encode proper
    pb_ostream_t unsigned_message_stream = pb_ostream_from_buffer(output_buffer, *output_length);
    bool status_encode_bytes = pb_encode(&unsigned_message_stream, fields, src_struct);
    if (!status_encode_bytes)
    {
      LOG_ERROR("pb_encode: Failed to encode message (err: %s)",
                PB_GET_ERROR(&unsigned_message_stream));
      return TeslaBLE_Status_E_ERROR_PB_ENCODING;
    }
    return TeslaBLE_Status_E_OK;
  }
} // namespace TeslaBLE
// #endif // MBEDTLS_CONFIG_FILE
