#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <pb_encode.h>
#include <pb.h>
#include <sstream>

namespace TeslaBLE
{
  int pb_encode_fields(
      pb_byte_t *output_buffer,
      size_t *output_length,
      const pb_msgdesc_t *fields,
      const void *src_struct)
  {
    pb_ostream_t unsigned_message_size_stream = {nullptr, 0, 0, 0, nullptr};
    bool status_encode_length = pb_encode(&unsigned_message_size_stream, fields, src_struct);
    if (!status_encode_length)
    {
      printf("Failed to get encoded message size (err: %s)",
             PB_GET_ERROR(&unsigned_message_size_stream));
      return 1;
    }
    // printf("Bytes written: %zu\n", unsigned_message_size_stream.bytes_written);
    if (unsigned_message_size_stream.bytes_written == 0)
    {
      printf("\033[1;31mNo bytes written\033[0m\n");
      return 1;
    }
    *output_length = unsigned_message_size_stream.bytes_written;
    // printf("Message size: %hhu\n", *output_length);

    // now encode proper
    // printf("Encoding message\n");
    pb_ostream_t unsigned_message_stream = pb_ostream_from_buffer(output_buffer, *output_length);
    bool status_encode_bytes = pb_encode(&unsigned_message_stream, fields, src_struct);
    if (!status_encode_bytes)
    {
      printf("Failed to encode message (err: %s)",
             PB_GET_ERROR(&unsigned_message_stream));
      return 1;
    }
    return 0;
  }
} // namespace TeslaBLE
// #endif // MBEDTLS_CONFIG_FILE
