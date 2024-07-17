#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <pb_encode.h>
#include <pb.h>
#include <sstream>

namespace TeslaBLE
{
  uint8_t *hexStrToUint8(const char *string)
  {
    if (string == NULL)
      return NULL;

    size_t slength = strlen(string);
    if ((slength % 2) != 0) // must be even
      return NULL;

    size_t dlength = slength / 2;
    uint8_t *data = (uint8_t *)malloc(dlength);
    memset(data, 0, dlength);
    size_t index = 0;

    while (index < slength)
    {
      char c = string[index];
      int value = 0;
      if (c >= '0' && c <= '9')
        value = (c - '0');
      else if (c >= 'A' && c <= 'F')
        value = (10 + (c - 'A'));
      else if (c >= 'a' && c <= 'f')
        value = (10 + (c - 'a'));
      else
        return NULL;

      data[(index / 2)] += value << (((index + 1) % 2) * 4);
      index++;
    }

    return data;
  }

  std::string uint8ToHexString(const uint8_t *v, size_t s)
  {
    std::stringstream stream;
    stream << std::hex << std::setfill('0');
    for (int i = 0; i < s; i++)
    {
      stream << std::hex << std::setw(2) << static_cast<int>(v[i]);
    }
    return stream.str();
  }

  void dumpHexBuffer(const char *title, pb_byte_t *buf, size_t len)
  {
    size_t i = 0;
    printf("\n%s", title);
    for (i = 0; i < len; i++)
    {
      printf("%c%c", "0123456789ABCDEF"[buf[i] / 16],
             "0123456789ABCDEF"[buf[i] % 16]);
    }
    printf("\n");
  }

  void dumpBuffer(const char *title, pb_byte_t *buf, size_t len)
  {
    size_t i = 0;
    printf("\n%s", title);
    for (i = 0; i < len; i++)
    {
      printf("%c", buf[i]);
    }
    printf("\n");
  }

  int pb_encode_fields(
      pb_byte_t *output_buffer,
      size_t *output_length,
      const pb_msgdesc_t *fields,
      const void *src_struct)
  {
    // pb_encode(pb_ostream_t *stream, const pb_msgdesc_t *fields, const void *src_struct)
    // first get message length
    // printf("Getting message length\n");

    pb_ostream_t unsigned_message_size_stream = {nullptr, 0, 0, 0, nullptr};
    bool status_encode_length = pb_encode(&unsigned_message_size_stream, fields, src_struct);
    if (!status_encode_length)
    {
      printf("Failed to get encoded message size (err: %s)",
             PB_GET_ERROR(&unsigned_message_size_stream));
      return 1;
    }
    printf("Bytes written: %zu\n", unsigned_message_size_stream.bytes_written);
    if (unsigned_message_size_stream.bytes_written == 0)
    {
      printf("\033[1;31mNo bytes written\033[0m\n");
      return 1;
    }
    *output_length = unsigned_message_size_stream.bytes_written;
    // printf("Message size: %hhu\n", *output_length);

    // now encode proper
    printf("Encoding message\n");
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
