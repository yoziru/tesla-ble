#ifndef TESLA_BLE_TB_UTILS_H
#define TESLA_BLE_TB_UTILS_H

#include <string>
#include "pb.h"

namespace TeslaBLE
{
  std::string uint8ToHexString(const uint8_t *v, size_t s);
  uint8_t *hexStrToUint8(const char *string);
  void dumpBuffer(const char *title, pb_byte_t *buf, size_t len);
  void dumpHexBuffer(const char *title, pb_byte_t *buf, size_t len);

  int pb_encode_fields(
      pb_byte_t *output_buffer,
      size_t *output_length,
      const pb_msgdesc_t *fields,
      const void *src_struct);
} // namespace TeslaBLE
#endif // TESLA_BLE_TB_UTILS_H
