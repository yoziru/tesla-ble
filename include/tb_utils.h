#ifndef TESLA_BLE_TB_UTILS_H
#define TESLA_BLE_TB_UTILS_H

#include <string>
#include "pb.h"

namespace TeslaBLE
{
  int pb_encode_fields(
      pb_byte_t *output_buffer,
      size_t *output_length,
      const pb_msgdesc_t *fields,
      const void *src_struct);
} // namespace TeslaBLE
#endif // TESLA_BLE_TB_UTILS_H
