#pragma once

#include <string>
#include "errors.h"
#include "pb.h"

namespace TeslaBLE {
std::string format_hex(const uint8_t *data, size_t length);

TeslaBLEStatus pb_encode_fields(pb_byte_t *output_buffer, size_t *output_length, const pb_msgdesc_t *fields,
                                const void *src_struct);
}  // namespace TeslaBLE
