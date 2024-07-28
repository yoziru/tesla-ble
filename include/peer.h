#pragma once

#include <array>
#include <cstdint>
#include <pb.h>
#include "signatures.pb.h"
#include "universal_message.pb.h"
#include "defs.h"

namespace TeslaBLE
{

  class Peer
  {
  public:
    uint32_t generateExpiresAt(int seconds) const;

    uint32_t getTimeZero() const { return time_zero_; }
    uint32_t getCounter() const { return counter_; }
    pb_byte_t *getEpoch() { return epoch_; }
    bool getIsAuthenticated() const { return is_authenticated_; }

    void incrementCounter();
    void setCounter(uint32_t counter);
    int setEpoch(pb_byte_t *epoch);
    void setIsAuthenticated(bool is_authenticated);
    void setTimeZero(uint32_t time_zero);

    int updateSession(Signatures_SessionInfo *session_info);

  private:
    UniversalMessage_Domain domain;

    pb_byte_t epoch_[16];
    uint32_t counter_ = 0;
    uint32_t time_zero_ = 0;
    bool is_authenticated_ = false;
  };

} // namespace TeslaBLE
