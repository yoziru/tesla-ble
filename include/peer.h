#ifndef TESLA_BLE_PEER_H
#define TESLA_BLE_PEER_H

#include <pb.h>
#include "universal_message.pb.h"

namespace TeslaBLE
{
  class Peer
  {
  public:
    // Session session;
    UniversalMessage_Domain domain;
    uint32_t counter_ = 0;
    pb_byte_t epoch_[16];
    uint32_t expires_at_ = 0;
    uint32_t time_zero_ = 0;

    void setCounter(const uint32_t *counter);
    void incrementCounter();
    void setExpiresAt(const uint32_t *expires_at);
    uint32_t generateExpiresAt(int seconds);
    void setTimeZero(const uint32_t *time_zero);
    void setEpoch(pb_byte_t *epoch);

    bool isAuthenticated = false;
    void setIsAuthenticated(bool isAuthenticated);
  };
} // namespace TeslaBLE
#endif // TESLA_BLE_PEER_H
