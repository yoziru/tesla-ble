#include <chrono>
#include <pb.h>

#include "peer.h"

namespace TeslaBLE
{
  void Peer::setCounter(const uint32_t *counter)
  {
    this->counter_ = *counter;
  }

  void Peer::incrementCounter()
  {
    this->counter_++;
  }

  void Peer::setEpoch(pb_byte_t *epoch)
  {
    memcpy(this->epoch_, epoch, 16);
  }
  void Peer::setExpiresAt(const uint32_t *expires_at)
  {
    this->expires_at_ = *expires_at;
  }
  uint32_t Peer::generateExpiresAt(int seconds)
  {
    uint32_t expiresAt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + std::chrono::seconds(seconds)) - this->time_zero_;
    return expiresAt;
  }
  void Peer::setTimeZero(const uint32_t *time_zero)
  {
    this->time_zero_ = *time_zero;
  }
  void Peer::setIsAuthenticated(bool isAuthenticated)
  {
    this->isAuthenticated = isAuthenticated;
  }
} // namespace TeslaBLE
