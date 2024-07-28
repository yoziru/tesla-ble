#include <chrono>
#include <pb.h>
#include <inttypes.h>

#include "signatures.pb.h"
#include "peer.h"
#include "errors.h"

namespace TeslaBLE
{
  void Peer::setCounter(const uint32_t counter)
  {
    this->counter_ = counter;
  }

  void Peer::incrementCounter()
  {
    this->counter_++;
  }

  int Peer::setEpoch(pb_byte_t *epoch)
  {
    if (epoch == nullptr)
    {
      LOG_ERROR("Epoch is null");
      return TeslaBLE_Status_E_ERROR_INVALID_SESSION;
    }

    // raise an error on empty / default epoch (e.g. epoch == 00000000000000000000000000000000)
    for (int i = 0; i < 16; i++)
    {
      if (epoch[i] != 0)
      {
        break;
      }
      if (i == 15)
      {
        LOG_ERROR("[Peer] Cannot set empty epoch");
        return TeslaBLE_Status_E_ERROR_INVALID_SESSION;
      }
    }

    for (int i = 0; i < 16; i++)
    {
      this->epoch_[i] = epoch[i];
    }
    return 0;
  }

  uint32_t Peer::generateExpiresAt(int seconds) const
  {
    uint32_t expiresAt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + std::chrono::seconds(seconds)) - this->time_zero_;
    return expiresAt;
  }

  void Peer::setTimeZero(const uint32_t time_zero)
  {
    this->time_zero_ = time_zero;
  }

  int Peer::updateSession(Signatures_SessionInfo *session_info)
  {
    LOG_DEBUG("Updating session..");
    // log epoch as hex
    char epoch_hex[33];
    for (int i = 0; i < 16; i++)
    {
      snprintf(epoch_hex + (i * 2), 3, "%02x", session_info->epoch[i]);
    }
    epoch_hex[32] = '\0';
    LOG_DEBUG("Epoch: %s", epoch_hex);
    LOG_DEBUG("Counter: %" PRIu32, session_info->counter);
    LOG_DEBUG("Clock time: %" PRIu32, session_info->clock_time);
    if (session_info == nullptr)
    {
      LOG_ERROR("Session info is null");
      return TeslaBLE_Status_E_ERROR_INVALID_SESSION;
    }

    int status = this->setEpoch(session_info->epoch);
    if (status != 0)
    {
      return status;
    }

    this->setCounter(session_info->counter);

    uint32_t generated_at = std::time(nullptr);
    uint32_t time_zero = generated_at - session_info->clock_time;
    this->setTimeZero(time_zero);

    this->setIsAuthenticated(true);

    // log epoch again to be sure
    char epoch_hex2[33];
    for (int i = 0; i < 16; i++)
    {
      snprintf(epoch_hex2 + (i * 2), 3, "%02x", this->epoch_[i]);
    }
    epoch_hex2[32] = '\0';
    LOG_DEBUG("Epoch [updated]: %s", epoch_hex2);
    return 0;
  }

  void Peer::setIsAuthenticated(bool is_authenticated)
  {
    this->is_authenticated_ = is_authenticated;
  }
} // namespace TeslaBLE
