/**
 * @file message_processor.cpp
 * @brief Ordered message processing implementation
 */

#include "message_processor.h"
#include "defs.h"
#include "vehicle.h"

namespace TeslaBLE {

MessageProcessor::MessageProcessor(MessageHandler handler) : message_handler_(std::move(handler)) {}

MessageProcessor::~MessageProcessor() = default;

void MessageProcessor::queue_message(const UniversalMessage_RoutableMessage &msg) {
  std::scoped_lock lock(queue_mutex_);
  message_queue_.push(msg);

  // Limit queue size to prevent memory exhaustion
  if (message_queue_.size() > MessageProcessor::MAX_QUEUE_SIZE) {
    LOG_WARNING("Message queue size limit reached, dropping oldest messages");
    message_queue_.pop();
  }
}

size_t MessageProcessor::process_messages() {
  std::queue<UniversalMessage_RoutableMessage> pending;
  {
    std::scoped_lock lock(queue_mutex_);
    if (message_queue_.empty()) {
      return 0;
    }

    pending.swap(message_queue_);
  }

  size_t processed = 0;
  if (message_handler_) {
    while (!pending.empty()) {
      const auto msg = pending.front();
      pending.pop();
      message_handler_(msg);
      processed++;
    }
  }

  return processed;
}

}  // namespace TeslaBLE
