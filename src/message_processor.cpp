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

void MessageProcessor::clear() {
  std::scoped_lock lock(queue_mutex_);
  while (!message_queue_.empty()) {
    message_queue_.pop();
  }
  ++generation_;
}

size_t MessageProcessor::process_messages() {
  // Called on every loop, usually with nothing queued. It used to build a
  // local std::queue first: a std::deque allocates its map and a node (one
  // ~750-byte RoutableMessage) even when empty, so every loop did two heap
  // allocations. Under BLE + Wi-Fi load that churn eventually failed and,
  // with exceptions disabled, aborted (seen on an ESP32). Now nothing is
  // allocated: messages are taken off the queue one at a time.
  size_t to_process;
  uint64_t generation;
  {
    std::scoped_lock lock(queue_mutex_);
    if (message_queue_.empty()) {
      return 0;
    }
    // Only what is queued now; messages queued meanwhile wait for the next call
    to_process = message_queue_.size();
    generation = generation_;
  }

  size_t processed = 0;
  for (size_t taken = 0; taken < to_process; ++taken) {
    UniversalMessage_RoutableMessage msg = UniversalMessage_RoutableMessage_init_default;
    {
      std::scoped_lock lock(queue_mutex_);
      if (message_queue_.empty() || generation != generation_) {
        break;
      }
      msg = message_queue_.front();
      message_queue_.pop();
    }
    if (message_handler_) {
      message_handler_(msg);
      processed++;
    }
  }

  return processed;
}

}  // namespace TeslaBLE
