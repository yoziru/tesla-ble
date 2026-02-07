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

    processing_ = true;
    pending.swap(message_queue_);
  }

  struct ProcessingGuard {
    MessageProcessor *processor;
    ~ProcessingGuard() {
      std::scoped_lock guard(processor->queue_mutex_);
      processor->processing_ = false;
    }
  } guard{this};

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

bool MessageProcessor::is_processing() const {
  std::scoped_lock lock(queue_mutex_);
  return processing_;
}

size_t MessageProcessor::get_queue_size() const {
  std::scoped_lock lock(queue_mutex_);
  return message_queue_.size();
}

void MessageProcessor::clear_queue() {
  std::scoped_lock lock(queue_mutex_);
  std::queue<UniversalMessage_RoutableMessage> empty;
  message_queue_.swap(empty);
}

// Global instance - now must be initialized with handler
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::unique_ptr<MessageProcessor> g_message_processor = nullptr;

void initialize_message_processor(MessageProcessor::MessageHandler handler) {
  if (!g_message_processor) {
    g_message_processor = std::make_unique<MessageProcessor>(std::move(handler));
    LOG_INFO("Global message processor initialized");
  }
}

void cleanup_message_processor() {
  if (g_message_processor) {
    g_message_processor->clear_queue();
    g_message_processor.reset();
    LOG_INFO("Global message processor cleaned up");
  }
}

}  // namespace TeslaBLE
