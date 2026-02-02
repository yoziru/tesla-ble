#include "message_processor.h"
#include <memory>
#include "defs.h"

namespace TeslaBLE {

MessageProcessor::MessageProcessor(MessageHandler handler) : message_handler_(std::move(handler)) {}

MessageProcessor::~MessageProcessor() = default;

void MessageProcessor::queue_message(const UniversalMessage_RoutableMessage &msg) {
  std::scoped_lock lock(queue_mutex_);
  message_queue_.push(msg);

  static constexpr size_t MAX_QUEUE_SIZE = 50;
  if (message_queue_.size() > MAX_QUEUE_SIZE) {
    LOG_WARNING("Message queue size limit reached, dropping oldest messages");
    message_queue_.pop();
  }
}

size_t MessageProcessor::process_messages() {
  std::scoped_lock lock(queue_mutex_);
  if (message_queue_.empty())
    return 0;

  processing_ = true;
  size_t processed = 0;

  while (!message_queue_.empty()) {
    auto msg = message_queue_.front();
    message_queue_.pop();
    if (message_handler_) {
      message_handler_(msg);
      processed++;
    }
  }

  processing_ = false;
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
  while (!message_queue_.empty())
    message_queue_.pop();
}

void MessageProcessor::process_message_(const UniversalMessage_RoutableMessage &msg) {
  LOG_DEBUG("Processing routed message from domain: %d",
            msg.has_from_destination ? static_cast<int>(msg.from_destination.sub_destination.domain) : -1);
}

namespace {
// Global instance
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::unique_ptr<MessageProcessor> g_message_processor = nullptr;
}  // namespace

MessageProcessor *get_message_processor() { return g_message_processor.get(); }

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