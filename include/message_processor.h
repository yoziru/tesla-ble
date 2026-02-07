/**
 * @file message_processor.h
 * @brief Ordered message processing to prevent race conditions
 *
 * This class provides a queue-based message processor that ensures
 * messages are processed in the order they are received, preventing
 * race conditions between error handling and session info processing.
 */

#pragma once

#include <queue>
#include <mutex>
#include <memory>
#include <functional>
#include "universal_message.pb.h"

namespace TeslaBLE {

/**
 * @brief Message processor with guaranteed order preservation
 *
 * Messages are queued and processed sequentially to prevent race conditions
 * that were causing issues like:
 * - ERROR_INVALID_SIGNATURE followed by immediate SessionInfo with cleared error state
 * - Session update being processed before error state could be checked
 */
class MessageProcessor {
 public:
  using MessageHandler = std::function<void(const UniversalMessage_RoutableMessage &)>;

  /**
   * @brief Constructor with message handler
   * @param handler Function to handle processed messages
   */
  explicit MessageProcessor(MessageHandler handler);

  /**
   * @brief Destructor
   */
  ~MessageProcessor();

  /**
   * @brief Queue a message for processing
   * @param msg Message to queue
   */
  void queue_message(const UniversalMessage_RoutableMessage &msg);

  /**
   * @brief Process all queued messages
   *
   * This should be called regularly to process messages in order.
   * Returns the number of messages processed.
   */
  size_t process_messages();

  /**
   * @brief Check if message processor is busy
   * @return true if messages are being processed
   */
  bool is_processing() const;

  /**
   * @brief Get current queue size
   * @return Number of queued messages
   */
  size_t get_queue_size() const;

  /**
   * @brief Clear all queued messages
   */
  void clear_queue();

 private:
  static constexpr size_t MAX_QUEUE_SIZE = 1000;
  MessageHandler message_handler_;
  std::queue<UniversalMessage_RoutableMessage> message_queue_;
  mutable std::mutex queue_mutex_;
  bool processing_ = false;
};

/**
 * @brief Global message processor instance
 */
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
extern std::unique_ptr<MessageProcessor> g_message_processor;

/**
 * @brief Initialize global message processor
 * @param handler Message handler function
 */
void initialize_message_processor(MessageProcessor::MessageHandler handler);

/**
 * @brief Cleanup global message processor
 */
void cleanup_message_processor();

}  // namespace TeslaBLE
