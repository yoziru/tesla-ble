#pragma once

#include <queue>
#include <mutex>
#include <functional>
#include "universal_message.pb.h"

namespace TeslaBLE {

class MessageProcessor {
 public:
  using MessageHandler = std::function<void(const UniversalMessage_RoutableMessage &)>;

  explicit MessageProcessor(MessageHandler handler);
  ~MessageProcessor();

  void queue_message(const UniversalMessage_RoutableMessage &msg);
  size_t process_messages();
  bool is_processing() const;
  size_t get_queue_size() const;
  void clear_queue();

 private:
  void process_message_(const UniversalMessage_RoutableMessage &msg);

  MessageHandler message_handler_;
  std::queue<UniversalMessage_RoutableMessage> message_queue_;
  mutable std::mutex queue_mutex_;
  bool processing_ = false;
};

MessageProcessor *get_message_processor();
void initialize_message_processor(MessageProcessor::MessageHandler handler);
void cleanup_message_processor();

}  // namespace TeslaBLE