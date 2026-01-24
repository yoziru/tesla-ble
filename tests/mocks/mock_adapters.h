#pragma once

#include <adapters.h>
#include <vector>
#include <string>
#include <map>
#include <gtest/gtest.h>

namespace TeslaBLE {

class MockBleAdapter : public BleAdapter {
 public:
  // Mock interface implementation
  void connect(const std::string &address) override {
    // No-op for mock
  }

  void disconnect() override {
    // No-op for mock
  }

  bool write(const std::vector<uint8_t> &data) override {
    written_data_.push_back(data);
    return true;  // Simulate success
  }

  // Helper for tests to inspect what was written
  const std::vector<std::vector<uint8_t>> &get_written_data() const { return written_data_; }

  void clear_written_data() { written_data_.clear(); }

 private:
  std::vector<std::vector<uint8_t>> written_data_;
};

class MockStorageAdapter : public StorageAdapter {
 public:
  // Mock interface implementation
  bool load(const std::string &key, std::vector<uint8_t> &value) override {
    if (storage_.count(key)) {
      value = storage_[key];
      return true;
    }
    return false;
  }

  bool save(const std::string &key, const std::vector<uint8_t> &value) override {
    storage_[key] = value;
    return true;
  }

  bool remove(const std::string &key) override { return storage_.erase(key) > 0; }

  // Helper to preload data
  void set_data(const std::string &key, const std::vector<uint8_t> &value) { storage_[key] = value; }

 private:
  std::map<std::string, std::vector<uint8_t>> storage_;
};

}  // namespace TeslaBLE
