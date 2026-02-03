#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace vanity {

class GpuVanity {
 public:
  explicit GpuVanity(size_t max_batch);
  ~GpuVanity();

  bool ok() const;
  const std::string& error() const;
  size_t max_batch() const;

  bool generate(size_t count, const uint8_t* seeds_in, uint8_t* pubkeys_out,
                uint8_t* hashes_out);

 private:
  uint8_t* d_seeds_;
  uint8_t* d_pubkeys_;
  uint8_t* d_hashes_;
  size_t capacity_;
  bool ok_;
  std::string error_;
};

}  // namespace vanity
