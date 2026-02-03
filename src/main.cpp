#include "gpu_vanity.h"
#include "match_rule.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iostream>
#include <mutex>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#include <cstring>

#include <sodium.h>

namespace {

constexpr size_t kSeedSize = 32;
constexpr size_t kPubKeySize = 32;
constexpr size_t kHashSize = 32;
constexpr size_t kPrivateKeySize = 64;
constexpr size_t kOpenSshBlockSize = 8;
constexpr size_t kPayloadSize = 51;

size_t base64_no_pad(const uint8_t* data, size_t len, char* out) {
  static constexpr char kTable[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t out_len = 0;
  size_t i = 0;
  for (; i + 2 < len; i += 3) {
    uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                 (static_cast<uint32_t>(data[i + 1]) << 8) |
                 static_cast<uint32_t>(data[i + 2]);
    out[out_len++] = kTable[(v >> 18) & 0x3f];
    out[out_len++] = kTable[(v >> 12) & 0x3f];
    out[out_len++] = kTable[(v >> 6) & 0x3f];
    out[out_len++] = kTable[v & 0x3f];
  }

  size_t remaining = len - i;
  if (remaining == 1) {
    uint32_t v = static_cast<uint32_t>(data[i]) << 16;
    out[out_len++] = kTable[(v >> 18) & 0x3f];
    out[out_len++] = kTable[(v >> 12) & 0x3f];
  } else if (remaining == 2) {
    uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                 (static_cast<uint32_t>(data[i + 1]) << 8);
    out[out_len++] = kTable[(v >> 18) & 0x3f];
    out[out_len++] = kTable[(v >> 12) & 0x3f];
    out[out_len++] = kTable[(v >> 6) & 0x3f];
  }

  return out_len;
}

std::string base64_encode(const uint8_t* data, size_t len) {
  static constexpr char kTable[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((len + 2) / 3) * 4);
  size_t i = 0;
  for (; i + 2 < len; i += 3) {
    uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                 (static_cast<uint32_t>(data[i + 1]) << 8) |
                 static_cast<uint32_t>(data[i + 2]);
    out.push_back(kTable[(v >> 18) & 0x3f]);
    out.push_back(kTable[(v >> 12) & 0x3f]);
    out.push_back(kTable[(v >> 6) & 0x3f]);
    out.push_back(kTable[v & 0x3f]);
  }

  size_t remaining = len - i;
  if (remaining == 1) {
    uint32_t v = static_cast<uint32_t>(data[i]) << 16;
    out.push_back(kTable[(v >> 18) & 0x3f]);
    out.push_back(kTable[(v >> 12) & 0x3f]);
    out.push_back('=');
    out.push_back('=');
  } else if (remaining == 2) {
    uint32_t v = (static_cast<uint32_t>(data[i]) << 16) |
                 (static_cast<uint32_t>(data[i + 1]) << 8);
    out.push_back(kTable[(v >> 18) & 0x3f]);
    out.push_back(kTable[(v >> 12) & 0x3f]);
    out.push_back(kTable[(v >> 6) & 0x3f]);
    out.push_back('=');
  }

  return out;
}

void append_u32(std::string& out, uint32_t value) {
  out.push_back(static_cast<char>((value >> 24) & 0xff));
  out.push_back(static_cast<char>((value >> 16) & 0xff));
  out.push_back(static_cast<char>((value >> 8) & 0xff));
  out.push_back(static_cast<char>(value & 0xff));
}

void append_string(std::string& out, std::string_view value) {
  append_u32(out, static_cast<uint32_t>(value.size()));
  out.append(value.data(), value.size());
}

void append_string(std::string& out, const uint8_t* data, size_t len) {
  append_u32(out, static_cast<uint32_t>(len));
  out.append(reinterpret_cast<const char*>(data), len);
}

uint32_t random_checkint() {
  thread_local std::mt19937 rng{std::random_device{}()};
  std::uniform_int_distribution<uint32_t> dist;
  return dist(rng);
}

std::string build_openssh_private_key(const uint8_t* seed, const uint8_t* pub,
                                      std::string_view comment) {
  std::array<uint8_t, kPrivateKeySize> private_key{};
  std::copy(seed, seed + kSeedSize, private_key.begin());
  std::copy(pub, pub + kPubKeySize, private_key.begin() + kSeedSize);

  std::string public_blob;
  append_string(public_blob, "ssh-ed25519");
  append_string(public_blob, pub, kPubKeySize);

  std::string private_blob;
  uint32_t check = random_checkint();
  append_u32(private_blob, check);
  append_u32(private_blob, check);
  append_string(private_blob, "ssh-ed25519");
  append_string(private_blob, pub, kPubKeySize);
  append_string(private_blob, private_key.data(), private_key.size());
  append_string(private_blob, comment);

  size_t pad_len = kOpenSshBlockSize - (private_blob.size() % kOpenSshBlockSize);
  if (pad_len == 0) {
    pad_len = kOpenSshBlockSize;
  }
  for (size_t i = 1; i <= pad_len; ++i) {
    private_blob.push_back(static_cast<char>(i));
  }

  std::string key_blob;
  key_blob.append("openssh-key-v1\0", 15);
  append_string(key_blob, "none");
  append_string(key_blob, "none");
  append_string(key_blob, std::string_view());
  append_u32(key_blob, 1);
  append_string(key_blob, std::string_view(public_blob.data(), public_blob.size()));
  append_string(key_blob, std::string_view(private_blob.data(), private_blob.size()));

  std::string encoded = base64_encode(reinterpret_cast<const uint8_t*>(
                                          key_blob.data()),
                                      key_blob.size());
  std::string out;
  out.append("-----BEGIN OPENSSH PRIVATE KEY-----\n");
  for (size_t i = 0; i < encoded.size(); i += 70) {
    size_t chunk = std::min<size_t>(70, encoded.size() - i);
    out.append(encoded.data() + i, chunk);
    out.push_back('\n');
  }
  out.append("-----END OPENSSH PRIVATE KEY-----\n");
  return out;
}

std::string build_openssh_public_key_line(const uint8_t* pub, std::string_view comment) {
  std::string public_blob;
  append_string(public_blob, "ssh-ed25519");
  append_string(public_blob, pub, kPubKeySize);

  std::string encoded = base64_encode(reinterpret_cast<const uint8_t*>(
                                          public_blob.data()),
                                      public_blob.size());
  std::string out;
  out.reserve(16 + encoded.size() + comment.size());
  out.append("ssh-ed25519 ");
  out.append(encoded);
  if (!comment.empty()) {
    out.push_back(' ');
    out.append(comment.data(), comment.size());
  }
  return out;
}

struct Options {
  std::string pattern;
  size_t batch = 65536;
  size_t threads = 0;
  size_t pipeline = 3;
  bool cpu_only = false;
};

void print_usage(const char* argv0) {
  std::cerr << "Usage: " << argv0
            << " --pattern <regex> [--batch N] [--threads N] [--pipeline N]"
            << " [--cpu-only]\n";
}

bool parse_args(int argc, char** argv, Options* out) {
  if (argc < 3) {
    return false;
  }

  for (int i = 1; i < argc; ++i) {
    std::string_view arg(argv[i]);
    if (arg == "--pattern" && i + 1 < argc) {
      out->pattern = argv[++i];
    } else if (arg == "--batch" && i + 1 < argc) {
      out->batch = static_cast<size_t>(std::stoull(argv[++i]));
    } else if (arg == "--threads" && i + 1 < argc) {
      out->threads = static_cast<size_t>(std::stoull(argv[++i]));
    } else if (arg == "--pipeline" && i + 1 < argc) {
      out->pipeline = static_cast<size_t>(std::stoull(argv[++i]));
    } else if (arg == "--cpu-only") {
      out->cpu_only = true;
    } else {
      return false;
    }
  }

  return !out->pattern.empty();
}

struct Batch {
  std::vector<uint8_t> seeds;
  std::vector<uint8_t> pubkeys;
  std::vector<uint8_t> hashes;
  size_t count = 0;
  std::atomic<size_t> remaining{0};
};

struct WorkItem {
  Batch* batch = nullptr;
  size_t start = 0;
  size_t end = 0;
};

void fill_payload_prefix(uint8_t* payload) {
  payload[0] = 0;
  payload[1] = 0;
  payload[2] = 0;
  payload[3] = 11;
  payload[4] = 's';
  payload[5] = 's';
  payload[6] = 'h';
  payload[7] = '-';
  payload[8] = 'e';
  payload[9] = 'd';
  payload[10] = '2';
  payload[11] = '5';
  payload[12] = '5';
  payload[13] = '1';
  payload[14] = '9';
  payload[15] = 0;
  payload[16] = 0;
  payload[17] = 0;
  payload[18] = 32;
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  if (!parse_args(argc, argv, &options)) {
    print_usage(argv[0]);
    return 1;
  }

  if (options.threads == 0) {
    options.threads = std::max<size_t>(1, std::thread::hardware_concurrency());
  }

  if (options.cpu_only) {
    if (sodium_init() < 0) {
      std::cerr << "libsodium init failed\n";
      return 1;
    }
  }

  MatchRule rule(options.pattern);
  if (!rule.ok()) {
    std::cerr << "Invalid regex: " << rule.error() << "\n";
    return 1;
  }

  std::unique_ptr<vanity::GpuVanity> gpu;
  if (!options.cpu_only) {
    gpu = std::make_unique<vanity::GpuVanity>(options.batch);
    if (!gpu->ok()) {
      std::cerr << "GPU init failed: " << gpu->error() << "\n";
      return 1;
    }
  }

  std::ofstream log("keys.log", std::ios::app | std::ios::binary);
  if (!log) {
    std::cerr << "Failed to open keys.log for writing\n";
    return 1;
  }

  std::atomic<uint64_t> total_checked{0};
  std::atomic<uint64_t> total_matches{0};
  std::atomic<bool> stop{false};
  std::mutex log_mutex;

  std::vector<std::unique_ptr<Batch>> batches;
  std::deque<Batch*> free_batches;
  std::mutex free_mutex;
  std::condition_variable free_cv;

  std::deque<WorkItem> work_queue;
  std::mutex work_mutex;
  std::condition_variable work_cv;

  if (!options.cpu_only) {
    if (options.pipeline == 0) {
      options.pipeline = 1;
    }
    batches.reserve(options.pipeline);
    for (size_t i = 0; i < options.pipeline; ++i) {
      auto batch = std::make_unique<Batch>();
      batch->seeds.resize(options.batch * kSeedSize);
      batch->pubkeys.resize(options.batch * kPubKeySize);
      batch->hashes.resize(options.batch * kHashSize);
      free_batches.push_back(batch.get());
      batches.push_back(std::move(batch));
    }
  }

  std::thread stats([&]() {
    using namespace std::chrono_literals;
    uint64_t last_checked = 0;
    uint64_t last_matches = 0;
    while (!stop.load()) {
      std::this_thread::sleep_for(5s);
      uint64_t checked = total_checked.load();
      uint64_t matches = total_matches.load();
      uint64_t delta_checked = checked - last_checked;
      uint64_t delta_matches = matches - last_matches;
      last_checked = checked;
      last_matches = matches;
      double rate = static_cast<double>(delta_checked) / 5.0;
      std::cout << "[stats] checked=" << checked << " matches=" << matches
                << " rate=" << rate << "/s matched_5s=" << delta_matches << "\n";
    }
  });

  auto worker = [&]() {
    while (true) {
      WorkItem item;
      {
        std::unique_lock<std::mutex> lock(work_mutex);
        work_cv.wait(lock, [&]() { return stop.load() || !work_queue.empty(); });
        if (work_queue.empty()) {
          return;
        }
        item = work_queue.front();
        work_queue.pop_front();
      }

      char b64[64];
      for (size_t i = item.start; i < item.end; ++i) {
        const uint8_t* hash = item.batch->hashes.data() + i * kHashSize;
        size_t b64_len = base64_no_pad(hash, kHashSize, b64);
        std::string_view fingerprint(b64, b64_len);
        if (!rule.match(fingerprint)) {
          continue;
        }

        total_matches.fetch_add(1, std::memory_order_relaxed);
        const uint8_t* seed = item.batch->seeds.data() + i * kSeedSize;
        const uint8_t* pub = item.batch->pubkeys.data() + i * kPubKeySize;
        std::string openssh_key = build_openssh_private_key(seed, pub, fingerprint);
        std::string openssh_pub = build_openssh_public_key_line(pub, fingerprint);

        std::lock_guard<std::mutex> guard(log_mutex);
        log << openssh_key;
        log << openssh_pub << "\n\n";
        log << "sha256_b64=" << fingerprint << "\n\n";
        log.flush();
        std::cout << "match: " << fingerprint
                  << " (OpenSSH key written to keys.log)\n";
      }

      if (item.batch->remaining.fetch_sub(1, std::memory_order_acq_rel) == 1) {
        std::lock_guard<std::mutex> lock(free_mutex);
        free_batches.push_back(item.batch);
        free_cv.notify_one();
      }
    }
  };

  if (options.cpu_only) {
    std::vector<std::thread> cpu_workers;
    cpu_workers.reserve(options.threads);
    for (size_t t = 0; t < options.threads; ++t) {
      cpu_workers.emplace_back([&]() {
        uint8_t payload[kPayloadSize];
        fill_payload_prefix(payload);
        std::array<uint8_t, kSeedSize> seed{};
        std::array<uint8_t, kPubKeySize> pub{};
        std::array<uint8_t, kPrivateKeySize> priv{};
        std::array<uint8_t, kHashSize> hash{};
        char b64[64];

        while (!stop.load()) {
          randombytes_buf(seed.data(), seed.size());
          crypto_sign_seed_keypair(pub.data(), priv.data(), seed.data());
          std::memcpy(payload + 19, pub.data(), kPubKeySize);
          crypto_hash_sha256(hash.data(), payload, kPayloadSize);

          size_t b64_len = base64_no_pad(hash.data(), kHashSize, b64);
          std::string_view fingerprint(b64, b64_len);
          if (rule.match(fingerprint)) {
            total_matches.fetch_add(1, std::memory_order_relaxed);
            std::string openssh_key = build_openssh_private_key(seed.data(), pub.data(),
                                                               fingerprint);
            std::string openssh_pub = build_openssh_public_key_line(pub.data(),
                                                                    fingerprint);
            std::lock_guard<std::mutex> guard(log_mutex);
            log << openssh_key;
            log << openssh_pub << "\n\n";
            log << "sha256_b64=" << fingerprint << "\n\n";
            log.flush();
            std::cout << "match: " << fingerprint
                      << " (OpenSSH key written to keys.log)\n";
          }

          total_checked.fetch_add(1, std::memory_order_relaxed);
        }
      });
    }

    for (auto& thread : cpu_workers) {
      thread.join();
    }
    stats.join();
    return 0;
  }

  std::vector<std::thread> workers;
  workers.reserve(options.threads);
  for (size_t i = 0; i < options.threads; ++i) {
    workers.emplace_back(worker);
  }

  while (true) {
    Batch* batch = nullptr;
    {
      std::unique_lock<std::mutex> lock(free_mutex);
      free_cv.wait(lock, [&]() { return stop.load() || !free_batches.empty(); });
      if (stop.load()) {
        break;
      }
      batch = free_batches.front();
      free_batches.pop_front();
    }

    if (!gpu->generate(options.batch, batch->seeds.data(), batch->pubkeys.data(),
                       batch->hashes.data())) {
      std::cerr << "GPU batch failed: " << gpu->error() << "\n";
      stop.store(true);
      work_cv.notify_all();
      free_cv.notify_all();
      break;
    }

    batch->count = options.batch;
    total_checked.fetch_add(options.batch, std::memory_order_relaxed);

    std::vector<WorkItem> tasks;
    tasks.reserve(options.threads);
    for (size_t t = 0; t < options.threads; ++t) {
      size_t start = options.batch * t / options.threads;
      size_t end = options.batch * (t + 1) / options.threads;
      if (start >= end) {
        continue;
      }
      tasks.push_back(WorkItem{batch, start, end});
    }

    if (tasks.empty()) {
      std::lock_guard<std::mutex> lock(free_mutex);
      free_batches.push_back(batch);
      free_cv.notify_one();
      continue;
    }

    {
      std::lock_guard<std::mutex> lock(work_mutex);
      batch->remaining.store(tasks.size(), std::memory_order_relaxed);
      for (const auto& task : tasks) {
        work_queue.push_back(task);
      }
    }
    work_cv.notify_all();
  }

  stop.store(true);
  work_cv.notify_all();
  free_cv.notify_all();

  for (auto& worker_thread : workers) {
    worker_thread.join();
  }
  stats.join();
  return 0;
}
