#include "gpu_vanity.h"

#include <cuda_runtime.h>
#include <string>

#include "ed25519.h"

namespace {

constexpr size_t kSeedSize = 32;
constexpr size_t kPubKeySize = 32;
constexpr size_t kHashSize = 32;
constexpr size_t kPayloadSize = 51;

__device__ __forceinline__ uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32 - n));
}

__device__ __forceinline__ uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (~x & z);
}

__device__ __forceinline__ uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

__device__ __forceinline__ uint32_t big_sigma0(uint32_t x) {
  return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22);
}

__device__ __forceinline__ uint32_t big_sigma1(uint32_t x) {
  return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25);
}

__device__ __forceinline__ uint32_t small_sigma0(uint32_t x) {
  return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

__device__ __forceinline__ uint32_t small_sigma1(uint32_t x) {
  return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

__device__ __constant__ uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

__device__ void sha256_51(const uint8_t* payload, uint8_t* out) {
  uint8_t block[64];
#pragma unroll
  for (int i = 0; i < 51; ++i) {
    block[i] = payload[i];
  }
  block[51] = 0x80;
#pragma unroll
  for (int i = 52; i < 56; ++i) {
    block[i] = 0;
  }
  block[56] = 0;
  block[57] = 0;
  block[58] = 0;
  block[59] = 0;
  block[60] = 0;
  block[61] = 0;
  block[62] = 0x01;
  block[63] = 0x98;

  uint32_t w[64];
#pragma unroll
  for (int i = 0; i < 16; ++i) {
    int idx = i * 4;
    w[i] = (static_cast<uint32_t>(block[idx]) << 24) |
           (static_cast<uint32_t>(block[idx + 1]) << 16) |
           (static_cast<uint32_t>(block[idx + 2]) << 8) |
           static_cast<uint32_t>(block[idx + 3]);
  }
#pragma unroll
  for (int i = 16; i < 64; ++i) {
    w[i] = small_sigma1(w[i - 2]) + w[i - 7] + small_sigma0(w[i - 15]) + w[i - 16];
  }

  uint32_t a = 0x6a09e667u;
  uint32_t b = 0xbb67ae85u;
  uint32_t c = 0x3c6ef372u;
  uint32_t d = 0xa54ff53au;
  uint32_t e = 0x510e527fu;
  uint32_t f = 0x9b05688cu;
  uint32_t g = 0x1f83d9abu;
  uint32_t h = 0x5be0cd19u;

#pragma unroll
  for (int i = 0; i < 64; ++i) {
    uint32_t t1 = h + big_sigma1(e) + ch(e, f, g) + kSha256K[i] + w[i];
    uint32_t t2 = big_sigma0(a) + maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  a += 0x6a09e667u;
  b += 0xbb67ae85u;
  c += 0x3c6ef372u;
  d += 0xa54ff53au;
  e += 0x510e527fu;
  f += 0x9b05688cu;
  g += 0x1f83d9abu;
  h += 0x5be0cd19u;

  uint32_t digest[8] = {a, b, c, d, e, f, g, h};
  for (int i = 0; i < 8; ++i) {
    out[i * 4] = static_cast<uint8_t>((digest[i] >> 24) & 0xffu);
    out[i * 4 + 1] = static_cast<uint8_t>((digest[i] >> 16) & 0xffu);
    out[i * 4 + 2] = static_cast<uint8_t>((digest[i] >> 8) & 0xffu);
    out[i * 4 + 3] = static_cast<uint8_t>(digest[i] & 0xffu);
  }
}

__global__ void vanity_generate(const uint8_t* seeds,
                               uint8_t* pubkeys,
                               uint8_t* hashes,
                               size_t count) {
  size_t idx = static_cast<size_t>(blockIdx.x) * blockDim.x + threadIdx.x;
  if (idx >= count) {
    return;
  }

  const uint8_t* seed = seeds + idx * kSeedSize;
  uint8_t pub[kPubKeySize];
  uint8_t priv[64];

  ed25519_create_keypair(pub, priv, seed);

  uint8_t payload[kPayloadSize];
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
#pragma unroll
  for (int i = 0; i < 32; ++i) {
    payload[19 + i] = pub[i];
  }

  sha256_51(payload, hashes + idx * kHashSize);

#pragma unroll
  for (int i = 0; i < 32; ++i) {
    pubkeys[idx * kPubKeySize + i] = pub[i];
  }
}

bool set_error(std::string* error, const char* prefix, cudaError_t code) {
  if (code == cudaSuccess) {
    return false;
  }
  std::string msg(prefix);
  msg.append(": ");
  msg.append(cudaGetErrorString(code));
  *error = msg;
  return true;
}

}  // namespace

namespace vanity {

GpuVanity::GpuVanity(size_t max_batch)
    : d_seeds_(nullptr),
      d_pubkeys_(nullptr),
      d_hashes_(nullptr),
      capacity_(max_batch),
      ok_(true) {
  if (max_batch == 0) {
    ok_ = false;
    error_ = "max_batch must be > 0";
    return;
  }

  int device_count = 0;
  if (set_error(&error_, "cudaGetDeviceCount", cudaGetDeviceCount(&device_count))) {
    ok_ = false;
    return;
  }
  if (device_count == 0) {
    ok_ = false;
    error_ = "no CUDA devices found";
    return;
  }

  if (set_error(&error_, "cudaSetDevice", cudaSetDevice(0))) {
    ok_ = false;
    return;
  }

  if (set_error(&error_, "cudaMalloc seeds",
                cudaMalloc(&d_seeds_, capacity_ * kSeedSize))) {
    ok_ = false;
    return;
  }
  if (set_error(&error_, "cudaMalloc pubkeys",
                cudaMalloc(&d_pubkeys_, capacity_ * kPubKeySize))) {
    ok_ = false;
    return;
  }
  if (set_error(&error_, "cudaMalloc hashes",
                cudaMalloc(&d_hashes_, capacity_ * kHashSize))) {
    ok_ = false;
    return;
  }
}

GpuVanity::~GpuVanity() {
  if (d_hashes_) {
    cudaFree(d_hashes_);
  }
  if (d_pubkeys_) {
    cudaFree(d_pubkeys_);
  }
  if (d_seeds_) {
    cudaFree(d_seeds_);
  }
}

bool GpuVanity::ok() const {
  return ok_;
}

const std::string& GpuVanity::error() const {
  return error_;
}

size_t GpuVanity::max_batch() const {
  return capacity_;
}

bool GpuVanity::generate(size_t count, const uint8_t* seeds_in, uint8_t* pubkeys_out,
                         uint8_t* hashes_out) {
  if (!ok_) {
    return false;
  }
  if (count > capacity_) {
    ok_ = false;
    error_ = "count exceeds max_batch";
    return false;
  }

  dim3 block(256);
  dim3 grid(static_cast<unsigned int>((count + block.x - 1) / block.x));

  if (set_error(&error_, "copy seeds",
                cudaMemcpy(d_seeds_, seeds_in, count * kSeedSize,
                           cudaMemcpyHostToDevice))) {
    ok_ = false;
    return false;
  }

  vanity_generate<<<grid, block>>>(d_seeds_, d_pubkeys_, d_hashes_, count);
  cudaError_t err = cudaGetLastError();
  if (set_error(&error_, "vanity_generate launch", err)) {
    ok_ = false;
    return false;
  }
  err = cudaDeviceSynchronize();
  if (set_error(&error_, "vanity_generate sync", err)) {
    ok_ = false;
    return false;
  }

  if (set_error(&error_, "copy pubkeys",
                cudaMemcpy(pubkeys_out, d_pubkeys_, count * kPubKeySize,
                           cudaMemcpyDeviceToHost))) {
    ok_ = false;
    return false;
  }
  if (set_error(&error_, "copy hashes",
                cudaMemcpy(hashes_out, d_hashes_, count * kHashSize,
                           cudaMemcpyDeviceToHost))) {
    ok_ = false;
    return false;
  }

  return true;
}

}  // namespace vanity
