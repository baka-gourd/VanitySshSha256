# VanitySshSha256

GPU-accelerated vanity generator for SSH Ed25519 keys on Windows. The GPU generates keypairs and SHA256 of the OpenSSH public-key payload; the CPU base64-encodes (no padding) and applies RE2 regex matching. Matches are written as OpenSSH private keys and public key lines.

## Key ideas

- Build the OpenSSH public-key payload: `string("ssh-ed25519") + string(pubkey)` (raw bytes)
- SHA256(payload)
- Base64 encode and remove `=` padding (this is the string matched by regex)

## Requirements

- Windows 10/11
- Visual Studio 2022 (MSVC), C++20
- CUDA Toolkit
- CMake 3.24+
- Ninja
- vcpkg (submodule in `third_party/vcpkg`)

## Build (Windows)

```powershell
# In VS prompt
git submodule update --init --recursive
third_party\vcpkg\bootstrap-vcpkg.bat

cmake -S . -B build -G Ninja `
  -DCMAKE_TOOLCHAIN_FILE=third_party/vcpkg/scripts/buildsystems/vcpkg.cmake `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static

cmake --build build -j
```

If you are not on RTX 3060, update `CMAKE_CUDA_ARCHITECTURES` in `CMakeLists.txt`.

## Usage

```bash
build\VanitySshSha256.exe --pattern "<regex>" [--batch N] [--threads N] [--pipeline N] [--cpu-only]
```

Options

- `--pattern` (required): RE2 regex matched against SHA256(payload) base64 **without** padding.
- `--batch` (default 65536): number of keys per GPU batch.
- `--threads` (default: CPU hardware concurrency): CPU worker threads for regex matching.
- `--pipeline` (default 3): number of in-flight batches to keep the GPU busy.
- `--cpu-only`: run the full pipeline on CPU (benchmark baseline).

Example

```bash
build\VanitySshSha256.exe --pattern "AAAAAA$" --batch 262144 --threads 8 --pipeline 3
```

CPU-only baseline example

```bash
build\VanitySshSha256.exe --pattern "AAAAAA$" --threads 16 --cpu-only
```

## Output

Matches are appended to `keys.log` in the current working directory:

- OpenSSH private key block (unencrypted, `ciphername none`)
- OpenSSH public key line: `ssh-ed25519 AAAA... <comment>`
- `sha256_b64=<base64_without_padding>` (exact string used for regex)

The key comment is the same base64-no-pad fingerprint for easy identification.

## Performance tuning

- Increase `--batch` to keep the GPU busy (watch VRAM).
- Increase `--threads` if CPU regex matching is the bottleneck.
- Increase `--pipeline` to overlap GPU generation with CPU matching.

Suggested starting point for RTX 3060:

- `--batch 262144 --threads 8 --pipeline 3`

## Notes

The last char must in `A E I M Q U Y c g k o s w 0 4 8`.

- Regex matching uses `RE2::PartialMatch`. Use `^...$` if you want an exact match.
- This tool writes unencrypted private keys. Keep `keys.log` secure.
