// Shared helpers for the libspatialindex fuzz harnesses.
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <unistd.h>

// Sequential reader over the fuzz input. Reads past the end return zeros, so a
// short input simply ends the op stream (callers check ok()).
struct FuzzReader {
  const uint8_t* p;
  size_t n;
  size_t off = 0;
  FuzzReader(const uint8_t* d, size_t s) : p(d), n(s) {}
  bool ok() const { return off < n; }
  size_t remaining() const { return off < n ? n - off : 0; }
  void bytes(void* out, size_t k) {
    size_t take = remaining() < k ? remaining() : k;
    std::memset(out, 0, k);
    if (take) std::memcpy(out, p + off, take);
    off += k;
  }
  uint8_t u8() { uint8_t v; bytes(&v, 1); return v; }
  uint16_t u16() { uint16_t v; bytes(&v, 2); return v; }
  uint32_t u32() { uint32_t v; bytes(&v, 4); return v; }
  int64_t i64() { int64_t v; bytes(&v, 8); return v; }
  // Raw IEEE-754 bits: NaN and +/-Inf reach the library unchanged.
  double f64() { double v; bytes(&v, 8); return v; }
};

// A per-process scratch directory under $TMPDIR (fallback /tmp), made once.
static inline const std::string& fuzz_scratch_dir() {
  static std::string dir;
  if (dir.empty()) {
    const char* t = getenv("TMPDIR");
    std::string tmpl = std::string(t && *t ? t : "/tmp") + "/sidx-fuzz-XXXXXX";
    char* buf = strdup(tmpl.c_str());
    if (mkdtemp(buf) == nullptr) abort();
    dir = buf;
    free(buf);
  }
  return dir;
}
