#include "signature_detector.h"

#include <fstream>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <limits.h>

namespace flutter_neo_shield {

bool SignatureDetector::Check() {
  return CheckElfIntegrity() || CheckEnvironment();
}

/// Basic ELF integrity check.
///
/// Verify the ELF magic bytes and that the executable hasn't been
/// obviously tampered with (e.g., corrupted header).
bool SignatureDetector::CheckElfIntegrity() {
  char exe_path[PATH_MAX];
  ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
  if (len == -1) return true;
  exe_path[len] = '\0';

  std::ifstream elf(exe_path, std::ios::binary);
  if (!elf.is_open()) return true;

  // Check ELF magic: 0x7f 'E' 'L' 'F'
  unsigned char magic[4];
  elf.read(reinterpret_cast<char*>(magic), 4);

  if (magic[0] != 0x7F || magic[1] != 'E' ||
      magic[2] != 'L' || magic[3] != 'F') {
    return true;  // Not a valid ELF — tampered
  }

  return false;
}

/// Check for DYLD/LD injection environment variables.
bool SignatureDetector::CheckEnvironment() {
  const char* dangerous_vars[] = {
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
  };

  for (const auto& var : dangerous_vars) {
    const char* val = getenv(var);
    if (val && strlen(val) > 0) {
      return true;
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
