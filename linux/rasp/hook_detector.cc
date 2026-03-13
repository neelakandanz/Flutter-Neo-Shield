#include "hook_detector.h"

#include <cstdlib>
#include <fstream>
#include <string>

namespace flutter_neo_shield {

bool HookDetector::Check() {
  return CheckLDPreload() || CheckMaps();
}

/// Check LD_PRELOAD environment variable.
///
/// LD_PRELOAD is the primary mechanism for injecting shared libraries
/// into Linux processes. Legitimate apps should not have this set.
bool HookDetector::CheckLDPreload() {
  const char* ld_preload = getenv("LD_PRELOAD");
  if (ld_preload && strlen(ld_preload) > 0) {
    return true;
  }

  // Also check /etc/ld.so.preload
  std::ifstream preload("/etc/ld.so.preload");
  if (preload.is_open()) {
    std::string line;
    while (std::getline(preload, line)) {
      // Skip empty lines and comments
      if (!line.empty() && line[0] != '#') {
        return true;
      }
    }
  }

  return false;
}

/// Scan /proc/self/maps for suspicious shared libraries.
bool HookDetector::CheckMaps() {
  std::ifstream maps("/proc/self/maps");
  if (!maps.is_open()) return false;

  const char* suspicious[] = {
    "substrate", "inject", "hook", "interpose",
    "frida", "cycript", "xposed",
  };

  std::string line;
  while (std::getline(maps, line)) {
    for (const auto& s : suspicious) {
      if (line.find(s) != std::string::npos) {
        return true;
      }
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
