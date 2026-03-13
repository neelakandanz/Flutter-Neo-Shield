#include "developer_mode_detector.h"

#include <fstream>
#include <string>
#include <unistd.h>

namespace flutter_neo_shield {

bool DeveloperModeDetector::Check() {
  return CheckPtraceScope() || CheckDevToolsInstalled();
}

/// Check kernel.yama.ptrace_scope.
///
/// 0 = classic ptrace permissions (any process can ptrace any other)
/// 1 = restricted (normal, only parent can ptrace child)
/// 2 = admin-only
/// 3 = no ptrace at all
///
/// Value 0 means developer-friendly permissive configuration.
bool DeveloperModeDetector::CheckPtraceScope() {
  std::ifstream f("/proc/sys/kernel/yama/ptrace_scope");
  if (!f.is_open()) return false;

  int scope = -1;
  f >> scope;

  return scope == 0;
}

/// Check if common debugging tools are installed.
bool DeveloperModeDetector::CheckDevToolsInstalled() {
  const char* tools[] = {
    "/usr/bin/gdb",
    "/usr/bin/strace",
    "/usr/bin/ltrace",
    "/usr/bin/valgrind",
    "/usr/bin/radare2",
    "/usr/bin/r2",
  };

  for (const auto& tool : tools) {
    if (access(tool, X_OK) == 0) {
      return true;
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
