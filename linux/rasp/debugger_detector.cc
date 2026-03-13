#include "debugger_detector.h"

#include <fstream>
#include <string>
#include <unistd.h>

namespace flutter_neo_shield {

bool DebuggerDetector::Check() {
  return CheckTracerPid() || CheckParentProcess();
}

/// Read /proc/self/status for TracerPid.
/// Non-zero TracerPid means a debugger (ptrace) is attached.
bool DebuggerDetector::CheckTracerPid() {
  std::ifstream status("/proc/self/status");
  if (!status.is_open()) return true;  // fail-closed

  std::string line;
  while (std::getline(status, line)) {
    if (line.compare(0, 10, "TracerPid:") == 0) {
      std::string pid_str = line.substr(10);
      // Trim whitespace
      size_t start = pid_str.find_first_not_of(" \t");
      if (start != std::string::npos) {
        int pid = std::stoi(pid_str.substr(start));
        return pid != 0;
      }
    }
  }

  return false;
}

/// Check if the parent process is a known debugger.
bool DebuggerDetector::CheckParentProcess() {
  pid_t ppid = getppid();
  std::string comm_path = "/proc/" + std::to_string(ppid) + "/comm";

  std::ifstream comm(comm_path);
  if (!comm.is_open()) return false;

  std::string parent_name;
  std::getline(comm, parent_name);

  const char* debuggers[] = {
    "gdb", "lldb", "strace", "ltrace", "dtruss",
    "valgrind", "radare2", "r2",
  };

  for (const auto& dbg : debuggers) {
    if (parent_name.find(dbg) != std::string::npos) {
      return true;
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
