#include "native_debug_detector.h"

#include <fstream>
#include <string>
#include <chrono>
#include <sys/ptrace.h>
#include <errno.h>

namespace flutter_neo_shield {

bool NativeDebugDetector::Check() {
  return CheckTracerPid() ||
         CheckPtrace() ||
         CheckWchan() ||
         CheckTimingAnomaly();
}

/// Read /proc/self/status TracerPid.
bool NativeDebugDetector::CheckTracerPid() {
  std::ifstream status("/proc/self/status");
  if (!status.is_open()) return true;

  std::string line;
  while (std::getline(status, line)) {
    if (line.compare(0, 10, "TracerPid:") == 0) {
      std::string pid_str = line.substr(10);
      size_t start = pid_str.find_first_not_of(" \t");
      if (start != std::string::npos) {
        int pid = std::stoi(pid_str.substr(start));
        return pid != 0;
      }
    }
  }

  return false;
}

/// Try PTRACE_TRACEME to detect if we're already being traced.
///
/// If a debugger is already attached, PTRACE_TRACEME fails with EPERM.
/// Note: This is a one-shot test — once called, it may affect future
/// ptrace operations.
bool NativeDebugDetector::CheckPtrace() {
  long result = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
  if (result == -1) {
    if (errno == EPERM) {
      return true;  // Already being traced
    }
  } else {
    // Successfully traced ourselves — detach
    ptrace(PTRACE_DETACH, 0, nullptr, nullptr);
  }
  return false;
}

/// Check /proc/self/wchan for ptrace-related wait.
bool NativeDebugDetector::CheckWchan() {
  std::ifstream wchan("/proc/self/wchan");
  if (!wchan.is_open()) return false;

  std::string content;
  std::getline(wchan, content);

  if (content.find("ptrace") != std::string::npos ||
      content.find("trace") != std::string::npos) {
    return true;
  }

  return false;
}

/// Timing-based detection.
bool NativeDebugDetector::CheckTimingAnomaly() {
  auto start = std::chrono::high_resolution_clock::now();

  volatile int sum = 0;
  for (int i = 0; i < 10000; i++) {
    sum += i;
  }

  auto end = std::chrono::high_resolution_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

  return elapsed.count() > 500;
}

}  // namespace flutter_neo_shield
