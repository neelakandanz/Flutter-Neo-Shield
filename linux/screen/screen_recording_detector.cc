#include "screen_recording_detector.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <dirent.h>
#include <fstream>

namespace flutter_neo_shield {

/// Detect screen recording by checking for known recording processes.
///
/// Scans /proc for processes that are commonly used for screen recording.
bool ScreenRecordingDetector::IsRecording() {
  const char* recording_processes[] = {
    "obs", "ffmpeg", "recordmydesktop", "simplescreenrecorder",
    "kazam", "peek", "vokoscreen", "wf-recorder",
  };

  DIR* proc_dir = opendir("/proc");
  if (!proc_dir) return false;

  bool found = false;
  struct dirent* entry;

  while ((entry = readdir(proc_dir)) != nullptr) {
    // Only check numeric directories (PIDs)
    if (entry->d_type != DT_DIR) continue;

    bool is_pid = true;
    for (const char* c = entry->d_name; *c; c++) {
      if (*c < '0' || *c > '9') {
        is_pid = false;
        break;
      }
    }
    if (!is_pid) continue;

    std::string comm_path = std::string("/proc/") + entry->d_name + "/comm";
    std::ifstream comm(comm_path);
    if (!comm.is_open()) continue;

    std::string name;
    std::getline(comm, name);

    for (const auto& recorder : recording_processes) {
      if (name.find(recorder) != std::string::npos) {
        found = true;
        break;
      }
    }

    if (found) break;
  }

  closedir(proc_dir);
  return found;
}

}  // namespace flutter_neo_shield
