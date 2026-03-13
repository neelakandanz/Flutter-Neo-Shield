#include "integrity_detector.h"

#include <fstream>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>

namespace flutter_neo_shield {

bool IntegrityDetector::Check() {
  return CheckProcExe() || CheckExecutableModified();
}

/// Check if /proc/self/exe points to an unexpected location.
///
/// If the binary has been copied/moved from its original install location,
/// the symlink may differ from what we expect.
bool IntegrityDetector::CheckProcExe() {
  char exe_path[PATH_MAX];
  ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
  if (len == -1) return true;  // Can't read — fail-closed

  exe_path[len] = '\0';

  // Check if the path ends with " (deleted)" — binary was replaced while running
  std::string path(exe_path);
  if (path.find(" (deleted)") != std::string::npos) {
    return true;
  }

  return false;
}

/// Check if the executable file has been modified since it was started.
///
/// Compare the inode of /proc/self/exe with the actual file.
/// If they differ, the binary was replaced.
bool IntegrityDetector::CheckExecutableModified() {
  struct stat proc_stat, file_stat;

  if (lstat("/proc/self/exe", &proc_stat) != 0) return false;

  char exe_path[PATH_MAX];
  ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
  if (len == -1) return false;
  exe_path[len] = '\0';

  if (stat(exe_path, &file_stat) != 0) return true;  // File doesn't exist anymore

  // If inodes differ, binary was replaced
  if (proc_stat.st_ino != file_stat.st_ino) {
    return true;
  }

  return false;
}

}  // namespace flutter_neo_shield
