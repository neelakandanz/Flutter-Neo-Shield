#include "privilege_detector.h"

#include <unistd.h>

namespace flutter_neo_shield {

/// Check if running as root (uid 0) or with effective root privileges.
bool PrivilegeDetector::Check() {
  return getuid() == 0 || geteuid() == 0;
}

}  // namespace flutter_neo_shield
