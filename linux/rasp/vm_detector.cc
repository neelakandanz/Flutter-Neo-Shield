#include "vm_detector.h"

#include <fstream>
#include <string>
#include <algorithm>
#include <cstdio>
#include <cstring>

#ifdef __x86_64__
#include <cpuid.h>
#endif

namespace flutter_neo_shield {

bool VMDetector::Check() {
  return CheckCPUID() || CheckDMI() || CheckSystemdDetectVirt();
}

/// Check CPUID hypervisor present bit.
bool VMDetector::CheckCPUID() {
#ifdef __x86_64__
  unsigned int eax, ebx, ecx, edx;
  if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
    return (ecx & (1 << 31)) != 0;
  }
#endif
  return false;
}

/// Check /sys/class/dmi/id for VM identifiers.
bool VMDetector::CheckDMI() {
  const char* dmi_files[] = {
    "/sys/class/dmi/id/product_name",
    "/sys/class/dmi/id/sys_vendor",
    "/sys/class/dmi/id/board_vendor",
    "/sys/class/dmi/id/bios_vendor",
  };

  const char* vm_strings[] = {
    "vmware", "virtualbox", "vbox", "qemu", "kvm",
    "xen", "parallels", "bhyve", "hyper-v", "microsoft corporation",
    "innotek", "oracle",
  };

  for (const auto& file : dmi_files) {
    std::ifstream f(file);
    if (!f.is_open()) continue;

    std::string content;
    std::getline(f, content);
    std::transform(content.begin(), content.end(), content.begin(), ::tolower);

    for (const auto& vm : vm_strings) {
      if (content.find(vm) != std::string::npos) {
        return true;
      }
    }
  }

  return false;
}

/// Use systemd-detect-virt if available.
bool VMDetector::CheckSystemdDetectVirt() {
  FILE* pipe = popen("systemd-detect-virt 2>/dev/null", "r");
  if (!pipe) return false;

  char buffer[128];
  std::string result;
  while (fgets(buffer, sizeof(buffer), pipe)) {
    result += buffer;
  }

  int status = pclose(pipe);
  if (status == 0 && !result.empty()) {
    // Non-"none" output means virtualization detected
    std::string trimmed = result;
    trimmed.erase(trimmed.find_last_not_of(" \n\r\t") + 1);
    return trimmed != "none";
  }

  return false;
}

}  // namespace flutter_neo_shield
