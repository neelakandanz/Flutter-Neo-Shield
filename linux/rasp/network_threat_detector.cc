#include "network_threat_detector.h"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <ifaddrs.h>
#include <net/if.h>

namespace flutter_neo_shield {

bool NetworkThreatDetector::CheckSimple() {
  return CheckProxy() || CheckVpn();
}

/// Check for proxy configuration via environment variables.
bool NetworkThreatDetector::CheckProxy() {
  const char* proxy_vars[] = {
    "http_proxy", "https_proxy", "HTTP_PROXY",
    "HTTPS_PROXY", "ALL_PROXY", "all_proxy",
  };

  for (const auto& var : proxy_vars) {
    const char* val = getenv(var);
    if (val && strlen(val) > 0) {
      return true;
    }
  }

  return false;
}

/// Check for VPN interfaces via getifaddrs.
bool NetworkThreatDetector::CheckVpn() {
  struct ifaddrs* ifaddr;
  if (getifaddrs(&ifaddr) != 0) return false;

  const char* vpn_prefixes[] = {"tun", "tap", "ppp", "wg"};
  bool found = false;

  for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    if (!ifa->ifa_name) continue;

    if (ifa->ifa_flags & IFF_UP) {
      std::string name(ifa->ifa_name);
      for (const auto& prefix : vpn_prefixes) {
        if (name.compare(0, strlen(prefix), prefix) == 0) {
          found = true;
          break;
        }
      }
      if (found) break;
    }
  }

  freeifaddrs(ifaddr);
  return found;
}

}  // namespace flutter_neo_shield
