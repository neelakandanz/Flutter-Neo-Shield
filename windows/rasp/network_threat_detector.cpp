#include "network_threat_detector.h"

#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <string>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace flutter_neo_shield {

bool NetworkThreatDetector::CheckSimple() {
  return CheckProxy() || CheckVpn() || CheckProxyEnvironment();
}

/// Check system proxy settings via WinHTTP.
///
/// Detects HTTP/HTTPS proxies configured at the system level
/// (Burp Suite, Charles Proxy, mitmproxy).
bool NetworkThreatDetector::CheckProxy() {
  WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig = {};

  if (::WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig)) {
    bool has_proxy = false;

    if (proxyConfig.lpszProxy && wcslen(proxyConfig.lpszProxy) > 0) {
      has_proxy = true;
    }

    // Clean up
    if (proxyConfig.lpszAutoConfigUrl) ::GlobalFree(proxyConfig.lpszAutoConfigUrl);
    if (proxyConfig.lpszProxy) ::GlobalFree(proxyConfig.lpszProxy);
    if (proxyConfig.lpszProxyBypass) ::GlobalFree(proxyConfig.lpszProxyBypass);

    return has_proxy;
  }

  return false;
}

/// Detect VPN connections via network adapter enumeration.
///
/// VPN clients install TAP/TUN virtual adapters. We check adapter
/// descriptions for known VPN indicators.
bool NetworkThreatDetector::CheckVpn() {
  ULONG bufferSize = 0;
  ::GetAdaptersInfo(NULL, &bufferSize);
  if (bufferSize == 0) return false;

  std::vector<BYTE> buffer(bufferSize);
  PIP_ADAPTER_INFO adapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

  if (::GetAdaptersInfo(adapterInfo, &bufferSize) != ERROR_SUCCESS) {
    return false;
  }

  const char *vpn_indicators[] = {
    "tap", "tun", "vpn", "wireguard", "wintun",
    "nordlynx", "proton", "mullvad", "openvpn",
    "cisco anyconnect", "fortinet", "palo alto",
  };

  PIP_ADAPTER_INFO adapter = adapterInfo;
  while (adapter) {
    std::string desc(adapter->Description);
    std::transform(desc.begin(), desc.end(), desc.begin(), ::tolower);

    for (const auto &indicator : vpn_indicators) {
      if (desc.find(indicator) != std::string::npos) {
        return true;
      }
    }

    adapter = adapter->Next;
  }

  return false;
}

/// Check for proxy environment variables.
bool NetworkThreatDetector::CheckProxyEnvironment() {
  const wchar_t *proxy_vars[] = {
    L"http_proxy", L"https_proxy", L"HTTP_PROXY",
    L"HTTPS_PROXY", L"ALL_PROXY",
  };

  for (const auto &var : proxy_vars) {
    wchar_t buffer[1024];
    DWORD size = ::GetEnvironmentVariableW(var, buffer, 1024);
    if (size > 0) {
      return true;
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
