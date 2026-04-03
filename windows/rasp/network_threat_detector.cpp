#include "network_threat_detector.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <string>
#include <algorithm>
#include "../shield_codec.h"

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace flutter_neo_shield {

// VPN adapter description indicators (encoded)
static const std::string kVpnIndicators[] = {
  ShieldCodec::Decode({58,50,56}),                                    // tap
  ShieldCodec::Decode({58,38,38}),                                    // tun
  ShieldCodec::Decode({56,35,38}),                                    // vpn
  ShieldCodec::Decode({57,58,58,41,35,59,50,58,40}),                 // wireguard
  ShieldCodec::Decode({57,58,38,56,49,32}),                           // wintun
  ShieldCodec::Decode({32,60,58,40,40,55,61,48}),                    // nordlynx
  ShieldCodec::Decode({62,33,39,56,43,32}),                           // proton
  ShieldCodec::Decode({35,38,36,32,50,47,55}),                       // mullvad
  ShieldCodec::Decode({33,35,45,34,50,62,61}),                       // openvpn
  ShieldCodec::Decode({45,58,59,47,43,110,50,38,53,39,33,61,38,41,39,58}), // cisco anyconnect
  ShieldCodec::Decode({40,60,58,56,45,32,54,60}),                    // fortinet
  ShieldCodec::Decode({62,50,36,35,100,47,63,60,35}),                // palo alto
};
static const size_t kVpnCount = sizeof(kVpnIndicators) / sizeof(kVpnIndicators[0]);

bool NetworkThreatDetector::CheckSimple() {
  return CheckProxy() || CheckVpn() || CheckProxyEnvironment();
}

bool NetworkThreatDetector::CheckProxy() {
  WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig = {};

  if (::WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig)) {
    bool has_proxy = false;

    if (proxyConfig.lpszProxy && wcslen(proxyConfig.lpszProxy) > 0) {
      has_proxy = true;
    }

    if (proxyConfig.lpszAutoConfigUrl) ::GlobalFree(proxyConfig.lpszAutoConfigUrl);
    if (proxyConfig.lpszProxy) ::GlobalFree(proxyConfig.lpszProxy);
    if (proxyConfig.lpszProxyBypass) ::GlobalFree(proxyConfig.lpszProxyBypass);

    return has_proxy;
  }

  return false;
}

bool NetworkThreatDetector::CheckVpn() {
  ULONG bufferSize = 0;
  ::GetAdaptersInfo(NULL, &bufferSize);
  if (bufferSize == 0) return false;

  std::vector<BYTE> buffer(bufferSize);
  PIP_ADAPTER_INFO adapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

  if (::GetAdaptersInfo(adapterInfo, &bufferSize) != ERROR_SUCCESS) {
    return false;
  }

  PIP_ADAPTER_INFO adapter = adapterInfo;
  while (adapter) {
    std::string desc(adapter->Description);
    std::transform(desc.begin(), desc.end(), desc.begin(), [](char c) { return (char)::tolower((unsigned char)c); });

    for (size_t i = 0; i < kVpnCount; i++) {
      if (desc.find(kVpnIndicators[i]) != std::string::npos) {
        return true;
      }
    }

    adapter = adapter->Next;
  }

  return false;
}

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
