#ifndef FLUTTER_NEO_SHIELD_NETWORK_THREAT_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_NETWORK_THREAT_DETECTOR_H_

namespace flutter_neo_shield {

/// Detects network-level threats on Windows.
///
/// Checks:
/// 1. System proxy configuration (WinHTTP, IE settings)
/// 2. VPN tunnel interfaces (TAP adapters)
/// 3. Proxy environment variables
class NetworkThreatDetector {
 public:
  static bool CheckSimple();

 private:
  static bool CheckProxy();
  static bool CheckVpn();
  static bool CheckProxyEnvironment();
};

}  // namespace flutter_neo_shield

#endif  // FLUTTER_NEO_SHIELD_NETWORK_THREAT_DETECTOR_H_
