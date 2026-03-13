#ifndef FLUTTER_NEO_SHIELD_NETWORK_THREAT_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_NETWORK_THREAT_DETECTOR_H_

namespace flutter_neo_shield {

class NetworkThreatDetector {
 public:
  static bool CheckSimple();
 private:
  static bool CheckProxy();
  static bool CheckVpn();
};

}  // namespace flutter_neo_shield

#endif
