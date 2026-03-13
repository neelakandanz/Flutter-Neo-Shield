#ifndef FLUTTER_NEO_SHIELD_FRIDA_DETECTOR_H_
#define FLUTTER_NEO_SHIELD_FRIDA_DETECTOR_H_

namespace flutter_neo_shield {

class FridaDetector {
 public:
  static bool Check();
 private:
  static bool CheckPorts();
  static bool CheckMaps();
  static bool CheckFiles();
};

}  // namespace flutter_neo_shield

#endif
