#ifndef FLUTTER_NEO_SHIELD_SCREEN_PROTECTOR_H_
#define FLUTTER_NEO_SHIELD_SCREEN_PROTECTOR_H_

#include <flutter/plugin_registrar_windows.h>

namespace flutter_neo_shield {

/// Prevents screen capture of the application window on Windows.
///
/// Uses SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) on Windows 10 2004+
/// to exclude the window from all capture methods (PrintScreen, Game Bar,
/// screen recording, remote desktop).
///
/// Falls back to WDA_MONITOR on older Windows 10 versions, which shows
/// the window as black in captures.
class ScreenProtector {
 public:
  explicit ScreenProtector(flutter::PluginRegistrarWindows *registrar);

  bool Enable();
  bool Disable();
  bool IsActive() const;

 private:
  HWND GetFlutterWindow() const;
  flutter::PluginRegistrarWindows *registrar_;
  bool is_active_ = false;
};

}  // namespace flutter_neo_shield

#endif  // FLUTTER_NEO_SHIELD_SCREEN_PROTECTOR_H_
