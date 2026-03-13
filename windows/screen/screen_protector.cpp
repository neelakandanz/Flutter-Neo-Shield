#include "screen_protector.h"

#include <windows.h>

// WDA_EXCLUDEFROMCAPTURE is available from Windows 10 version 2004 (build 19041)
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

namespace flutter_neo_shield {

ScreenProtector::ScreenProtector(flutter::PluginRegistrarWindows *registrar)
    : registrar_(registrar) {}

/// Enable screen capture protection.
///
/// WDA_EXCLUDEFROMCAPTURE (Windows 10 2004+): Window is completely excluded
/// from all capture APIs. Most secure option — window doesn't appear at all.
///
/// WDA_MONITOR (older Windows 10): Window appears as black in captures.
/// Less ideal but still prevents content leakage.
bool ScreenProtector::Enable() {
  if (is_active_) return true;

  HWND hwnd = GetFlutterWindow();
  if (!hwnd) return false;

  // Try WDA_EXCLUDEFROMCAPTURE first (Windows 10 2004+)
  if (::SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)) {
    is_active_ = true;
    return true;
  }

  // Fall back to WDA_MONITOR (Windows 10 1709+)
  if (::SetWindowDisplayAffinity(hwnd, WDA_MONITOR)) {
    is_active_ = true;
    return true;
  }

  return false;
}

/// Disable screen capture protection.
bool ScreenProtector::Disable() {
  if (!is_active_) return true;

  HWND hwnd = GetFlutterWindow();
  if (!hwnd) return false;

  if (::SetWindowDisplayAffinity(hwnd, WDA_NONE)) {
    is_active_ = false;
    return true;
  }

  return false;
}

bool ScreenProtector::IsActive() const {
  return is_active_;
}

/// Get the Flutter application's main window handle.
HWND ScreenProtector::GetFlutterWindow() const {
  return registrar_->GetView()->GetNativeWindow();
}

}  // namespace flutter_neo_shield
