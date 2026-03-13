#ifndef FLUTTER_NEO_SHIELD_SCREEN_PROTECTOR_H_
#define FLUTTER_NEO_SHIELD_SCREEN_PROTECTOR_H_

namespace flutter_neo_shield {

/// Screen protection on Linux.
///
/// Linux screen capture prevention is limited:
/// - Wayland: compositors control screen capture; apps can't block it
/// - X11: No standard API to prevent screenshots
///
/// This provides best-effort detection rather than prevention.
class ScreenProtector {
 public:
  bool Enable();
  bool Disable();
  bool IsActive() const;

 private:
  bool is_active_ = false;
};

}  // namespace flutter_neo_shield

#endif
