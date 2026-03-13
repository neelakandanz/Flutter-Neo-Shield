#include "screen_protector.h"

namespace flutter_neo_shield {

/// Enable screen protection.
///
/// On Linux, true screen capture prevention is not possible at the
/// application level. Wayland compositors control capture permissions,
/// and X11 has no standard prevention API.
///
/// Returns true to indicate the request was acknowledged, but actual
/// protection depends on the display server and compositor.
bool ScreenProtector::Enable() {
  is_active_ = true;
  return true;
}

bool ScreenProtector::Disable() {
  is_active_ = false;
  return true;
}

bool ScreenProtector::IsActive() const {
  return is_active_;
}

}  // namespace flutter_neo_shield
