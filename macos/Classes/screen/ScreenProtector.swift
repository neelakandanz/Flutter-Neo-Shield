import Cocoa

/// Prevents screen capture of the application window on macOS.
///
/// Uses NSWindow's sharingType property to control screen capture behavior:
/// - `.none` — window content is excluded from screenshots and screen recording
/// - `.readOnly` — normal behavior (default)
///
/// macOS 10.14+: `NSWindow.SharingType.none` prevents the window from
/// appearing in screenshots, screen recordings, and screen sharing sessions.
/// The window appears as a black rectangle in captures.
class ScreenProtector {
    private var isEnabled = false

    /// Enable screen protection on all application windows.
    func enable() -> Bool {
        guard !isEnabled else { return true }

        DispatchQueue.main.async {
            for window in NSApplication.shared.windows {
                window.sharingType = .none
            }
        }

        isEnabled = true
        return true
    }

    /// Disable screen protection.
    func disable() -> Bool {
        guard isEnabled else { return true }

        DispatchQueue.main.async {
            for window in NSApplication.shared.windows {
                window.sharingType = .readOnly
            }
        }

        isEnabled = false
        return true
    }

    /// Whether screen protection is currently active.
    var isActive: Bool {
        return isEnabled
    }
}
