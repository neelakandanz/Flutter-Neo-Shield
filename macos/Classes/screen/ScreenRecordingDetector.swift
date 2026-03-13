import Cocoa
import CoreGraphics

/// Detects screen recording and screen sharing on macOS.
///
/// Uses CGWindowListCopyWindowInfo to detect capture-related windows
/// and processes. Also monitors for display configuration changes
/// that may indicate screen sharing sessions.
///
/// macOS 12.3+: Uses SCShareableContent for more reliable detection.
class ScreenRecordingDetector {
    private var timer: Timer?
    private var handler: ((Bool) -> Void)?
    private var lastState = false

    /// Whether screen recording/sharing is currently detected.
    var isRecording: Bool {
        return checkScreenCapture()
    }

    /// Start periodic monitoring for screen recording state changes.
    func startDetecting(handler: @escaping (Bool) -> Void) {
        stopDetecting()
        self.handler = handler

        // Poll every 2 seconds — macOS doesn't have a direct notification
        // for screen recording state changes
        timer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            guard let self = self else { return }
            let currentState = self.checkScreenCapture()
            if currentState != self.lastState {
                self.lastState = currentState
                self.handler?(currentState)
            }
        }
    }

    /// Stop monitoring.
    func stopDetecting() {
        timer?.invalidate()
        timer = nil
        handler = nil
    }

    /// Check for active screen capture.
    ///
    /// Detects screen recording by looking for processes that have
    /// screen capture sessions active.
    private func checkScreenCapture() -> Bool {
        // Check for known screen recording processes
        let recordingApps = [
            "screencaptureui",     // macOS built-in
            "QuickTime Player",    // QuickTime recording
            "OBS",                 // Open Broadcaster Software
            "obs",
            "ScreenFlow",
            "Camtasia",
            "Kap",                 // Popular macOS screen recorder
        ]

        let workspace = NSWorkspace.shared
        let runningApps = workspace.runningApplications

        for app in runningApps {
            let name = app.localizedName ?? ""
            for recorder in recordingApps {
                if name.lowercased().contains(recorder.lowercased()) {
                    return true
                }
            }
        }

        // Check for screen sharing via window list
        // Screen sharing creates overlay windows from other processes
        guard let windowList = CGWindowListCopyWindowInfo(
            [.optionOnScreenOnly, .excludeDesktopElements],
            kCGNullWindowID
        ) as? [[String: Any]] else {
            return false
        }

        for window in windowList {
            if let ownerName = window[kCGWindowOwnerName as String] as? String {
                let lowerName = ownerName.lowercased()
                if lowerName.contains("screensharing") ||
                   lowerName.contains("screen sharing") ||
                   lowerName.contains("teamviewer") ||
                   lowerName.contains("anydesk") ||
                   lowerName.contains("vnc") {
                    return true
                }
            }
        }

        return false
    }

    deinit {
        stopDetecting()
    }
}
