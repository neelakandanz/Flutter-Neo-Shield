import Foundation

/// Detects if System Integrity Protection (SIP) is disabled on macOS.
///
/// SIP (rootless) is macOS's equivalent of root/jailbreak protection.
/// When SIP is disabled, the system is vulnerable to kernel extensions,
/// unsigned code injection, and file system tampering.
///
/// Also checks if the process is running with elevated (root) privileges.
public class SIPDetector {
    public static func check() -> Bool {
        return checkRootPrivileges() || checkSIPDisabled() || checkSuspiciousPaths()
    }

    /// Check if the current process is running as root.
    private static func checkRootPrivileges() -> Bool {
        return getuid() == 0 || geteuid() == 0
    }

    /// Check if SIP is disabled by running csrutil status.
    ///
    /// When SIP is disabled, `csrutil status` outputs:
    ///   "System Integrity Protection status: disabled."
    /// When enabled:
    ///   "System Integrity Protection status: enabled."
    private static func checkSIPDisabled() -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/csrutil")
        process.arguments = ["status"]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        do {
            try process.run()
            process.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""

            // "disabled" in the output means SIP is off
            if output.lowercased().contains("disabled") {
                return true
            }
        } catch {
            // If we can't run csrutil, fail-closed
            return true
        }

        return false
    }

    /// Check for paths that should not be writable with SIP enabled.
    private static func checkSuspiciousPaths() -> Bool {
        // These directories are protected by SIP — if writable, SIP may be off
        let protectedPaths = [
            "/System/Library",
            "/usr/lib",
            "/usr/bin"
        ]

        let testFile = "/.neo_shield_sip_test"
        for base in protectedPaths {
            let path = base + testFile
            let fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
            if fd != -1 {
                close(fd)
                unlink(path)
                return true
            }
        }

        return false
    }
}
