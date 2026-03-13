import Foundation

/// Detects if developer tools and configurations are present on macOS.
///
/// Unlike iOS (which has a Developer Mode toggle), macOS developer mode
/// is indicated by:
/// 1. Xcode Command Line Tools installed
/// 2. Developer directory presence
/// 3. DevToolsSecurity enabled (allows debugging unsigned code)
/// 4. Gatekeeper disabled or permissive settings
public class DeveloperModeDetector {
    public static func check() -> Bool {
        return checkDevToolsSecurity() || checkXcodePresence() || checkGatekeeper()
    }

    /// Check if DevToolsSecurity is enabled.
    ///
    /// When enabled, non-admin users can attach debuggers to processes.
    /// This is a strong indicator of a developer machine.
    private static func checkDevToolsSecurity() -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        process.arguments = ["authorizationdb", "read", "system.privilege.taskport"]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        do {
            try process.run()
            process.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""

            // If allow is set, developer mode is essentially enabled
            if output.contains("allow") {
                return true
            }
        } catch {
            // Can't check — don't fail-closed for this heuristic
        }

        return false
    }

    /// Check if Xcode or developer tools are installed.
    private static func checkXcodePresence() -> Bool {
        let developerPaths = [
            "/Applications/Xcode.app",
            "/Library/Developer/CommandLineTools",
            "/usr/bin/xcode-select",
        ]

        for path in developerPaths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }

        // Also check xcode-select -p to see if dev tools are configured
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/xcode-select")
        process.arguments = ["-p"]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()

        do {
            try process.run()
            process.waitUntilExit()

            if process.terminationStatus == 0 {
                return true
            }
        } catch {
            // xcode-select not available
        }

        return false
    }

    /// Check if Gatekeeper is disabled.
    ///
    /// Disabled Gatekeeper allows unsigned apps to run freely.
    private static func checkGatekeeper() -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/spctl")
        process.arguments = ["--status"]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
            process.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""

            // "assessments disabled" means Gatekeeper is off
            if output.lowercased().contains("disabled") {
                return true
            }
        } catch {
            // Can't check Gatekeeper status
        }

        return false
    }
}
