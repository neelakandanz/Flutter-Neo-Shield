import Flutter
import UIKit

/// FlutterNeoShieldPlugin — iOS platform implementation.
///
/// Provides native memory allocation, secure wipe operations,
/// RASP checks, and screen protection.
public class FlutterNeoShieldPlugin: NSObject, FlutterPlugin {
    private var secureStorage: [String: Data] = [:]

    // Screen Shield
    private let screenProtector = ScreenProtector()
    private let screenshotDetector = ScreenshotDetector()
    private let recordingDetector = ScreenRecordingDetector()
    private let appSwitcherGuard = AppSwitcherGuard()
    private var screenEventSink: FlutterEventSink?

    public static func register(with registrar: FlutterPluginRegistrar) {
        let memoryChannel = FlutterMethodChannel(
            name: "com.neelakandan.flutter_neo_shield/memory",
            binaryMessenger: registrar.messenger()
        )
        let raspChannel = FlutterMethodChannel(
            name: "com.neelakandan.flutter_neo_shield/rasp",
            binaryMessenger: registrar.messenger()
        )
        let screenChannel = FlutterMethodChannel(
            name: "com.neelakandan.flutter_neo_shield/screen",
            binaryMessenger: registrar.messenger()
        )
        let screenEventChannel = FlutterEventChannel(
            name: "com.neelakandan.flutter_neo_shield/screen_events",
            binaryMessenger: registrar.messenger()
        )

        let instance = FlutterNeoShieldPlugin()
        registrar.addMethodCallDelegate(instance, channel: memoryChannel)
        registrar.addMethodCallDelegate(instance, channel: raspChannel)
        registrar.addMethodCallDelegate(instance, channel: screenChannel)
        screenEventChannel.setStreamHandler(instance)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        // Allow methods that don't require arguments
        let args = call.arguments as? [String: Any]

        switch call.method {
        // Memory Shield
        case "allocateSecure":
            guard let args = args,
                  let id = args["id"] as? String,
                  let data = args["data"] as? FlutterStandardTypedData else {
                result(FlutterError(code: "INVALID_ARGS", message: "id and data required", details: nil))
                return
            }
            secureStorage[id] = Data(data.data)
            result(nil)

        case "readSecure":
            guard let args = args,
                  let id = args["id"] as? String,
                  let data = secureStorage[id] else {
                result(FlutterError(code: "NOT_FOUND", message: "No secure data found", details: nil))
                return
            }
            result(FlutterStandardTypedData(bytes: data))

        case "wipeSecure":
            let id = args?["id"] as? String
            if let id = id, var data = secureStorage[id] {
                data.resetBytes(in: 0..<data.count)
                secureStorage.removeValue(forKey: id)
            }
            result(nil)

        case "wipeAll":
            wipeAll()
            result(nil)

        // RASP Shield
        case "checkDebugger":
            result(DebuggerDetector.check())

        case "checkRoot":
            result(JailbreakDetector.check())

        case "checkEmulator":
            result(EmulatorDetector.check())

        case "checkHooks":
            result(HookDetector.check())

        case "checkFrida":
            result(FridaDetector.check())

        case "checkIntegrity":
            result(IntegrityDetector.check())

        case "checkDeveloperMode":
            result(DeveloperModeDetector.check())

        // Screen Shield
        case "enableScreenProtection":
            let window = UIApplication.shared.windows.first { $0.isKeyWindow }
                ?? UIApplication.shared.windows.first
            result(screenProtector.enable(in: window))

        case "disableScreenProtection":
            result(screenProtector.disable())

        case "isScreenProtectionActive":
            result(screenProtector.isActive)

        case "enableAppSwitcherGuard":
            let window = UIApplication.shared.windows.first { $0.isKeyWindow }
                ?? UIApplication.shared.windows.first
            appSwitcherGuard.enable(in: window)
            result(true)

        case "disableAppSwitcherGuard":
            appSwitcherGuard.disable()
            result(true)

        case "isScreenBeingRecorded":
            result(recordingDetector.isRecording)

        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func wipeAll() {
        for key in secureStorage.keys {
            if var data = secureStorage[key] {
                data.resetBytes(in: 0..<data.count)
            }
        }
        secureStorage.removeAll()
    }

    /// Set up screenshot and recording detection, sending events to the Dart side.
    private func startDetection() {
        screenshotDetector.startDetecting { [weak self] in
            self?.screenEventSink?(["type": "screenshot"])
        }
        recordingDetector.startDetecting { [weak self] isCaptured in
            self?.screenEventSink?(["type": "recording", "isRecording": isCaptured])
        }
    }

    private func stopDetection() {
        screenshotDetector.stopDetecting()
        recordingDetector.stopDetecting()
    }
}

// MARK: - FlutterStreamHandler for Screen Events
extension FlutterNeoShieldPlugin: FlutterStreamHandler {
    public func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        screenEventSink = events
        startDetection()
        return nil
    }

    public func onCancel(withArguments arguments: Any?) -> FlutterError? {
        screenEventSink = nil
        stopDetection()
        return nil
    }
}
