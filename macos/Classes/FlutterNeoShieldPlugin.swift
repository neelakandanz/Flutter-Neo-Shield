import Cocoa
import FlutterMacOS

/// FlutterNeoShieldPlugin — macOS platform implementation.
///
/// Provides native memory allocation, secure wipe operations,
/// RASP checks, and screen protection for macOS.
public class FlutterNeoShieldPlugin: NSObject, FlutterPlugin {
    private var secureStorage: [String: Data] = [:]

    // Screen Shield
    private let screenProtector = ScreenProtector()
    private let screenRecordingDetector = ScreenRecordingDetector()
    private var screenEventSink: FlutterEventSink?

    public static func register(with registrar: FlutterPluginRegistrar) {
        let memoryChannel = FlutterMethodChannel(
            name: "com.neelakandan.flutter_neo_shield/memory",
            binaryMessenger: registrar.messenger
        )
        let raspChannel = FlutterMethodChannel(
            name: "com.neelakandan.flutter_neo_shield/rasp",
            binaryMessenger: registrar.messenger
        )
        let screenChannel = FlutterMethodChannel(
            name: "com.neelakandan.flutter_neo_shield/screen",
            binaryMessenger: registrar.messenger
        )
        let screenEventChannel = FlutterEventChannel(
            name: "com.neelakandan.flutter_neo_shield/screen_events",
            binaryMessenger: registrar.messenger
        )

        let instance = FlutterNeoShieldPlugin()
        registrar.addMethodCallDelegate(instance, channel: memoryChannel)
        registrar.addMethodCallDelegate(instance, channel: raspChannel)
        registrar.addMethodCallDelegate(instance, channel: screenChannel)
        screenEventChannel.setStreamHandler(instance)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
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
            if let id = id, let count = secureStorage[id]?.count, count > 0 {
                secureStorage[id]?.resetBytes(in: 0..<count)
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
            result(SIPDetector.check())

        case "checkEmulator":
            result(VMDetector.check())

        case "checkHooks":
            result(HookDetector.check())

        case "checkFrida":
            result(FridaDetector.check())

        case "checkIntegrity":
            result(IntegrityDetector.check())

        case "checkDeveloperMode":
            result(DeveloperModeDetector.check())

        case "checkSignature":
            result(SignatureDetector.check())

        case "getSignatureHash":
            result(nil)

        case "checkNativeDebug":
            result(NativeDebugDetector.check())

        case "checkNetworkThreats":
            result(NetworkThreatDetector.checkSimple())

        // Screen Shield
        case "enableScreenProtection":
            result(screenProtector.enable())

        case "disableScreenProtection":
            result(screenProtector.disable())

        case "isScreenProtectionActive":
            result(screenProtector.isActive)

        case "enableAppSwitcherGuard":
            // macOS doesn't have an app switcher like iOS
            // but we can hide window content on deactivation
            result(false)

        case "disableAppSwitcherGuard":
            result(false)

        case "isScreenBeingRecorded":
            result(screenRecordingDetector.isRecording)

        default:
            result(FlutterMethodNotImplemented)
        }
    }

    private func wipeAll() {
        for key in secureStorage.keys {
            if let count = secureStorage[key]?.count, count > 0 {
                secureStorage[key]?.resetBytes(in: 0..<count)
            }
        }
        secureStorage.removeAll()
    }

    private func startDetection() {
        screenRecordingDetector.startDetecting { [weak self] isRecording in
            self?.screenEventSink?(["type": "recording", "isRecording": isRecording])
        }
    }

    private func stopDetection() {
        screenRecordingDetector.stopDetecting()
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
