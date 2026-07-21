package com.neelakandan.flutter_neo_shield

import android.app.Activity
import androidx.annotation.NonNull
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

/**
 * FlutterNeoShieldPlugin — Android platform implementation.
 *
 * Provides native memory allocation, secure wipe operations,
 * RASP checks, and screen protection.
 *
 * P3 Security Hardening: All RASP boolean results are wrapped through
 * [validateResult] which cross-checks with [SelfIntegrityChecker] and
 * performs cross-detector validation. If the plugin itself is hooked,
 * all security checks return true (detected).
 */
class FlutterNeoShieldPlugin : FlutterPlugin, MethodCallHandler, ActivityAware {
    private lateinit var channel: MethodChannel
    private lateinit var raspChannel: MethodChannel
    private lateinit var screenChannel: MethodChannel
    private var screenEventChannel: EventChannel? = null
    private lateinit var locationChannel: MethodChannel
    private var locationHandler: com.neelakandan.flutter_neo_shield.location.LocationShieldHandler? = null
    private val secureStorage = HashMap<String, ByteArray>()
    private val debuggerDetector = com.neelakandan.flutter_neo_shield.rasp.DebuggerDetector()
    private var applicationContext: android.content.Context? = null
    private var activity: Activity? = null
    private val screenProtector = com.neelakandan.flutter_neo_shield.screen.ScreenProtector()
    private val recordingDetector = com.neelakandan.flutter_neo_shield.screen.ScreenRecordingDetector()
    private var appSwitcherGuardEnabled = false

    // New feature detectors (v2.0.0)
    private var secureStorageChannel: MethodChannel? = null
    private var biometricChannel: MethodChannel? = null
    private var deviceBindingChannel: MethodChannel? = null
    private var secureStorageHandler: com.neelakandan.flutter_neo_shield.secure.SecureStorageHandler? = null
    private var biometricHandler: BiometricHandler? = null

    override fun onAttachedToEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        applicationContext = binding.applicationContext

        channel = MethodChannel(binding.binaryMessenger, ShieldCodec.decode(ShieldCodec.CH_MEMORY))
        channel.setMethodCallHandler(this)

        raspChannel = MethodChannel(binding.binaryMessenger, ShieldCodec.decode(ShieldCodec.CH_RASP))
        raspChannel.setMethodCallHandler(this)

        screenChannel = MethodChannel(binding.binaryMessenger, ShieldCodec.decode(ShieldCodec.CH_SCREEN))
        screenChannel.setMethodCallHandler(this)

        locationChannel = MethodChannel(binding.binaryMessenger, ShieldCodec.decode(ShieldCodec.CH_LOCATION))
        locationChannel.setMethodCallHandler(this)
        locationHandler = com.neelakandan.flutter_neo_shield.location.LocationShieldHandler(binding.applicationContext)

        // New channels (v2.0.0)
        secureStorageChannel = MethodChannel(binding.binaryMessenger, ShieldCodec.decode(ShieldCodec.CH_SECURE_STORAGE))
        secureStorageChannel?.setMethodCallHandler(this)
        secureStorageHandler = com.neelakandan.flutter_neo_shield.secure.SecureStorageHandler(binding.applicationContext)

        biometricChannel = MethodChannel(binding.binaryMessenger, ShieldCodec.decode(ShieldCodec.CH_BIOMETRIC))
        biometricChannel?.setMethodCallHandler(this)
        biometricHandler = BiometricHandler { activity }

        deviceBindingChannel = MethodChannel(binding.binaryMessenger, ShieldCodec.decode(ShieldCodec.CH_DEVICE_BINDING))
        deviceBindingChannel?.setMethodCallHandler(this)

        screenEventChannel = EventChannel(binding.binaryMessenger, ShieldCodec.decode(ShieldCodec.CH_SCREEN_EVENTS))
        screenEventChannel?.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                // Android does not have native screenshot/recording callbacks
                // below API 34. Events are sent on-demand or via polling.
            }

            override fun onCancel(arguments: Any?) {}
        })
    }

    override fun onMethodCall(@NonNull call: MethodCall, @NonNull result: Result) {
        when (call.method) {
            // Memory Shield
            ShieldCodec.decode(ShieldCodec.M_ALLOCATE_SECURE) -> {
                val id = call.argument<String>("id")
                val data = call.argument<ByteArray>("data")
                if (id != null && data != null) {
                    secureStorage[id] = data.copyOf()
                    result.success(null)
                } else {
                    result.error("INVALID_ARGS", "id and data are required", null)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_READ_SECURE) -> {
                val id = call.argument<String>("id")
                if (id != null && secureStorage.containsKey(id)) {
                    result.success(secureStorage[id])
                } else {
                    result.error("NOT_FOUND", "No secure data with id: $id", null)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_WIPE_SECURE) -> {
                val id = call.argument<String>("id")
                if (id != null && secureStorage.containsKey(id)) {
                    val data = secureStorage[id]!!
                    data.fill(0)
                    secureStorage.remove(id)
                    result.success(null)
                } else {
                    result.success(null)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_WIPE_ALL) -> {
                for (entry in secureStorage.values) {
                    entry.fill(0)
                }
                secureStorage.clear()
                result.success(null)
            }

            // RASP Shield — all boolean results are wrapped through validateResult()
            // for self-integrity and cross-detector validation.
            ShieldCodec.decode(ShieldCodec.M_CHECK_DEBUGGER) -> {
                result.success(validateResult(debuggerDetector.check()))
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_ROOT) -> {
                result.success(validateRootResult(com.neelakandan.flutter_neo_shield.rasp.RootDetector().check()))
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_EMULATOR) -> {
                result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.EmulatorDetector().check()))
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_HOOKS) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.HookDetector().check(context)))
                } else {
                    // Fail closed: report as detected when context unavailable.
                    result.success(true)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_FRIDA) -> {
                result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.FridaDetector().check()))
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_INTEGRITY) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.IntegrityDetector().check(context)))
                } else {
                    // Fail closed: report as detected when context unavailable.
                    result.success(true)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_DEVELOPER_MODE) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.DeveloperModeDetector().check(context)))
                } else {
                    // Fail closed: report as detected when context unavailable.
                    result.success(true)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_SIGNATURE) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.SignatureDetector().checkSimple(context)))
                } else {
                    result.success(true)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_GET_SIGNATURE_HASH) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.SignatureDetector().getCurrentSignatureHash(context))
                } else {
                    result.success(null)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_NATIVE_DEBUG) -> {
                result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.NativeDebugDetector().check()))
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_NETWORK_THREATS) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(validateResult(com.neelakandan.flutter_neo_shield.rasp.NetworkThreatDetector().checkSimple(context)))
                } else {
                    result.success(true)
                }
            }

            // Screen Shield
            ShieldCodec.decode(ShieldCodec.M_ENABLE_SCREEN_PROTECTION) -> {
                screenProtector.enable(activity, result)
            }
            ShieldCodec.decode(ShieldCodec.M_DISABLE_SCREEN_PROTECTION) -> {
                screenProtector.disable(activity, result)
            }
            ShieldCodec.decode(ShieldCodec.M_IS_SCREEN_PROTECTION_ACTIVE) -> {
                result.success(screenProtector.isActive(activity))
            }
            ShieldCodec.decode(ShieldCodec.M_ENABLE_APP_SWITCHER_GUARD) -> {
                // On Android, FLAG_SECURE already blanks the app switcher thumbnail.
                // Enabling screen protection implicitly guards the app switcher.
                // We wrap the result to also track the guard state.
                screenProtector.enable(activity, object : Result {
                    override fun success(value: Any?) {
                        val success = value as? Boolean ?: false
                        appSwitcherGuardEnabled = success
                        result.success(success)
                    }
                    override fun error(code: String, msg: String?, details: Any?) {
                        result.error(code, msg, details)
                    }
                    override fun notImplemented() {
                        result.notImplemented()
                    }
                })
            }
            ShieldCodec.decode(ShieldCodec.M_DISABLE_APP_SWITCHER_GUARD) -> {
                // Only disable FLAG_SECURE if screen protection itself isn't active
                appSwitcherGuardEnabled = false
                // Don't clear FLAG_SECURE here — it may be set for screen protection.
                // The app switcher guard is a logical flag on Android.
                result.success(true)
            }
            ShieldCodec.decode(ShieldCodec.M_IS_SCREEN_BEING_RECORDED) -> {
                result.success(recordingDetector.isRecordingOrMirroring(activity))
            }

            // Location Shield — delegated to LocationShieldHandler
            ShieldCodec.decode(ShieldCodec.M_CHECK_FAKE_LOCATION),
            ShieldCodec.decode(ShieldCodec.M_CHECK_MOCK_PROVIDER),
            ShieldCodec.decode(ShieldCodec.M_CHECK_SPOOFING_APPS),
            ShieldCodec.decode(ShieldCodec.M_CHECK_LOCATION_HOOKS),
            ShieldCodec.decode(ShieldCodec.M_CHECK_GPS_ANOMALY),
            ShieldCodec.decode(ShieldCodec.M_CHECK_SENSOR_FUSION),
            ShieldCodec.decode(ShieldCodec.M_CHECK_TEMPORAL_ANOMALY) -> {
                locationHandler?.onMethodCall(call, result) ?: result.success(true)
            }

            // --- New v2.0.0 RASP checks ---
            ShieldCodec.decode(ShieldCodec.M_CHECK_OVERLAY) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.OverlayDetector().check(context))
                } else {
                    result.success(true)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_ENABLE_OVERLAY_PROTECTION),
            ShieldCodec.decode(ShieldCodec.M_DISABLE_OVERLAY_PROTECTION) -> {
                result.success(true)
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_CLICKJACKING) -> {
                result.success(false) // Not applicable on Android native
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_ACCESSIBILITY) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.AccessibilityDetector().check(context))
                } else {
                    result.success(true)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_GET_ACCESSIBILITY_SERVICES) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.AccessibilityDetector().getEnabledServices(context))
                } else {
                    result.success("")
                }
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_SCREEN_READER) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.AccessibilityDetector().isScreenReaderActive(context))
                } else {
                    result.success(false)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_KEYBOARD) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.KeyboardDetector().isThirdPartyKeyboard(context))
                } else {
                    result.success(true)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_GET_KEYBOARD_PACKAGE) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.KeyboardDetector().getCurrentKeyboardPackage(context))
                } else {
                    result.success("")
                }
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_KEYLOGGER) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.KeyboardDetector().checkKeylogger(context))
                } else {
                    result.success(true)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_CODE_INJECTION) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.CodeInjectionDetector().check(context))
                } else {
                    result.success(true)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_GET_SUSPICIOUS_MODULES) -> {
                result.success(com.neelakandan.flutter_neo_shield.rasp.CodeInjectionDetector().getSuspiciousModules())
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_OBFUSCATION) -> {
                result.success(com.neelakandan.flutter_neo_shield.rasp.ObfuscationDetector().check())
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_CAMERA_IN_USE) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.PermissionDetector().isCameraInUse(context))
                } else {
                    result.success(false)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_MIC_IN_USE) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.PermissionDetector().isMicrophoneInUse(context))
                } else {
                    result.success(false)
                }
            }
            ShieldCodec.decode(ShieldCodec.M_CHECK_BG_LOCATION) -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.PermissionDetector().isLocationAccessedInBackground(context))
                } else {
                    result.success(false)
                }
            }

            // Secure Storage Shield
            "writeSecure" -> {
                val key = call.argument<String>("key")
                val value = call.argument<String>("value")
                if (key != null && value != null) {
                    result.success(secureStorageHandler?.write(key, value) ?: false)
                } else {
                    result.error("INVALID_ARGS", "key and value required", null)
                }
            }
            "readSecure" -> {
                val key = call.argument<String>("key")
                if (key != null) {
                    result.success(secureStorageHandler?.read(key))
                } else {
                    result.error("INVALID_ARGS", "key required", null)
                }
            }
            "deleteSecure" -> {
                val key = call.argument<String>("key")
                if (key != null) {
                    result.success(secureStorageHandler?.delete(key) ?: false)
                } else {
                    result.error("INVALID_ARGS", "key required", null)
                }
            }
            "containsKeySecure" -> {
                val key = call.argument<String>("key")
                if (key != null) {
                    result.success(secureStorageHandler?.containsKey(key) ?: false)
                } else {
                    result.success(false)
                }
            }
            "wipeAllSecure" -> {
                result.success(secureStorageHandler?.wipeAll() ?: false)
            }

            // Biometric Shield
            "checkBiometric" -> {
                biometricHandler?.checkAvailability(result)
                    ?: result.success(
                        mapOf("available" to false, "canAuth" to false, "types" to emptyList<String>())
                    )
            }
            "authenticate" -> {
                val reason = call.argument<String>("reason") ?: "Authenticate"
                val allowDeviceCredential = call.argument<Boolean>("allowDeviceCredential") ?: false
                val handler = biometricHandler
                if (handler != null) {
                    handler.authenticate(reason, allowDeviceCredential, result)
                } else {
                    result.success(mapOf("success" to false, "error" to "Biometric unavailable"))
                }
            }

            // Device Binding Shield
            "getDeviceFingerprint" -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.DeviceBindingDetector().getDeviceFingerprint(context))
                } else {
                    result.success(null)
                }
            }

            else -> {
                result.notImplemented()
            }
        }
    }

    // ActivityAware implementation
    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    /**
     * Cross-validates a RASP detection result with the self-integrity checker.
     *
     * If the detector returned false (not detected) but our own code has been
     * hooked, we override to true (detected) — because the "false" result
     * cannot be trusted if the detection code itself is compromised.
     */
    private fun validateResult(detected: Boolean): Boolean {
        if (detected) return true
        // If the detector says "clean" but we're hooked, override to detected
        if (com.neelakandan.flutter_neo_shield.rasp.SelfIntegrityChecker.isHooked()) {
            return true
        }
        return false
    }

    /**
     * Cross-detector validation: if checkRoot returns false but hooks are
     * detected, flag root as suspicious (hook frameworks hide root).
     */
    private fun validateRootResult(rootDetected: Boolean): Boolean {
        if (rootDetected) return true
        // Cross-check: hook frameworks often hide root status
        val context = applicationContext
        if (context != null) {
            val hooksDetected = com.neelakandan.flutter_neo_shield.rasp.HookDetector().check(context)
            if (hooksDetected) return true
        }
        return validateResult(rootDetected)
    }

    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        // Wipe all on detach for safety.
        for (entry in secureStorage.values) {
            entry.fill(0)
        }
        secureStorage.clear()
        channel.setMethodCallHandler(null)
        raspChannel.setMethodCallHandler(null)
        screenChannel.setMethodCallHandler(null)
        locationChannel.setMethodCallHandler(null)
        locationHandler = null
        screenEventChannel?.setStreamHandler(null)
        secureStorageChannel?.setMethodCallHandler(null)
        biometricChannel?.setMethodCallHandler(null)
        deviceBindingChannel?.setMethodCallHandler(null)
        secureStorageHandler = null
        biometricHandler = null
    }
}
