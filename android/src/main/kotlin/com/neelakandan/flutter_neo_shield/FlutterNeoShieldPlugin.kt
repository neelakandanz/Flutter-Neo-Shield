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
 */
class FlutterNeoShieldPlugin : FlutterPlugin, MethodCallHandler, ActivityAware {
    private lateinit var channel: MethodChannel
    private lateinit var raspChannel: MethodChannel
    private lateinit var screenChannel: MethodChannel
    private var screenEventChannel: EventChannel? = null
    private val secureStorage = HashMap<String, ByteArray>()
    private val debuggerDetector = com.neelakandan.flutter_neo_shield.rasp.DebuggerDetector()
    private var applicationContext: android.content.Context? = null
    private var activity: Activity? = null
    private val screenProtector = com.neelakandan.flutter_neo_shield.screen.ScreenProtector()
    private val recordingDetector = com.neelakandan.flutter_neo_shield.screen.ScreenRecordingDetector()
    private var appSwitcherGuardEnabled = false

    override fun onAttachedToEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        applicationContext = binding.applicationContext

        channel = MethodChannel(binding.binaryMessenger, "com.neelakandan.flutter_neo_shield/memory")
        channel.setMethodCallHandler(this)

        raspChannel = MethodChannel(binding.binaryMessenger, "com.neelakandan.flutter_neo_shield/rasp")
        raspChannel.setMethodCallHandler(this)

        screenChannel = MethodChannel(binding.binaryMessenger, "com.neelakandan.flutter_neo_shield/screen")
        screenChannel.setMethodCallHandler(this)

        screenEventChannel = EventChannel(binding.binaryMessenger, "com.neelakandan.flutter_neo_shield/screen_events")
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
            "allocateSecure" -> {
                val id = call.argument<String>("id")
                val data = call.argument<ByteArray>("data")
                if (id != null && data != null) {
                    secureStorage[id] = data.copyOf()
                    result.success(null)
                } else {
                    result.error("INVALID_ARGS", "id and data are required", null)
                }
            }
            "readSecure" -> {
                val id = call.argument<String>("id")
                if (id != null && secureStorage.containsKey(id)) {
                    result.success(secureStorage[id])
                } else {
                    result.error("NOT_FOUND", "No secure data with id: $id", null)
                }
            }
            "wipeSecure" -> {
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
            "wipeAll" -> {
                for (entry in secureStorage.values) {
                    entry.fill(0)
                }
                secureStorage.clear()
                result.success(null)
            }

            // RASP Shield
            "checkDebugger" -> {
                result.success(debuggerDetector.check())
            }
            "checkRoot" -> {
                result.success(com.neelakandan.flutter_neo_shield.rasp.RootDetector().check())
            }
            "checkEmulator" -> {
                result.success(com.neelakandan.flutter_neo_shield.rasp.EmulatorDetector().check())
            }
            "checkHooks" -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.HookDetector().check(context))
                } else {
                    // Fail closed: report as detected when context unavailable.
                    result.success(true)
                }
            }
            "checkFrida" -> {
                result.success(com.neelakandan.flutter_neo_shield.rasp.FridaDetector().check())
            }
            "checkIntegrity" -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.IntegrityDetector().check(context))
                } else {
                    // Fail closed: report as detected when context unavailable.
                    result.success(true)
                }
            }
            "checkDeveloperMode" -> {
                val context = applicationContext
                if (context != null) {
                    result.success(com.neelakandan.flutter_neo_shield.rasp.DeveloperModeDetector().check(context))
                } else {
                    // Fail closed: report as detected when context unavailable.
                    result.success(true)
                }
            }

            // Screen Shield
            "enableScreenProtection" -> {
                result.success(screenProtector.enable(activity))
            }
            "disableScreenProtection" -> {
                result.success(screenProtector.disable(activity))
            }
            "isScreenProtectionActive" -> {
                result.success(screenProtector.isActive(activity))
            }
            "enableAppSwitcherGuard" -> {
                // On Android, FLAG_SECURE already blanks the app switcher thumbnail.
                // Enabling screen protection implicitly guards the app switcher.
                val success = screenProtector.enable(activity)
                appSwitcherGuardEnabled = success
                result.success(success)
            }
            "disableAppSwitcherGuard" -> {
                // Only disable FLAG_SECURE if screen protection itself isn't active
                appSwitcherGuardEnabled = false
                // Don't clear FLAG_SECURE here — it may be set for screen protection.
                // The app switcher guard is a logical flag on Android.
                result.success(true)
            }
            "isScreenBeingRecorded" -> {
                result.success(recordingDetector.isRecordingOrMirroring(activity))
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

    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        // Wipe all on detach for safety.
        for (entry in secureStorage.values) {
            entry.fill(0)
        }
        secureStorage.clear()
        channel.setMethodCallHandler(null)
        raspChannel.setMethodCallHandler(null)
        screenChannel.setMethodCallHandler(null)
        screenEventChannel?.setStreamHandler(null)
    }
}
