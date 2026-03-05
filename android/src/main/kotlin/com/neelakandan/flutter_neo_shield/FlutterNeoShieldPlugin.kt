package com.neelakandan.flutter_neo_shield

import androidx.annotation.NonNull
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result

/**
 * FlutterNeoShieldPlugin — Android platform implementation.
 *
 * Provides native memory allocation and secure wipe operations
 * for the Memory Shield module.
 */
class FlutterNeoShieldPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel
    private lateinit var raspChannel: MethodChannel
    private val secureStorage = HashMap<String, ByteArray>()
    private val debuggerDetector = com.neelakandan.flutter_neo_shield.rasp.DebuggerDetector()
    private var applicationContext: android.content.Context? = null

    override fun onAttachedToEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        applicationContext = binding.applicationContext
        
        channel = MethodChannel(binding.binaryMessenger, "com.neelakandan.flutter_neo_shield/memory")
        channel.setMethodCallHandler(this)

        raspChannel = MethodChannel(binding.binaryMessenger, "com.neelakandan.flutter_neo_shield/rasp")
        raspChannel.setMethodCallHandler(this)
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
            else -> {
                result.notImplemented()
            }
        }
    }

    override fun onDetachedFromEngine(@NonNull binding: FlutterPlugin.FlutterPluginBinding) {
        // Wipe all on detach for safety.
        for (entry in secureStorage.values) {
            entry.fill(0)
        }
        secureStorage.clear()
        channel.setMethodCallHandler(null)
        raspChannel.setMethodCallHandler(null)
    }
}
