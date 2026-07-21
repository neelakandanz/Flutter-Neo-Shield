package com.neelakandan.flutter_neo_shield

import android.app.Activity
import android.os.Handler
import android.os.Looper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.plugin.common.MethodChannel

/**
 * Android biometric authentication via androidx.biometric [BiometricPrompt].
 *
 * Uses Class-3 (BIOMETRIC_STRONG) authenticators. Device-credential
 * (PIN/pattern/password) is offered as a fallback when requested.
 *
 * [activityProvider] resolves the current host [Activity] lazily so this
 * handler stays valid across configuration changes.
 */
class BiometricHandler(private val activityProvider: () -> Activity?) {

    /** Reports biometric hardware/enrollment availability to Flutter. */
    fun checkAvailability(result: MethodChannel.Result) {
        val activity = activityProvider()
        if (activity == null) {
            result.success(unavailable())
            return
        }
        val manager = BiometricManager.from(activity)
        val status = manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        val canAuth = status == BiometricManager.BIOMETRIC_SUCCESS
        val available = status == BiometricManager.BIOMETRIC_SUCCESS ||
            status == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED
        val types = if (canAuth) listOf("biometric") else emptyList<String>()
        result.success(
            mapOf(
                "available" to available,
                "canAuth" to canAuth,
                "types" to types
            )
        )
    }

    /**
     * Presents the system biometric prompt. Replies exactly once with
     * `{ "success": Boolean, "error": String? }`.
     */
    fun authenticate(reason: String, allowDeviceCredential: Boolean, result: MethodChannel.Result) {
        val activity = activityProvider()
        if (activity !is FragmentActivity) {
            result.success(mapOf("success" to false, "error" to "Biometric requires a FragmentActivity host"))
            return
        }

        // BiometricPrompt and the Flutter Result callback must both run on the
        // main thread.
        Handler(Looper.getMainLooper()).post {
            try {
                var settled = false
                fun reply(value: Map<String, Any?>) {
                    if (settled) return
                    settled = true
                    result.success(value)
                }

                val callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        reply(mapOf("success" to false, "error" to errString.toString()))
                    }

                    override fun onAuthenticationSucceeded(authResult: BiometricPrompt.AuthenticationResult) {
                        reply(mapOf("success" to true, "error" to null))
                    }

                    override fun onAuthenticationFailed() {
                        // Non-terminal: the user may retry. Do not settle here.
                    }
                }

                val prompt = BiometricPrompt(
                    activity,
                    ContextCompat.getMainExecutor(activity),
                    callback
                )

                val builder = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Authenticate")
                    .setSubtitle(reason)

                if (allowDeviceCredential) {
                    builder.setAllowedAuthenticators(
                        BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            BiometricManager.Authenticators.DEVICE_CREDENTIAL
                    )
                } else {
                    builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    builder.setNegativeButtonText("Cancel")
                }

                prompt.authenticate(builder.build())
            } catch (e: Exception) {
                result.success(mapOf("success" to false, "error" to (e.message ?: "Biometric error")))
            }
        }
    }

    private fun unavailable(): Map<String, Any?> =
        mapOf("available" to false, "canAuth" to false, "types" to emptyList<String>())
}
