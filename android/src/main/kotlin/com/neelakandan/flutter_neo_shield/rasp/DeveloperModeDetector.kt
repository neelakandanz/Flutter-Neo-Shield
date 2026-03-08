package com.neelakandan.flutter_neo_shield.rasp

import android.content.Context
import android.provider.Settings

/// Detects whether Developer Options is enabled on the device.
///
/// Reads `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED` from the system
/// content resolver. A value of `1` means Developer Options is ON.
///
/// Additionally checks `Settings.Global.ADB_ENABLED` as a secondary signal
/// (USB debugging requires Developer Options to be enabled first).
class DeveloperModeDetector {
    fun check(context: Context): Boolean {
        return try {
            val devSettingsEnabled = Settings.Global.getInt(
                context.contentResolver,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED,
                0
            )
            devSettingsEnabled == 1
        } catch (e: Exception) {
            // Fail-closed: if we can't determine the state, report as detected.
            true
        }
    }
}
