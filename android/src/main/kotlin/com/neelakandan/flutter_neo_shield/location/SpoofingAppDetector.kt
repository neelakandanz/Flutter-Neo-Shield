package com.neelakandan.flutter_neo_shield.location

import android.app.ActivityManager
import android.content.Context
import android.content.pm.PackageManager

/**
 * Layer 2: Spoofing App Detection.
 *
 * Scans for known GPS spoofing apps, running spoofer processes,
 * and suspicious accessibility services.
 */
class SpoofingAppDetector(private val context: Context) {

    // Known spoofing app package names (comprehensive list)
    private val knownSpoofingPackages = listOf(
        "com.lexa.fakegps",
        "com.incorporateapps.fakegps.fre",
        "com.fakegps.mock",
        "com.blogspot.newlocat",
        "com.lkr.fakelocation",
        "com.marlon.floating.fake.location",
        "com.location.changer",
        "com.evezzon.fakegps",
        "com.theappninjas.fakegpsjoystick",
        "com.theappninjas.gpsjoystick",
        "com.divi.fakeGPS",
        "org.hola.gpslocation",
        "com.byterev.bytefakegpslocation",
        "fake.location.changer.mock.gps",
        "com.fake.gps.go.location.spoofer",
        "com.rosteam.gpsemulator",
        "com.fakemygps.android",
        "com.mock.location",
        "ru.gavrikov.mocklocations",
        "com.incorporateapps.fakegps_route",
        "com.gsmartstudio.fakegps",
        "com.gps.faker",
        "location.faker.fake.gps.spoof",
        "com.fakegps.route",
        "com.pe.fakegpsrun",
        "com.icecoldapps.gpsfaker",
        "com.usefullapps.fakegpslocationpro",
        "com.gratzisoft.fakegps",
        "com.ltp.pro.fakelocation",
        "com.gsmartstudio.fakegps",
    )

    /** Check for installed spoofing apps. Returns list of found package names. */
    fun checkInstalledSpoofingApps(): List<String> {
        val pm = context.packageManager
        val detected = mutableListOf<String>()
        for (pkg in knownSpoofingPackages) {
            try {
                pm.getPackageInfo(pkg, 0)
                detected.add(pkg)
            } catch (_: PackageManager.NameNotFoundException) {
                // Not installed — good
            }
        }
        return detected
    }

    /** Check running processes for known spoofer keywords. */
    fun checkRunningSpoofers(): Boolean {
        try {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
                ?: return false
            @Suppress("DEPRECATION")
            val runningApps = am.runningAppProcesses ?: return false

            val suspiciousKeywords = listOf(
                "fakegps", "fake.gps", "mock.location", "gps.spoof",
                "location.faker", "gps_joystick", "fakemygps",
                "gpsemulator", "fakelocation", "gpsfaker"
            )

            return runningApps.any { process ->
                suspiciousKeywords.any { keyword ->
                    process.processName.contains(keyword, ignoreCase = true)
                }
            }
        } catch (_: Exception) {
            return false
        }
    }

    /** Check which app is set as the default mock location app in developer settings. */
    fun checkDefaultMockLocationApp(): String? {
        return try {
            android.provider.Settings.Secure.getString(context.contentResolver, "mock_location_app")
        } catch (_: Exception) {
            null
        }
    }
}
