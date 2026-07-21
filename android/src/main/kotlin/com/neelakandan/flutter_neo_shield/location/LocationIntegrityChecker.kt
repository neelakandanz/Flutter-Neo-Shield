package com.neelakandan.flutter_neo_shield.location

/**
 * Layer 7: Environment Integrity Check.
 *
 * Aggregates scores from all detection layers using weighted scoring.
 * Cross-references results for consistency and applies amplification.
 */
class LocationIntegrityChecker {

    private val weights = mapOf(
        "mockProvider" to 1.0,
        "spoofingApp" to 0.9,
        "locationHook" to 0.95,
        "gpsSignal" to 0.7,
        "sensorFusion" to 0.8,
        "temporalAnomaly" to 0.85
    )

    /**
     * Layers whose positive result is conclusive on its own. A single such
     * signal (e.g. an active mock-location provider) must flag as spoofed even
     * though the weighted average of all six layers would fall below the 0.5
     * threshold — otherwise a real spoof using only mock location goes
     * undetected while the "advanced" layers report 0.
     */
    private val vetoThresholds = mapOf(
        "mockProvider" to 1.0,
        "locationHook" to 0.95,
        "spoofingApp" to 1.0
    )

    /** Confidence assigned when a high-confidence veto layer fires. */
    private val vetoConfidence = 0.9

    /** Compute weighted confidence from all layer scores. */
    fun computeConfidence(scores: Map<String, Double>): Double {
        var totalScore = 0.0
        var totalWeight = 0.0

        for ((key, weight) in weights) {
            val score = scores[key] ?: 0.0
            totalScore += score * weight
            totalWeight += weight
        }

        if (totalWeight == 0.0) return 0.0

        val normalized = totalScore / totalWeight

        // Cross-validation amplification:
        // If multiple layers agree, increase confidence
        val triggeredLayers = scores.count { it.value > 0.3 }
        val amplifier = when {
            triggeredLayers >= 4 -> 1.5
            triggeredLayers >= 3 -> 1.3
            triggeredLayers >= 2 -> 1.1
            else -> 1.0
        }

        val weighted = (normalized * amplifier).coerceIn(0.0, 1.0)

        // High-confidence veto: any definitive single signal is conclusive.
        val vetoed = vetoThresholds.any { (key, threshold) ->
            (scores[key] ?: 0.0) >= threshold
        }

        return if (vetoed) maxOf(weighted, vetoConfidence) else weighted
    }
}
