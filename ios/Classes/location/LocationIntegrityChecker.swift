import Foundation

/// Layer 7: Environment Integrity Check for iOS.
class LocationIntegrityChecker {

    private let weights: [String: Double] = [
        "mockProvider": 1.0,
        "spoofingApp": 0.9,
        "locationHook": 0.95,
        "gpsSignal": 0.7,
        "sensorFusion": 0.8,
        "temporalAnomaly": 0.85,
    ]

    /// Layers whose positive result is conclusive on its own. A single such
    /// signal (e.g. a simulated location) must flag as spoofed even though the
    /// weighted average of all six layers would fall below the 0.5 threshold.
    private let vetoThresholds: [String: Double] = [
        "mockProvider": 1.0,
        "locationHook": 0.95,
        "spoofingApp": 1.0,
    ]

    /// Confidence assigned when a high-confidence veto layer fires.
    private let vetoConfidence: Double = 0.9

    func computeConfidence(scores: [String: Double]) -> Double {
        var totalScore: Double = 0.0
        var totalWeight: Double = 0.0

        for (key, weight) in weights {
            let score = scores[key] ?? 0.0
            totalScore += score * weight
            totalWeight += weight
        }

        guard totalWeight > 0 else { return 0.0 }

        let normalized = totalScore / totalWeight

        let triggeredLayers = scores.filter { $0.value > 0.3 }.count
        let amplifier: Double
        switch triggeredLayers {
        case 4...: amplifier = 1.5
        case 3: amplifier = 1.3
        case 2: amplifier = 1.1
        default: amplifier = 1.0
        }

        let weighted = min(normalized * amplifier, 1.0)

        // High-confidence veto: any definitive single signal is conclusive.
        let vetoed = vetoThresholds.contains { key, threshold in
            (scores[key] ?? 0.0) >= threshold
        }

        return vetoed ? max(weighted, vetoConfidence) : weighted
    }
}
