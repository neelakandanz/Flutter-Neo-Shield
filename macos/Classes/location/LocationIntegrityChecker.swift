import Foundation

/// Layer 7: Environment Integrity for macOS.
class LocationIntegrityChecker {
    private let weights: [String: Double] = [
        "mockProvider": 1.0,
        "spoofingApp": 0.9,
        "locationHook": 0.95,
        "gpsSignal": 0.7,
        "sensorFusion": 0.8,
        "temporalAnomaly": 0.85,
    ]

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
        let amplifier: Double = triggeredLayers >= 4 ? 1.5 :
                                triggeredLayers >= 3 ? 1.3 :
                                triggeredLayers >= 2 ? 1.1 : 1.0

        let weighted = min(normalized * amplifier, 1.0)

        // High-confidence veto: any definitive single signal is conclusive,
        // even when the "advanced" layers report 0.
        let vetoThresholds: [String: Double] = [
            "mockProvider": 1.0, "locationHook": 0.95, "spoofingApp": 1.0,
        ]
        let vetoed = vetoThresholds.contains { key, threshold in
            (scores[key] ?? 0.0) >= threshold
        }
        return vetoed ? max(weighted, 0.9) : weighted
    }
}
