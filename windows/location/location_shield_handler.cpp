#include "location_shield_handler.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <cmath>
#include <algorithm>
#include <chrono>

#include "../shield_codec.h"

namespace flutter_neo_shield {

LocationShieldHandler::LocationShieldHandler() {}
LocationShieldHandler::~LocationShieldHandler() {}

void LocationShieldHandler::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue>& method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  const auto& method = method_call.method_name();

  if (method == ShieldCodec::Decode(ShieldCodec::MethodCheckFakeLocation())) {
    HandleFullCheck(std::move(result));
  }
  else if (method == ShieldCodec::Decode(ShieldCodec::MethodCheckMockProvider())) {
    result->Success(flutter::EncodableValue(CheckMockProvider()));
  }
  else if (method == ShieldCodec::Decode(ShieldCodec::MethodCheckSpoofingApps())) {
    auto apps = CheckSpoofingApps();
    flutter::EncodableMap map;
    map[flutter::EncodableValue("detected")] = flutter::EncodableValue(!apps.empty());
    flutter::EncodableList appList;
    for (const auto& app : apps) {
      appList.push_back(flutter::EncodableValue(app));
    }
    map[flutter::EncodableValue("detectedApps")] = flutter::EncodableValue(appList);
    result->Success(flutter::EncodableValue(map));
  }
  else if (method == ShieldCodec::Decode(ShieldCodec::MethodCheckLocationHooks())) {
    result->Success(flutter::EncodableValue(CheckLocationHooks()));
  }
  else if (method == ShieldCodec::Decode(ShieldCodec::MethodCheckGpsAnomaly())) {
    result->Success(flutter::EncodableValue(CheckGpsAnomaly()));
  }
  else if (method == ShieldCodec::Decode(ShieldCodec::MethodCheckSensorFusion())) {
    result->Success(flutter::EncodableValue(CheckSensorFusion()));
  }
  else if (method == ShieldCodec::Decode(ShieldCodec::MethodCheckTemporalAnomaly())) {
    result->Success(flutter::EncodableValue(CheckTemporalAnomaly()));
  }
  else {
    result->NotImplemented();
  }
}

void LocationShieldHandler::HandleFullCheck(
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  std::map<std::string, double> scores;
  flutter::EncodableList detected_methods;

  // Layer 1
  bool mock = CheckMockProvider();
  scores["mockProvider"] = mock ? 1.0 : 0.0;
  if (mock) detected_methods.push_back(flutter::EncodableValue("mockProvider"));

  // Layer 2
  auto apps = CheckSpoofingApps();
  double spoof_score = apps.empty() ? 0.0 : 0.8;
  scores["spoofingApp"] = spoof_score;
  if (spoof_score > 0.3) detected_methods.push_back(flutter::EncodableValue("spoofingApp"));

  // Layer 3
  bool hooks = CheckLocationHooks();
  scores["locationHook"] = hooks ? 0.95 : 0.0;
  if (hooks) detected_methods.push_back(flutter::EncodableValue("locationHook"));

  // Layer 4
  scores["gpsSignal"] = CheckGpsAnomaly();
  if (scores["gpsSignal"] > 0.3) detected_methods.push_back(flutter::EncodableValue("gpsSignal"));

  // Layer 5
  scores["sensorFusion"] = CheckSensorFusion();

  // Layer 6
  scores["temporalAnomaly"] = CheckTemporalAnomaly();
  if (scores["temporalAnomaly"] > 0.3) detected_methods.push_back(flutter::EncodableValue("temporalAnomaly"));

  // Layer 7
  double confidence = ComputeConfidence(scores);
  scores["integrity"] = confidence;
  bool is_spoofed = confidence >= 0.5;

  flutter::EncodableMap layer_scores;
  for (const auto& s : scores) {
    layer_scores[flutter::EncodableValue(s.first)] = flutter::EncodableValue(s.second);
  }

  flutter::EncodableMap res;
  res[flutter::EncodableValue("isSpoofed")] = flutter::EncodableValue(is_spoofed);
  res[flutter::EncodableValue("confidence")] = flutter::EncodableValue(confidence);
  res[flutter::EncodableValue("detectedMethods")] = flutter::EncodableValue(detected_methods);
  res[flutter::EncodableValue("layerScores")] = flutter::EncodableValue(layer_scores);
  res[flutter::EncodableValue("summary")] = flutter::EncodableValue(
      is_spoofed ? std::string("Fake location detected") : std::string("Location appears authentic"));

  result->Success(flutter::EncodableValue(res));
}

// Layer 1: Check for virtual GPS drivers and simulator software
bool LocationShieldHandler::CheckMockProvider() {
  // Check for known GPS simulator processes
  return !CheckSpoofingApps().empty();
}

// Layer 2: Check for GPS simulation software processes
std::vector<std::string> LocationShieldHandler::CheckSpoofingApps() {
  std::vector<std::string> detected;
  const wchar_t* suspicious_processes[] = {
      L"gpssimulator.exe",
      L"fakegps.exe",
      L"gps_simulator.exe",
      L"gpsdirect.exe",
      L"nmeasimulator.exe",
      L"gpsgate.exe",
      L"mocklocation.exe",
      L"gps_faker.exe",
      L"locationchanger.exe",
  };

  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE) return detected;

  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);

  if (Process32FirstW(snapshot, &pe)) {
    do {
      for (const auto& proc : suspicious_processes) {
        if (_wcsicmp(pe.szExeFile, proc) == 0) {
          // Convert wide string to narrow for return
          char narrow[260];
          WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, narrow, 260, nullptr, nullptr);
          detected.push_back(std::string(narrow));
        }
      }
    } while (Process32NextW(snapshot, &pe));
  }

  CloseHandle(snapshot);
  return detected;
}

// Layer 3: Check for IAT hooks on location-related DLLs
bool LocationShieldHandler::CheckLocationHooks() {
  // Check if LocationAPI.dll has been loaded and potentially hooked
  HMODULE hMod = GetModuleHandleW(L"LocationAPI.dll");
  if (!hMod) return false;  // Not loaded = no hooks possible

  // Check for known hook indicators
  HMODULE hFrida = GetModuleHandleW(L"frida-agent.dll");
  if (hFrida) return true;

  HMODULE hDetours = GetModuleHandleW(L"detours.dll");
  if (hDetours) return true;

  return false;
}

// Layer 4: GPS signal anomaly (limited on Windows desktop)
double LocationShieldHandler::CheckGpsAnomaly() {
  return 0.0;  // Limited capability on Windows
}

// Layer 5: Sensor fusion (limited on Windows desktop)
double LocationShieldHandler::CheckSensorFusion() {
  return 0.0;  // Limited capability on Windows
}

// Layer 6: Temporal anomaly
double LocationShieldHandler::CheckTemporalAnomaly() {
  return last_temporal_score_;
}

// Layer 7: Weighted confidence aggregation
double LocationShieldHandler::ComputeConfidence(
    const std::map<std::string, double>& scores) {
  struct WeightEntry { const char* key; double weight; };
  static const WeightEntry weights[] = {
      {"mockProvider", 1.0},
      {"spoofingApp", 0.9},
      {"locationHook", 0.95},
      {"gpsSignal", 0.7},
      {"sensorFusion", 0.8},
      {"temporalAnomaly", 0.85},
  };

  double total_score = 0.0;
  double total_weight = 0.0;

  for (const auto& w : weights) {
    auto it = scores.find(w.key);
    double score = (it != scores.end()) ? it->second : 0.0;
    total_score += score * w.weight;
    total_weight += w.weight;
  }

  if (total_weight <= 0.0) return 0.0;
  double normalized = total_score / total_weight;

  int triggered = 0;
  for (const auto& s : scores) {
    if (s.second > 0.3) triggered++;
  }

  double amplifier = triggered >= 4 ? 1.5 : triggered >= 3 ? 1.3 : triggered >= 2 ? 1.1 : 1.0;
  return std::min(normalized * amplifier, 1.0);
}

double LocationShieldHandler::HaversineDistance(
    double lat1, double lon1, double lat2, double lon2) {
  const double R = 6371000.0;
  const double PI = 3.14159265358979323846;
  double dLat = (lat2 - lat1) * PI / 180.0;
  double dLon = (lon2 - lon1) * PI / 180.0;
  double a = sin(dLat / 2) * sin(dLat / 2) +
             cos(lat1 * PI / 180.0) * cos(lat2 * PI / 180.0) *
             sin(dLon / 2) * sin(dLon / 2);
  double c = 2 * atan2(sqrt(a), sqrt(1.0 - a));
  return R * c;
}

}  // namespace flutter_neo_shield
