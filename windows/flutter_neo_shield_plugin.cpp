#include "include/flutter_neo_shield/flutter_neo_shield_plugin_c_api.h"

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>
#include <flutter/event_channel.h>
#include <flutter/event_stream_handler_functions.h>

#include <memory>
#include <string>
#include <map>
#include <vector>
#include <mutex>

#include "rasp/debugger_detector.h"
#include "rasp/privilege_detector.h"
#include "rasp/vm_detector.h"
#include "rasp/frida_detector.h"
#include "rasp/hook_detector.h"
#include "rasp/integrity_detector.h"
#include "rasp/developer_mode_detector.h"
#include "rasp/signature_detector.h"
#include "rasp/native_debug_detector.h"
#include "rasp/network_threat_detector.h"
#include "screen/screen_protector.h"
#include "screen/screen_recording_detector.h"

namespace flutter_neo_shield {

class FlutterNeoShieldPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

  FlutterNeoShieldPlugin(flutter::PluginRegistrarWindows *registrar);
  virtual ~FlutterNeoShieldPlugin();

 private:
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue> &method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);

  // Secure memory storage
  std::map<std::string, std::vector<uint8_t>> secure_storage_;
  std::mutex storage_mutex_;

  // Screen components
  ScreenProtector screen_protector_;
  ScreenRecordingDetector screen_recording_detector_;

  flutter::PluginRegistrarWindows *registrar_;
};

void FlutterNeoShieldPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows *registrar) {
  auto memory_channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(),
          "com.neelakandan.flutter_neo_shield/memory",
          &flutter::StandardMethodCodec::GetInstance());

  auto rasp_channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(),
          "com.neelakandan.flutter_neo_shield/rasp",
          &flutter::StandardMethodCodec::GetInstance());

  auto screen_channel =
      std::make_unique<flutter::MethodChannel<flutter::EncodableValue>>(
          registrar->messenger(),
          "com.neelakandan.flutter_neo_shield/screen",
          &flutter::StandardMethodCodec::GetInstance());

  auto plugin = std::make_unique<FlutterNeoShieldPlugin>(registrar);
  auto plugin_ptr = plugin.get();

  memory_channel->SetMethodCallHandler(
      [plugin_ptr](const auto &call, auto result) {
        plugin_ptr->HandleMethodCall(call, std::move(result));
      });

  rasp_channel->SetMethodCallHandler(
      [plugin_ptr](const auto &call, auto result) {
        plugin_ptr->HandleMethodCall(call, std::move(result));
      });

  screen_channel->SetMethodCallHandler(
      [plugin_ptr](const auto &call, auto result) {
        plugin_ptr->HandleMethodCall(call, std::move(result));
      });

  registrar->AddPlugin(std::move(plugin));
}

FlutterNeoShieldPlugin::FlutterNeoShieldPlugin(
    flutter::PluginRegistrarWindows *registrar)
    : registrar_(registrar), screen_protector_(registrar) {}

FlutterNeoShieldPlugin::~FlutterNeoShieldPlugin() {
  // Secure wipe all stored data
  std::lock_guard<std::mutex> lock(storage_mutex_);
  for (auto &pair : secure_storage_) {
    if (!pair.second.empty()) {
      SecureZeroMemory(pair.second.data(), pair.second.size());
    }
  }
  secure_storage_.clear();
}

void FlutterNeoShieldPlugin::HandleMethodCall(
    const flutter::MethodCall<flutter::EncodableValue> &method_call,
    std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result) {
  const auto &method = method_call.method_name();

  // Memory Shield
  if (method == "allocateSecure") {
    const auto *args = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (!args) {
      result->Error("INVALID_ARGS", "Arguments required");
      return;
    }
    auto id_it = args->find(flutter::EncodableValue("id"));
    auto data_it = args->find(flutter::EncodableValue("data"));
    if (id_it == args->end() || data_it == args->end()) {
      result->Error("INVALID_ARGS", "id and data required");
      return;
    }
    auto id = std::get<std::string>(id_it->second);
    auto data = std::get<std::vector<uint8_t>>(data_it->second);
    std::lock_guard<std::mutex> lock(storage_mutex_);
    secure_storage_[id] = std::move(data);
    result->Success();
  }
  else if (method == "readSecure") {
    const auto *args = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (!args) {
      result->Error("NOT_FOUND", "No secure data found");
      return;
    }
    auto id_it = args->find(flutter::EncodableValue("id"));
    if (id_it == args->end()) {
      result->Error("NOT_FOUND", "No secure data found");
      return;
    }
    auto id = std::get<std::string>(id_it->second);
    std::lock_guard<std::mutex> lock(storage_mutex_);
    auto it = secure_storage_.find(id);
    if (it == secure_storage_.end()) {
      result->Error("NOT_FOUND", "No secure data found");
      return;
    }
    result->Success(flutter::EncodableValue(it->second));
  }
  else if (method == "wipeSecure") {
    const auto *args = std::get_if<flutter::EncodableMap>(method_call.arguments());
    if (args) {
      auto id_it = args->find(flutter::EncodableValue("id"));
      if (id_it != args->end()) {
        auto id = std::get<std::string>(id_it->second);
        std::lock_guard<std::mutex> lock(storage_mutex_);
        auto it = secure_storage_.find(id);
        if (it != secure_storage_.end()) {
          if (!it->second.empty()) {
            SecureZeroMemory(it->second.data(), it->second.size());
          }
          secure_storage_.erase(it);
        }
      }
    }
    result->Success();
  }
  else if (method == "wipeAll") {
    std::lock_guard<std::mutex> lock(storage_mutex_);
    for (auto &pair : secure_storage_) {
      if (!pair.second.empty()) {
        SecureZeroMemory(pair.second.data(), pair.second.size());
      }
    }
    secure_storage_.clear();
    result->Success();
  }
  // RASP Shield
  else if (method == "checkDebugger") {
    result->Success(flutter::EncodableValue(DebuggerDetector::Check()));
  }
  else if (method == "checkRoot") {
    result->Success(flutter::EncodableValue(PrivilegeDetector::Check()));
  }
  else if (method == "checkEmulator") {
    result->Success(flutter::EncodableValue(VMDetector::Check()));
  }
  else if (method == "checkHooks") {
    result->Success(flutter::EncodableValue(HookDetector::Check()));
  }
  else if (method == "checkFrida") {
    result->Success(flutter::EncodableValue(FridaDetector::Check()));
  }
  else if (method == "checkIntegrity") {
    result->Success(flutter::EncodableValue(IntegrityDetector::Check()));
  }
  else if (method == "checkDeveloperMode") {
    result->Success(flutter::EncodableValue(DeveloperModeDetector::Check()));
  }
  else if (method == "checkSignature") {
    result->Success(flutter::EncodableValue(SignatureDetector::Check()));
  }
  else if (method == "getSignatureHash") {
    result->Success();
  }
  else if (method == "checkNativeDebug") {
    result->Success(flutter::EncodableValue(NativeDebugDetector::Check()));
  }
  else if (method == "checkNetworkThreats") {
    result->Success(flutter::EncodableValue(NetworkThreatDetector::CheckSimple()));
  }
  // Screen Shield
  else if (method == "enableScreenProtection") {
    result->Success(flutter::EncodableValue(screen_protector_.Enable()));
  }
  else if (method == "disableScreenProtection") {
    result->Success(flutter::EncodableValue(screen_protector_.Disable()));
  }
  else if (method == "isScreenProtectionActive") {
    result->Success(flutter::EncodableValue(screen_protector_.IsActive()));
  }
  else if (method == "enableAppSwitcherGuard") {
    result->Success(flutter::EncodableValue(false));
  }
  else if (method == "disableAppSwitcherGuard") {
    result->Success(flutter::EncodableValue(false));
  }
  else if (method == "isScreenBeingRecorded") {
    result->Success(flutter::EncodableValue(screen_recording_detector_.IsRecording()));
  }
  else {
    result->NotImplemented();
  }
}

}  // namespace flutter_neo_shield

void FlutterNeoShieldPluginCApiRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
  flutter_neo_shield::FlutterNeoShieldPlugin::RegisterWithRegistrar(
      flutter::PluginRegistrarManager::GetInstance()
          ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
