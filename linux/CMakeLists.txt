cmake_minimum_required(VERSION 3.10)

set(PROJECT_NAME "flutter_neo_shield")
project(${PROJECT_NAME} LANGUAGES CXX)

# This value is used when generating builds using this plugin, so it must
# not be changed
set(PLUGIN_NAME "flutter_neo_shield_plugin")

add_library(${PLUGIN_NAME} SHARED
  "flutter_neo_shield_plugin.cc"
  "rasp/debugger_detector.cc"
  "rasp/privilege_detector.cc"
  "rasp/vm_detector.cc"
  "rasp/frida_detector.cc"
  "rasp/hook_detector.cc"
  "rasp/integrity_detector.cc"
  "rasp/developer_mode_detector.cc"
  "rasp/signature_detector.cc"
  "rasp/native_debug_detector.cc"
  "rasp/network_threat_detector.cc"
  "screen/screen_protector.cc"
  "screen/screen_recording_detector.cc"
)

apply_standard_settings(${PLUGIN_NAME})

set_target_properties(${PLUGIN_NAME} PROPERTIES CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)

target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(${PLUGIN_NAME} PRIVATE flutter)
target_link_libraries(${PLUGIN_NAME} PRIVATE PkgConfig::GTK)

# List of absolute paths to libraries that should be bundled with the plugin
set(flutter_neo_shield_bundled_libraries "" PARENT_SCOPE)
