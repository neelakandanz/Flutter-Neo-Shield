cmake_minimum_required(VERSION 3.14)

set(PROJECT_NAME "flutter_neo_shield")
project(${PROJECT_NAME} LANGUAGES CXX)

# This value is used when generating builds using this plugin, so it must
# not be changed
set(PLUGIN_NAME "flutter_neo_shield_plugin")

add_library(${PLUGIN_NAME} SHARED
  "flutter_neo_shield_plugin.cpp"
  "rasp/debugger_detector.cpp"
  "rasp/privilege_detector.cpp"
  "rasp/vm_detector.cpp"
  "rasp/frida_detector.cpp"
  "rasp/hook_detector.cpp"
  "rasp/integrity_detector.cpp"
  "rasp/developer_mode_detector.cpp"
  "rasp/signature_detector.cpp"
  "rasp/native_debug_detector.cpp"
  "rasp/network_threat_detector.cpp"
  "screen/screen_protector.cpp"
  "screen/screen_recording_detector.cpp"
  "location/location_shield_handler.cpp"
)

apply_standard_settings(${PLUGIN_NAME})

set_target_properties(${PLUGIN_NAME} PROPERTIES CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)

target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(${PLUGIN_NAME} PRIVATE
  flutter
  flutter_wrapper_plugin
  wintrust
  crypt32
  ws2_32
  iphlpapi
  psapi
  ntdll
)

# Build-level security hardening
target_compile_options(${PLUGIN_NAME} PRIVATE
  $<$<CONFIG:Release>:/O2 /GL>
)
set_target_properties(${PLUGIN_NAME} PROPERTIES
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)
target_link_options(${PLUGIN_NAME} PRIVATE
  $<$<CONFIG:Release>:/LTCG>
)

# List of absolute paths to libraries that should be bundled with the plugin
set(flutter_neo_shield_bundled_libraries "" PARENT_SCOPE)
