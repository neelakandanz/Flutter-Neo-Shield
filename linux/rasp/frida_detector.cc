#include "frida_detector.h"

#include <fstream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

namespace flutter_neo_shield {

bool FridaDetector::Check() {
  return CheckPorts() || CheckMaps() || CheckFiles();
}

/// Scan Frida default ports on localhost.
bool FridaDetector::CheckPorts() {
  int ports[] = {27042, 27043, 4444};

  for (int port : ports) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) continue;

    // Set non-blocking with timeout
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);

    if (result == 0) return true;
  }

  return false;
}

/// Scan /proc/self/maps for frida-agent and frida-gadget.
bool FridaDetector::CheckMaps() {
  std::ifstream maps("/proc/self/maps");
  if (!maps.is_open()) return false;

  std::string line;
  while (std::getline(maps, line)) {
    if (line.find("frida") != std::string::npos ||
        line.find("linjector") != std::string::npos) {
      return true;
    }
  }

  return false;
}

/// Check for frida-server binaries.
bool FridaDetector::CheckFiles() {
  const char* paths[] = {
    "/usr/bin/frida-server",
    "/usr/local/bin/frida-server",
    "/usr/local/bin/frida",
    "/tmp/frida-server",
  };

  for (const auto& path : paths) {
    if (access(path, F_OK) == 0) {
      return true;
    }
  }

  return false;
}

}  // namespace flutter_neo_shield
