#pragma once
#include "networking.h"
#include <string>

namespace utils {
void dump_hex(const void* data, size_t size);
unsigned short checksum(void* b, int len);
uint32_t randon_uint32();
bool initialize_dependencies();
void deinitialize_dependencies();
bool resolve_host(const std::string& hostname, sockaddr_in* addr);
} // namespace utils