#pragma once
#include "networking.h"
#include <string>

class ping_sender {
public:
    static bool init();
    static void deinit();
    static bool send(const void* payload, unsigned int payload_len, const sockaddr_in* addr);
    static bool reply(const void* reply_payload, unsigned int reply_payload_len, const sockaddr_in* addr, const icmp_packet_t* ping_request);
    static const std::string& get_last_error();

private:
    static socket_t raw_socket;
    static uint16_t secuence_number;
    static std::string last_error;
};