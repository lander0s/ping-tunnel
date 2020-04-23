#include "ping_sender.h"
#include "networking.h"
#include "utils.h"
#include <iostream>
#include <string.h>

socket_t ping_sender::raw_socket      = INVALID_SOCKET;
uint16_t ping_sender::secuence_number = 0;
std::string ping_sender::last_error   = "";

bool ping_sender::init()
{
    raw_socket = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw_socket == INVALID_SOCKET) {
        last_error = "couldn't create raw socket";
        return false;
    }
    return true;
}

bool ping_sender::send(const void* payload, unsigned int payload_len, const sockaddr_in* addr)
{
    if (payload_len > 1024) {
        last_error = "payload size exceeds limit of 1024";
        return false;
    }

    icmp_packet_t ping;
    memset(&ping, 0, sizeof(icmp_packet_t));

    ping.header.type     = ICMP_ECHO;
    ping.header.sequence = secuence_number++;
    ping.header.id       = utils::randon_uint32();
    int ping_len         = sizeof(ping.header) + payload_len;

    memcpy(ping.payload, payload, payload_len);
    ping.header.checksum = utils::checksum(&ping, ping_len);

    if (sendto(raw_socket, (char*)&ping, ping_len, 0, (sockaddr*)addr, sizeof(sockaddr_in)) >= 0) {
        last_error = "send function failed";
        return false;
    }
    return true;
}

bool ping_sender::reply(const void* reply_payload, unsigned int reply_payload_len, const sockaddr_in* addr, const icmp_packet_t* ping_request)
{
    if (reply_payload_len > 1024) {
        last_error = "payload size exceeds limit of 1024";
        return false;
    }

    int reply_len;
    icmp_packet_t reply;
    memset(&reply, 0, sizeof(icmp_packet_t));

    reply.header.type     = ICMP_ECHOREPLY;
    reply.header.sequence = ping_request->header.sequence;
    reply.header.id       = ping_request->header.id;
    reply_len             = sizeof(reply.header) + reply_payload_len;
    memcpy(reply.payload, reply_payload, reply_payload_len);
    reply.header.checksum = utils::checksum(&reply, reply_len);

    if (sendto(raw_socket, (char*)&reply, reply_len, 0, (sockaddr*)addr, sizeof(sockaddr_in)) < 0) {
        last_error = "reply function failed";
        return false;
    }
    return true;
}

const std::string& ping_sender::get_last_error()
{
    return last_error;
}

void ping_sender::deinit()
{
#if defined(_WIN32)
    closesocket(raw_socket);
#else
    close(raw_socket);
#endif
}