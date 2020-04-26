/*
 MIT License
 
 Copyright (c) 2020 David Landeros
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 */

#pragma once
#include <stdint.h>
#if defined(_WIN32)
#include <WinSock2.h>
#include <Windows.h>
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define INVALID_SOCKET (-1)
#define closesocket close
#endif

#if defined(_WIN32)
#define socket_t SOCKET
#else
#define socket_t int
#endif

#ifdef __GNUC__
#define PACKED __attribute__((__packed__))
#else
#define PACKED
#endif

#define ETHERNET_ADDRESS_LENGTH 6
#define ETHERTYPE_IP 0x0800

#define ICMP_ECHOREPLY 0
#define ICMP_ECHO 8
#define ICMP_PAYLOAD_MAX_SIZE 2048

extern "C" {
#pragma pack(push, 1)
struct ethernet_header_t {
    uint8_t destination_host[ETHERNET_ADDRESS_LENGTH];
    uint8_t source_host[ETHERNET_ADDRESS_LENGTH];
    uint16_t ether_type;
} PACKED;

struct ip_header_t {
    uint8_t ip_verlen;       // 4-bit IPv4 version 4-bit header length (in 32-bit words)
    uint8_t ip_tos;          // IP type of service
    uint16_t ip_totallength; // Total length
    uint16_t ip_id;          // Unique identifier
    uint16_t ip_offset;      // Fragment offset field
    uint8_t ip_ttl;          // Time to live
    uint8_t ip_protocol;     // Protocol(TCP,UDP etc)
    uint16_t ip_checksum;    // IP checksum
    uint32_t ip_srcaddr;     // Source address
    uint32_t ip_destaddr;    // Source address
} PACKED;

struct icmp_packet_t {
    struct {
        uint8_t type;
        uint8_t code;
        uint16_t checksum;
        uint16_t id;
        uint16_t sequence;
    } header;
    uint8_t payload[ICMP_PAYLOAD_MAX_SIZE];
} PACKED;

#pragma pack(pop)
}