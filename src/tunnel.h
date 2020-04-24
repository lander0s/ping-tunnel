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
#include "networking.h"
#include <chrono>
#include <ctime>
#include <map>
#include <queue>
#include <string>

#define TEST(bitflag, mask) ((bitflag & mask) == mask)

static const uint8_t SYN_MASK      = 1 << 0; // new connection
static const uint8_t PSH_MASK      = 1 << 1; // the message contains data
static const uint8_t ACK_MASK      = 1 << 2; // acknowledge
static const uint8_t FIN_MASK      = 1 << 3; // close connection
static const uint8_t PROXY_MASK    = 1 << 4; // the message was sent by the proxy facet
static const uint32_t MAGIC_NUMBER = 0xdeadbeef;

struct tunnel_packet_t {
    struct {
        uint32_t magic_number;
        uint32_t dst_addr;
        uint32_t dst_port;
        uint32_t seq_no;
        uint32_t ack_no;
        uint32_t data_len;
        uint32_t connection_id;
        uint8_t flags;
    } header;
    uint8_t data[ICMP_PAYLOAD_MAX_SIZE - sizeof(header)];

    bool is_syn() const { return TEST(header.flags, SYN_MASK); }
    bool is_psh() const { return TEST(header.flags, PSH_MASK); }
    bool is_ack() const { return TEST(header.flags, ACK_MASK); }
    bool is_fin() const { return TEST(header.flags, FIN_MASK); }
    bool was_sent_by_proxy() const { return TEST(header.flags, PROXY_MASK); }
    bool has_valid_magic_number() const { return header.magic_number == MAGIC_NUMBER; }
    unsigned int size() { return sizeof(header) + header.data_len; }
};

typedef std::queue<tunnel_packet_t> packet_queue;

struct connection_t {
    uint32_t connection_id;
    sockaddr_in tunnel_addr;
    sockaddr_in destination_addr;
    packet_queue outgoing_packets;
    uint32_t local_sequence_number;
    uint32_t remote_sequence_number;
    uint32_t sequence_counter;
    std::chrono::time_point<std::chrono::steady_clock> last_transmission_time;
    icmp_packet_t last_received_icmp_packet;
    socket_t tcp_socket;
};

typedef std::map<uint32_t, connection_t> connection_map;

struct port_mapping_t {
    uint16_t local_port;
    uint16_t dst_port;
    std::string dst_hostname;
    socket_t listener_socket;
};

typedef std::vector<port_mapping_t> port_mapping_list;

class tunnel {
private:
    static port_mapping_list port_mappings;
    static connection_map connections;
    static void main_loop();
    static connection_t* get_connection(uint32_t connection_id);
    static void handle_ack(connection_t* connection, const tunnel_packet_t* packet);
    static void handle_push(connection_t* connection, const tunnel_packet_t* packet);
    static void handle_syn(const ip_header_t* ip_header, icmp_packet_t* icmp_packet, const tunnel_packet_t* packet);
    static void handle_fin(connection_t* connection, const tunnel_packet_t* packet);
    static void send_syn(connection_t* connection);
    static void send_ack(connection_t* connection, const tunnel_packet_t* packet);
    static void send_fin(connection_t* connection);
    static bool should_process_packet(const tunnel_packet_t* packet);
    static bool should_send_new_message(connection_t* connection);
    static tunnel_packet_t get_next_message_to_send(connection_t* connection);
    static void send_message(connection_t* connection, const char* data, int len);
    static void on_message(connection_t* connection, const char* data, int len);
    static connection_t* add_forwarder_side_connection(socket_t tcp_socket, std::string dst_hostname, int dst_port);
    static connection_t* add_proxy_side_connection(uint32_t id, const ip_header_t* ip_header, const tunnel_packet_t* initiator);
    static void remove_connection(connection_t* connection);
    static void initialize_port_mappings();
    static void cleanup();

public:
    static void run();
};