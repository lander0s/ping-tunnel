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
#include "connection.h"
#include "net.h"
#include <string>

struct port_forwarding {
    uint16_t local_port;
    uint16_t dst_port;
    std::string dst_hostname;
    socket_t listener_socket;
};

typedef std::vector<port_forwarding> port_forwarding_list;

class tunnel {
private:
    static bool stopped_by_user;
    static port_forwarding_list forwardings;
    static connection_list alive_connections;
    static connection* get_connection(uint32_t connection_id);
    static connection* add_connection(socket_t tcp_socket, std::string dst_hostname, int dst_port);
    static connection* add_connection(uint32_t id, const ip_header_t* ip_header, icmp_packet_t* icmp_packet, const tunnel_packet* syn_packet);
    static void remove_connection(connection* connection);

    static void main_loop();
    static bool should_process_packet(const tunnel_packet* packet);
    static void handle_syn(const ip_header_t* ip_header, icmp_packet_t* icmp_packet, const tunnel_packet* packet);

    static void initialize_port_forwarding();
    static void check_new_connections();

    static void cleanup();

public:
    static void run(std::string config_file);
};