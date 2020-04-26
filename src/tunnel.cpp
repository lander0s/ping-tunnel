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

#include "tunnel.h"
#include "config.h"
#include "net.h"
#include "ping_sender.h"
#include "sniffer.h"
#include "utils.h"
#include <chrono>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string.h>
#include <thread>

bool tunnel::stopped_by_user = false;
port_forwarding_list tunnel::forwardings;
connection_list tunnel::connections;

void tunnel::run(std::string config_file)
{
    try {
        std::string sniffer_filter;
        config::load_config(config_file);

        if (config::is_proxy()) {
            std::cout << "[+] Running as proxy" << std::endl;
            sniffer_filter = "icmp[icmptype] == 8";
        } else {
            std::cout << "[+] Running as forwarder" << std::endl;
            sniffer_filter = "icmp[icmptype] == 0";
            initialize_port_forwarding();
        }

        utils::install_ctrlc_handler([]() {
            stopped_by_user = true;
        });

        sniffer::init(config::get_network_interface(), sniffer_filter);
        ping_sender::init();
        main_loop();
    } catch (std::runtime_error e) {
        std::cout << "[-] " << e.what() << std::endl;
    }

    cleanup();
    ping_sender::deinit();
    sniffer::deinit();
}

void tunnel::initialize_port_forwarding()
{
    int count = config::get_port_forwarding_count();
    for (int i = 0; i < count; i++) {
        port_forwarding forwarding;
        forwarding.dst_hostname    = config::get_destination_address(i);
        forwarding.dst_port        = config::get_destination_port(i);
        forwarding.local_port      = config::get_local_port(i);
        forwarding.listener_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in addr           = {};
        addr.sin_family            = AF_INET;
        addr.sin_port              = htons(forwarding.local_port);
        addr.sin_addr.s_addr       = INADDR_ANY;
        int result                 = ::bind(forwarding.listener_socket, (sockaddr*)&addr, sizeof(sockaddr_in));
        if (result == -1) {
            char err_buf[1024];
            sprintf(err_buf, "Couldn't listen on port %d, %s", forwarding.local_port, strerror(errno));
            throw std::runtime_error(err_buf);
        }
        result = ::listen(forwarding.listener_socket, 0);
        if (result == -1) {
            char err_buf[1024];
            sprintf(err_buf, "Couldn't listen on port %d, %s", forwarding.local_port, strerror(errno));
            throw std::runtime_error(err_buf);
        }
        forwardings.push_back(forwarding);
        std::cout << "[+] Listening on 0.0.0.0:"
                  << forwarding.local_port
                  << "\t" << config::get_port_forwarding_description(i)
                  << std::endl;
    }
}

void tunnel::main_loop()
{
    while (!stopped_by_user) {
        char raw_packet[2048];
        int len = sniffer::get_next_capture(raw_packet, sizeof(raw_packet));
        if (len > 0) {
            // the sniffer's filter guarantees the packet is either echo request or echo reply
            ethernet_header_t* ethernet_header = (ethernet_header_t*)raw_packet;
            ip_header_t* ip_header             = (ip_header_t*)(raw_packet + sizeof(ethernet_header_t));
            icmp_packet_t* icmp_packet         = (icmp_packet_t*)(raw_packet + sizeof(ethernet_header_t) + sizeof(ip_header_t));
            tunnel_packet* tun_packet          = (tunnel_packet*)icmp_packet->payload;

            if (should_process_packet(tun_packet)) {

                uint32_t conn_id = tun_packet->header.connection_id;
                connection* conn = get_connection(conn_id);

                if (tun_packet->is_syn()) {
                    handle_syn(ip_header, icmp_packet, tun_packet);
                }

                if (conn) {
                    conn->last_received_icmp_packet = *icmp_packet;

                    if (tun_packet->is_ack()) {
                        conn->handle_ack(tun_packet);
                    }

                    if (tun_packet->is_psh()) {
                        conn->handle_push(tun_packet);
                    }

                    if (tun_packet->is_fin()) {
                        conn->handle_fin(tun_packet);
                    }
                }
            }
        }

        connection_list::iterator it = connections.begin();
        while (it != connections.end()) {
            connection* conn = &it->second;
            conn->update();
            if (conn->is_dead) {
                it++;
                remove_connection(conn);
                continue;
            }
            it++;
        }

		if (config::is_proxy() == false) {
            check_new_connections();
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

connection* tunnel::get_connection(uint32_t connection_id)
{
    connection_list::iterator iterator = connections.find(connection_id);
    if (iterator != connections.end()) {
        return &iterator->second;
    }
    return nullptr;
}

bool tunnel::should_process_packet(const tunnel_packet* packet)
{
    // the packet must have a valid magic number
    if (packet->has_valid_magic_number() == false) {
        return false;
    }

    // the packet must have been created by the oposite facet
    if (packet->was_sent_by_proxy() == config::is_proxy()) {
        return false;
	}

    return true;
}

void tunnel::handle_syn(const ip_header_t* ip_header, icmp_packet_t* icmp_packet, const tunnel_packet* packet)
{
    // only create the connection if it does not exist previously
    connection* conn = get_connection(packet->header.connection_id);
    if (conn == nullptr) {
        conn                            = add_connection(packet->header.connection_id, ip_header, packet);
        conn->last_received_icmp_packet = *icmp_packet;
    }
    conn->send_ack(packet);
}

void tunnel::check_new_connections()
{
    for (auto& it : forwardings) {
        port_forwarding fwd = it;
        fd_set set;
        timeval time;
        FD_ZERO(&set);
        FD_SET(fwd.listener_socket, &set);
        time.tv_sec    = 0;
        time.tv_usec   = 0;
        int max_socket = static_cast<int>(fwd.listener_socket) + 1;
        if (select(max_socket, &set, 0, 0, &time) > 0) {
            socket_t new_sock    = accept(fwd.listener_socket, nullptr, 0);
            connection* new_conn = add_connection(new_sock, fwd.dst_hostname, fwd.dst_port);
            new_conn->send_syn();
        }
    }
}

connection* tunnel::add_connection(socket_t tcp_socket, std::string dst_hostname, int dst_port)
{
    connection conn       = {};
    conn.is_dead          = false;
    conn.connection_id    = utils::randon_uint32();
    conn.tcp_socket       = tcp_socket;
    conn.sequence_counter = utils::randon_uint32();
    utils::resolve_host(config::get_proxy_address(), &conn.tunnel_addr);

    conn.destination_addr = {};
    utils::resolve_host(dst_hostname, &conn.destination_addr);
    conn.destination_addr.sin_port = htons(dst_port);

    std::cout << "[+] New connection to forward: " << conn.connection_id << std::endl;

    connections[conn.connection_id] = conn;
    return &connections[conn.connection_id];
}

connection* tunnel::add_connection(uint32_t id, const ip_header_t* ip_header, const tunnel_packet* initiator)
{
    std::cout << "[+] New connection to forward: " << id << std::endl;

    connection conn       = {};
    conn.is_dead          = false;
    conn.connection_id    = id;
    conn.sequence_counter = utils::randon_uint32();

    // discover tunnel addr from ip header of incomming ping
    conn.tunnel_addr                 = {};
    conn.tunnel_addr.sin_family      = AF_INET;
    conn.tunnel_addr.sin_addr.s_addr = ip_header->ip_srcaddr;

    // discover destination addr from incomming tunnel packet
    conn.destination_addr                 = {};
    conn.destination_addr.sin_family      = AF_INET;
    conn.destination_addr.sin_addr.s_addr = initiator->header.dst_addr;
    conn.destination_addr.sin_port        = initiator->header.dst_port;

    conn.tcp_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int result      = connect(conn.tcp_socket, (sockaddr*)&conn.destination_addr, sizeof(sockaddr_in));
    if (result == -1) {
        conn.send_fin();
        std::cout << "[-] Connection failed: "
                  << strerror(errno)
                  << std::endl;
    }

    connections[id] = conn;
    return &connections[id];
}

void tunnel::remove_connection(connection* conn)
{
    std::cout << "[+] Removing connection with id: "
              << conn->connection_id
              << std::endl;
    conn->destroy();
    connections.erase(conn->connection_id);
}

void tunnel::cleanup()
{
    std::cout << "[+] Gracefully shutting down... " << std::endl;
    for (auto& it : connections) {
        connection* conn = &it.second;
        conn->destroy();
    }
    connections.clear();

    for (auto& it : forwardings) {
        port_forwarding port_fwd = it;
        if (port_fwd.listener_socket != INVALID_SOCKET) {
            closesocket(port_fwd.listener_socket);
            port_fwd.listener_socket = INVALID_SOCKET;
        }
    }
    forwardings.clear();
}