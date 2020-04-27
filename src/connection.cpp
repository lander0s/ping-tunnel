#include "connection.h"
#include "config.h"
#include "ping_sender.h"
#include "tunnel.h"
#include "utils.h"
#include <iostream>

bool connection::quiet_mode = false;

connection::connection(connection&& conn) noexcept
    : is_dead(conn.is_dead)
    , connection_id(conn.connection_id)
    , resend_counter(conn.resend_counter)
    , tunnel_addr(conn.tunnel_addr)
    , destination_addr(conn.destination_addr)
    , local_sequence_number(conn.local_sequence_number)
    , remote_sequence_number(conn.remote_sequence_number)
    , sequence_counter(conn.sequence_counter)
    , last_transmission_time(conn.last_transmission_time)
    , last_received_icmp_packet(conn.last_received_icmp_packet)
    , tcp_socket(conn.tcp_socket)
    , outgoing_packets(conn.outgoing_packets)
{
}

// constructor used by the proxy facet
connection::connection(uint32_t id, const ip_header_t* ip_header, icmp_packet_t* icmp_packet, const tunnel_packet* syn_packet) noexcept
    : is_dead(false)
    , connection_id(id)
    , last_received_icmp_packet(*icmp_packet)
    , sequence_counter(utils::randon_uint32())
    , resend_counter(0)
    , local_sequence_number(0)
    , remote_sequence_number(0)
{
    std::cout << "[+] New connection to forward: " << id << std::endl;

    // discover tunnel addr from ip header of incomming ping
    tunnel_addr                 = {};
    tunnel_addr.sin_family      = AF_INET;
    tunnel_addr.sin_addr.s_addr = ip_header->ip_srcaddr;

    // discover destination addr from incomming tunnel packet
    destination_addr                 = {};
    destination_addr.sin_family      = AF_INET;
    destination_addr.sin_addr.s_addr = syn_packet->header.dst_addr;
    destination_addr.sin_port        = syn_packet->header.dst_port;

    tcp_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int result = ::connect(tcp_socket, (sockaddr*)&destination_addr, sizeof(sockaddr_in));
    if (result == -1) {
        send_fin();
        std::cout << "[-] Connection failed: "
                  << strerror(errno)
                  << std::endl;
    }
}

// constructor used by the forwarder facet
connection::connection(socket_t socket, std::string dst_hostname, int dst_port) noexcept
    : is_dead(false)
    , tcp_socket(socket)
    , resend_counter(0)
    , connection_id(utils::randon_uint32())
    , sequence_counter(utils::randon_uint32())
    , local_sequence_number(0)
    , remote_sequence_number(0)
    , last_received_icmp_packet()
{
    utils::resolve_host(config::get_proxy_address(), &tunnel_addr);
    destination_addr = {};
    utils::resolve_host(dst_hostname, &destination_addr);
    destination_addr.sin_port = htons(dst_port);

    std::cout << "[+] New connection to forward: " << connection_id << std::endl;
}

void connection::update()
{
    if (should_send_new_message()) {

        tunnel_packet packet   = get_next_message_to_send();
        local_sequence_number  = packet.header.seq_no;
        last_transmission_time = std::chrono::steady_clock::now();

        if (config::is_proxy()) {
            ping_sender::reply(&packet, packet.size(), &tunnel_addr, &last_received_icmp_packet);
        } else {
            ping_sender::send(&packet, packet.size(), &tunnel_addr);
        }
    }

    if (tcp_socket != INVALID_SOCKET) {
        fd_set set   = {};
        timeval time = {};
        FD_ZERO(&set);
        FD_SET(tcp_socket, &set);
        int max_socket = static_cast<int>(tcp_socket) + 1;
        if (select(max_socket, &set, 0, 0, &time) > 0) {
            char buf[500];
            int len = recv(tcp_socket, buf, sizeof(buf), 0);
            if (len > 0) {
                send_message(buf, len);
            }

            if (len <= 0) {
                send_fin();
                std::cout << "[+] TCP connection closed on "
                          << (config::is_proxy() ? "proxy" : "forwarder")
                          << " side" << std::endl;
                destroy_tcp_connection();
            }
        }
    }

    if (resend_counter > 5) {
        std::cout << "[-] Connection "
                  << connection_id
                  << " seems dead, removing..."
                  << std::endl;
        is_dead = true;
    }
}

void connection::on_tunnel_packet(const tunnel_packet* packet, icmp_packet_t* icmp_packet)
{
    last_received_icmp_packet = *icmp_packet;

    if (packet->is_ack()) {
        handle_ack(packet);
    }

    if (packet->is_psh()) {
        handle_push(packet);
    }

    if (packet->is_fin()) {
        handle_fin(packet);
    }
}

void connection::handle_ack(const tunnel_packet* packet)
{
    if (outgoing_packets.empty()) {
        return;
    }

    tunnel_packet* top       = &outgoing_packets.front();
    uint32_t expected_seq_no = top->header.seq_no;
    uint32_t actual_seq_no   = packet->header.seq_no;

    if (expected_seq_no == actual_seq_no) {
        resend_counter = 0;

		if (!quiet_mode) {
            std::cout << "[+] Packet confirmed as delivered, seq: " << actual_seq_no << std::endl;
		}

        if (top->is_fin()) {
            is_dead = true;
        } else {
            outgoing_packets.pop();
        }
    }
}

void connection::handle_push(const tunnel_packet* packet)
{
    if (!quiet_mode) {
        std::cout << "[+] Packet received, seq: " << packet->header.seq_no << std::endl;
    }

    send_ack(packet);

    if (remote_sequence_number != packet->header.seq_no) {
        remote_sequence_number = packet->header.seq_no;
        on_message((char*)packet->data, packet->header.data_len);
    }
}

void connection::handle_fin(const tunnel_packet* packet)
{
    // I won't be able to resend this ACK in case of loss
    // because i'm removing the connection from the list
    send_ack(packet);
    send_ack(packet);
    send_ack(packet);
    send_ack(packet);

    std::cout << "[+] TCP connection closed on " << (config::is_proxy() ? "forwarder" : "proxy") << " side" << std::endl;
    is_dead = true;
}

void connection::send_ack(const tunnel_packet* incomming_packet)
{
    tunnel_packet ack        = {};
    ack.header.magic_number  = tunnel_packet::MAGIC_NUMBER;
    ack.header.seq_no        = incomming_packet->header.seq_no;
    ack.header.connection_id = incomming_packet->header.connection_id;

    ack.header.flags |= tunnel_packet::ACK_MASK;
    if (config::is_proxy()) {
        ack.header.flags |= tunnel_packet::PROXY_MASK;
    }

    if (config::is_proxy()) {
        ping_sender::reply(&ack, ack.size(), &tunnel_addr, &last_received_icmp_packet);
    } else {
        ping_sender::send(&ack, ack.size(), &tunnel_addr);
    }
}

void connection::send_syn()
{
    tunnel_packet syn = {};

    syn.header.connection_id = connection_id;
    syn.header.magic_number  = tunnel_packet::MAGIC_NUMBER;
    syn.header.dst_addr      = destination_addr.sin_addr.s_addr;
    syn.header.dst_port      = destination_addr.sin_port;
    syn.header.seq_no        = sequence_counter++;

    syn.header.flags |= tunnel_packet::SYN_MASK;
    outgoing_packets.push(syn);
}

void connection::send_fin()
{
    tunnel_packet fin = {};

    fin.header.connection_id = connection_id;
    fin.header.magic_number  = tunnel_packet::MAGIC_NUMBER;
    fin.header.dst_addr      = destination_addr.sin_addr.s_addr;
    fin.header.dst_port      = destination_addr.sin_port;
    fin.header.seq_no        = sequence_counter++;

    fin.header.flags |= tunnel_packet::FIN_MASK;
    if (config::is_proxy()) {
        fin.header.flags |= tunnel_packet::PROXY_MASK;
    }
    outgoing_packets.push(fin);
}

bool connection::should_send_new_message()
{
    // if there is a message in the queue than has never been transmitted before
    if (outgoing_packets.size() > 0 && outgoing_packets.front().header.seq_no != local_sequence_number) {
        return true;
    }

    // or if the last transmition was 500ms ago
    auto elapsed_time = std::chrono::steady_clock::now() - last_transmission_time;
    if (std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_time).count() > 1000) {

        if (quiet_mode == false && outgoing_packets.empty() == false) {
            std::cout << "[*] Resending unconfirmed packet, seq: "
                      << outgoing_packets.front().header.seq_no
                      << ", size: " << outgoing_packets.front().header.data_len
                      << std::endl;
        }
        return true;
    }
    return false;
}

tunnel_packet connection::get_next_message_to_send()
{
    if (outgoing_packets.empty() == false) {
        resend_counter++;
        return outgoing_packets.front();
    }

    // send an empty packet to keep 'ICMP Query Mapping' alive (rfc5508)
    tunnel_packet keep_alive        = {};
    keep_alive.header.connection_id = connection_id;
    keep_alive.header.magic_number  = tunnel_packet::MAGIC_NUMBER;
    keep_alive.header.dst_addr      = destination_addr.sin_addr.s_addr;
    keep_alive.header.dst_port      = destination_addr.sin_port;
    return keep_alive;
}

void connection::on_message(const char* data, int len)
{
    // forwarding received message through TCP connection
    int sent = send(tcp_socket, data, len, 0);
    if (sent <= 0) {
        send_fin();
        std::cout << "[-] Failed to send data through tcp socket: "
                  << strerror(errno)
                  << std::endl;
    }
}

void connection::send_message(const char* data, int len)
{
    tunnel_packet packet        = {};
    packet.header.connection_id = connection_id;
    packet.header.magic_number  = tunnel_packet::MAGIC_NUMBER;
    packet.header.seq_no        = sequence_counter++;
    packet.header.data_len      = len;
    packet.header.dst_addr      = destination_addr.sin_addr.s_addr;
    packet.header.dst_port      = destination_addr.sin_port;
    packet.header.flags |= tunnel_packet::PSH_MASK;
    if (config::is_proxy()) {
        packet.header.flags |= tunnel_packet::PROXY_MASK;
    }
    memcpy(packet.data, data, len);
    outgoing_packets.push(packet);
}

void connection::destroy_tcp_connection()
{
    if (tcp_socket != INVALID_SOCKET) {
        closesocket(tcp_socket);
        tcp_socket = INVALID_SOCKET;
    }
}