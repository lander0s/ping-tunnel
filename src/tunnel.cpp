#include "tunnel.h"
#include "ping_sender.h"
#include "sniffer.h"
#include "tcp_ip.h"
#include "utils.h"
#include <chrono>
#include <iostream>
#include <string.h>
#include <thread>

string tunnel::dst_hostname;
uint16_t tunnel::dst_port;

connection_map_t tunnel::connections;
bool tunnel::is_proxy            = false;
string tunnel::proxy_hostname    = "";
int tunnel::listen_port          = 12345;
socket_t tunnel::listener_socket = INVALID_SOCKET;

void tunnel::run_as_proxy(const string network_interface)
{
    string sniffer_filter = "icmp[icmptype] == 8"; // ping requests only
    sniffer::init(network_interface, sniffer_filter);
    ping_sender::init();

    is_proxy = true;
    main_loop();

    ping_sender::deinit();
    sniffer::deinit();
}

void tunnel::run_as_forwarder(
    const string network_interface, const string& proxy_hostname,
    int listen_port, const string& dst_address, int dst_port)
{
    string sniffer_filter = "icmp[icmptype] == 0"; // ping replies only
    sniffer::init(network_interface, sniffer_filter);
    ping_sender::init();

    tunnel::dst_hostname = dst_address;
    tunnel::dst_port     = dst_port;

    is_proxy               = false;
    tunnel::proxy_hostname = proxy_hostname;
    tunnel::listen_port    = listen_port;
    initialize_listener_socket();
    main_loop();

    ping_sender::deinit();
    sniffer::deinit();
}

void tunnel::initialize_listener_socket()
{
    listener_socket      = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr     = {};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(listen_port);
    addr.sin_addr.s_addr = INADDR_ANY;
    bind(listener_socket, (sockaddr*)&addr, sizeof(sockaddr_in));
    listen(listener_socket, 0);
}

void tunnel::main_loop()
{
    while (true) {
        char raw_packet[1024];
        int len = sniffer::get_next_capture(raw_packet, 1024);
        if (len > 0) {
            // the sniffer's filter guarantees the packet is either echo request or echo reply
            ethernet_header_t* ethernet_header = (ethernet_header_t*)raw_packet;
            ip_header_t* ip_header             = (ip_header_t*)(raw_packet + sizeof(ethernet_header_t));
            icmp_packet_t* icmp_packet         = (icmp_packet_t*)(raw_packet + sizeof(ethernet_header_t) + sizeof(ip_header_t));
            tunnel_packet_t* tunnel_packet     = (tunnel_packet_t*)icmp_packet->payload;

            if (should_process_packet(tunnel_packet)) {
                uint32_t conn_id         = tunnel_packet->header.connection_id;
                connection_t* connection = get_connection(conn_id);

                if (tunnel_packet->is_syn()) {
                    handle_syn(ip_header, tunnel_packet);
                }

                if (connection) {
                    connection->last_received_icmp_packet = *icmp_packet;

                    if (tunnel_packet->is_ack()) {
                        handle_ack(connection, tunnel_packet);
                    }

                    if (tunnel_packet->is_psh()) {
                        handle_push(connection, tunnel_packet);
                    }

                    if (tunnel_packet->is_fin()) {
                        handle_fin(connection, tunnel_packet);
                    }
                }
            }
        }

        for (auto& it : connections) {
            connection_t* connection = &it.second;
            if (should_send_new_message(connection)) {
                tunnel_packet_t packet             = get_next_message_to_send(connection);
                connection->local_sequence_number  = packet.header.seq_no;
                connection->last_transmission_time = steady_clock::now();

                if (is_proxy) {
                    ping_sender::reply(&packet, packet.size(), &connection->tunnel_addr, &connection->last_received_icmp_packet);
                } else {
                    ping_sender::send(&packet, packet.size(), &connection->tunnel_addr);
                }
            }

            // poll tcp events
            fd_set set;
            timeval time;
            FD_ZERO(&set);
            FD_SET(connection->tcp_socket, &set);
            time.tv_sec  = 0;
            time.tv_usec = 0;
            if (select(connection->tcp_socket + 1, &set, 0, 0, &time) > 0) {
                char buf[500];
                int len = recv(connection->tcp_socket, buf, 500, 0);
                if (len > 0) {
                    send_message(connection, buf, len);
                }

                if (len <= 0) {
                    send_fin(connection);
                    cout << "[+] tcp connection closed on " << (is_proxy ? "proxy" : "forwarder") << " side" << endl;
                }
            }
        }

        fd_set set;
        timeval time;
        FD_ZERO(&set);
        FD_SET(listener_socket, &set);
        time.tv_sec  = 0;
        time.tv_usec = 0;
        if (select(listener_socket + 1, &set, 0, 0, &time) > 0) {
            socket_t new_sock      = accept(listener_socket, nullptr, 0);
            connection_t* new_conn = add_forwarder_side_connection(new_sock, dst_hostname, dst_port);
            send_syn(new_conn);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

connection_t* tunnel::get_connection(uint32_t connection_id)
{
    connection_map_t::iterator iterator = connections.find(connection_id);
    if (iterator != connections.end()) {
        return &iterator->second;
    }
    return nullptr;
}

bool tunnel::should_process_packet(const tunnel_packet_t* packet)
{
    // the packet must have a valid magic number
    if (packet->has_valid_magic_number() == false)
        return false;

    // the packet must have been created by the oposite facet
    if (packet->was_sent_by_proxy() == is_proxy)
        return false;

    return true;
}

void tunnel::handle_ack(connection_t* connection, const tunnel_packet_t* packet)
{
    if (connection->outgoing_packets.empty()) {
        return;
    }

    tunnel_packet_t* top     = &connection->outgoing_packets.front();
    uint32_t expected_seq_no = top->header.seq_no;
    uint32_t actual_seq_no   = packet->header.seq_no;

    if (expected_seq_no == actual_seq_no) {
        cout << "[+] packet confirmed as delivered, seq: " << actual_seq_no << endl;
        if (top->is_fin()) {
            remove_connection(connection);
        } else {
            connection->outgoing_packets.pop();
        }
    }
}

void tunnel::handle_push(connection_t* connection, const tunnel_packet_t* packet)
{
    cout << "[+] packet received, seq: " << packet->header.seq_no << endl;
    send_ack(connection, packet);

    if (connection->remote_sequence_number != packet->header.seq_no) {
        connection->remote_sequence_number = packet->header.seq_no;
        on_message(connection, (char*)packet->data, packet->header.data_len);
    }
}

void tunnel::handle_fin(connection_t* connection, const tunnel_packet_t* packet)
{
    // I won't be able to resend this ACK in case of loss
    // because i'm removing the connection from the list
    send_ack(connection, packet);
    send_ack(connection, packet);
    send_ack(connection, packet);
    send_ack(connection, packet);

    cout << "[+] tcp connection closed on " << (is_proxy ? "forwarder" : "proxy") << " side" << endl;
    remove_connection(connection);
}

void tunnel::handle_syn(const ip_header_t* ip_header, const tunnel_packet_t* packet)
{
    // only create the connection if it does not exist previously
    connection_t* conn = get_connection(packet->header.connection_id);
    if (conn == nullptr) {
        conn = add_proxy_side_connection(packet->header.connection_id, ip_header, packet);
    }
    send_ack(conn, packet);
}

void tunnel::send_ack(connection_t* connection, const tunnel_packet_t* incomming_packet)
{
    tunnel_packet_t ack      = {};
    ack.header.magic_number  = MAGIC_NUMBER;
    ack.header.seq_no        = incomming_packet->header.seq_no;
    ack.header.connection_id = incomming_packet->header.connection_id;

    ack.header.flags |= ACK_MASK;
    if (is_proxy) {
        ack.header.flags |= PROXY_MASK;
    }

    if (is_proxy) {
        ping_sender::reply(&ack, ack.size(), &connection->tunnel_addr, &connection->last_received_icmp_packet);
    } else {
        ping_sender::send(&ack, ack.size(), &connection->tunnel_addr);
    }
}

void tunnel::send_syn(connection_t* connection)
{
    tunnel_packet_t syn = {};

    syn.header.connection_id = connection->connection_id;
    syn.header.magic_number  = MAGIC_NUMBER;
    syn.header.dst_addr      = connection->destination_addr.sin_addr.s_addr;
    syn.header.dst_port      = connection->destination_addr.sin_port;
    syn.header.seq_no        = connection->sequence_counter++;

    syn.header.flags |= SYN_MASK;
    if (is_proxy) {
        syn.header.flags |= PROXY_MASK;
    }
    connection->outgoing_packets.push(syn);
}

void tunnel::send_fin(connection_t* connection)
{
    tunnel_packet_t fin = {};

    fin.header.connection_id = connection->connection_id;
    fin.header.magic_number  = MAGIC_NUMBER;
    fin.header.dst_addr      = connection->destination_addr.sin_addr.s_addr;
    fin.header.dst_port      = connection->destination_addr.sin_port;
    fin.header.seq_no        = connection->sequence_counter++;

    fin.header.flags |= FIN_MASK;
    if (is_proxy) {
        fin.header.flags |= PROXY_MASK;
    }
    connection->outgoing_packets.push(fin);
}

bool tunnel::should_send_new_message(connection_t* connection)
{
    // if there is a message in the queue than has never been transmitted before
    if (connection->outgoing_packets.size() > 0 && connection->outgoing_packets.front().header.seq_no != connection->local_sequence_number) {
        return true;
    }

    // or if the last transmition was 500ms ago
    auto elapsed_time = steady_clock::now() - connection->last_transmission_time;
    if (duration_cast<milliseconds>(elapsed_time).count() > 1000) {

        if (connection->outgoing_packets.empty() == false) {
            cout << "[*] resending unconfirmed packet, seq: "
                 << connection->outgoing_packets.front().header.seq_no
                 << ", size: " << connection->outgoing_packets.front().header.data_len
                 << endl;
        }

        return true;
    }

    return false;
}

tunnel_packet_t tunnel::get_next_message_to_send(connection_t* connection)
{
    if (connection->outgoing_packets.empty() == false) {
        return connection->outgoing_packets.front();
    }

    // send an empty packet to keep 'ICMP Query Mapping' alive (rfc5508)
    tunnel_packet_t keep_alive      = {};
    keep_alive.header.connection_id = connection->connection_id;
    keep_alive.header.magic_number  = MAGIC_NUMBER;
    keep_alive.header.dst_addr      = connection->destination_addr.sin_addr.s_addr;
    keep_alive.header.dst_port      = connection->destination_addr.sin_port;
    return keep_alive;
}

void tunnel::on_message(connection_t* connection, const char* data, int len)
{
    // forwarding received message through TCP connection
    int sent = send(connection->tcp_socket, data, len, 0);
    if (sent <= 0) {
        send_fin(connection);
        cout << "[-] failed to send data through tcp socket: " << strerror(errno) << endl;
    }
}

void tunnel::send_message(connection_t* connection, const char* data, int len)
{
    tunnel_packet_t packet      = {};
    packet.header.connection_id = connection->connection_id;
    packet.header.magic_number  = MAGIC_NUMBER;
    packet.header.seq_no        = connection->sequence_counter++;
    packet.header.data_len      = len;
    packet.header.dst_addr      = connection->destination_addr.sin_addr.s_addr;
    packet.header.dst_port      = connection->destination_addr.sin_port;
    packet.header.flags |= PSH_MASK;
    if (is_proxy) {
        packet.header.flags |= PROXY_MASK;
    }
    memcpy(packet.data, data, len);
    connection->outgoing_packets.push(packet);
}

connection_t* tunnel::add_forwarder_side_connection(socket_t tcp_socket, std::string dst_hostname, int dst_port)
{
    connection_t conn     = {};
    conn.connection_id    = utils::randon_uint32();
    conn.tcp_socket       = tcp_socket;
    conn.sequence_counter = utils::randon_uint32();
    utils::resolve_host(proxy_hostname, &conn.tunnel_addr);

    conn.destination_addr = {};
    utils::resolve_host(dst_hostname, &conn.destination_addr);
    conn.destination_addr.sin_port = htons(dst_port);

    cout << "[+] new connection to forward: " << conn.connection_id << endl;

    connections[conn.connection_id] = conn;
    return &connections[conn.connection_id];
}

connection_t* tunnel::add_proxy_side_connection(uint32_t id, const ip_header_t* ip_header, const tunnel_packet_t* initiator)
{
    cout << "[+] new connection to forward: " << id << endl;

    connection_t conn     = {};
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
        send_fin(&conn);
        cout << "[-] connection failed: " << strerror(errno) << endl;
    }

    connections[id] = conn;
    return &connections[id];
}

void tunnel::remove_connection(connection_t* connection)
{
    cout << "[+] removing connection with id: " << connection->connection_id << endl;
    if (connection->tcp_socket != INVALID_SOCKET) {
        closesocket(connection->tcp_socket);
        connection->tcp_socket = INVALID_SOCKET;
    }
    connections.erase(connection->connection_id);
}