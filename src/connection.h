#pragma once
#include "net.h"
#include <chrono>
#include <ctime>
#include <map>
#include <queue>
#include <string>

#define TEST(bitflag, mask) ((bitflag & mask) == mask)

struct tunnel_packet {

    static const uint8_t SYN_MASK      = 1 << 0; // new connection
    static const uint8_t PSH_MASK      = 1 << 1; // the message contains data
    static const uint8_t ACK_MASK      = 1 << 2; // acknowledge
    static const uint8_t FIN_MASK      = 1 << 3; // close connection
    static const uint8_t PROXY_MASK    = 1 << 4; // the message was sent by the proxy facet
    static const uint32_t MAGIC_NUMBER = 0xdeadbeef;

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

typedef std::queue<tunnel_packet> packet_queue;

class connection {
public:
    static bool quiet_mode;

    connection(connection&& conn) noexcept;
    connection(uint32_t id, const ip_header_t* ip_header, icmp_packet_t* icmp_packet, const tunnel_packet* syn_packet) noexcept;
    connection(socket_t socket, std::string dst_hostname, int dst_port) noexcept;

    bool is_dead;
    uint32_t connection_id;
    void update();
    void on_tunnel_packet(const tunnel_packet* packet, icmp_packet_t* icmp_packet);
    void handle_ack(const tunnel_packet* packet);
    void handle_push(const tunnel_packet* packet);
    void handle_fin(const tunnel_packet* packet);
    void send_syn();
    void send_ack(const tunnel_packet* packet);
    void send_fin();
    bool should_send_new_message();
    tunnel_packet get_next_message_to_send();
    void send_message(const char* data, int len);
    void on_message(const char* data, int len);
    void destroy_tcp_connection();

private:
    int resend_counter;
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

typedef std::map<uint32_t, connection> connection_list;