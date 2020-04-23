#pragma once
#define HAVE_REMOTE
#include <pcap.h>
#include <string>

class sniffer {
public:
    static bool init(const std::string& interface_name, const std::string& filter);
    static void deinit();
    static int get_next_capture(char* raw_packet, uint16_t len);
    static const std::string& get_last_error();
    static void display_available_interfaces();

private:
    static std::string last_error;
    static pcap_t* handle;
    static bpf_program filter;
};