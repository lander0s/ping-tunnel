#pragma once
#define HAVE_REMOTE
#include <pcap.h>
#include <string>

class sniffer {
public:
    static void init(const std::string& interface_name, const std::string& filter);
    static void deinit();
    static int get_next_capture(char* raw_packet, uint16_t len);
    static void display_available_interfaces();

private:
    static pcap_t* handle;
    static bpf_program filter;
};