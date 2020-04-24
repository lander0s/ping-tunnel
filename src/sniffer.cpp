#include "sniffer.h"
#include "networking.h"
#include <stdexcept>
#include <string.h>

pcap_t* sniffer::handle = nullptr;
bpf_program sniffer::filter;

void sniffer::init(const std::string& interface_name, const std::string& filter)
{
    bpf_u_int32 subnet_mask;
    bpf_u_int32 network_addr;
    char error_message_buffer[PCAP_ERRBUF_SIZE];
    int result = pcap_lookupnet(interface_name.c_str(), &network_addr, &subnet_mask, error_message_buffer);
    if (result == PCAP_ERROR) {
        throw std::runtime_error(error_message_buffer);
    }

    handle = pcap_open_live(interface_name.c_str(), 2048, 0, -1, error_message_buffer);
    if (handle == nullptr) {
        std::string error = "failed to open network interface: " + interface_name;
        throw std::runtime_error(error.c_str());
    }

    result = pcap_compile(handle, &sniffer::filter, filter.c_str(), 0, network_addr);
    if (result == PCAP_ERROR) {
        throw std::runtime_error(error_message_buffer);
    }

    result = pcap_setfilter(handle, &sniffer::filter);
    if (result == PCAP_ERROR) {
        throw std::runtime_error(error_message_buffer);
    }
}

void sniffer::deinit()
{
    pcap_freecode(&filter);
    pcap_close(handle);
}

int sniffer::get_next_capture(char* raw_packet, uint16_t len)
{
    struct pcap_pkthdr header;
    const u_char* packet = pcap_next(handle, &header);
    if (packet == nullptr) {
        return 0;
    }
    len = header.len > len ? len : header.len;
    memcpy(raw_packet, packet, len);
    return len;
}

void sniffer::display_available_interfaces()
{
    pcap_if_t *devs, *cur_dev;
    pcap_addr_t* cur_addr;
    char errbuf[PCAP_ERRBUF_SIZE + 1];

    pcap_findalldevs(&devs, errbuf);

    printf("Available pcap devices:\n");
    for (cur_dev = devs; cur_dev; cur_dev = cur_dev->next) {
        if (cur_dev->description)
            printf(
                "\n\t%s%c '%s'\n", cur_dev->name, (cur_dev->addresses ? ':' : ' '),
                cur_dev->description);
        else
            printf("\n\t%s%c\n", cur_dev->name, (cur_dev->addresses ? ':' : ' '));
        for (cur_addr = cur_dev->addresses; cur_addr; cur_addr = cur_addr->next) {
            if (cur_addr->addr->sa_family == AF_INET)
                printf(
                    "\t\t%s\n",
                    inet_ntoa(((struct sockaddr_in*)cur_addr->addr)->sin_addr));
        }
    }
    pcap_freealldevs(devs);
}