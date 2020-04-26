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

#include "sniffer.h"
#include "net.h"
#include <iostream>
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
        char err_buf[1024];
        sprintf(err_buf, "Failed to open network interface: %s\r\n\t%s", interface_name.c_str(), error_message_buffer);
        throw std::runtime_error(err_buf);
    }

    handle = pcap_open_live(interface_name.c_str(), 1024, 0, -1, error_message_buffer);
    if (handle == nullptr) {
        char err_buf[1024];
        sprintf(err_buf, "Failed to open network interface: %s\r\n\t%s", interface_name.c_str(), error_message_buffer);
        throw std::runtime_error(err_buf);
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
    if (handle) {
        pcap_freecode(&filter);
        pcap_close(handle);
    }
}

int sniffer::get_next_capture(char* raw_packet, uint16_t len)
{
    struct pcap_pkthdr* header;
    const u_char* packet;
    int result = pcap_next_ex(handle, &header, &packet);
    if (result == PCAP_ERROR) {
        char buf[1024];
        sprintf(buf, "Error capturing packets\r\n\t%s", pcap_geterr(handle));
        throw std::runtime_error(buf);
    }
    if (result == 1) {
        len = header->len > len ? len : header->len;
        memcpy(raw_packet, packet, len);
        return len;
    }
    return 0;
}

void sniffer::display_available_interfaces()
{
    pcap_if_t *devs, *current_device;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    pcap_findalldevs(&devs, errbuf);

    std::cout << "Available network interfaces:\r\n\r\n";
    for (current_device = devs; current_device; current_device = current_device->next) {
        std::cout << "\t- " << current_device->name
                  << " (" << current_device->description << ")\r\n";
    }
    std::cout << std::endl;
    pcap_freealldevs(devs);
}