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

#include "utils.h"
#include "networking.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <time.h>

#if defined(_WIN32)
#include <Windows.h>
#include <tchar.h>
#endif

bool utils::initialize_dependencies()
{
#if defined(_WIN32)
    // Initialize WinSucks2
    WSADATA wsaData;
    WORD wVersionRequested = MAKEWORD(2, 2);
    (void)WSAStartup(wVersionRequested, &wsaData);

    // Load NpCap Dlls
    TCHAR npcap_dir[512];
    unsigned int len;
    len = GetSystemDirectory(npcap_dir, 480);
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return false;
    }
    _tcscat_s(npcap_dir, 512, TEXT("\\Npcap"));
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return false;
    }
    return true;
#endif
    return true;
}

void utils::deinitialize_dependencies()
{
#if defined(_WIN32)
    WSACleanup();
#endif
}

void utils::dump_hex(const void* data, size_t size)
{
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

unsigned short utils::checksum(void* b, int len)
{
    unsigned short* buf = (unsigned short*)b;
    unsigned int sum    = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

uint32_t utils::randon_uint32()
{
    static unsigned int num = 0;
    srand((unsigned int)time(0) + num++);
    return rand();
}

bool utils::resolve_host(const std::string& hostname, sockaddr_in* addr)
{
    struct addrinfo hints, *res_info;
    memset(&hints, 0, sizeof(addrinfo));
    hints.ai_family = AF_INET;
    getaddrinfo(hostname.c_str(), NULL, &hints, &res_info);
    if (res_info == nullptr) {
        return false;
    }
    memcpy(addr, res_info->ai_addr, res_info->ai_addrlen);
    freeaddrinfo(res_info);
    return true;
}
