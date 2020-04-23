#pragma once

#if defined(_WIN32)
#include <WinSock2.h>
#include <Windows.h>
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#define INVALID_SOCKET (-1)
#define closesocket close
#endif

#if defined(_WIN32)
#define socket_t SOCKET
#else
#define socket_t int
#endif