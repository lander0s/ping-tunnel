
CC=g++

SOURCE=./src/main.cpp \
       ./src/ping_sender.cpp \
       ./src/sniffer.cpp \
       ./src/tunnel.cpp \
       ./src/connection.cpp \
       ./src/utils.cpp \
       ./src/config.cpp

INCLUDES=-I ./libs/popl/include \
         -I ./libs/json/include

CFLAGS  = -std=c++11 -lpcap -ggdb

all:
	$(CC) $(SOURCE) $(INCLUDES) $(CFLAGS) -o ping-tunnel

clean:
	rm ping-tunnel