# Ping-Tunnel
C++ [ICMP tunnel](https://en.wikipedia.org/wiki/ICMP_tunnel) implementation

This tool is for tunneling TCP traffic over ping requests and replies to **bypass TCP filters**,
in contrast with the old ptunnel implementation for Linux, this version supports multiple connections on
different TCP ports mapped to different destinations at the same time.

## Supported platforms
- Windows
- Linux

## Usage
#### As Proxy:
create a file called **ping-tunnel.json** with the following content:
```json
{
    "run_as_proxy"      : true,
    "network_interface" : "eth0",
}
```
Replace the field *network_interface* with the interface you want the proxy to listen for pings.  
In the same folder run the program ```./ping-tunnel``` (you need to run it as root/administrator)

#### As forwarder:
create a file called **ping-tunnel.json** with a content like this:
```json
{
    "run_as_proxy"      : false,
    "proxy_address"     : "192.168.0.9",
    "network_interface" : "eth0",
    "port_mappings" : [
        {
            "__comments"          : "SMTP server",
            "local_port"          : 25,
            "destination_port"    : 25,
            "destination_address" : "otherserver.com"
        },
        {
            "__comments"          : "IMAP server",
            "local_port"          : 143,
            "destination_port"    : 143,
            "destination_address" : "otherserver.com"
        },
        {
            "__comments"          : "Mysql server",
            "local_port"          : 3306,
            "destination_port"    : 3306,
            "destination_address" : "192.168.0.9"
        }
    ]
}
```
Replace the field *network_interface* with the interface you want the forwarder to listen for pings.  
In the same folder run the program ```./ping-tunnel``` (you need to run it as root/administrator)

Once you have both facets up and running, you can use your forwarder address/ports as if they were your destination address/port, since the TCP conections will be forwarded
