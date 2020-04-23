
#include "sniffer.h"
#include "tunnel.h"
#include "utils.h"
#include <iostream>
#include <popl.hpp>

std::string dst_addr_str       = "127.0.0.1";
std::string proxy_addr_str     = "127.0.0.1";
std::string net_interface_name = "\\Device\\NPF_{EED844F6-F6EC-4D0B-9FCA-52F474164A4B}";
int dst_port                   = 12345;
int listen_port                = 12346;
bool run_as_proxy              = true;

void parse_arguments(int argc, char* argv[]);

int main(int argc, char* argv[])
{
    parse_arguments(argc, argv);
    utils::initialize_dependencies();

    if (run_as_proxy) {
        std::cout << "[+] running as proxy" << std::endl;
        tunnel::run_as_proxy(net_interface_name);
    } else {
        std::cout << "[+] running as forwarder" << std::endl;
        tunnel::run_as_forwarder(net_interface_name, proxy_addr_str, listen_port, dst_addr_str, dst_port);
    }

    utils::deinitialize_dependencies();
    return 0;
}

void parse_arguments(int argc, char* argv[])
{
    popl::OptionParser op("Options");

    auto help_option            = op.add<popl::Switch>("h", "help", "shows this help message");
    auto list_interfaces_option = op.add<popl::Switch>("L", "list-interfaces", "shows a list of available interfaces");

    auto proxy_addr_option = op.add<popl::Value<std::string>>("P", "proxy-addr", "proxy address");
    auto dst_addr_option   = op.add<popl::Value<std::string>>("a", "dst-addr", "destination address");
    auto dst_port_option   = op.add<popl::Value<int>>("p", "dst-port", "destination port");

    auto net_interface_option = op.add<popl::Value<std::string>>("i", "interface", "network interface to listen");
    auto listen_port_option   = op.add<popl::Value<int>>("l", "listen-port", "port to listen as proxy");

    op.parse(argc, argv);

    if (help_option->is_set()) {
        std::cout << op << std::endl;
        exit(0);
    }

    if (list_interfaces_option->is_set()) {
        sniffer::display_available_interfaces();
        exit(0);
    }

    if (proxy_addr_option->is_set()) {
        proxy_addr_str = proxy_addr_option->value();
        run_as_proxy   = false;
    }

    if (dst_addr_option->is_set()) {
        dst_addr_str = dst_addr_option->value();
    }

    if (dst_port_option->is_set()) {
        dst_port = dst_port_option->value();
    }

    if (net_interface_option->is_set()) {
        net_interface_name = net_interface_option->value();
    }

    if (listen_port_option->is_set()) {
        listen_port = listen_port_option->value();
    }
}