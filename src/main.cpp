
#include "config.h"
#include "sniffer.h"
#include "tunnel.h"
#include "utils.h"
#include <iostream>
#include <popl.hpp>

int main(int argc, char* argv[])
{
    try {
        utils::initialize_dependencies();
        config::load_config("ping-tunnel.json");
        tunnel::start();
        return 0;
    } catch (std::runtime_error e) {
        std::cout << "[-] " << e.what() << std::endl;
        return -1;
    }
    utils::deinitialize_dependencies();
}
