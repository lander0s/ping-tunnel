#include "config.h"

bool config::load_config(const string& ini_file)
{
    return true;
}

bool config::is_proxy()
{
    return false;
}

const string& config::get_proxy_address()
{
    return "";
}

const string& config::get_network_interface()
{
    return "";
}

int config::get_listen_port()
{
    return 12345;
}