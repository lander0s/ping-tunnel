#include "config.h"
#include <fstream>
#include <iostream>
#include <json.hpp>
#include <sstream>
#include <stdexcept>

json config::json_obj;

void config::load_config(const std::string& config_filename)
{
    std::ifstream file(config_filename, std::ifstream::in);
    if (file.good() == false) {
        throw std::runtime_error("couldn't open configuration file");
    }

    std::stringstream str_stream;
    str_stream << file.rdbuf();

    try {
        json_obj = json::parse(str_stream.str());
    } catch (...) {
        throw std::runtime_error("failed to parse configuration file");
    }
}

bool config::is_proxy()
{
    return json_obj["run_as_proxy"].get<bool>();
}

std::string config::get_proxy_address()
{
    return json_obj["proxy_address"].get<std::string>();
}

std::string config::get_network_interface()
{
    return json_obj["network_interface"].get<std::string>();
}

int config::get_listen_port()
{
    return json_obj["listen_port"].get<int>();
}

std::string config::get_dst_address()
{
    return json_obj["destination_address"].get<std::string>();
}

int config::get_dst_port()
{
    return json_obj["destination_port"].get<int>();
}