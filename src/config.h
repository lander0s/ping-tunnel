#pragma once
#include <json.hpp>
#include <string>

using json = nlohmann::json;

class config {
private:
    static json json_obj;
    static void verify_config();

public:
    static void load_config(const std::string& config_file);
    static bool is_proxy();
    static std::string get_proxy_address();
    static std::string get_network_interface();
    static int get_listen_port();
    static std::string get_dst_address();
    static int get_dst_port();
};