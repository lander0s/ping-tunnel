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
    static int get_port_mapping_count();
    static int get_local_port(unsigned int index);
    static std::string get_destination_address(unsigned int index);
    static int get_destination_port(unsigned int index);
};

#define REQUIRE(object, member, method, type)                                           \
    if (object[member].method() == false) {                                             \
        throw std::runtime_error("option '" member "' is required and must be: " type); \
    }
