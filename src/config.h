#pragma once
#include <string>
using namespace std;

class config {
public:
    static bool load_config(const string& ini_file);
    static bool is_proxy();
    static const string& get_proxy_address();
    static const string& get_network_interface();
    static int get_listen_port();
};