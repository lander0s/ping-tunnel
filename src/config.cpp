/*
 MIT License
 
 Copyright (c) 2020 David Landeros
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 */

#include "config.h"
#include <fstream>
#include <functional>
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

    verify_config();
}

void config::verify_config()
{
    REQUIRE(json_obj, "run_as_proxy", is_boolean, "boolean");
    REQUIRE(json_obj, "network_interface", is_string, "string");

    if (is_proxy() == false) {
        REQUIRE(json_obj, "proxy_address", is_string, "string");
        REQUIRE(json_obj, "port_mappings", is_array, "array");
        size_t mappigs_count = json_obj["port_mappings"].size();
        if (mappigs_count == 0) {
            throw std::runtime_error("you need to define at least one port mapping");
        }
        for (int i = 0; i < mappigs_count; i++) {
            REQUIRE(json_obj["port_mappings"][i], "local_port", is_number, "number (check port_mappings array)");
            REQUIRE(json_obj["port_mappings"][i], "destination_port", is_number, "number (check port_mappings array)");
            REQUIRE(json_obj["port_mappings"][i], "destination_address", is_string, "string (check port_mappings array)");
        }
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

int config::get_port_mapping_count()
{
    return (int)json_obj["port_mappings"].size();
}

int config::get_local_port(unsigned int index)
{
    return json_obj["port_mappings"][index]["local_port"].get<int>();
}

std::string config::get_destination_address(unsigned int index)
{
    return json_obj["port_mappings"][index]["destination_address"].get<std::string>();
}

int config::get_destination_port(unsigned int index)
{
    return json_obj["port_mappings"][index]["destination_port"].get<int>();
}