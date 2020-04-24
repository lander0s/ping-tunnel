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
