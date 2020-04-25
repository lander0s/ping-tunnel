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
#include "sniffer.h"
#include "tunnel.h"
#include "utils.h"
#include <iostream>
#include <popl.hpp>

std::string config_file = "ping-tunnel.json";

int main(int argc, char* argv[])
{
    popl::OptionParser op("Available options");
    auto help_option   = op.add<popl::Switch>("h", "help", "produce this help message");
    auto quiet_option  = op.add<popl::Switch>("q", "quiet", "reduce verbosity");
    auto list_option   = op.add<popl::Switch>("l", "list", "display a list of available network interfaces");
    auto config_option = op.add<popl::Value<std::string>>("c", "config", "specifies the configuration file to use");
    op.parse(argc, argv);

    if (help_option->is_set()) {
        std::cout << op << std::endl;
        std::cout << "\tconfig file defaults to ping-tunnel.json" << std::endl;
        return 0;
    }

    if (list_option->is_set()) {
        sniffer::display_available_interfaces();
        return 0;
    }

    if (config_option->is_set()) {
        config_file = config_option->value();
    }

    utils::initialize_dependencies();
    tunnel::run(config_file, quiet_option->is_set());
    utils::deinitialize_dependencies();
    return 0;
}