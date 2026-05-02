#ifndef DPI_HPP
#define DPI_HPP
#include "yara.hpp"
#include <vector>
#include <string>

bool scanBuffer(const std::string& content, Rule& rule);
void start_dpi(const std::string& interface, std::vector<Rule>& rules);

#endif
