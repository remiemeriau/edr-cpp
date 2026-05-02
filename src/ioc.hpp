#ifndef IOC_HPP
#define IOC_HPP
#include <unordered_set>
#include <string>

extern std::unordered_set<std::string> g_ioc_hashes;

void loadIOC(const std::string& hashes_path);
bool checkHashIOC(const std::string& filePath);

#endif
