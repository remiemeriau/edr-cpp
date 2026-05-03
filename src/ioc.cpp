#include "ioc.hpp"
#include "logger.hpp"
#include <fstream>
#include <cstdio>

using namespace std;

unordered_set<string> ioc_hashes;

void loadIOC(const string& hashes_path) {
    string line;
    ifstream f(hashes_path);
    while (getline(f, line))
        ioc_hashes.insert(line);

    log_msg("[IOC] Loaded " + to_string(ioc_hashes.size()) + " hashes");
}

bool checkHashIOC(const string& filePath) {
    FILE* pipe = popen(("sha256sum \"" + filePath + "\"").c_str(), "r");
    char buf[65] = {};
    fgets(buf, sizeof(buf), pipe);
    pclose(pipe);
    return ioc_hashes.count(buf) > 0;
}
