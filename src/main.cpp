#include "yara.hpp"
#include "dpi.hpp"
#include <sys/fanotify.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <sstream>
#include <vector>   // std::vector is used to store multiple rules from the .yar file look : https://en.cppreference.com/w/cpp/container/vector
#include <thread>
using namespace std;

int main(int argc, char* argv[]) 
{
    if (argc < 3) {
        cerr << "Usage: " << argv[0] << " <directory_path> <rule_path>" << endl;
        return 1;
    }

    string directoryPath = argv[1];
    string rulePath = argv[2];

    // We use std::vector<Rule> because one Rule object can only store a single rule
    // Our .yar file can contain many rules (example: SimpleMalware + ransomware)
    // vector lets us load all rules once at startup and keep them in memory
    // Then, every time a file is modified, we can quickly check it against ALL rules
    // without having to reopen and reparse the rule file again (wich was the case before)
    // See: https://en.cppreference.com/w/cpp/container/vector

    vector<Rule> rules;
    ifstream ruleFile(rulePath);
    if (!ruleFile.is_open()) {
        cerr << "Error: Could not open rule file." << endl;
        return 1;
    }

    string line, firstWord, conditionLines;
    bool inStrings(false), inCondition(false);
    Rule currentRule;

    while(getline(ruleFile, line)){
        istringstream fromLineToWord(line);
        fromLineToWord >> firstWord;
        if(firstWord == "rule") {
            if (!currentRule.getRuleName().empty()) {
                conditionLines.erase(remove(conditionLines.begin(), conditionLines.end(), '}'), conditionLines.end());
                currentRule.setCondition(trim(conditionLines));
                rules.push_back(currentRule);
                currentRule = Rule();
                conditionLines = "";
                inStrings = false;
                inCondition = false;
            }
            string ruleName;
            fromLineToWord >> ruleName;
            currentRule.setName(ruleName);
        }
        if(inStrings){
            if(firstWord == "condition:"){
                inStrings = false;
            } else {
                size_t equalPosition = line.find('=');
                if (equalPosition != string::npos) {
                    string id = trim(line.substr(0, equalPosition));
                    string value = trim(line.substr(equalPosition + 1));
                    currentRule.addString(id, value);
                }
            }
        }
        if(inCondition) conditionLines += line;
        if(firstWord == "strings:") inStrings = true;
        if(firstWord == "condition:") inCondition = true;
    }
    if (!currentRule.getRuleName().empty()) {
        conditionLines.erase(remove(conditionLines.begin(), conditionLines.end(), '}'), conditionLines.end());
        currentRule.setCondition(trim(conditionLines));
        rules.push_back(currentRule);
    }
    ruleFile.close();

    thread network_thread(start_dpi, "lo", ref(rules));
    network_thread.detach();

    int fd = fanotify_init(FAN_CLASS_NOTIF, O_RDONLY);
    if (fd == -1) {
        perror("fanotify_init");
        return 1;
    }

    if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT, 
                     FAN_CLOSE_WRITE | FAN_EVENT_ON_CHILD, 
                     AT_FDCWD, directoryPath.c_str()) == -1) {
        perror("fanotify_mark");
        return 1;
    }

    struct fanotify_event_metadata event;

    cout << "Antivirus started on " << directoryPath << " using rule " << rulePath << endl;

    while (read(fd, &event, sizeof(event)) > 0) {
        string linkStr = "/proc/self/fd/" + to_string(event.fd);

        // C++23 modern buffer handling
        // std::string::resize_and_overwrite lets us write directly into the string's internal buffer
        // and set the exact final size in one operation. This is cleaner and safer than manual resize + data()

        // From the documentation:
        // "Resizes the string to contain count characters and invokes the operation on the string's buffer."
        // https://en.cppreference.com/w/cpp/string/basic_string/resize_and_overwrite 
        // before we juste wrote two 4096, it was not good and can lead to buffer if size differ. 


        string currentFilePath;
        currentFilePath.__resize_and_overwrite(4096, [&](char* buf, size_t n) -> size_t {
            ssize_t len = readlink(linkStr.c_str(), buf, n - 1); // n - 1 we let 1 byte safety margin https://man7.org/linux/man-pages/man2/readlink.2.html, "readlink() does not append a terminating null byte to buf." so we add one
            return (len > 0) ? static_cast<size_t>(len) : 0;
        });

        if (currentFilePath.find(directoryPath) != string::npos) {
            for (auto& r : rules) {
                if (scanFile(currentFilePath, r)) {
                    cout << "[ALERT] Rule matched: " << r.getRuleName() << " | FILE: " << currentFilePath << endl;
                }
            }
        }
        close(event.fd);
    }
    return 0;
}
