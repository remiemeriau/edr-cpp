#include "yara.hpp"
#include <sys/fanotify.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <sstream>

using namespace std;

int main(int argc, char* argv[]) 
{
    if (argc < 3) {
        cerr << "Usage: " << argv[0] << " <directory_path> <rule_path>" << endl;
        return 1;
    }

    string directoryPath = argv[1];
    string rulePath = argv[2];

    Rule rule;
    ifstream ruleFile(rulePath);
    if (!ruleFile.is_open()) {
        cerr << "Error: Could not open rule file." << endl;
        return 1;
    }

    string line, firstWord, conditionLines;
    bool inStrings(false), inCondition(false);

    while(getline(ruleFile, line)){
        istringstream fromLineToWord(line);
        fromLineToWord >> firstWord;
        if(firstWord == "rule") {
            string ruleName;
            fromLineToWord >> ruleName;
            rule.setName(ruleName);
        }
        if(inStrings){
            if(firstWord == "condition:"){
                inStrings = false;
            } else {
                size_t equalPosition = line.find('=');
                if (equalPosition != string::npos) {
                    string id = trim(line.substr(0, equalPosition));
                    string value = trim(line.substr(equalPosition + 1));
                    rule.addString(id, value);
                }
            }
        }
        if(inCondition) conditionLines += line;
        if(firstWord == "strings:") inStrings = true;
        if(firstWord == "condition:") inCondition = true;
    }
    conditionLines.erase(remove(conditionLines.begin(), conditionLines.end(), '}'), conditionLines.end());
    rule.setCondition(trim(conditionLines));
    ruleFile.close();

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
    char path[4096];

    cout << "Antivirus started on " << directoryPath << " using rule " << rulePath << endl;

    while (read(fd, &event, sizeof(event)) > 0) {
        string linkStr = "/proc/self/fd/" + to_string(event.fd);
        ssize_t len = readlink(linkStr.c_str(), path, 4096);
        if (len != -1) {
            path[len] = '\0';
            string currentFilePath(path);

            if (currentFilePath.find(directoryPath) != string::npos) {
                if (scanFile(currentFilePath, rule)) {
                    cout << "[ALERT] Rule matched: " << rule.getRuleName() << " | FILE: " << currentFilePath << endl;
                }
            }
        }
        close(event.fd);
    }
    return 0;
}