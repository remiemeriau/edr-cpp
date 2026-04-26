#ifndef YARA_HPP
#define YARA_HPP
#include <string>
#include <unordered_map>

class Rule {
    private:
        std::string _name;
        std::unordered_map<std::string, std::string> _strings;
        std::unordered_map<std::string, bool> _boolean;
        std::string _condition;
    public:
        void setName(std::string name) { _name = name; }
        void addString(std::string id, std::string value){ _strings[id] = value; }
        void addBool(std::string id, bool boolean){ _boolean[id] = boolean; }
        void setCondition(std::string condition){ _condition = condition; }
        std::unordered_map<std::string, std::string>& getStrings(){ return(_strings); }
        std::string& getCondition(){ return(_condition); }
        bool getBool(std::string id) { return _boolean[id]; }
        std::string getRuleName() { return _name; }
        void clearResults() { _boolean.clear(); }
};

std::string trim(const std::string& str);
bool scanFile(const std::string& filePath, Rule& rule);

#endif