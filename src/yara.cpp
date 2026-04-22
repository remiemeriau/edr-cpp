#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <unordered_map>
#include <algorithm>
#include <cstdint>
#include <sstream>

using namespace std;

string trim(const string& str){
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == string::npos) return "";
    size_t end = str.find_last_not_of(" \t\n\r");
    return str.substr(start, end - start + 1);
}

class Rule {
    private:
        string _name;
        unordered_map<string, string> _strings;
        unordered_map<string, bool> _boolean;
        string _condition;
    public:
        void setName(string name) { _name = name; }
        void addString(string id, string value){ _strings[id] = value; }
        void addBool(string id, bool boolean){ _boolean[id] = boolean; }
        void setCondition(string condition){ _condition = condition; }
        unordered_map<string, string>& getStrings(){ return(_strings); }
        string& getCondition(){ return(_condition); }
        bool getBool(string id) { return _boolean[id]; }
        string getRuleName() { return _name; }
        void clearResults() { _boolean.clear(); }
};

class StringMatcher {
    private:
        string _pattern;
    public:
        bool match(const string& text) const {
            return text.find(_pattern) != string::npos;
        }
        void setPattern(string pattern){ _pattern = pattern; }
};

class HexMatcher {
    private:
        string _binaryPattern;
    public:
        void setPattern(const string& binary) { _binaryPattern = binary; }
        bool match(const string& text) const {
            return text.find(_binaryPattern) != string::npos;
        }
};

bool scanFile(const string& filePath, Rule& rule) {
    ifstream File(filePath);
    if (!File.is_open()) return false;

    char c;
    string fileContent;
    while (File.get(c)){ 
        fileContent += c;
    }
    File.close();

    rule.clearResults();

    for (auto& [id, pattern_orig] : rule.getStrings()) { 
        string pattern = pattern_orig; 
        rule.addBool(id, false);

        if (pattern[0] == '\"'){
            StringMatcher matching;
            pattern.erase(remove(pattern.begin(), pattern.end(), '\"'), pattern.end());
            matching.setPattern(pattern);
            if (matching.match(fileContent)) rule.addBool(id, true);
        }
        else if (pattern[0] == '{'){
            HexMatcher matching;
            pattern.erase(remove(pattern.begin(), pattern.end(), ' '), pattern.end());
            pattern.erase(remove(pattern.begin(), pattern.end(), '{'), pattern.end());
            pattern.erase(remove(pattern.begin(), pattern.end(), '}'), pattern.end());
            string binaryBuffer;
            string byteBuffer = ""; 
            for (int i = 0; i < (int)pattern.size(); i++){ 
                byteBuffer += pattern[i];
                if (byteBuffer.size() == 2){
                    char byte = static_cast<char>(stoul(byteBuffer, nullptr, 16));
                    binaryBuffer += byte;
                    byteBuffer = "";
                }
            }
            matching.setPattern(binaryBuffer);
            if (matching.match(fileContent)) rule.addBool(id, true);
        }
        else if (pattern[0] == '/'){
            pattern.erase(remove(pattern.begin(), pattern.end(), '/'), pattern.end());
            regex search(pattern);
            if(regex_search(fileContent, search)) rule.addBool(id, true);
        }
    }

    istringstream streamingCondition(rule.getCondition());
    string mot1, operation, mot2;
    streamingCondition >> mot1 >> operation >> mot2;

    bool val1 = rule.getBool(mot1);
    bool val2 = rule.getBool(mot2);

    if (operation == "and") return (val1 && val2);
    return (val1 || val2);
}