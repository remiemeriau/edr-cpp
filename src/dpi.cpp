#include "dpi.hpp"
#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <algorithm>
#include <sstream>
#include <vector>

using namespace std;

// Scan a buffer against a rule (simplified YARA-like logic)
bool scanBuffer(const string& content, Rule& rule) {
    rule.clearResults();

    for (auto& [id, pattern_orig] : rule.getStrings()) {
        string pattern = pattern_orig;
        rule.addBool(id, false);

        // Handle quoted string patterns: "example"
        if (pattern.size() >= 2 && pattern.front() == '\"' && pattern.back() == '\"') {
            string cleanPattern = pattern.substr(1, pattern.size() - 2);
            if (content.find(cleanPattern) != string::npos) {
                rule.addBool(id, true);
            }
        }
        // Extend here for hex/regex if needed
    }
    
    string cond = trim(rule.getCondition());
    if (cond.empty()) return false;

    // Very basic condition parser: $a, $a and $b, $a or $b
    istringstream iss(cond);
    string m1, op, m2;

    if (!(iss >> m1)) return false;
    if (!(iss >> op >> m2)) return rule.getBool(m1);

    if (op == "and") return rule.getBool(m1) && rule.getBool(m2);
    if (op == "or")  return rule.getBool(m1) || rule.getBool(m2);
    
    return false;
}

// libpcap callback: called for each captured packet
void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    vector<Rule>* rules = (vector<Rule>*)user;
    
    // Skip Ethernet header and parse IP
    struct ip* ip_h = (struct ip*)(packet + 14);
    int ip_len = ip_h->ip_hl * 4;

    u_char* payload = nullptr;
    int payload_len = 0;
    uint16_t dport = 0;
    string proto = "OTHERS";

    // TCP handling
    if (ip_h->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcp_h = (struct tcphdr*)(packet + 14 + ip_len);
        dport = ntohs(tcp_h->dest);
        int tcp_header_len = tcp_h->doff * 4;
        
        payload = (u_char*)(packet + 14 + ip_len + tcp_header_len);
        payload_len = ntohs(ip_h->ip_len) - (ip_len + tcp_header_len);
    } 
    // UDP handling
    else if (ip_h->ip_p == IPPROTO_UDP) {
        struct udphdr* udp_h = (struct udphdr*)(packet + 14 + ip_len);
        dport = ntohs(udp_h->dest);
        payload = (u_char*)(packet + 14 + ip_len + 8);
        payload_len = ntohs(ip_h->ip_len) - (ip_len + 8);
    }

    if (payload && payload_len > 0) {
        // Prevent reading beyond captured buffer
        int safe_len = min(payload_len, (int)(header->caplen - (int)((u_char*)payload - packet)));
        if (safe_len <= 0) return;

        string data((const char*)payload, safe_len);

        // Lightweight protocol detection
        if (data.find("GET ") == 0 || data.find("POST ") == 0 || data.find("HTTP/") != string::npos) {
            proto = "HTTP";
        } else if (dport == 25 || data.find("220 ") == 0 || data.find("EHLO") == 0) {
            proto = "SMTP";
        } else if (dport == 23 || (unsigned char)data[0] == 0xff) {
            proto = "TELNET";
        }

        for (auto& r : *rules) {
            if (scanBuffer(data, r)) {
                size_t endLine = data.find("\r\n");
                string firstLine = (endLine != string::npos) ? data.substr(0, endLine) : data;

                if (proto == "HTTP") {
                    cout << "[HTTP] Request: " << firstLine << endl;
                    
                    // Extract Host header if present
                    size_t hostPos = data.find("Host: ");
                    if (hostPos != string::npos) {
                        size_t hostEnd = data.find("\r\n", hostPos);
                        cout << "[HTTP] " << data.substr(hostPos, hostEnd - hostPos) << endl;
                    }
                } else {
                    cout << "[" << proto << "] Alert: " << r.getRuleName() 
                         << " | SRC: " << inet_ntoa(ip_h->ip_src) << endl;
                }
            }
        }
    }
}

// Initialize DPI and start packet capture
void start_dpi(const string& interface, vector<Rule>& rules) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(interface.c_str(), 65535, 1, 100, errbuf);
    
    if (handle == NULL) {
        cerr << "DPI Error: " << errbuf << endl;
        return;
    }
    
    cout << "DPI Network Monitoring started on " << interface << "..." << endl;

    pcap_loop(handle, 0, packet_handler, (u_char*)&rules);
    pcap_close(handle);
}
