#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <json/json.h>

class PatternMatcher {
private:
    std::vector<std::pair<std::string, std::regex>> patterns;
    
public:
    PatternMatcher() {
        // SQL Injection patterns
        patterns.push_back({"SQL Injection", std::regex("you have an error in your sql syntax", std::regex_constants::icase)});
        patterns.push_back({"SQL Injection", std::regex("warning: mysql", std::regex_constants::icase)});
        patterns.push_back({"SQL Injection", std::regex("unclosed quotation mark", std::regex_constants::icase)});
        patterns.push_back({"SQL Injection", std::regex("microsoft ole db provider for odbc drivers error", std::regex_constants::icase)});
        
        // XSS patterns
        patterns.push_back({"XSS", std::regex("<script>", std::regex_constants::icase)});
        patterns.push_back({"XSS", std::regex("javascript:", std::regex_constants::icase)});
        patterns.push_back({"XSS", std::regex("onerror\\s*=", std::regex_constants::icase)});
        patterns.push_back({"XSS", std::regex("onload\\s*=", std::regex_constants::icase)});
        
        // Directory Traversal patterns
        patterns.push_back({"Directory Traversal", std::regex("root:x:0:0", std::regex_constants::icase)});
        patterns.push_back({"Directory Traversal", std::regex("# localhost", std::regex_constants::icase)});
        patterns.push_back({"Directory Traversal", std::regex("\\[boot loader\\]", std::regex_constants::icase)});
        
        // Information Disclosure patterns
        patterns.push_back({"Information Disclosure", std::regex("internal server error", std::regex_constants::icase)});
        patterns.push_back({"Information Disclosure", std::regex("stack trace", std::regex_constants::icase)});
        patterns.push_back({"Information Disclosure", std::regex("fatal error", std::regex_constants::icase)});
    }
    
    Json::Value match(const std::string& text) {
        Json::Value results(Json::arrayValue);
        
        for (const auto& pattern : patterns) {
            std::smatch matches;
            if (std::regex_search(text, matches, pattern.second)) {
                Json::Value result;
                result["type"] = pattern.first;
                result["match"] = matches[0].str();
                results.append(result);
            }
        }
        
        return results;
    }
};

int main() {
    // Read text from stdin
    std::string text;
    std::string line;
    while (std::getline(std::cin, line)) {
        text += line + "\n";
    }
    
    PatternMatcher matcher;
    Json::Value results = matcher.match(text);
    
    // Output JSON result
    Json::StreamWriterBuilder builder;
    std::cout << Json::writeString(builder, results) << std::endl;
    
    return 0;
}
