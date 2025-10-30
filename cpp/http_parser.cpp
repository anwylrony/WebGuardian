#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cctype>
#include <json/json.h>

class HTMLParser {
private:
    std::string html;
    
    std::string extractTagContent(const std::string& tag) {
        std::string openTag = "<" + tag;
        std::string closeTag = "</" + tag + ">";
        
        size_t startPos = html.find(openTag);
        if (startPos == std::string::npos) return "";
        
        startPos = html.find(">", startPos) + 1;
        size_t endPos = html.find(closeTag, startPos);
        
        if (endPos == std::string::npos) return "";
        
        return html.substr(startPos, endPos - startPos);
    }
    
    int countTagOccurrences(const std::string& tag) {
        std::string openTag = "<" + tag;
        size_t pos = 0;
        int count = 0;
        
        while ((pos = html.find(openTag, pos)) != std::string::npos) {
            count++;
            pos += openTag.length();
        }
        
        return count;
    }
    
public:
    HTMLParser(const std::string& htmlContent) : html(htmlContent) {}
    
    Json::Value parse() {
        Json::Value result;
        
        // Extract title
        std::string title = extractTagContent("title");
        result["title"] = title;
        
        // Count various elements
        result["forms"] = countTagOccurrences("form");
        result["links"] = countTagOccurrences("a");
        result["scripts"] = countTagOccurrences("script");
        result["inputs"] = countTagOccurrences("input");
        
        // Extract forms
        Json::Value forms(Json::arrayValue);
        size_t pos = 0;
        std::string formTag = "<form";
        
        while ((pos = html.find(formTag, pos)) != std::string::npos) {
            size_t endPos = html.find("</form>", pos);
            if (endPos == std::string::npos) break;
            
            std::string formContent = html.substr(pos, endPos - pos + 7);
            Json::Value form;
            
            // Extract action
            size_t actionPos = formContent.find("action=");
            if (actionPos != std::string::npos) {
                size_t startQuote = formContent.find("\"", actionPos) + 1;
                size_t endQuote = formContent.find("\"", startQuote);
                if (endQuote != std::string::npos) {
                    form["action"] = formContent.substr(startQuote, endQuote - startQuote);
                }
            }
            
            // Extract method
            size_t methodPos = formContent.find("method=");
            if (methodPos != std::string::npos) {
                size_t startQuote = formContent.find("\"", methodPos) + 1;
                size_t endQuote = formContent.find("\"", startQuote);
                if (endQuote != std::string::npos) {
                    form["method"] = formContent.substr(startQuote, endQuote - startQuote);
                }
            }
            
            // Extract inputs
            Json::Value inputs(Json::arrayValue);
            size_t inputPos = 0;
            std::string inputTag = "<input";
            
            while ((inputPos = formContent.find(inputTag, inputPos)) != std::string::npos) {
                Json::Value input;
                
                // Extract type
                size_t typePos = formContent.find("type=", inputPos);
                if (typePos != std::string::npos && typePos < formContent.find(">", inputPos)) {
                    size_t startQuote = formContent.find("\"", typePos) + 1;
                    size_t endQuote = formContent.find("\"", startQuote);
                    if (endQuote != std::string::npos) {
                        input["type"] = formContent.substr(startQuote, endQuote - startQuote);
                    }
                }
                
                // Extract name
                size_t namePos = formContent.find("name=", inputPos);
                if (namePos != std::string::npos && namePos < formContent.find(">", inputPos)) {
                    size_t startQuote = formContent.find("\"", namePos) + 1;
                    size_t endQuote = formContent.find("\"", startQuote);
                    if (endQuote != std::string::npos) {
                        input["name"] = formContent.substr(startQuote, endQuote - startQuote);
                    }
                }
                
                inputs.append(input);
                inputPos += inputTag.length();
            }
            
            form["inputs"] = inputs;
            forms.append(form);
            pos = endPos + 7;
        }
        
        result["forms_data"] = forms;
        
        return result;
    }
};

int main() {
    // Read HTML from stdin
    std::string html;
    std::string line;
    while (std::getline(std::cin, line)) {
        html += line + "\n";
    }
    
    HTMLParser parser(html);
    Json::Value result = parser.parse();
    
    // Output JSON result
    Json::StreamWriterBuilder builder;
    std::cout << Json::writeString(builder, result) << std::endl;
    
    return 0;
}
