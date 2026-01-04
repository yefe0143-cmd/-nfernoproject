#include <iostream>
#include <string>
#include <windows.h>
#include <wininet.h>
#include <vector>
#include <sstream>
#include <sddl.h> // Required for ConvertSidToStringSid

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

// CONSTANTS (User Provided)
const std::string API_URL = "https://infhell.xyz/api.php";
const std::string APP_SECRET = ""; // YOUR APP SECRET

// Helper for HWID (Volume Serial Number)
std::string GetHWID() {
    DWORD volSerial = 0;
    if (GetVolumeInformationA("C:\\", NULL, 0, &volSerial, NULL, NULL, NULL, 0)) {
        char buf[16];
        sprintf_s(buf, "%08X", volSerial); // Generates 8-char Hex like A4B1C8D9
        return std::string(buf);
    }
    return "UNKNOWN-HWID";
}

// Simple JSON-like parser since we don't want external deps in this simple resource
std::string ParseJsonValue(const std::string& json, const std::string& key) {
    std::string keyPattern = "\"" + key + "\":";
    size_t pos = json.find(keyPattern);
    if (pos == std::string::npos) return "";

    pos += keyPattern.length();
    
    // Skip whitespace
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    if (pos >= json.length()) return "";

    // String value
    if (json[pos] == '"') {
        size_t end = json.find("\"", pos + 1);
        if (end == std::string::npos) return "";
        return json.substr(pos + 1, end - pos - 1);
    } 
    // Boolean/Number value
    else {
        size_t end = json.find_first_of(",}", pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    }
}

// HTTP Request using WinINet (Standard Windows API)
std::string MakeRequest(std::string url) {
    HINTERNET hInternet = InternetOpenA("AuthClient/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return "";

    HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return "";
    }

    std::string response;
    char buffer[4096];
    DWORD bytesRead;

    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        response.append(buffer, bytesRead);
    }

    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return response;
}

int main()
{
    SetConsoleTitleA("Infinity Auth - C++ Resource");
    system("color 4"); // Red color for 'Hell' theme :)

    std::cout << "============================================" << std::endl;
    std::cout << "        INFINITY AUTH CHECKER C++           " << std::endl;
    std::cout << "============================================" << std::endl;
    
    std::string key;
    std::cout << "\n[>] Enter License Key: ";
    std::cin >> key;

    std::string hwid = GetHWID();
    std::cout << "[i] Your HWID: " << hwid << std::endl;

    std::cout << "[*] Checking license..." << std::endl;

    // Construct URL
    // Endpoint: ?action=verify&secret=...&key=...&hwid=...
    std::stringstream ss;
    ss << API_URL << "?action=verify"
       << "&secret=" << APP_SECRET
       << "&key=" << key
       << "&hwid=" << hwid;

    std::string response = MakeRequest(ss.str());

    if (response.empty()) {
        std::cout << "\n[!] Connection Failed! Check your internet." << std::endl;
        system("pause");
        return 1;
    }

    // Parse Response
    std::string success = ParseJsonValue(response, "success");
    std::string message = ParseJsonValue(response, "message");

    if (success == "true") {
        std::cout << "\n[+] LOGIN SUCCESSFUL!" << std::endl;
        std::cout << "[+] Message: " << message << std::endl;
        
        // Extra data
        std::string days_left = ParseJsonValue(response, "days_left");
        if (!days_left.empty()) std::cout << "[+] Days Left: " << days_left << std::endl;
    } else {
        std::cout << "\n[-] LOGIN FAILED!" << std::endl;
        std::cout << "[-] Reason: " << message << std::endl;
    }

    std::cout << "\n============================================" << std::endl;
    system("pause");
    return 0;
}
