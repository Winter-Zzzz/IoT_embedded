#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <curl/curl.h>
#include <map>
#include <sstream>
#include <iomanip>
#include "matter_tunnel.cpp"

size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::string *userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

class VirtualCarDevice {
private:
    std::string privateKey;
    std::string passcode;
    std::string publicKey;
    uint64_t currentIndex;
    std::string lastExecutedFunction;
    std::string lastReceivedTX;

    // 차량 상태
    bool engineOn;
    bool windowOpen;
    int temperature;
    std::pair<double, double> coordinates;

    std::string bytesToHex(const unsigned char* data, size_t len) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for(size_t i = 0; i < len; i++) {
            ss << std::setw(2) << static_cast<int>(data[i]);
        }
        return ss.str();
    }

    std::string httpGet(const std::string& url) {
        CURL* curl = curl_easy_init();
        std::string response;

        if(curl) {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            CURLcode res = curl_easy_perform(curl);
            if(res != CURLE_OK) {
                throw std::runtime_error("Failed to perform HTTP request");
            }

            curl_easy_cleanup(curl);
        }

        return response;
    }

    std::string httpPost(const std::string& url, const std::string& data) {
        CURL* curl = curl_easy_init();
        std::string response;

        if(curl) {
            struct curl_slist* headers = NULL;
            headers = curl_slist_append(headers, "Content-Type: application/json");

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            CURLcode res = curl_easy_perform(curl);

            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);

            if(res != CURLE_OK) {
                throw std::runtime_error("Failed to perform HTTP request");
            }
        }

        return response;
    }

    void drawCar() {
        std::stringstream display;
        display << "\033[H\033[2J";  // Clear screen

        // Status information
        display << "Smart Car Status:\n";
        display << "Public Key: " << publicKey.substr(0, 20) << "...\n";
        display << "Temperature: " << temperature << "°C\n";
        display << "Window: " << (windowOpen ? "OPEN" : "CLOSED") << "\n";
        display << "Coordinates: (" << coordinates.first << ", " << coordinates.second << ")\n\n";

        // Speed effect (only when engine is on)
        if (engineOn) {
            display << "부릉부릉~~~~~      \n";
        }else{
            display << "                 \n";
        }
        
        display << "          ___________\n";
        if (windowOpen) {
            display << "         //   |||   \\\\ \n";
            display << "      __//____|||____\\\\____   \n";
        } else {
            display << "         //===|||===\\\\ \n";
            display << "      __//====|||====\\\\____   \n";
        }
        
        // Center part with temperature
        display << "     | _|    "<< std::setw(2) << temperature << "°C" <<"    --_  ||\n";
        
        // Bottom part
        display << "     |/ \\______|______/ \\_|| \n";
        display << "      \\_/             \\_/     \n";

        // Last executed function
        display << "\nLastReceivedTX: " << lastReceivedTX << "\n";
        display << "\nLast executed: " << lastExecutedFunction << "\n";

        std::cout << display.str();
        std::cout.flush();
    }

    bool handleSetup(const std::string& srcPubKey, const std::string& receivedPasscode) {
        if(receivedPasscode == passcode) {
            try {
                std::string signature = MatterTunnel::sign(srcPubKey, privateKey);
                std::string jsonData = "{\"publicKey1\":\"" + publicKey +
                                     "\",\"publicKey2\":\"" + srcPubKey +
                                     "\",\"sign\":\"" + signature + "\"}";

                std::string response = httpPost("http://localhost:8080/register", jsonData);
                lastExecutedFunction = "Setup successful - Registered: " + srcPubKey.substr(0, 20) + "...";
                return true;
            }
            catch(const std::exception& e) {
                lastExecutedFunction = "Setup failed: " + std::string(e.what());
                return false;
            }
        }
        lastExecutedFunction = "Setup failed: Invalid passcode";
        return false;
    }

    void sendFeedback(const std::string& destPubKey, const std::string& result) {
        try {
            std::vector<std::string> feedbackData = {result};
            std::vector<unsigned char> tx = MatterTunnel::makeTX(
                "feedback",
                privateKey,
                destPubKey,
                feedbackData);

            std::string txHex = bytesToHex(tx.data(), tx.size());
            std::string jsonData = "{\"publicKey\":\"" + destPubKey +
                                 "\",\"tx\":\"" + txHex + "\"}";

            std::string response = httpPost("http://localhost:8080/queuing", jsonData);
            lastExecutedFunction += " (Feedback sent)";
        }
        catch(const std::exception& e) {
            lastExecutedFunction += " (Failed to send feedback: " + std::string(e.what()) + ")";
        }
    }

public:
    VirtualCarDevice() {
        // Hardcoded values
        privateKey = "180a4b2bef2465edbb2cd54fcb7e644a0fcb9508009a18bf35eb1de7a604defb";
        passcode = "98e06e5484c272362ed03d138c420e2c";
        currentIndex = 1;
        lastExecutedFunction = "No tx executed yet";
        lastReceivedTX = "tx does not exist yet";

        // Initial state
        engineOn = false;
        windowOpen = false;
        temperature = 22;  // Default temperature
        coordinates = {37.5665, 126.9780};  // Default coordinates (Seoul)

        // Generate public key
        publicKey = MatterTunnel::derivePublicKey(privateKey);
    }

    std::string executeFunction(const std::string& name, const std::string& srcPubKey, const std::vector<std::string>& args) {
        std::string result;

        if(name == "setup" && !args.empty()) {
            bool success = handleSetup(srcPubKey, args[0]);
            result = success ? "Setup successful" : "Setup failed";
        }
        else if(name == "engine" && !args.empty()) {
            engineOn = (args[0] == "true");
            result = engineOn ? "Engine started" : "Engine stopped";
        }
        else if(name == "window" && !args.empty()) {
            windowOpen = (args[0] == "true");
            result = windowOpen ? "Window opened" : "Window closed";
        }
        else if(name == "setTemp" && !args.empty()) {
            temperature = std::stoi(args[0]);
            result = "Temperature set to " + std::to_string(temperature);
        }
        else if(name == "getCoordinate") {
            std::stringstream ss;
            ss << std::fixed << std::setprecision(4)
               << "Current location: ("
               << coordinates.first << ", "
               << coordinates.second << ")";
            result = ss.str();
        }
        else if(name == "feedback") {
            result = !args.empty() ? "Received feedback: " + args[0] : "Received empty feedback";
        }
        else {
            result = "Unknown function: " + name;
        }

        lastExecutedFunction = result;
        if(name != "feedback" && name != "setup") {
            sendFeedback(srcPubKey, result);
        }
        return result;
    }

    void run() {
        // Initialize terminal
        std::cout << "\033[2J";    // Clear screen
        std::cout << "\033[?25l";  // Hide cursor

        // Show initial state
        drawCar();

        while(true) {
            try {
                std::string url = "http://localhost:8080/getTransaction?publicKey=" +
                                publicKey + "&index=" + std::to_string(currentIndex);

                std::string response = httpGet(url);

                if(!response.empty()) {
                    std::string txData = MatterTunnel::extractTXDataWithoutSign(privateKey, response);
                    lastReceivedTX = response;
                    
                    // Parse JSON
                    size_t funcStart = txData.find("\"funcName\":\"") + 12;
                    size_t funcEnd = txData.find("\"", funcStart);
                    std::string funcName = txData.substr(funcStart, funcEnd - funcStart);

                    size_t srcPubStart = txData.find("\"srcPub\":\"") + 10;
                    size_t srcPubEnd = txData.find("\"", srcPubStart);
                    std::string srcPub = txData.substr(srcPubStart, srcPubEnd - srcPubStart);

                    std::vector<std::string> args;
                    size_t dataStart = txData.find("\"data\":[");
                    if(dataStart != std::string::npos) {
                        size_t dataEnd = txData.find("]", dataStart);
                        std::string dataStr = txData.substr(dataStart + 8, dataEnd - (dataStart + 8));

                        size_t pos = 0;
                        while((pos = dataStr.find("\",\"")) != std::string::npos) {
                            std::string arg = dataStr.substr(1, pos - 1);
                            args.push_back(arg);
                            dataStr.erase(0, pos + 3);
                        }
                        if(!dataStr.empty()) {
                            args.push_back(dataStr.substr(1, dataStr.length() - 2));
                        }
                    }

                    executeFunction(funcName, srcPub, args);
                    currentIndex++;
                }
            }
            catch(const std::exception& e) {
                // Error handling
            }

            drawCar();
            coordinates.first += 0.001;
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }

    ~VirtualCarDevice() {
        std::cout << "\033[?25h";  // Show cursor
    }
};

int main() {
    curl_global_init(CURL_GLOBAL_ALL);

    VirtualCarDevice device;
    device.run();

    curl_global_cleanup();
    return 0;
}
