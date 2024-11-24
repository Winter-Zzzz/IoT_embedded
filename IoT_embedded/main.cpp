#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <curl/curl.h>
#include "matter_tunnel.cpp"

// HTTP 응답을 저장하기 위한 콜백 함수
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

class VirtualLightDevice {
private:
    std::string privateKey;
    std::string passcode;
    std::string publicKey;
    uint64_t currentIndex;
    std::string lastExecutedFunction;
    bool isOn;
    std::string currentColor;
    
    std::string bytesToHex(const unsigned char* data, size_t len) {
            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (size_t i = 0; i < len; i++) {
                ss << std::setw(2) << static_cast<int>(data[i]);
            }
            return ss.str();
        }
    
    // HTTP GET 요청 함수
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

    // HTTP POST 요청 함수
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
    
    // 전구 ASCII 아트 출력 (화면 전체를 지우지 않고 커서를 움직여 그리기)
    void drawLight() {
            std::stringstream display;
            
            // 커서를 화면 맨 위로 이동
            display << "\033[H";
            
            std::string color = isOn ? currentColor : "off";
            std::string bulbColor = isOn ? (currentColor == "red" ? "\033[91m" : "\033[97m") : "\033[90m";
            std::string resetColor = "\033[0m";
            
            // Device info
            display << "Device Public Key: " << publicKey.substr(0, 20) << "...\n";
            display << "Current Index: " << currentIndex << "\n\n";
            
            // Light ASCII art
            display << "      ▄▄▄▄▄▄▄      \n";
            display << "    ▄████████▄    \n";
            display << bulbColor;
            display << "   ████████████   \n";
            display << "   ████████████   \n";
            display << "   ████████████   \n";
            display << "    ██████████    \n";
            display << resetColor;
            display << "      ║║║║║║      \n";
            display << "      ║║║║║║      \n";
            display << "    ▀▀▀▀▀▀▀▀▀▀    \n\n";
            
            // Status info
            display << "Status: " << (isOn ? "ON " : "OFF") << "\n";
            display << "Color: " << color << "\n";
            display << "Last executed: " << lastExecutedFunction << "\n\n";
            
            // Clear the rest of the screen
            display << "\033[J";
            
            // 모든 내용을 한 번에 출력
            std::cout << display.str();
            std::cout.flush();
        }

    // Setup 함수 처리
    bool handleSetup(const std::string& srcPubKey, const std::string& receivedPasscode) {
        if (receivedPasscode == passcode) {
            try {
                // 상대방의 publicKey에 대한 서명 생성
                std::string signature = MatterTunnel::sign(srcPubKey, privateKey);
                
                // Register API 호출을 위한 JSON 생성
                std::string jsonData = "{\"publicKey1\":\"" + publicKey +
                                     "\",\"publicKey2\":\"" + srcPubKey +
                                     "\",\"sign\":\"" + signature + "\"}";
                
                // Register API 호출
                std::string response = httpPost("http://localhost:8080/register", jsonData);
                
                lastExecutedFunction = "Setup successful - Registered: " + srcPubKey.substr(0, 20) + "...";
                return true;
            } catch (const std::exception& e) {
                lastExecutedFunction = "Setup failed: " + std::string(e.what());
                return false;
            }
        }
        lastExecutedFunction = "Setup failed: Invalid passcode";
        return false;
    }
    
    void sendFeedback(const std::string& destPubKey, const std::string& result) {
            try {
                // 피드백용 트랜잭션 생성
                std::vector<std::string> feedbackData = {result};
                std::vector<unsigned char> tx = MatterTunnel::makeTX(
                    "feedback",
                    privateKey,
                    destPubKey,
                    feedbackData
                );
                
                // 16진수 문자열로 변환
                std::string txHex = bytesToHex(tx.data(), tx.size());
                
                // Queuing API 호출을 위한 JSON 생성
                std::string jsonData = "{\"publicKey\":\"" + destPubKey +
                                     "\",\"tx\":\"" + txHex + "\"}";
                
                // Queuing API 호출
                std::string response = httpPost("http://localhost:8080/queuing", jsonData);
                
                lastExecutedFunction += " (Feedback sent)";
            } catch (const std::exception& e) {
                lastExecutedFunction += " (Failed to send feedback: " + std::string(e.what()) + ")";
            }
        }


public:
    VirtualLightDevice() {
        // 하드코딩된 값들
        privateKey = "1165ff4036a18bb4c1383cc344d90dccfb175211484ea6b05c7a1073de11c5b1";
        passcode = "7ffab5ac243a87975e4042b2cce5636f";
        currentIndex = 1;
        isOn = false;
        currentColor = "white";
        lastExecutedFunction = "No tx executed yet";
        
        // 공개키 생성
        publicKey = MatterTunnel::derivePublicKey(privateKey);
    }
    
    std::string executeFunction(const std::string& name, const std::string& srcPubKey, const std::vector<std::string>& args) {
            std::string result;

            if (name == "setup" && !args.empty()) {
                bool success = handleSetup(srcPubKey, args[0]);
                result = success ? "Setup successful" : "Setup failed";
                lastExecutedFunction = result;
                return result;
            }
            else if (name == "on") {
                isOn = true;
                result = "Light turned on";
                lastExecutedFunction = result;
                sendFeedback(srcPubKey, result);
                return result;
            }
            else if (name == "off") {
                isOn = false;
                result = "Light turned off";
                lastExecutedFunction = result;
                sendFeedback(srcPubKey, result);
                return result;
            }
            else if (name == "colorChange" && !args.empty()) {
                if (args[0] == "red" || args[0] == "white") {
                    currentColor = args[0];
                    result = "Color changed to " + args[0];
                    lastExecutedFunction = result;
                    sendFeedback(srcPubKey, result);
                    return result;
                }
                result = "Invalid color";
                lastExecutedFunction = result;
                sendFeedback(srcPubKey, result);
                return result;
            }
            else if (name == "feedback") {
                // feedback 함수는 피드백을 받는 용도이므로 별도의 피드백을 보내지 않음
                if (!args.empty()) {
                    result = "Received feedback: " + args[0];
                    lastExecutedFunction = result;
                } else {
                    result = "Received empty feedback";
                    lastExecutedFunction = result;
                }
                return result;
            }
            
            result = "Unknown function: " + name;
            lastExecutedFunction = result;
            return result;
        }
    
    void run() {
        // 터미널 초기화
        std::cout << "\033[2J";  // 화면 지우기
        std::cout << "\033[?25l"; // 커서 숨기기
        
        // 초기 상태 표시
        drawLight();
        
        while (true) {
            try {
                // 트랜잭션 폴링
                std::string url = "http://localhost:8080/getTransaction?publicKey=" +
                                publicKey + "&index=" + std::to_string(currentIndex);
                
                std::cout << url << std::endl;
                
                std::string response = httpGet(url);
                
                std::cout << response << std::endl;
                
                if (!response.empty()) {
                    // 트랜잭션 디코딩 및 실행
                    std::string txData = MatterTunnel::extractTXDataWithoutSign(privateKey, response);
                    
                    std::cout << "txData" << std::endl;
                    std::cout << txData << std::endl;
                    
                    // JSON 파싱 (간단한 구현을 위해 문자열 처리로 대체)
                    size_t funcStart = txData.find("\"funcName\":\"") + 12;
                    size_t funcEnd = txData.find("\"", funcStart);
                    std::string funcName = txData.substr(funcStart, funcEnd - funcStart);
                    
                    // srcPub 파싱
                    size_t srcPubStart = txData.find("\"srcPub\":\"") + 10;
                    size_t srcPubEnd = txData.find("\"", srcPubStart);
                    std::string srcPub = txData.substr(srcPubStart, srcPubEnd - srcPubStart);
                    
                    // data 배열 파싱
                    std::vector<std::string> args;
                    size_t dataStart = txData.find("\"data\":[");
                    if (dataStart != std::string::npos) {
                        size_t dataEnd = txData.find("]", dataStart);
                        std::string dataStr = txData.substr(dataStart + 8, dataEnd - (dataStart + 8));
                        
                        // 쉼표로 구분된 인자들 파싱
                        size_t pos = 0;
                        while ((pos = dataStr.find("\",\"")) != std::string::npos) {
                            std::string arg = dataStr.substr(1, pos - 1);
                            args.push_back(arg);
                            dataStr.erase(0, pos + 3);
                        }
                        if (!dataStr.empty()) {
                            args.push_back(dataStr.substr(1, dataStr.length() - 2));
                        }
                    }
                    
                    // 함수 실행
                    executeFunction(funcName, srcPub, args);
                    currentIndex++;
                }
            } catch (const std::exception& e) {
            }
            
            // 화면 갱신
            drawLight();
            
            // 폴링 간격
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    
    ~VirtualLightDevice() {
        // 프로그램 종료 시 커서 다시 보이게 하기
        std::cout << "\033[?25h";
    }
};

int main() {
    curl_global_init(CURL_GLOBAL_ALL);
    
    VirtualLightDevice device;
    device.run();
    
    curl_global_cleanup();
    return 0;
}
