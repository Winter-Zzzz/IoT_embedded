#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <curl/curl.h>
#include <map>
#include "matter_tunnel.cpp"

// HTTP 응답을 저장하기 위한 콜백 함수
size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::string *userp)
{
    userp->append((char *)contents, size * nmemb);
    return size * nmemb;
}

class VirtualFridgeDevice
{
private:
    std::string privateKey;
    std::string passcode;
    std::string publicKey;
    uint64_t currentIndex;
    std::string lastExecutedFunction;

    // 냉장고 상태
    int temperatureMode; // 0: 에너지 절약, 1: 기본, 2: 급속
    std::string currentColor;
    std::string animalMode;
    bool waterEnabled;

    // 색상 매핑
    std::map<std::string, std::string> colorCodes = {
        {"white", "\033[97m"},
        {"red", "\033[91m"},
        {"green", "\033[92m"},
        {"yellow", "\033[93m"},
        {"blue", "\033[94m"},
        {"magenta", "\033[95m"},
        {"cyan", "\033[96m"},
        {"black", "\033[30m"}};

    // 온도 모드 매핑
    std::map<int, std::string> tempModes = {
        {0, "Energy Saving"},
        {1, "Normal"},
        {2, "Rapid Cooling"}};

    // 동물 아스키 아트
    const std::string CAT_ART = R"(  /\___/\ 
 (  o o  )
 (  =^=  ))";

    const std::string DOG_ART = R"(  /^___^\ 
 (  . .  )
  \  ^  / )";

    std::string bytesToHex(const unsigned char *data, size_t len)
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; i++)
        {
            ss << std::setw(2) << static_cast<int>(data[i]);
        }
        return ss.str();
    }

    // HTTP GET 요청 함수
    std::string httpGet(const std::string &url)
    {
        CURL *curl = curl_easy_init();
        std::string response;

        if (curl)
        {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK)
            {
                throw std::runtime_error("Failed to perform HTTP request");
            }

            curl_easy_cleanup(curl);
        }

        return response;
    }

    // HTTP POST 요청 함수
    std::string httpPost(const std::string &url, const std::string &data)
    {
        CURL *curl = curl_easy_init();
        std::string response;

        if (curl)
        {
            struct curl_slist *headers = NULL;
            headers = curl_slist_append(headers, "Content-Type: application/json");

            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

            CURLcode res = curl_easy_perform(curl);

            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);

            if (res != CURLE_OK)
            {
                throw std::runtime_error("Failed to perform HTTP request");
            }
        }

        return response;
    }

    void drawFridge()
    {
        std::stringstream display;
        display << "\033[H"; // 커서를 화면 맨 위로 이동

        std::string fridgeColor = colorCodes[currentColor];
        std::string resetColor = "\033[0m";

        // 디바이스 정보
        display << "Smart Fridge Status:\n";
        display << "Public Key: " << publicKey.substr(0, 20) << "...\n";
        display << "Temperature Mode: " << tempModes[temperatureMode] << "\n";
        display << "Color: " << currentColor << "\n\n";

        // 냉장고 상단부
        display << "    ╔════════════════════╗    \n";
        display << fridgeColor;
        display << "    ║   Smart  Fridge    ║    \n";

        // 온도 표시
        std::string tempIndicator;
        switch (temperatureMode)
        {
        case 0:
            tempIndicator = "♪ ECO ";
            break;
        case 1:
            tempIndicator = "● NORM";
            break;
        case 2:
            tempIndicator = "❄ COOL";
            break;
        }
        display << "    ║  [" << tempIndicator << "]          ║    \n";

        // 동물 디스플레이 영역
        if (animalMode == "cat")
        {
            std::stringstream ss(CAT_ART);
            std::string line;
            while (std::getline(ss, line))
            {
                display << "    ║  " << line << "        ║    \n";
            }
        }
        else if (animalMode == "dog")
        {
            std::stringstream ss(DOG_ART);
            std::string line;
            while (std::getline(ss, line))
            {
                display << "    ║  " << line << "        ║    \n";
            }
        }
        else
        {
            display << "    ║                    ║    \n";
            display << "    ║                    ║    \n";
            display << "    ║                    ║    \n";
        }

        // 물 디스펜서
        display << "    ║                    ║    \n";
        if (waterEnabled)
        {
            display << "    ║              [═╗]  ║    \n";
            display << "    ║                ║   ║    \n";
            display << "    ║                ○   ║    \n";
            display << "    ║                │   ║    \n";
            display << "    ║               \\│/  ║    \n";
        }
        else
        {
            display << "    ║              [═╗]  ║    \n";
            display << "    ║                ║   ║    \n";
            display << "    ║                ○   ║    \n";
            display << "    ║                    ║    \n";
            display << "    ║                    ║    \n";
        }

        // 냉장고 하단부
        display << "    ╠════════════════════╣    \n";
        display << "    ║                    ║    \n";
        display << "    ║     [ ==== ]       ║    \n";
        display << "    ║                    ║    \n";
        display << "    ╚════════════════════╝    \n";
        display << resetColor;

        // 상태 정보
        display << "\nLast executed: " << lastExecutedFunction << "\n";

        // 화면 나머지 부분 지우기
        display << "\033[J";

        std::cout << display.str();
        std::cout.flush();
    }

    // Setup 함수 처리
    bool handleSetup(const std::string &srcPubKey, const std::string &receivedPasscode)
    {
        if (receivedPasscode == passcode)
        {
            try
            {
                std::string signature = MatterTunnel::sign(srcPubKey, privateKey);
                std::string jsonData = "{\"publicKey1\":\"" + publicKey +
                                       "\",\"publicKey2\":\"" + srcPubKey +
                                       "\",\"sign\":\"" + signature + "\"}";

                std::string response = httpPost("http://localhost:8080/register", jsonData);
                lastExecutedFunction = "Setup successful - Registered: " + srcPubKey.substr(0, 20) + "...";
                return true;
            }
            catch (const std::exception &e)
            {
                lastExecutedFunction = "Setup failed: " + std::string(e.what());
                return false;
            }
        }
        lastExecutedFunction = "Setup failed: Invalid passcode";
        return false;
    }

    void sendFeedback(const std::string &destPubKey, const std::string &result)
    {
        try
        {
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
        catch (const std::exception &e)
        {
            lastExecutedFunction += " (Failed to send feedback: " + std::string(e.what()) + ")";
        }
    }

public:
    VirtualFridgeDevice()
    {
        // 하드코딩된 값들
        privateKey = "f4747d206ad6dec5816ed235c3eb69b0088f10246619f27bbcddb5c1e2afa4b8";
        passcode = "3f20ded60a70ad3d918d6c293bfaf863";
        currentIndex = 1;
        lastExecutedFunction = "No tx executed yet";

        // 초기 상태
        temperatureMode = 1; // 기본 모드
        currentColor = "black";
        animalMode = "none";
        waterEnabled = false;

        // 공개키 생성
        publicKey = MatterTunnel::derivePublicKey(privateKey);
    }

    std::string executeFunction(const std::string &name, const std::string &srcPubKey, const std::vector<std::string> &args)
    {
        std::string result;

        if (name == "setup" && !args.empty())
        {
            bool success = handleSetup(srcPubKey, args[0]);
            result = success ? "Setup successful" : "Setup failed";
        }
        else if (name == "setTemperatureMode" && !args.empty())
        {
            int mode = std::stoi(args[0]);
            if (mode >= 0 && mode <= 2)
            {
                temperatureMode = mode;
                result = "Temperature mode set to: " + tempModes[mode];
            }
            else
            {
                result = "Invalid temperature mode";
            }
        }
        else if (name == "changeColor" && !args.empty())
        {
            if (colorCodes.find(args[0]) != colorCodes.end())
            {
                currentColor = args[0];
                result = "Color changed to " + args[0];
            }
            else
            {
                result = "Invalid color";
            }
        }
        else if (name == "setAnimal" && !args.empty())
        {
            if (args[0] == "cat" || args[0] == "dog" || args[0] == "none")
            {
                animalMode = args[0];
                result = "Animal display set to: " + args[0];
            }
            else
            {
                result = "Invalid animal type";
            }
        }
        else if (name == "water" && !args.empty())
        {
            waterEnabled = (args[0] == "true");
            result = waterEnabled ? "Water dispenser activated" : "Water dispenser deactivated";
        }
        else if (name == "feedback")
        {
            if (!args.empty())
            {
                result = "Received feedback: " + args[0];
            }
            else
            {
                result = "Received empty feedback";
            }
        }
        else
        {
            result = "Unknown function: " + name;
        }

        lastExecutedFunction = result;
        if (name != "feedback" && name != "setup")
        {
            sendFeedback(srcPubKey, result);
        }
        return result;
    }

    void run()
    {
        // 터미널 초기화
        std::cout << "\033[2J";   // 화면 지우기
        std::cout << "\033[?25l"; // 커서 숨기기

        // 초기 상태 표시
        drawFridge();

        while (true)
        {
            try
            {
                // 트랜잭션 폴링
                std::string url = "http://localhost:8080/getTransaction?publicKey=" +
                                  publicKey + "&index=" + std::to_string(currentIndex);

                std::string response = httpGet(url);

                if (!response.empty())
                {
                    std::string txData = MatterTunnel::extractTXDataWithoutSign(privateKey, response);

                    // JSON 파싱
                    size_t funcStart = txData.find("\"funcName\":\"") + 12;
                    size_t funcEnd = txData.find("\"", funcStart);
                    std::string funcName = txData.substr(funcStart, funcEnd - funcStart);

                    size_t srcPubStart = txData.find("\"srcPub\":\"") + 10;
                    size_t srcPubEnd = txData.find("\"", srcPubStart);
                    std::string srcPub = txData.substr(srcPubStart, srcPubEnd - srcPubStart);

                    std::vector<std::string> args;
                    size_t dataStart = txData.find("\"data\":[");
                    if (dataStart != std::string::npos)
                    {
                        size_t dataEnd = txData.find("]", dataStart);
                        std::string dataStr = txData.substr(dataStart + 8, dataEnd - (dataStart + 8));

                        size_t pos = 0;
                        while ((pos = dataStr.find("\",\"")) != std::string::npos)
                        {
                            std::string arg = dataStr.substr(1, pos - 1);
                            args.push_back(arg);
                            dataStr.erase(0, pos + 3);
                        }
                        if (!dataStr.empty())
                        {
                            args.push_back(dataStr.substr(1, dataStr.length() - 2));
                        }
                    }

                    // 함수 실행
                    executeFunction(funcName, srcPub, args);
                    currentIndex++;
                }
            }
            catch (const std::exception &e)
            {
                // 에러 처리
            }

            // 화면 갱신
            drawFridge();

            // 폴링 간격
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }

    ~VirtualFridgeDevice()
    {
        // 프로그램 종료 시 커서 다시 보이게 하기
        std::cout << "\033[?25h";
    }
};

int main()
{
    curl_global_init(CURL_GLOBAL_ALL);

    VirtualFridgeDevice device;
    device.run();

    curl_global_cleanup();
    return 0;
}
