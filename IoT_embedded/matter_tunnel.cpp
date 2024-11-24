#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>

class MatterTunnel
{
private:
    static std::string bytesToHex(const unsigned char *data, size_t len)
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (size_t i = 0; i < len; i++)
        {
            ss << std::setw(2) << static_cast<int>(data[i]);
        }
        return ss.str();
    }

    static std::vector<unsigned char> hexToBytes(const std::string &hex)
    {
        std::vector<unsigned char> bytes;
        for (size_t i = 0; i < hex.length(); i += 2)
        {
            std::string byteString = hex.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

    static std::string getTypeString(uint16_t types)
    {
        std::string result;
        // 상위 14비트에서 7개의 2비트 패턴 처리 (인자)
        for (int i = 6; i >= 0; i--)
        {
            uint16_t argType = (types >> (i * 2 + 2)) & 0x03;
            if (argType == 0x00)
                break; // void는 더 이상의 인자가 없음을 의미

            if (result.length() > 0)
                result += ",";

            switch (argType)
            {
            case 0x01:
                result += "string";
                break;
            case 0x02:
                result += "number";
                break;
            case 0x03:
                result += "boolean";
                break;
            }
        }

        result += ")";

        // 하위 2비트 처리 (반환값)
        std::string returnType;
        switch (types & 0x03)
        {
        case 0x00:
            returnType = "void";
            break;
        case 0x01:
            returnType = "string";
            break;
        case 0x02:
            returnType = "number";
            break;
        case 0x03:
            returnType = "boolean";
            break;
        }

        return result + "->" + returnType;
    }

    // 데이터 리스트 직렬화를 위한 메서드
    static std::vector<unsigned char> serializeDataList(const std::vector<std::string> &dataList)
    {
        std::vector<unsigned char> serialized;

        for (const auto &data : dataList)
        {
            // 데이터 길이를 1바이트로 추가
            unsigned char length = static_cast<unsigned char>(data.length());
            serialized.push_back(length);

            // 데이터 추가
            serialized.insert(serialized.end(), data.begin(), data.end());
        }

        return serialized;
    }

    // 직렬화된 데이터를 문자열 리스트로 변환하는 새로운 메서드
    static std::vector<std::string> deserializeDataList(const std::string &serializedData)
    {
        std::vector<std::string> result;
        size_t pos = 0;

        while (pos < serializedData.length())
        {
            // 데이터 길이 읽기 (1바이트)
            unsigned char length = static_cast<unsigned char>(serializedData[pos++]);

            // 데이터 추출
            if (pos + length <= serializedData.length())
            {
                result.push_back(serializedData.substr(pos, length));
                pos += length;
            }
            else
            {
                break; // 잘못된 형식이면 중단
            }
        }

        return result;
    }

public:
    // 시크릿키 생성 (64자리 16진수 문자열 반환)
    static std::string generatePrivateKey()
    {
        unsigned char privateKey[32];
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!key)
        {
            throw std::runtime_error("Failed to create EC_KEY");
        }

        if (!EC_KEY_generate_key(key))
        {
            EC_KEY_free(key);
            throw std::runtime_error("Failed to generate private key");
        }

        const BIGNUM *priv = EC_KEY_get0_private_key(key);
        BN_bn2binpad(priv, privateKey, 32);
        EC_KEY_free(key);

        return bytesToHex(privateKey, 32);
    }

    // 공개키 파생 (16진수 문자열 반환)
    static std::string derivePublicKey(const std::string &privateKeyHex)
    {
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!key)
        {
            throw std::runtime_error("Failed to create EC_KEY");
        }

        BIGNUM *priv = BN_new();
        std::vector<unsigned char> privateKeyBytes = hexToBytes(privateKeyHex);
        BN_bin2bn(privateKeyBytes.data(), privateKeyBytes.size(), priv);

        if (!EC_KEY_set_private_key(key, priv))
        {
            BN_free(priv);
            EC_KEY_free(key);
            throw std::runtime_error("Failed to set private key");
        }

        const EC_GROUP *group = EC_KEY_get0_group(key);
        EC_POINT *pub = EC_POINT_new(group);
        if (!EC_POINT_mul(group, pub, priv, nullptr, nullptr, nullptr))
        {
            EC_POINT_free(pub);
            BN_free(priv);
            EC_KEY_free(key);
            throw std::runtime_error("Failed to compute public key");
        }

        EC_KEY_set_public_key(key, pub);

        unsigned char publicKey[65];
        size_t len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED,
                                        publicKey, 65, nullptr);

        EC_POINT_free(pub);
        BN_free(priv);
        EC_KEY_free(key);

        return bytesToHex(publicKey, len);
    }

    // 서명 생성
    static std::string sign(const std::string &message, const std::string &privateKeyHex)
    {
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        BIGNUM *priv = BN_new();
        std::vector<unsigned char> privateKeyBytes = hexToBytes(privateKeyHex);
        BN_bin2bn(privateKeyBytes.data(), privateKeyBytes.size(), priv);
        EC_KEY_set_private_key(key, priv);

        // 메시지 해시 생성
        unsigned char hash[32];
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(mdctx, message.c_str(), message.length());
        EVP_DigestFinal_ex(mdctx, hash, nullptr);
        EVP_MD_CTX_free(mdctx);

        // 서명 생성
        ECDSA_SIG *signature = ECDSA_do_sign(hash, sizeof(hash), key);
        if (!signature)
        {
            BN_free(priv);
            EC_KEY_free(key);
            throw std::runtime_error("Failed to create signature");
        }

        // R, S 값 추출
        const BIGNUM *r, *s;
        ECDSA_SIG_get0(signature, &r, &s);

        // R, S 값을 32바이트 고정 길이로 변환
        unsigned char rBytes[32] = {0};
        unsigned char sBytes[32] = {0};
        BN_bn2binpad(r, rBytes, 32);
        BN_bn2binpad(s, sBytes, 32);

        // R과 S를 연결하여 64바이트 시그니처 생성
        std::string signatureHex;
        signatureHex.reserve(128); // 64바이트 * 2
        signatureHex += bytesToHex(rBytes, 32);
        signatureHex += bytesToHex(sBytes, 32);

        ECDSA_SIG_free(signature);
        BN_free(priv);
        EC_KEY_free(key);

        return signatureHex;
    }

    // 서명 검증
    static bool verify(const std::string &signatureHex, const std::string &message,
                       const std::string &publicKeyHex)
    {
        if (signatureHex.length() != 128)
        { // 64바이트 시그니처 (R: 32바이트, S: 32바이트)
            throw std::runtime_error("Invalid signature length");
        }

        EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        const EC_GROUP *group = EC_KEY_get0_group(key);
        EC_POINT *pub = EC_POINT_new(group);

        // 공개키 설정
        std::vector<unsigned char> publicKeyBytes = hexToBytes(publicKeyHex);
        EC_POINT_oct2point(group, pub, publicKeyBytes.data(),
                           publicKeyBytes.size(), nullptr);
        EC_KEY_set_public_key(key, pub);

        // 메시지 해시 생성
        unsigned char hash[32];
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(mdctx, message.c_str(), message.length());
        EVP_DigestFinal_ex(mdctx, hash, nullptr);
        EVP_MD_CTX_free(mdctx);

        // R, S 값 추출 및 ECDSA_SIG 구조체 생성
        std::string rHex = signatureHex.substr(0, 64);
        std::string sHex = signatureHex.substr(64, 64);
        std::vector<unsigned char> rBytes = hexToBytes(rHex);
        std::vector<unsigned char> sBytes = hexToBytes(sHex);

        ECDSA_SIG *signature = ECDSA_SIG_new();
        BIGNUM *r = BN_new();
        BIGNUM *s = BN_new();
        BN_bin2bn(rBytes.data(), rBytes.size(), r);
        BN_bin2bn(sBytes.data(), sBytes.size(), s);
        ECDSA_SIG_set0(signature, r, s); // r, s 소유권이 signature로 이전됨

        // 검증
        int result = ECDSA_do_verify(hash, sizeof(hash), signature, key);

        ECDSA_SIG_free(signature); // 내부적으로 r, s도 해제됨
        EC_POINT_free(pub);
        EC_KEY_free(key);

        return result == 1;
    }

    // 공유키 생성
    static std::string getSharedKey(const std::string &secretKeyHex, const std::string &publicKeyHex)
    {
        EC_KEY *privateKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!privateKey)
        {
            throw std::runtime_error("Failed to create EC_KEY for private key");
        }

        // 개인키 설정
        BIGNUM *priv = BN_new();
        std::vector<unsigned char> secretKeyBytes = hexToBytes(secretKeyHex);
        BN_bin2bn(secretKeyBytes.data(), secretKeyBytes.size(), priv);
        if (!EC_KEY_set_private_key(privateKey, priv))
        {
            BN_free(priv);
            EC_KEY_free(privateKey);
            throw std::runtime_error("Failed to set private key");
        }

        // 공개키 포인트 생성
        const EC_GROUP *group = EC_KEY_get0_group(privateKey);
        EC_POINT *pub = EC_POINT_new(group);
        std::vector<unsigned char> publicKeyBytes = hexToBytes(publicKeyHex);

        if (!EC_POINT_oct2point(group, pub, publicKeyBytes.data(), publicKeyBytes.size(), nullptr))
        {
            EC_POINT_free(pub);
            BN_free(priv);
            EC_KEY_free(privateKey);
            throw std::runtime_error("Failed to create public key point");
        }

        // 공유 비밀 계산
        unsigned char sharedSecret[32];
        BIGNUM *sharedSecretBN = BN_new();
        EC_POINT *sharedPoint = EC_POINT_new(group);

        // 공유 포인트 계산: publicKey * privateKey
        if (!EC_POINT_mul(group, sharedPoint, nullptr, pub, priv, nullptr))
        {
            BN_free(sharedSecretBN);
            EC_POINT_free(sharedPoint);
            EC_POINT_free(pub);
            BN_free(priv);
            EC_KEY_free(privateKey);
            throw std::runtime_error("Failed to compute shared point");
        }

        // x 좌표만 추출
        if (!EC_POINT_get_affine_coordinates(group, sharedPoint, sharedSecretBN, nullptr, nullptr))
        {
            BN_free(sharedSecretBN);
            EC_POINT_free(sharedPoint);
            EC_POINT_free(pub);
            BN_free(priv);
            EC_KEY_free(privateKey);
            throw std::runtime_error("Failed to get shared secret");
        }

        // BIGNUM을 바이트 배열로 변환
        BN_bn2binpad(sharedSecretBN, sharedSecret, 32);

        // 정리
        BN_free(sharedSecretBN);
        EC_POINT_free(sharedPoint);
        EC_POINT_free(pub);
        BN_free(priv);
        EC_KEY_free(privateKey);

        return bytesToHex(sharedSecret, 32);
    }

    // 암호화
    static std::string encrypt(const std::string &key, const std::string &msg) {
        // IV 생성 (16 bytes for AES)
        unsigned char iv[16];
        if (RAND_bytes(iv, sizeof(iv)) != 1) {
            throw std::runtime_error("Failed to generate IV");
        }

        // 키 해시 생성 (SHA-256)
        unsigned char keyHash[32];
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(mdctx, key.c_str(), key.length());
        EVP_DigestFinal_ex(mdctx, keyHash, nullptr);
        EVP_MD_CTX_free(mdctx);

        // 암호문을 저장할 버퍼 (패딩을 고려하여 msg 길이보다 블록 크기만큼 더 크게)
        std::vector<unsigned char> ciphertext(msg.length() + EVP_MAX_BLOCK_LENGTH);
        int ciphertext_len;
        int final_len;

        // CBC 컨텍스트 초기화
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        // CBC 모드 초기화
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, keyHash, iv)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize CBC mode");
        }

        // 암호화 수행
        if (!EVP_EncryptUpdate(ctx, ciphertext.data(), &ciphertext_len,
                              reinterpret_cast<const unsigned char*>(msg.c_str()),
                              msg.length())) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to encrypt message");
        }

        // 암호화 종료 및 패딩 처리
        if (!EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertext_len, &final_len)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize encryption");
        }

        EVP_CIPHER_CTX_free(ctx);

        // IV(16) + ciphertext를 하나의 문자열로 결합
        std::string result;
        result.reserve(16 + ciphertext_len + final_len);
        result.append(reinterpret_cast<char*>(iv), 16);
        result.append(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len + final_len);

        return bytesToHex(reinterpret_cast<const unsigned char*>(result.c_str()), result.length());
    }

    // 복호화
    static std::string decrypt(const std::string &key, const std::string &encryptedHex) {
        // 16진수 문자열을 바이트로 변환
        std::vector<unsigned char> encrypted = hexToBytes(encryptedHex);
        if (encrypted.size() < 16) { // 최소 IV(16) 필요
            throw std::runtime_error("Invalid encrypted data length");
        }

        // 키 해시 생성
        unsigned char keyHash[32];
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(mdctx, key.c_str(), key.length());
        EVP_DigestFinal_ex(mdctx, keyHash, nullptr);
        EVP_MD_CTX_free(mdctx);

        // IV와 암호문 분리
        unsigned char *iv = encrypted.data();
        unsigned char *ciphertext = encrypted.data() + 16;
        int ciphertext_len = encrypted.size() - 16;

        // 복호화할 평문 버퍼
        std::vector<unsigned char> plaintext(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
        int plaintext_len;
        int final_len;

        // CBC 컨텍스트 초기화
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        // CBC 모드 초기화
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, keyHash, iv)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize CBC mode");
        }

        // 복호화 수행
        if (!EVP_DecryptUpdate(ctx, plaintext.data(), &plaintext_len,
                              ciphertext, ciphertext_len)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to decrypt message");
        }

        // 복호화 종료 및 패딩 제거
        if (!EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintext_len, &final_len)) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize decryption");
        }

        EVP_CIPHER_CTX_free(ctx);

        return std::string(reinterpret_cast<char*>(plaintext.data()),
                          plaintext_len + final_len);
    }
    // 디바이스 정보 추출
    static std::string extractDeviceInfo(const std::vector<unsigned char> &data)
    {
        if (data.size() < 49)
        { // 최소 크기: publicKey(33) + passcode(16)
            throw std::runtime_error("Invalid data size");
        }

        // 1. Public Key 처리
        std::vector<unsigned char> compressedKey(data.begin(), data.begin() + 33);

        // compressed public key를 uncompressed form으로 변환
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        const EC_GROUP *group = EC_KEY_get0_group(key);
        EC_POINT *point = EC_POINT_new(group);

        if (!EC_POINT_oct2point(group, point, compressedKey.data(), compressedKey.size(), nullptr))
        {
            EC_POINT_free(point);
            EC_KEY_free(key);
            throw std::runtime_error("Failed to decompress public key");
        }

        unsigned char uncompressedKey[65];
        size_t uncompressedLen = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                                    uncompressedKey, 65, nullptr);

        // 2. Passcode 처리
        std::vector<unsigned char> passcode(data.begin() + 33, data.begin() + 49);

        // 3. Functions 처리
        std::vector<std::string> functions;
        size_t pos = 49;

        while (pos + 20 <= data.size())
        {
            // Function name (18 bytes)
            std::string funcName;
            for (size_t i = 0; i < 18; i++)
            {
                if (data[pos + i] != 0)
                {
                    funcName += static_cast<char>(data[pos + i]);
                }
            }

            // Function types (2 bytes)
            uint16_t types = (data[pos + 18] << 8) | data[pos + 19];

            // Function signature 생성
            std::string funcSig = funcName + "(" + getTypeString(types);
            functions.push_back(funcSig);

            pos += 20;
        }

        // JSON 형식의 출력 생성
        std::stringstream json;
        json << "{\"publicKey\":\"" << bytesToHex(uncompressedKey, uncompressedLen)
             << "\",\"passcode\":\"" << bytesToHex(passcode.data(), passcode.size())
             << "\",\"functions\":[";

        for (size_t i = 0; i < functions.size(); i++)
        {
            if (i > 0)
                json << ",";
            json << "\"" << functions[i] << "\"";
        }
        json << "]}";

        EC_POINT_free(point);
        EC_KEY_free(key);

        return json.str();
    }

    static std::vector<unsigned char> makeTX(const std::string &funcName,
                                             const std::string &src_priv,
                                             const std::string &dest_pub,
                                             const std::vector<std::string> &data_list)
    {
        std::vector<unsigned char> result;

        // 1. 공유키 생성
        std::string sharedKey = getSharedKey(src_priv, dest_pub);

        // 2. src_pub 파생
        std::string src_pub = derivePublicKey(src_priv);

        // 압축된 공개키로 변환 (uncompressed -> compressed)
        std::vector<unsigned char> uncompressedPubBytes = hexToBytes(src_pub);
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        const EC_GROUP *group = EC_KEY_get0_group(key);
        EC_POINT *point = EC_POINT_new(group);
        EC_POINT_oct2point(group, point, uncompressedPubBytes.data(), uncompressedPubBytes.size(), nullptr);

        unsigned char compressedKey[33];
        EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, compressedKey, 33, nullptr);

        // 3. 데이터 직렬화
        std::vector<unsigned char> serializedData = serializeDataList(data_list);

        // 4. 직렬화된 데이터 암호화
        std::string encryptedData = encrypt(sharedKey,
                                            std::string(serializedData.begin(), serializedData.end()));
        std::vector<unsigned char> encryptedBytes = hexToBytes(encryptedData);

        // 5. 현재 타임스탬프 얻기
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                             now.time_since_epoch())
                             .count();

        // 6. TX 데이터 조합
        // 6.1 Function name (18 bytes)
        std::string paddedFuncName = funcName;
        paddedFuncName.resize(18, '\0');
        result.insert(result.end(), paddedFuncName.begin(), paddedFuncName.end());

        // 6.2 Compressed public key (33 bytes)
        result.insert(result.end(), compressedKey, compressedKey + 33);

        // 6.3 Timestamp (8 bytes)
        for (int i = 0; i < 8; i++)
        {
            result.push_back(static_cast<unsigned char>((timestamp >> (i * 8)) & 0xFF));
        }

        // 6.4 Encrypted data
        result.insert(result.end(), encryptedBytes.begin(), encryptedBytes.end());
        
        std::string resultHex = bytesToHex(result.data(), result.size());

        // 7. 서명 생성 및 추가
        std::string signature = sign(resultHex, src_priv);
        std::vector<unsigned char> signatureBytes = hexToBytes(signature);

        // 최종 결과: signature + TX data
        std::vector<unsigned char> finalResult;
        finalResult.insert(finalResult.end(), signatureBytes.begin(), signatureBytes.end());
        finalResult.insert(finalResult.end(), result.begin(), result.end());

        // 정리
        EC_POINT_free(point);
        EC_KEY_free(key);

        return finalResult;
    }

    static std::string extractTXData(const std::string &privateKey,
                                     const std::vector<unsigned char> &txBytes)
    {
        if (txBytes.size() < 71)
        { // 최소 크기: signature(64) + funcName(18) + compressed pubkey(33) + timestamp(8)
            throw std::runtime_error("Invalid TX data size");
        }

        // 1. 서명과 데이터 분리
        std::vector<unsigned char> signature(txBytes.begin(), txBytes.begin() + 64);
        std::vector<unsigned char> txData(txBytes.begin() + 64, txBytes.end());

        // 2. 서명 검증
        std::string signatureHex = bytesToHex(signature.data(), signature.size());
        std::string txDataHex = bytesToHex(txData.data(), txData.size());

        // compressed public key 추출 (33바이트)
        std::vector<unsigned char> compressedPubKey(txData.begin() + 18, txData.begin() + 51);

        // compressed public key를 uncompressed form으로 변환
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        const EC_GROUP *group = EC_KEY_get0_group(key);
        EC_POINT *point = EC_POINT_new(group);

        if (!EC_POINT_oct2point(group, point, compressedPubKey.data(), compressedPubKey.size(), nullptr))
        {
            EC_POINT_free(point);
            EC_KEY_free(key);
            throw std::runtime_error("Failed to decompress public key");
        }

        unsigned char uncompressedKey[65];
        size_t uncompressedLen = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                                    uncompressedKey, 65, nullptr);

        std::string srcPub = bytesToHex(uncompressedKey, uncompressedLen);

        if (!verify(signatureHex, txDataHex, srcPub))
        {
            EC_POINT_free(point);
            EC_KEY_free(key);
            throw std::runtime_error("Invalid signature");
        }

        // 3. 데이터 파싱
        // 3.1 Function name (18바이트)
        std::string funcName(txData.begin(), txData.begin() + 18);
        // null 문자 제거
        funcName = funcName.substr(0, funcName.find('\0'));

        // 3.2 Source public key는 이미 추출됨 (33바이트)

        // 3.3 Timestamp (8바이트)
        uint64_t timestamp = 0;
        for (int i = 0; i < 8; i++)
        {
            timestamp |= static_cast<uint64_t>(txData[51 + i]) << (i * 8);
        }

        // 3.4 암호화된 데이터
        std::vector<unsigned char> encryptedData(txData.begin() + 59, txData.end());
        std::string encryptedHex = bytesToHex(encryptedData.data(), encryptedData.size());

        // 4. 공유키 생성 및 복호화
        std::string sharedKey = getSharedKey(privateKey, srcPub);
        std::string decryptedData = decrypt(sharedKey, encryptedHex);

        // 5. 복호화된 데이터 역직렬화
        std::vector<std::string> dataList = deserializeDataList(decryptedData);

        // 6. JSON 형식으로 결과 생성
        std::stringstream json;
        json << "{\"funcName\":\"" << funcName << "\","
             << "\"srcPub\":\"" << srcPub << "\","
             << "\"timeStamp\":\"" << timestamp << "\","
             << "\"data\":[";

        for (size_t i = 0; i < dataList.size(); i++)
        {
            if (i > 0)
                json << ",";
            json << "\"" << dataList[i] << "\"";
        }
        json << "]}";

        EC_POINT_free(point);
        EC_KEY_free(key);

        return json.str();
    }
    
    static std::string extractTXDataWithoutSign(const std::string &privateKey, const std::string &txHex)
    {
        // 16진수 문자열을 바이트로 변환
        std::vector<unsigned char> txData = hexToBytes(txHex);
        
        if (txData.size() < 59) { // 최소 크기: funcName(18) + compressed pubkey(33) + timestamp(8)
            throw std::runtime_error("Invalid TX data size");
        }

        // 1. 데이터 파싱
        // 1.1 Function name (18바이트)
        std::string funcName(txData.begin(), txData.begin() + 18);
        // null 문자 제거
        funcName = funcName.substr(0, funcName.find('\0'));

        // 1.2 Compressed public key 추출 및 변환 (33바이트)
        std::vector<unsigned char> compressedPubKey(txData.begin() + 18, txData.begin() + 51);

        // compressed public key를 uncompressed form으로 변환
        EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        const EC_GROUP *group = EC_KEY_get0_group(key);
        EC_POINT *point = EC_POINT_new(group);

        if (!EC_POINT_oct2point(group, point, compressedPubKey.data(), compressedPubKey.size(), nullptr)) {
            EC_POINT_free(point);
            EC_KEY_free(key);
            throw std::runtime_error("Failed to decompress public key");
        }

        unsigned char uncompressedKey[65];
        size_t uncompressedLen = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                                    uncompressedKey, 65, nullptr);

        std::string srcPub = bytesToHex(uncompressedKey, uncompressedLen);

        // 1.3 Timestamp (8바이트)
        uint64_t timestamp = 0;
        for (int i = 0; i < 8; i++) {
            timestamp |= static_cast<uint64_t>(txData[51 + i]) << (i * 8);
        }

        // 1.4 암호화된 데이터
        std::vector<unsigned char> encryptedData(txData.begin() + 59, txData.end());
        std::string encryptedHex = bytesToHex(encryptedData.data(), encryptedData.size());

        // 2. 공유키 생성 및 복호화
        std::string sharedKey = getSharedKey(privateKey, srcPub);
        std::string decryptedData = decrypt(sharedKey, encryptedHex);

        // 3. 복호화된 데이터 역직렬화
        std::vector<std::string> dataList = deserializeDataList(decryptedData);

        // 4. JSON 형식으로 결과 생성
        std::stringstream json;
        json << "{\"funcName\":\"" << funcName << "\","
             << "\"srcPub\":\"" << srcPub << "\","
             << "\"timeStamp\":\"" << timestamp << "\","
             << "\"data\":[";

        for (size_t i = 0; i < dataList.size(); i++) {
            if (i > 0)
                json << ",";
            json << "\"" << dataList[i] << "\"";
        }
        json << "]}";

        EC_POINT_free(point);
        EC_KEY_free(key);

        return json.str();
    }
};
