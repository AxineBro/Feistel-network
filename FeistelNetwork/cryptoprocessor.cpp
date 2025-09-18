#include "cryptoprocessor.h"
#include <QFile>
#include <stdexcept>
#include <random>
#include <QDebug>

CryptoProcessor::CryptoProcessor() {}

uint32_t CryptoProcessor::rotl32(uint32_t x, int shift) {
    return (x << shift) | (x >> (32 - shift));
}

uint32_t CryptoProcessor::rotr32(uint32_t x, int shift) {
    return (x >> shift) | (x << (32 - shift));
}

uint64_t CryptoProcessor::rotr64(uint64_t x, int shift) {
    shift %= 64;
    return (x >> shift) | (x << (64 - shift));
}

uint32_t CryptoProcessor::F(uint32_t val, uint32_t key) {
    return rotl32(val, 9) ^ ~rotr32(val, 11) ^ (val * key);
}

void CryptoProcessor::encrypt(uint32_t& L, uint32_t& R, uint64_t K) {
    for (int i = 0; i < NUM_ROUNDS; ++i) {
        uint64_t rotated = rotr64(K, 3 * i);
        uint32_t Ki = static_cast<uint32_t>(rotated & 0xFFFFFFFFULL);
        uint32_t temp = R;
        R = L ^ F(R, Ki);
        L = temp;
    }
}

void CryptoProcessor::decrypt(uint32_t& L, uint32_t& R, uint64_t K) {
    for (int i = NUM_ROUNDS - 1; i >= 0; --i) {
        uint64_t rotated = rotr64(K, 3 * i);
        uint32_t Ki = static_cast<uint32_t>(rotated & 0xFFFFFFFFULL);
        uint32_t temp = L;
        L = R ^ F(L, Ki);
        R = temp;
    }
}

void CryptoProcessor::uint64_to_bytes(uint64_t val, unsigned char* bytes) {
    for (int i = 7; i >= 0; --i) {
        bytes[i] = val & 0xFF;
        val >>= 8;
    }
}

uint64_t CryptoProcessor::bytes_to_uint64(const unsigned char* bytes) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | bytes[i];
    }
    return val;
}

std::vector<unsigned char> CryptoProcessor::add_padding(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> padded = data;
    size_t padding_needed = BLOCK_SIZE - (padded.size() % BLOCK_SIZE);
    if (padding_needed == 0)
        padding_needed = BLOCK_SIZE;

    unsigned char pad_byte = static_cast<unsigned char>(padding_needed);
    padded.insert(padded.end(), padding_needed, pad_byte);
    return padded;
}

std::vector<unsigned char> CryptoProcessor::remove_padding(const std::vector<unsigned char>& padded) {
    if (padded.empty() || padded.size() % BLOCK_SIZE != 0) {
        throw std::runtime_error("Invalid padded data");
    }
    unsigned char pad_byte = padded.back();
    size_t padding_len = static_cast<size_t>(pad_byte);
    if (padding_len == 0 || padding_len > BLOCK_SIZE || padding_len > padded.size()) {
        throw std::runtime_error("Invalid padding");
    }
    for (size_t i = padded.size() - padding_len; i < padded.size(); ++i) {
        if (padded[i] != pad_byte) {
            throw std::runtime_error("Invalid padding");
        }
    }
    return std::vector<unsigned char>(padded.begin(), padded.end() - padding_len);
}

void CryptoProcessor::process_encrypt_file(const QString& inputFile, const QString& outputFile, uint64_t K) {
    QFile inFile(inputFile);
    if (!inFile.open(QIODevice::ReadOnly)) {
        throw std::runtime_error("Cannot open input file");
    }

    QByteArray fileData = inFile.readAll();
    inFile.close();

    std::vector<unsigned char> data(fileData.begin(), fileData.end());

    std::vector<unsigned char> padded = add_padding(data);
    std::vector<unsigned char> encrypted(padded.size());

    for (size_t i = 0; i < padded.size(); i += BLOCK_SIZE) {
        unsigned char block[8];
        std::memcpy(block, &padded[i], 8);
        uint64_t val = bytes_to_uint64(block);
        uint32_t L = static_cast<uint32_t>(val >> 32);
        uint32_t R = static_cast<uint32_t>(val & 0xFFFFFFFFULL);

        encrypt(L, R, K);

        val = (static_cast<uint64_t>(L) << 32) | R;
        uint64_to_bytes(val, block);
        std::memcpy(&encrypted[i], block, 8);
    }

    QFile outFile(outputFile);
    if (!outFile.open(QIODevice::WriteOnly)) {
        throw std::runtime_error("Cannot open output file");
    }
    outFile.write(QByteArray::fromRawData(reinterpret_cast<const char*>(encrypted.data()), encrypted.size()));
    outFile.close();
}

void CryptoProcessor::process_decrypt_file(const QString& inputFile, const QString& outputFile, uint64_t K) {
    QFile inFile(inputFile);
    if (!inFile.open(QIODevice::ReadOnly)) {
        throw std::runtime_error("Cannot open input file");
    }

    QByteArray fileData = inFile.readAll();
    inFile.close();

    std::vector<unsigned char> encrypted_data(fileData.begin(), fileData.end());

    if (encrypted_data.size() % BLOCK_SIZE != 0) {
        throw std::runtime_error("Invalid encrypted data size");
    }

    std::vector<unsigned char> decrypted_bytes(encrypted_data.size());

    for (size_t i = 0; i < encrypted_data.size(); i += BLOCK_SIZE) {
        unsigned char block[8];
        std::memcpy(block, &encrypted_data[i], 8);
        uint64_t val = bytes_to_uint64(block);
        uint32_t L = static_cast<uint32_t>(val >> 32);
        uint32_t R = static_cast<uint32_t>(val & 0xFFFFFFFFULL);

        decrypt(L, R, K);

        val = (static_cast<uint64_t>(L) << 32) | R;
        uint64_to_bytes(val, block);
        std::memcpy(&decrypted_bytes[i], block, 8);
    }

    std::vector<unsigned char> unpadded = remove_padding(decrypted_bytes);

    QFile outFile(outputFile);
    if (!outFile.open(QIODevice::WriteOnly)) {
        throw std::runtime_error("Cannot open output file");
    }
    outFile.write(QByteArray::fromRawData(reinterpret_cast<const char*>(unpadded.data()), unpadded.size()));
    outFile.close();
}

uint64_t CryptoProcessor::generate_key() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(0, UINT64_MAX);
    return dis(gen);
}

uint64_t CryptoProcessor::parse_key(const QString& keyStr) {
    if (keyStr.length() != 16) {
        return 0;
    }
    bool ok;
    uint64_t key = keyStr.toULongLong(&ok, 16);
    if (!ok) {
        return 0;
    }
    return key;
}
