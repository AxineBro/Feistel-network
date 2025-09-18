#ifndef CRYPTOPROCESSOR_H
#define CRYPTOPROCESSOR_H

#include <cstdint>
#include <vector>
#include <QString>

class CryptoProcessor {
public:
    CryptoProcessor();

    void process_encrypt_file(const QString& inputFile, const QString& outputFile, uint64_t key);

    void process_decrypt_file(const QString& inputFile, const QString& outputFile, uint64_t key);

    uint64_t generate_key();

    uint64_t parse_key(const QString& keyStr);

private:
    static const int NUM_ROUNDS = 16;
    static const size_t BLOCK_SIZE = 8;

    uint32_t rotl32(uint32_t x, int shift);
    uint32_t rotr32(uint32_t x, int shift);
    uint64_t rotr64(uint64_t x, int shift);
    uint32_t F(uint32_t val, uint32_t key);
    void encrypt(uint32_t& L, uint32_t& R, uint64_t K);
    void decrypt(uint32_t& L, uint32_t& R, uint64_t K);
    void uint64_to_bytes(uint64_t val, unsigned char* bytes);
    uint64_t bytes_to_uint64(const unsigned char* bytes);
    std::vector<unsigned char> add_padding(const std::vector<unsigned char>& data);
    std::vector<unsigned char> remove_padding(const std::vector<unsigned char>& padded);
};

#endif
