#include <iostream>
#include <fstream>
#include <cstdint>
#include <vector>
#include <string>
#include <iomanip>
#include <cstring>
#include <random>
#include <sstream>

using namespace std;

const int NUM_ROUNDS = 16;
const size_t BLOCK_SIZE = 8;

uint32_t rotl32(uint32_t x, int shift) {
    return (x << shift) | (x >> (32 - shift));
}

uint32_t rotr32(uint32_t x, int shift) {
    return (x >> shift) | (x << (32 - shift));
}

uint64_t rotr64(uint64_t x, int shift) {
    shift %= 64;
    return (x >> shift) | (x << (64 - shift));
}

uint32_t F(uint32_t val, uint32_t key) {
    return rotl32(val, 9) ^ ~rotr32(val, 11) ^ (val * key);
}

void encrypt(uint32_t& L, uint32_t& R, uint64_t K) {
    for (int i = 0; i < NUM_ROUNDS; ++i) {
        uint64_t rotated = rotr64(K, 3 * i);
        uint32_t Ki = static_cast<uint32_t>(rotated & 0xFFFFFFFFULL);
        uint32_t temp = R;
        R = L ^ F(R, Ki);
        L = temp;
    }
}

void decrypt(uint32_t& L, uint32_t& R, uint64_t K) {
    for (int i = NUM_ROUNDS - 1; i >= 0; --i) {
        uint64_t rotated = rotr64(K, 3 * i);
        uint32_t Ki = static_cast<uint32_t>(rotated & 0xFFFFFFFFULL);
        uint32_t temp = L;
        L = R ^ F(L, Ki);
        R = temp;
    }
}

void uint64_to_bytes(uint64_t val, unsigned char* bytes) {
    for (int i = 7; i >= 0; --i) {
        bytes[i] = val & 0xFF;
        val >>= 8;
    }
}

uint64_t bytes_to_uint64(const unsigned char* bytes) {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | bytes[i];
    }
    return val;
}

vector<unsigned char> add_padding(const vector<unsigned char>& data) {
    vector<unsigned char> padded = data;
    size_t padding_needed = BLOCK_SIZE - (padded.size() % BLOCK_SIZE);
    if (padding_needed == 0)
        padding_needed = BLOCK_SIZE;

    unsigned char pad_byte = static_cast<unsigned char>(padding_needed);
    padded.insert(padded.end(), padding_needed, pad_byte);
    return padded;
}

vector<unsigned char> remove_padding(const vector<unsigned char>& padded) {
    if (padded.empty() || padded.size() % BLOCK_SIZE != 0) {
        throw runtime_error("Invalid padded data");
    }
    unsigned char pad_byte = padded.back();
    size_t padding_len = static_cast<size_t>(pad_byte);
    if (padding_len == 0 || padding_len > BLOCK_SIZE || padding_len > padded.size()) {
        throw runtime_error("Invalid padding");
    }
    for (size_t i = padded.size() - padding_len; i < padded.size(); ++i) {
        if (padded[i] != pad_byte) {
            throw runtime_error("Invalid padding");
        }
    }
    return vector<unsigned char>(padded.begin(), padded.end() - padding_len);
}

void process_encrypt(const string& input_str, vector<unsigned char>& encrypted, uint64_t K) {
    vector<unsigned char> data(input_str.begin(), input_str.end());
    vector<unsigned char> padded = add_padding(data);
    encrypted.resize(padded.size());

    for (size_t i = 0; i < padded.size(); i += BLOCK_SIZE) {
        unsigned char block[8];
        memcpy(block, &padded[i], 8);
        uint64_t val = bytes_to_uint64(block);
        uint32_t L = static_cast<uint32_t>(val >> 32);
        uint32_t R = static_cast<uint32_t>(val & 0xFFFFFFFFULL);

        encrypt(L, R, K);

        val = (static_cast<uint64_t>(L) << 32) | R;
        uint64_to_bytes(val, block);
        memcpy(&encrypted[i], block, 8);
    }
}

void process_decrypt(const vector<unsigned char>& encrypted_data, string& decrypted_text, uint64_t K) {
    if (encrypted_data.size() % BLOCK_SIZE != 0) {
        throw runtime_error("Invalid encrypted data size");
    }

    vector<unsigned char> decrypted_bytes(encrypted_data.size());

    for (size_t i = 0; i < encrypted_data.size(); i += BLOCK_SIZE) {
        unsigned char block[8];
        memcpy(block, &encrypted_data[i], 8);
        uint64_t val = bytes_to_uint64(block);
        uint32_t L = static_cast<uint32_t>(val >> 32);
        uint32_t R = static_cast<uint32_t>(val & 0xFFFFFFFFULL);

        decrypt(L, R, K);

        val = (static_cast<uint64_t>(L) << 32) | R;
        uint64_to_bytes(val, block);
        memcpy(&decrypted_bytes[i], block, 8);
    }

    vector<unsigned char> unpadded = remove_padding(decrypted_bytes);
    decrypted_text = string(unpadded.begin(), unpadded.end());
}

double inputNumber(const string& str, const bool& isInteger, const bool& isPositive) {
    double number;
    while (true) {
        cout << str;
        cin >> number;
        if (cin.fail() || cin.peek() != '\n') {
            cout << "ERROR: INCORRECT DATA ENTERED" << endl;
            cout << "Please try again" << endl << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            continue;
        }
        if (isInteger && fabs(number - round(number)) > 1e-10) {
            cout << "ERROR: YOU NEED TO ENTER AN INTEGER" << endl;
            cout << "Please try again" << endl << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            continue;
        }
        if (isPositive && number <= 0) {
            cout << "ERROR: YOU NEED TO ENTER AN POSITIVE" << endl;
            cout << "Please try again" << endl << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            continue;
        }
        return number;
    }
}

uint64_t getKeyFromUser() {
    string input;
    while (true) {
        cout << "Enter 64-bit key in hexadecimal format (16 characters, e.g., 0123456789ABCDEF): ";
        cin >> input;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        if (input.length() != 16) {
            cout << "Error: Please enter exactly 16 hexadecimal characters!\n";
            continue;
        }
        bool valid = true;
        for (char c : input) {
            if (!isxdigit(c)) {
                valid = false;
                break;
            }
        }
        if (!valid) {
            cout << "Error: Invalid hexadecimal characters! Use 0-9, A-F, or a-f.\n";
            continue;
        }
        try {
            return stoull(input, nullptr, 16);
        }
        catch (const exception& e) {
            cout << "Error: Invalid key format! Try again.\n";
        }
    }
}

vector<unsigned char> hexStringToBytes(const string& hex_str) {
    vector<unsigned char> bytes;
    stringstream ss(hex_str);
    string hex_byte;

    while (ss >> hex_byte) {
        try {
            int byte = stoi(hex_byte, nullptr, 16);
            if (byte < 0 || byte > 255) {
                throw runtime_error("Invalid hex byte value");
            }
            bytes.push_back(static_cast<unsigned char>(byte));
        }
        catch (const exception& e) {
            throw runtime_error("Invalid hex input format");
        }
    }
    return bytes;
}

int main() {
    cout << "Select the mode:" << endl;
    cout << "1. Encrypt" << endl;
    cout << "2. Decrypt" << endl;

    int choice;
    bool validChoice = false;
    string input_text;
    uint64_t K;

    while (!validChoice) {
        choice = inputNumber("Your choice: ", true, true);
        switch (choice) {
        case 1:
            cout << "Enter text to encrypt: ";
            cin.ignore();
            getline(cin, input_text);
            validChoice = true;
            break;
        case 2:
            cout << "Enter text to decrypt (hex, space-separated, e.g., 01 2A 3B): ";
            cin.ignore();
            getline(cin, input_text);
            validChoice = true;
            break;
        default:
            cout << "Invalid choice! Please try again." << endl;
        }
    }

    if (choice == 1) {
        random_device rd;
        mt19937_64 gen(rd());
        uniform_int_distribution<uint64_t> dis(0, UINT64_MAX);
        K = dis(gen);
        cout << "Generated key: " << hex << setw(16) << setfill('0') << K << endl;

        vector<unsigned char> encrypted;
        process_encrypt(input_text, encrypted, K);

        cout << "Encrypted (hex): ";
        for (size_t i = 0; i < encrypted.size(); ++i) {
            cout << setw(2) << setfill('0') << hex << (int)encrypted[i] << " ";
        }
        cout << endl;
    }
    else {
        K = getKeyFromUser();

        try {
            vector<unsigned char> encrypted_data = hexStringToBytes(input_text);
            string decrypted_text;
            process_decrypt(encrypted_data, decrypted_text, K);

            cout << "Decrypted text: " << decrypted_text << endl;
        }
        catch (const exception& e) {
            cout << "Error: " << e.what() << endl;
            return 1;
        }
    }

    return 0;
}