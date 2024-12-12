//
//  main.cpp
//  sBox
//
//  Created by Sanjay Dey on 2024-12-11.
//

#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <sys/stat.h>

using namespace std;

#define ROTL8(x, shift) ((uint8_t)((x) << (shift)) | ((x) >> (8 - (shift))))

string customDirectory = "/Users/sanjaydey/Documents/WhiteboxCryptography/Source/WhiteboxCryptography";
string filePath = customDirectory + "/Sbox_InvSbox_Rcon.txt";

// Function to generate the AES S-box and its inverse
void generateSbox(vector<int>& sbox, vector<int>& inverseSbox) {
    uint8_t p = 1, q = 1;

    // Loop invariant: p * q == 1 in GF(2^8)
    do {
        // Multiply p by 3 (modulo 0x1B if overflow occurs in GF(2^8))
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

        // Divide q by 3 (equivalent to multiplication by 0xF6 in GF(2^8))
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;

        // Compute the affine transformation
        uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

        // Assign the transformed value to the S-box
        sbox[p] = xformed ^ 0x63;
    } while (p != 1);

    // Handle the special case for 0 (has no multiplicative inverse in GF(2^8))
    sbox[0] = 0x63;

    // Generate the inverse S-box by reversing the S-box mapping
    for (int i = 0; i < 256; ++i) {
        inverseSbox[sbox[i]] = i;
    }
}

// Function to generate the round constants (rcon)
void generateRcon(vector<int>& rcon) {
    rcon[0] = 0x8d; // Rcon[0] starts from 0x8d

    for (int i = 1; i < 10; ++i) {
        rcon[i] = rcon[i - 1] << 1;
        if (rcon[i] & 0x100) {
            rcon[i] ^= 0x11B;  // Polynomial mod
        }
    }
}

// Function to create a custom output directory if it doesn't exist
void createDirectoryIfNeeded(const string& dirPath) {
    struct stat info;
    if (stat(dirPath.c_str(), &info) != 0) {
        cout << "Directory does not exist, creating: " << dirPath << endl;
        if (mkdir(dirPath.c_str(), 0777) != 0) {
            cerr << "Failed to create directory: " << dirPath << endl;
            exit(1);
        }
    }
}

// Function to write the S-box, Inverse S-box, and rcon to a file as unsigned char
void writeToFileAsUnsignedChars(const vector<int>& sbox, const vector<int>& inverseSbox, const vector<int>& rcon, const string& directory) {
    ofstream outFile(filePath, ios::binary);
    if (!outFile.is_open()) {
        cerr << "Error: Could not open file for writing: " << filePath << endl;
        return;
    }

    // Helper lambda to write a vector of integers as unsigned char
    auto writeVectorAsUnsignedChars = [&outFile](const vector<int>& data) {
        for (int value : data) {
            unsigned char byte = static_cast<unsigned char>(value);
            outFile.write(reinterpret_cast<const char*>(&byte), sizeof(byte));
        }
    };

    // Write S-box
    writeVectorAsUnsignedChars(sbox);

    // Write Inverse S-box
    writeVectorAsUnsignedChars(inverseSbox);

    // Write Rcon
    writeVectorAsUnsignedChars(rcon);

    outFile.close();
    cout << "S-box, Inverse S-box, and Rcon written as unsigned chars to: " << filePath << endl;
}

// Function to read the S-box, Inverse S-box, and Rcon from a file and display as hex
bool readFromFile(const string& filePath, vector<int>& sbox, vector<int>& inverseSbox, vector<int>& rcon) {
    ifstream inFile(filePath, ios::binary);
    if (!inFile.is_open()) {
        cerr << "Error: Could not open file for reading: " << filePath << endl;
        return false;
    }

    // Read the file content
    vector<unsigned char> data((istreambuf_iterator<char>(inFile)), istreambuf_iterator<char>());
    inFile.close();

    // Validate file size
    if (data.size() < 256 + 256 + 10) {
        cerr << "Error: File does not contain enough data." << endl;
        return false;
    }

    // Extract S-box, Inverse S-box, and Rcon
    sbox.assign(data.begin(), data.begin() + 256);
    inverseSbox.assign(data.begin() + 256, data.begin() + 512);
    rcon.assign(data.begin() + 512, data.begin() + 522);

    return true;
}

void trimString(string& str) {
    str.erase(remove_if(str.begin(), str.end(), [](unsigned char c) {
        return isspace(c);
    }), str.end());
}

void logVector(const vector<int>& vec, const string& label, int length) {
    cout << label << " (Hexadecimal):" << endl;
    for (int i = 0; i < length; ++i) {
        cout << hex << uppercase << setw(2) << setfill('0') << vec[i] << " ";
        if ((i + 1) % 16 == 0) cout << endl;
    }
    cout << endl;
}

void validateData(const vector<int>& vec, const string& label, int expectedSize) {
    if (vec.size() != expectedSize) {
        cerr << "Error: " << label << " data is incomplete! Expected size: " << expectedSize
             << ", Actual size: " << vec.size() << endl;
        return;
    }
    cout << label << " successfully validated." << endl;
}

void compareVectors(const vector<int>& original, const vector<int>& read, const string& label) {
    if (original.size() != read.size()) {
        cerr << "Error: " << label << " size mismatch!" << endl;
        return;
    }

    for (size_t i = 0; i < original.size(); ++i) {
        if (original[i] != read[i]) {
            cerr << "Error: Mismatch in " << label << " at index " << i
                 << ". Original: " << original[i]
                 << ", Read: " << read[i] << endl;
            return;
        }
    }
    cout << label << " matches perfectly!" << endl;
}

// Function to test if S-box and Inverse S-box are correctly generated
void testSboxAndInverseSbox(const vector<int>& sbox, const vector<int>& inverseSbox) {
    for (int i = 0; i < 256; ++i) {
        int sboxValue = sbox[i];
        int inverseValue = inverseSbox[sboxValue];
        if (inverseValue != i) {
            cout << "Error: Inverse of S-box value " << sboxValue << " is not correct." << endl;
            return;
        }
    }
    cout << "S-box and Inverse S-box are correct!" << endl;
}

// Function to print the S-box, Inverse S-box, and Rcon as hexadecimal values
void printSbox(const vector<int>& sbox) {
    cout << "S-box (Hexadecimal):" << endl;
    for (int i = 0; i < 256; ++i) {
        cout << hex << uppercase << setw(2) << setfill('0') << sbox[i] << " ";
        if ((i + 1) % 16 == 0) cout << endl;
    }
}

void printInverseSbox(const vector<int>& inverseSbox) {
    cout << "Inverse S-box (Hexadecimal):" << endl;
    for (int i = 0; i < 256; ++i) {
        cout << hex << uppercase << setw(2) << setfill('0') << inverseSbox[i] << " ";
        if ((i + 1) % 16 == 0) cout << endl;
    }
}

void printRcon(const vector<int>& rcon) {
    cout << "Round Constants (Rcon, Hexadecimal):" << endl;
    for (int i = 0; i < 10; ++i) {
        cout << hex << uppercase << setw(2) << setfill('0') << rcon[i] << " ";
        if ((i + 1) % 16 == 0) cout << endl;
    }
}

int main() {
    vector<int> sbox(256), inverseSbox(256), rcon(10);
    vector<int> sboxFromFile(256), inverseSboxFromFile(256), rconFromFile(10);

    try {
        generateSbox(sbox, inverseSbox);
        generateRcon(rcon);

        logVector(sbox, "Generated S-box", 256);
        logVector(inverseSbox, "Generated Inverse S-box", 256);
        logVector(rcon, "Generated Rcon", 10);

        writeToFileAsUnsignedChars(sbox, inverseSbox, rcon, customDirectory);
       

        if (readFromFile(filePath, sboxFromFile, inverseSboxFromFile, rconFromFile)) {
            validateData(sboxFromFile, "S-box", 256);
            validateData(inverseSboxFromFile, "Inverse S-box", 256);
            validateData(rconFromFile, "Rcon", 10);
    
            compareVectors(sbox, sboxFromFile, "S-box");
            compareVectors(inverseSbox, inverseSboxFromFile, "Inverse S-box");
            compareVectors(rcon, rconFromFile, "Rcon");
    
            testSboxAndInverseSbox(sboxFromFile, inverseSboxFromFile);
    
            printSbox(sboxFromFile);
            printInverseSbox(inverseSboxFromFile);
            printRcon(rconFromFile);
        }
       


    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
    }

    return 0;
}
