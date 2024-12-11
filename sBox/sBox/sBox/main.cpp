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
#include <sys/stat.h>

using namespace std;

// Utility function to perform multiplicative inverse in GF(2^8)
int multiplicativeInverse(int x) {
    int i = 1;
    while ((x * i) % 0x11B != 1) {
        i++;
    }
    return i;
}

// Utility function for affine transformation
int affineTransformation(int x) {
    // Apply the affine transformation as per AES standard
    x ^= (x >> 1);
    x ^= (x >> 2);
    x ^= (x >> 3);
    x ^= (x >> 4);
    x ^= 0x63;  // XOR with 0x63 (constant from the AES standard)
    
    // Constrain to 0-255 range using modulo 256
    return x & 0xFF;
}

// Function to generate the S-box
void generateSbox(vector<int>& sbox, vector<int>& inverseSbox) {
    for (int i = 0; i < 256; ++i) {
        // Compute multiplicative inverse and apply affine transformation
        if (i != 0) {
            int inv = multiplicativeInverse(i);
            sbox[i] = affineTransformation(inv);
            if (sbox[i] >= 0 && sbox[i] < 256) {
                inverseSbox[sbox[i]] = i;  // Ensure valid index for inverseSbox
            } else {
                cout << "S-box value out of range: " << sbox[i] << " at index " << i << endl;
                throw out_of_range("S-box value out of range.");
            }
        } else {
            sbox[i] = 0x63;  // 0 has no inverse in GF(2^8), so use 0x63
            inverseSbox[sbox[i]] = i;
        }
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

// Function to write the S-box, Inverse S-box, and rcon to a file as characters
void writeToFileAsChars(const vector<int>& sbox, const vector<int>& inverseSbox, const vector<int>& rcon, const string& dirPath) {
    // Create the custom output directory if it doesn't exist
    createDirectoryIfNeeded(dirPath);

    // Define the output file path in the custom directory
    string filePath = dirPath + "/Sbox_InvSbox_Rcon";

    ofstream outFile(filePath);

    if (outFile.is_open()) {
        outFile << "S-box (as characters):" << endl;
        for (int i = 0; i < 256; ++i) {
            // Convert hex values to characters and print
            char charOut = static_cast<char>(sbox[i]);
            outFile << charOut;
            if ((i + 1) % 16 == 0) {
                outFile << endl;
            }
        }

        outFile << "\nInverse S-box (as characters):" << endl;
        for (int i = 0; i < 256; ++i) {
            // Convert hex values to characters and print
            char charOut = static_cast<char>(inverseSbox[i]);
            outFile << charOut;
            if ((i + 1) % 16 == 0) {
                outFile << endl;
            }
        }

        outFile << "\nRound Constants (rcon) (as characters):" << endl;
        for (int i = 0; i < 10; ++i) {
            // Convert hex values to characters and print
            char charOut = static_cast<char>(rcon[i]);
            outFile << charOut;
            if ((i + 1) % 16 == 0) {
                outFile << endl;
            }
        }

        outFile.close();
        cout << "S-box, Inverse S-box, and rcon written as characters to: " << filePath << endl;
    } else {
        cout << "Error opening file!" << endl;
    }
}

// Function to read the file and reconstruct the S-box, Inverse S-box, and Rcon
void readFromFileAsChars(vector<int>& sbox, vector<int>& inverseSbox, vector<int>& rcon, const string& filePath) {
    ifstream inFile(filePath);
    if (!inFile.is_open()) {
        cerr << "Error opening file!" << endl;
        return;
    }

    string line;
    int index = 0;

    // Reading S-box
    getline(inFile, line); // Read the first line ("S-box (as characters):")
    while (getline(inFile, line) && index < 256) {
        for (char ch : line) {
            sbox[index++] = static_cast<unsigned char>(ch);  // Convert char to int (unsigned byte)
        }
    }

    // Reset index for Inverse S-box
    index = 0;

    // Reading Inverse S-box
    getline(inFile, line); // Read the second line ("Inverse S-box (as characters):")
    while (getline(inFile, line) && index < 256) {
        for (char ch : line) {
            inverseSbox[index++] = static_cast<unsigned char>(ch);  // Convert char to int (unsigned byte)
        }
    }

    // Reset index for Rcon
    index = 0;

    // Reading Round Constants (rcon)
    getline(inFile, line); // Read the third line ("Round Constants (rcon) (as characters):")
    while (getline(inFile, line) && index < 10) {
        for (char ch : line) {
            rcon[index++] = static_cast<unsigned char>(ch);  // Convert char to int (unsigned byte)
        }
    }

    inFile.close();
    cout << "S-box, Inverse S-box, and Rcon read from file: " << filePath << endl;
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

    // Specify your custom output directory here
    string customDirectory = "/Users/sanjaydey/Documents/WhiteboxCryptography/Source/WhiteboxCryptography";

    try {
        generateSbox(sbox, inverseSbox);
        generateRcon(rcon);
        writeToFileAsChars(sbox, inverseSbox, rcon, customDirectory);
        // Read the file and reconstruct the S-box, Inverse S-box, and Rcon
        readFromFileAsChars(sbox, inverseSbox, rcon, customDirectory);

        // Print the data in the original hexadecimal format
        printSbox(sbox);
        printInverseSbox(inverseSbox);
        printRcon(rcon);
    } catch (const out_of_range& e) {
        cout << "Error: " << e.what() << endl;
    }

    return 0;
}
