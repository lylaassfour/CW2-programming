#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <thread> // for multi-threading
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

#define PORT 54321
#define SHIFT 3
#define AES_KEY_LENGTH 256
#define AES_BLOCK_SIZE 16

// Function to save username and password to a text file with Caesar cipher encryption
void saveCredentials(const string& username, const string& password) {
    // Encrypt password using Caesar cipher (not secure, only for demonstration)
    string encryptedPassword = password;
    for (char& c : encryptedPassword) {
        if (isalpha(c)) {
            if (islower(c)) {
                c = 'a' + (c - 'a' + SHIFT) % 26;
            } else {
                c = 'A' + (c - 'A' + SHIFT) % 26;
            }
        }
    }

    // Save username and encrypted password to file
    ofstream file("credentials.txt", ios::app);
    if (file.is_open()) {
        file << username << " " << encryptedPassword << endl;
        file.close();
        cout << "Account created successfully!" << endl;
    } else {
        cerr << "Unable to open file." << endl;
    }
}

// Function to decrypt Caesar cipher encrypted password
string decryptPassword(const string& encryptedPassword) {
    string decryptedPassword = encryptedPassword;
    for (char& c : decryptedPassword) {
        if (isalpha(c)) {
            if (islower(c)) {
                c = 'a' + (c - 'a' - SHIFT + 26) % 26;
            } else {
                c = 'A' + (c - 'A' - SHIFT + 26) % 26;
            }
        }
    }
    return decryptedPassword;
}

// AES encryption function
string aesEncrypt(const string& plainText, const string& key) {
    string cipherText;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cerr << "AES encryption initialization failed." << endl;
        return "";
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.c_str(), (const unsigned char*)"0000000000000000") != 1) {
        cerr << "AES encryption initialization failed." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    int len;
    int maxLen = plainText.length() + AES_BLOCK_SIZE;
    unsigned char* ciphertext = new unsigned char[maxLen];
    if (!ciphertext) {
        cerr << "Memory allocation failed." << endl;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char*)plainText.c_str(), plainText.length()) != 1) {
        cerr << "AES encryption failed." << endl;
        delete[] ciphertext;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    cipherText.assign(reinterpret_cast<char*>(ciphertext), len);

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        cerr << "AES encryption finalization failed." << endl;
        delete[] ciphertext;
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    cipherText.append(reinterpret_cast<char*>(ciphertext + len), len);

    delete[] ciphertext;
    EVP_CIPHER_CTX_free(ctx);

    return cipherText;
}

// Function to handle signup process
void signUp() {
    string username, password;
    cout << "Enter username: ";
    cin >> username;
    cout << "Enter password: ";
    cin >> password;
    saveCredentials(username, password);
}

// Function to handle login process
bool login(const string& username, const string& password, int sockfd) {
    ifstream file("credentials.txt");
    if (file.is_open()) {
        string line;
        while (getline(file, line)) {
            stringstream ss(line);
            string storedUsername, storedPassword;
            ss >> storedUsername >> storedPassword;
            if (username == storedUsername) {
                string decryptedPassword = decryptPassword(storedPassword);
                if (password == decryptedPassword) {
                    cout << "Login successful!" << endl;
                    // Notify the server of successful login
                    send(sockfd, "login", strlen("login"), 0);
                    return true;
                }
            }
        }
        cout << "Login failed. Username or password incorrect." << endl;
    } else {
        cerr << "Unable to open file." << endl;
    }
    return false;
}

// Function to handle receiving messages from the server
void handleReceive(int sockfd, const string& key) {
    char buffer[1024] = {0};
    while (true) {
        int valread = read(sockfd, buffer, sizeof(buffer));
        if (valread <= 0) {
            cerr << "Connection closed by server." << endl;
            break;
        }
        string encryptedMessage(buffer);
        string decryptedMessage = aesDecrypt(encryptedMessage, key);
        cout << "Server: " << decryptedMessage << endl;
    }
}

// Function to handle sending messages to the server
void handleSend(int sockfd, const string& key) {
    string message;
    while (true) {
        cout << "You: ";
        getline(cin, message);
        string encryptedMessage = aesEncrypt(message, key);
        if (send(sockfd, encryptedMessage.c_str(), encryptedMessage.length(), 0) <= 0) {
            cerr << "Message sending failed. Server may have closed the connection." << endl;
            break;
        }
    }
}

int main() {
    int choice;
    cout << "Welcome to the Chat Application!" << endl;
    cout << "1. Login" << endl;
    cout << "2. Sign up" << endl;
    cout << "Enter your choice: ";
    cin >> choice;

    if (choice == 2) {
        signUp();
        return 0;
    }

    string username, password;
    cout << "Enter username: ";
    cin >> username;
    cout << "Enter password: ";
    cin >> password;

    // Connect to server and proceed with chat
    int sockfd;
    struct sockaddr_in serv_addr;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "Socket creation error." << endl;
        return 1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        cerr << "Invalid address/ Address not supported" << endl;
        return 1;
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        cerr << "Connection Failed" << endl;
        return 1;
    }

    // Generate a random AES key
    unsigned char aesKey[AES_KEY_LENGTH / 8];
    if (RAND_bytes(aesKey, AES_KEY_LENGTH / 8) != 1) {
        cerr << "Failed to generate AES key." << endl;
        return 1;
    }
    string key(reinterpret_cast<char*>(aesKey), AES_KEY_LENGTH / 8);

    if (login(username, password, sockfd)) {
        // Create threads for sending and receiving messages
        thread sendThread(handleSend, sockfd, key);
        thread receiveThread(handleReceive, sockfd, key);

        // Join the threads
        sendThread.join();
        receiveThread.join();
    }

    return 0;
}
