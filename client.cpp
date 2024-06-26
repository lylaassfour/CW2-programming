#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <thread> // for multi-threading

using namespace std;

#define PORT 54321
#define SHIFT 3
#define CAESAR_KEY "MYKEY" // Assigned Caesar cipher key

// Function to encrypt message using Caesar cipher
string encryptMessage(const string& message) {
    string encryptedMessage = message;
    for (char& c : encryptedMessage) {
        if (isalpha(c)) {
            c = 'a' + (c - 'a' + SHIFT) % 26; // Add SHIFT to each character
        }
    }
    return encryptedMessage;
}

// Function to decrypt Caesar cipher encrypted message
string decryptMessage(const string& encryptedMessage) {
    string decryptedMessage = encryptedMessage;
    for (char& c : decryptedMessage) {
        if (isalpha(c)) {
            c = 'a' + (c - 'a' - SHIFT + 26) % 26; // Subtract SHIFT from each character
        }
    }
    return decryptedMessage;
}

// Function to save username and password to a text file with Caesar cipher encryption
void saveCredentials(const string& username, const string& password) {
    // Encrypt password using Caesar cipher
    string encryptedPassword = password;
    for (char& c : encryptedPassword) {
        if (isalpha(c)) {
            c = 'a' + (c - 'a' + SHIFT) % 26;
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
            c = 'a' + (c - 'a' - SHIFT + 26) % 26;
        }
    }
    return decryptedPassword;
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

// Function to handle sending messages to the server
void handleSend(int sockfd) {
    string message;
    while (true) {
        cout << "You: ";
        getline(cin, message);

        // Ensure message is not empty
        if (message.empty()) {
            cerr << "Message cannot be empty." << endl;
            continue;
        }

        // Encrypt message using Caesar cipher
        string encryptedMessage = encryptMessage(message);

        // Send the message along with null terminator
        if (send(sockfd, encryptedMessage.c_str(), encryptedMessage.length() + 1, 0) <= 0) {
            cerr << "Message sending failed. Server may have closed the connection." << endl;
            break;
        }
    }
}

// Function to handle receiving messages from the server
void handleReceive(int sockfd) {
    char buffer[1024] = {0};
    while (true) {
        int valread = read(sockfd, buffer, sizeof(buffer));
        if (valread <= 0) {
            cerr << "Connection closed by server." << endl;
            break;
        }

        // Decrypt received message using Caesar cipher
        string decryptedMessage = decryptMessage(buffer);
        cout << "Server: " << decryptedMessage << endl;
    }
}

// Function to handle receiving messages from other clients
void handleClientReceive(int sockfd) {
    char buffer[1024] = {0};
    while (true) {
        int valread = read(sockfd, buffer, sizeof(buffer));
        if (valread <= 0) {
            cerr << "Connection closed." << endl;
            break;
        }

        // Decrypt received message from another client using Caesar cipher
        string decryptedMessage = decryptMessage(buffer);
        cout << "Message from another client: " << decryptedMessage << endl;
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

    if (login(username, password, sockfd)) {
        // Notify the server of successful login
        send(sockfd, "login", strlen("login"), 0);

        // Create threads for sending and receiving messages
        thread sendThread(handleSend, sockfd);
        thread receiveThread(handleReceive, sockfd);
        thread clientReceiveThread(handleClientReceive, sockfd);

        // Join the threads
        sendThread.join();
        receiveThread.join();
        clientReceiveThread.join();
    }

    close(sockfd); // Close socket when finished
    return 0;
}
