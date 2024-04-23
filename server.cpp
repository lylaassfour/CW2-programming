#include <iostream>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>

using namespace std;

#define MAX_CLIENTS 10
#define PORT 54321

// Function to handle client communication
void handleClient(int clientSocket, int clients[], int& clientCount) {
    char buffer[1024] = {0};
    while (true) {
        int valread = read(clientSocket, buffer, sizeof(buffer));
        if (valread <= 0) {
            // Connection closed by client
            cerr << "Connection closed by client." << endl;
            for (int i = 0; i < clientCount; ++i) {
                if (clients[i] == clientSocket) {
                    for (int j = i; j < clientCount - 1; ++j) {
                        clients[j] = clients[j + 1];
                    }
                    clientCount--;
                    break;
                }
            }
            close(clientSocket);
            break;
        }

        // Broadcast message to all clients
        cout << "Client " << clientSocket << ": " << buffer << endl;
        for (int i = 0; i < clientCount; ++i) {
            if (clients[i] != clientSocket) {
                send(clients[i], buffer, strlen(buffer), 0);
            }
        }
    }
}

int main() {
    cout << "Server connected" << endl;

    // Socket creation
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        cerr << "Error creating socket." << endl;
        return 1;
    }

    // Specify that the address can be reused
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        cerr << "Error setting socket options." << endl;
        return 1;
    }

    // Specifying the address
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // Binding
    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1) {
        cerr << "Error binding socket." << endl;
        return 1;
    }

    // Listening to the assigned socket
    if (listen(serverSocket, 5) == -1) {
        cerr << "Error listening on socket." << endl;
        return 1;
    }

    int clients[MAX_CLIENTS]; // Store client sockets
    int clientCount = 0;

    // Accepting connection requests in a loop
    while (true) {
        // Accepting connection request
        sockaddr_in clientAddress;
        socklen_t clientAddrLen = sizeof(clientAddress);
        int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddrLen);
        if (clientSocket == -1) {
            cerr << "Error accepting connection." << endl;
            return 1;
        }

        // Connection established message
        cout << "Client connected: " << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) << endl;
        clients[clientCount++] = clientSocket;

        // Create thread to handle client communication
        thread clientThread(handleClient, clientSocket, clients, ref(clientCount));
        clientThread.detach();
    }

    // Close server socket (This code will never be reached in this implementation)
    close(serverSocket);

    return 0;
}
