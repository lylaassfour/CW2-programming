#include <iostream>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

using namespace std;

int main()
{
    cout << "Server connected" << endl;

    // Socket creation
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        cerr << "Error creating socket." << endl;
        return 1;
    }

    // Specify that the address can be reused
    int opt = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1)
    {
        cerr << "Error setting socket options." << endl;
        return 1;
    }

    // Specifying the address
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(54321);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // Binding 
    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1)
    {
        cerr << "Error binding socket." << endl;
        return 1;
    }


    // Listening to the assigned socket
    if (listen(serverSocket, 5) == -1)
    {
        cerr << "Error listening on socket." << endl;
        return 1;
    }

    // Accepting connection requests in a loop
    while (true)
    {
        // Accepting connection request
        sockaddr_in clientAddress;
        socklen_t clientAddrLen = sizeof(clientAddress);
        int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddress, &clientAddrLen);
        if (clientSocket == -1)
        {
            cerr << "Error accepting connection." << endl;
            return 1;
        }

        // Connection established message
        cout << "Client connected: " << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) << endl;

        // Handle client communication
        char buffer[1024] = {0};
        while (true) {
            int valread = read(clientSocket, buffer, sizeof(buffer));
            if (valread <= 0) {
                cerr << "Connection closed by client." << endl;
                break;
            }
            // Display client's message
            cout << "Client: " << buffer << endl;

            // Send message to all clients
            for (int i = 0; i < 1024; ++i) {
                if (buffer[i] == '\0')
                    break;
                for (int j = 0; j < 1024; ++j) {
                    if (i != j && buffer[j] != '\0') {
                        send(j, &buffer[i], 1, 0);
                    }
                }
            }
        }

        // Close client socket
        close(clientSocket);
    }

    // Close server socket (This code will never be reached in this implementation)
    close(serverSocket);

    return 0;
}
