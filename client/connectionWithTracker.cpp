#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <openssl/ssl.h>
#include "client.h"

using namespace std;

/********************************************************************************************************
                Function to read the tracker information from the tracker_info.txt file 
********************************************************************************************************/
bool extractTrackerInfo(const string &tracker_info, string &trackerIP1, int &trackerPort1, string &trackerIP2, int &trackerPort2) {
    int fd = open(tracker_info.c_str(), O_RDONLY);
    if (fd < 0) {
        perror("open failed");
        return false;
    }

    char buf[256];
    memset(buf, 0, sizeof(buf));

    int n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0) {
        perror("read failed");
        close(fd);
        return false;
    }
    buf[n] = '\0';

    close(fd);

    // Parse the file content into 2 IP + 2 port values
    char ip1_c[64], ip2_c[64];
    if (sscanf(buf, "%s %d %s %d", ip1_c, &trackerPort1, ip2_c, &trackerPort2) != 4) {
        cerr << "Error parsing tracker info" << endl;
        return false;
    }

    trackerIP1 = string(ip1_c);
    trackerIP2 = string(ip2_c);
    return true;
}

/********************************************************************************************************
                Connecting to the tracker using ip:port got from the tracker_info.txt file
********************************************************************************************************/
int tryConnectingWithTracker(const string &trackerIp, int trackerPort) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port   = htons(trackerPort);

    if (inet_pton(AF_INET, trackerIp.c_str(), &serverAddr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == 0) {
        return sock;  // connected successfully 
    }

    close(sock);
    return -1;  // failed to connect to this tracker
}

int connectToTracker(const string &trackerIP1, int trackerPort1, const string &trackerIP2, int trackerPort2) {
    // Always try tracker1 first (it may have recovered)
    int trackerSocket = tryConnectingWithTracker(trackerIP1, trackerPort1);
    if (trackerSocket >= 0) return trackerSocket;

    // Fall back to tracker2
    trackerSocket = tryConnectingWithTracker(trackerIP2, trackerPort2);
    if (trackerSocket >= 0) return trackerSocket;

    cerr << "\033[31mFailed to connect to any tracker!\033[0m" << endl;
    return -1;
}

/********************************************************************************************************
    Connect to tracker and wrap in TLS — returns SSL* or nullptr on failure (Fix 2)
********************************************************************************************************/
SSL* connectToTrackerSSL(const string &trackerIP1, int trackerPort1, const string &trackerIP2, int trackerPort2) {
    int rawSock = connectToTracker(trackerIP1, trackerPort1, trackerIP2, trackerPort2);
    if (rawSock < 0) return nullptr;

    SSL* ssl = connectSSL(g_clientSSLCtx, rawSock);
    if (!ssl) {
        cerr << "\033[31m[TLS] SSL handshake failed with tracker\033[0m" << endl;
        close(rawSock);
        return nullptr;
    }

    cout << "\033[32m[TLS] Secure connection established with tracker\033[0m" << endl;
    return ssl;
}