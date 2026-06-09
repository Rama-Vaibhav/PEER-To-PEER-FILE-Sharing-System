#include "tracker.h"
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <openssl/ssl.h>

using namespace std;

SSL* peerTrackerSSL = nullptr;
mutex peerSendMutex;  // protects ALL accesses to peerTrackerSSL

void keepPeerConnected(string peerIP, int peerPort) {
    while (true) {
        bool connected = false;
        {
            lock_guard<mutex> lk(peerSendMutex);
            if (peerTrackerSSL != nullptr) {
                connected = true;
            }
        }
        if (connected) {
            this_thread::sleep_for(chrono::seconds(1));
            continue;
        }
        // Socket is down — try to reconnect (outside the lock, connect can block)
        if (connectToPeerTracker(peerIP, peerPort)) {
            thread peerSyncListenerThread(peerSyncListener);
            peerSyncListenerThread.detach();
        }
        this_thread::sleep_for(chrono::seconds(1));
    }
}

bool connectToPeerTracker(const string &peerIP, int peerPort) {
    int newSock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(peerPort);
    inet_pton(AF_INET, peerIP.c_str(), &addr.sin_addr);

    if (connect(newSock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(newSock);
        return false;
    }

    // Wrap the TCP socket in TLS (Fix 2)
    SSL* ssl = connectSSL(g_clientSSLCtx, newSock);
    if (!ssl) {
        cerr << "\033[31m[SYNC] TLS handshake failed to peer tracker\033[0m" << endl;
        close(newSock);
        return false;
    }

    {
        lock_guard<mutex> lk(peerSendMutex);
        peerTrackerSSL = ssl;
    }
    cout << "\033[33m[SYNC] Connected to peer tracker (TLS)\033[0m " << peerIP << ":" << peerPort << endl;
    return true;
}

void peerSyncListener() {
    // Take a local snapshot of the SSL so we know which one we're listening on
    SSL* mySSL;
    {
        lock_guard<mutex> lk(peerSendMutex);
        mySSL = peerTrackerSSL;
    }

    char buffer[4096];
    while (true) {
        int bytes = SSL_read(mySSL, buffer, sizeof(buffer));
        if (bytes <= 0) {
            cerr << "\033[31m[SYNC] Peer tracker disconnected.\033[0m\n";
            {
                lock_guard<mutex> lk(peerSendMutex);
                if (peerTrackerSSL == mySSL) {
                    int fd = SSL_get_fd(mySSL);
                    SSL_shutdown(mySSL);
                    SSL_free(mySSL);
                    close(fd);
                    peerTrackerSSL = nullptr;
                }
            }
            break;
        }
        string msg(buffer, bytes);
        applyCommand(msg, nullptr, true);
    }
}

void forwardToPeer(const string &message) {
    lock_guard<mutex> lk(peerSendMutex);
    if (peerTrackerSSL == nullptr) return;

    string wire = "SYNC " + message;
    int n = SSL_write(peerTrackerSSL, wire.c_str(), wire.size());
    if (n <= 0) {
        cerr << "[SYNC] SSL_write failed" << endl;
        int fd = SSL_get_fd(peerTrackerSSL);
        SSL_shutdown(peerTrackerSSL);
        SSL_free(peerTrackerSSL);
        close(fd);
        peerTrackerSSL = nullptr;
    } else {
        cout << "\033[33m[SYNC] Forwarded\033[0m" << endl;
    }
}

bool extractTrackerInfo(const string &tracker_info, int &trackerNumber, string &currTrackerIP, int &currTrackerPort) {
    int fd = open(tracker_info.c_str(), O_RDONLY);
    if (fd < 0) { perror("open failed"); return false; }

    char buf[256];
    memset(buf, 0, sizeof(buf));
    int n = read(fd, buf, sizeof(buf) - 1);
    if (n < 0) { perror("read failed"); close(fd); return false; }
    buf[n] = '\0';
    close(fd);

    char ip1_c[64], ip2_c[64];
    int port1, port2;
    if (sscanf(buf, "%s %d %s %d", ip1_c, &port1, ip2_c, &port2) != 4) {
        cerr << "Error parsing tracker info" << endl;
        return false;
    }

    if (trackerNumber == 1) {
        currTrackerIP = string(ip1_c);
        currTrackerPort = port1;
    } else if (trackerNumber == 2) {
        currTrackerIP = string(ip2_c);
        currTrackerPort = port2;
    } else {
        cerr << "Invalid tracker number (use 1 or 2)" << endl;
        return false;
    }
    return true;
}

int startTrackerServer(const string &ip, int port) {
    int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0) { perror("server socket creation failed"); exit(EXIT_FAILURE); }

    sockaddr_in serveraddr{};
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &serveraddr.sin_addr);

    int opt = 1;
    setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (::bind(listenSocket, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) {
        perror("bind failed"); close(listenSocket); exit(EXIT_FAILURE);
    }
    if (listen(listenSocket, SOMAXCONN) < 0) {
        perror("listen failed"); close(listenSocket); exit(EXIT_FAILURE);
    }

    cout << "Tracker listening on " << ip << ":" << port << "..." << endl;
    return listenSocket;
}