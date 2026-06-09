#include "client.h"
#include "../common/cryptoUtil.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sstream>
#include <openssl/err.h>

using namespace std;

static bool recvAllSSL(SSL* ssl, char *buf, size_t len) {
    size_t totalBytesReceived = 0;
    while (totalBytesReceived < len) {
        int bytesGotNow = SSL_read(ssl, buf+totalBytesReceived, len-totalBytesReceived);
        if (bytesGotNow <= 0) return false;
        totalBytesReceived += bytesGotNow;
    }
    return true;
}

bool fetchChunkFromPeer(const string &peerIp, int peerPort, const string &fileName, int chunkIndex, const string &localDestPath, size_t chunkSize, vector<char> &outChunkData) {
    // we will send the data in outChunkData
    // 1. connect to the peer at peerIp:peerPort over TCP
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(peerPort);
    if (inet_pton(AF_INET, peerIp.c_str(), &addr.sin_addr) <= 0) {
        close(sock);
        return false;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return false;
    }

    // Wrap the TCP connection in TLS
    SSL* peerSSL = connectSSL(g_clientSSLCtx, sock);
    if (!peerSSL) {
        close(sock);
        return false;
    }

    // 2. send the request like REQUEST_CHUNK <filename> <chunk index> to the peer from where we want to download 
    ostringstream req;
    req << "REQUEST_CHUNK " << fileName << " " << chunkIndex << "\n";
    string reqStr = req.str();
    if (SSL_write(peerSSL, reqStr.c_str(), reqStr.size()) != (int)reqStr.size()) {
        SSL_shutdown(peerSSL);
        SSL_free(peerSSL);
        close(sock);
        return false;
    }

    // 3. we will read header line
    string header;
    char c;
    while (true) {
        int n = SSL_read(peerSSL, &c, 1);
        if (n <= 0) {
            SSL_shutdown(peerSSL);
            SSL_free(peerSSL);
            close(sock);
            return false;
        }
        if (c == '\n') break;
        header.push_back(c);
        if (header.size() > 128) {
            SSL_shutdown(peerSSL);
            SSL_free(peerSSL);
            close(sock);
            return false;
        }
    }

    istringstream hs(header);
    string tag;
    hs >> tag;
    if (tag == "ERROR") {
        string errorMsg;
        getline(hs, errorMsg);  // read rest of the line after the word "ERROR"
        cerr << "[ERROR] Peer " << peerIp << ":" << peerPort  << " reported: " << errorMsg << "\n";
        SSL_shutdown(peerSSL);
        SSL_free(peerSSL);
        close(sock);
        return false;
    } 
    else if (tag == "CHUNK") {
        int size = 0;
        string serverHash, ivHex;
        hs >> size >> serverHash >> ivHex;
        if (size <= 0 || serverHash.empty() || ivHex.empty()) { 
            SSL_shutdown(peerSSL);
            SSL_free(peerSSL);
            close(sock);
            return false; 
        }

        // Receive encrypted chunk
        vector<char> ciphertext(size);
        if (!recvAllSSL(peerSSL, ciphertext.data(), size)) {
            SSL_shutdown(peerSSL);
            SSL_free(peerSSL);
            close(sock);
            return false;
        }

        // Retrieve group key
        string groupId = "";
        {
            lock_guard<mutex> lock(localPathMutex);
            auto git = fileNameToGroupId.find(fileName);
            if (git != fileNameToGroupId.end()) {
                groupId = git->second;
            }
        }
        string groupKey = "";
        if (!groupId.empty()) {
            auto kit = g_groupKeys.find(groupId);
            if (kit != g_groupKeys.end()) {
                groupKey = kit->second;
            }
        }

        if (groupKey.empty()) {
            cerr << "[Fetcher] Error: Group key not found locally for file: " << fileName << endl;
            SSL_shutdown(peerSSL);
            SSL_free(peerSSL);
            close(sock);
            return false;
        }

        // Decrypt AES
        outChunkData = decryptAES(ciphertext, groupKey, ivHex);
        if (outChunkData.empty()) {
            cerr << "[Fetcher] Error: AES decryption failed for chunk " << chunkIndex << endl;
            SSL_shutdown(peerSSL);
            SSL_free(peerSSL);
            close(sock);
            return false;
        }

        // verify hash
        string localHash = sha1_hex_buffer(reinterpret_cast<const unsigned char*>(outChunkData.data()), outChunkData.size());
        if (localHash != serverHash) {
            cerr << "[Fetcher] CHUNK hash mismatch for " << fileName << " idx=" << chunkIndex << " expected=" << serverHash << " got=" << localHash << "\n";
            SSL_shutdown(peerSSL);
            SSL_free(peerSSL);
            close(sock);
            return false;
        }

        const char *ack = "CHUNK HASH VERIFIED\n";
        int as = SSL_write(peerSSL, ack, strlen(ack));
        if (as <= 0) {
            cerr << "Failed to send ACK: " << ERR_error_string(ERR_get_error(), nullptr) << "\n";
        } else {
            cout << "CHUNK HASH VERIFIED for " << "index = " << chunkIndex << "\n";
        }
        SSL_shutdown(peerSSL);
        SSL_free(peerSSL);
        close(sock);
        return true;
    } 

    else {
        // if its neither error nor chunk then just close the process 
        SSL_shutdown(peerSSL);
        SSL_free(peerSSL);
        close(sock);
        return false;
    }
}