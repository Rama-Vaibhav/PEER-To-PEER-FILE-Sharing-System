#include "client.h"
#include "../common/cryptoUtil.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>
#include <sstream>
#include <thread>
#include <sys/stat.h>
#include <openssl/ssl.h>

using namespace std;

static const size_t DEFAULT_CHUNK_SIZE = 512 * 1024;   // 512 Kb

// Reliable sender over SSL: make sure "ALL" bytes in buffer are sent
static bool sendAllSSL(SSL* ssl, const char *buffer, size_t totalBytesToBeSent) {
    size_t totalBytesSent = 0;
    while (totalBytesSent < totalBytesToBeSent) {
        int bytesSent = SSL_write(ssl, buffer + totalBytesSent, totalBytesToBeSent - totalBytesSent);
        if (bytesSent <= 0) return false;
        totalBytesSent += bytesSent;
    }
    return true;
}

// think of this function as the chunk uploader, as this is the server so some client will ask for some chunk and that
// thing would be managed through this function
void handleChunkRequest(SSL* ssl) {
    // REQUEST_CHUNK file.mp4 3
    // 1. Read the first request 
    string requestLine;
    char ch;
    while (true) {
        int bytesReceived = SSL_read(ssl, &ch, 1);
        if (bytesReceived <= 0) { 
            int fd = SSL_get_fd(ssl);
            SSL_shutdown(ssl); SSL_free(ssl); close(fd); 
            return; 
        }
        if (ch == '\n') break;
        requestLine.push_back(ch);
    }

    // 2. parse: REQUEST_CHUNK <fileName> <chunkIndex>
    istringstream ss(requestLine);
    string command, fileName;
    int requestedChunkIndex;
    ss >> command >> fileName >> requestedChunkIndex;

    // 3. find local path from the file name
    string path;
    {
        std::lock_guard<std::mutex> l(localPathMutex);
        auto it = fileNameToPath.find(fileName);
        if (it != fileNameToPath.end()) {
            path = it->second;
        }
    }
    if (path.empty()) {
        string err = string("ERROR file not found\n");
        sendAllSSL(ssl, err.c_str(), err.size());
        int fd = SSL_get_fd(ssl);
        SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        return;
    }

    // stat file to compute offset
    // 4. Open the file and then check the bounds for the requested chunk
    struct stat st;
    stat(path.c_str(), &st);

    size_t chunkSize = DEFAULT_CHUNK_SIZE;
    // it checks whether the requested chunk actually exists in the file before reading it from there
    off_t offset = (off_t)requestedChunkIndex * (off_t)chunkSize;

    // open and read the chunk
    int sourceFileFd = open(path.c_str(), O_RDONLY);
    if (sourceFileFd < 0) {
        string err = string("ERROR failed to open the file\n");
        sendAllSSL(ssl, err.c_str(), err.size());
        int fd = SSL_get_fd(ssl);
        SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        return;
    }

    // this will ensure that even when the size of the last chunk is less than 512 KB still it will properly handle it
    size_t toRead = chunkSize;
    if ((off_t)(offset + (off_t)chunkSize) > st.st_size) {
        toRead = st.st_size - offset;   // number of bytes to be read 
    }

    // we will go to the particular location from where the requested chunk actually starts
    if (lseek(sourceFileFd, offset, SEEK_SET) == -1) {
        string err = string("ERROR failed to seek in the file\n");
        sendAllSSL(ssl, err.c_str(), err.size());
        close(sourceFileFd);
        int fd = SSL_get_fd(ssl);
        SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        return;
    }

    // we are going to store the read bytes in this buffer and we are reading from the file 
    vector<char> buf(toRead);  // this will allocate the size according to the chunk size which will be <= 512 KB
    ssize_t bytesRead = read(sourceFileFd, buf.data(), toRead);
    close(sourceFileFd);
    if (bytesRead <= 0) {
        string err = string("ERROR failed to read from the file\n");
        sendAllSSL(ssl, err.c_str(), err.size());
        int fd = SSL_get_fd(ssl);
        SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        return;
    }

    // Get Group Key
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
        string err = string("ERROR Group key not found for file\n");
        sendAllSSL(ssl, err.c_str(), err.size());
        int fd = SSL_get_fd(ssl);
        SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        return;
    }

    // Encrypt Chunk Data
    string ivHex;
    vector<char> ciphertext = encryptAES(buf, groupKey, ivHex);
    if (ciphertext.empty()) {
        string err = string("ERROR Failed to encrypt chunk\n");
        sendAllSSL(ssl, err.c_str(), err.size());
        int fd = SSL_get_fd(ssl);
        SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        return;
    }

    // calculated hash value for that particular plaintext chunk
    string chunkHash = sha1_hex_buffer(reinterpret_cast<const unsigned char*>(buf.data()), buf.size());
    // Send header: CHUNK <size_of_ciphertext> <shaHash> <ivHex>\n then raw encrypted bytes
    ostringstream hdr;
    hdr << "CHUNK " << ciphertext.size() << " " << chunkHash << " " << ivHex << "\n";
    string header = hdr.str();
    // first we are sending the header and then we are sending the actual raw data
    if (!sendAllSSL(ssl, header.c_str(), header.size())) {
        int fd = SSL_get_fd(ssl);
        SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        return;
    }
    if (!sendAllSSL(ssl, ciphertext.data(), ciphertext.size())) {
        int fd = SSL_get_fd(ssl);
        SSL_shutdown(ssl); SSL_free(ssl); close(fd);
        return;
    }
    int fd = SSL_get_fd(ssl);
    SSL_shutdown(ssl); SSL_free(ssl); close(fd);
}

/********************************************************************************************************
     This will allow the peer to act as a client and also it will create threads for all the clients
    which are trying to connect with it
********************************************************************************************************/
void runPeerServer(int listenPort) {
    int listenSock = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock < 0) {
        perror("peer server socket");
        return;
    }

    int opt = 1;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listenPort);
    addr.sin_addr.s_addr = INADDR_ANY; // bind all interfaces

    if (::bind(listenSock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("peer server bind");
        close(listenSock);
        return;
    }

    if (listen(listenSock, 16) < 0) {
        perror("peer server listen");
        close(listenSock);
        return;
    }

    // now the peer server has started running successfully on this port

    while (true) {
        int clientSock = accept(listenSock, nullptr, nullptr);
        if (clientSock < 0) continue;

        // Wrap accepted socket in TLS (Fix 2)
        SSL* peerSSL = acceptSSL(g_peerServerSSLCtx, clientSock);
        if (!peerSSL) {
            cerr << "\033[31m[PeerServer] TLS handshake failed\033[0m\n";
            close(clientSock);
            continue;
        }

        // handle each peer in a detached thread and this will help to share or upload the chunk to another peer
        thread t(handleChunkRequest, peerSSL);
        t.detach();
    }

    close(listenSock);
}
