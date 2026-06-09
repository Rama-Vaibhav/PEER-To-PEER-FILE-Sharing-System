#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#include <map>
#include <mutex>
#include <vector>
#include <unordered_map>
#include <openssl/ssl.h>

void sendCommands(SSL* trackerSSL, const std::string &clientIP, int clientPort, const std::string &trackerIP1, int trackerPort1, const std::string &trackerIP2, int trackerPort2);
bool extractTrackerInfo(const std::string &tracker_info, std::string &trackerIP1, int &trackerPort1, std::string &trackerIP2, int &trackerPort2);
int connectToTracker(const std::string &trackerIP1, int trackerPort1, const std::string &trackerIP2, int trackerPort2);

// TLS wrapper for tracker connections — wraps raw socket fd in SSL
SSL* connectToTrackerSSL(const std::string &trackerIP1, int trackerPort1, const std::string &trackerIP2, int trackerPort2);

// this is for the file storage on the client side 
extern std::mutex localPathMutex;
extern std::unordered_map<std::string, std::string> fileNameToPath; // key: fileName -> local file path
extern std::unordered_map<std::string, std::string> fileNameToGroupId; // key: fileName -> groupId
void addLocalFilePath(const std::string &fileName, const std::string &filePath);
std::string getLocalFilePath(const std::string &fileName);
void removeLocalFilePath(const std::string &fileName);

// functionality related to calculating the sha
std::string sha1_hex_buffer(const unsigned char *buf, size_t len);
std::string sha1_hex_of_file(const std::string& path);

void startDownloadFromTrackerResponse(const std::string &trackerResp, const std::string &groupId, const std::string &fileName,
                                      const std::string &destPath, const std::string &clientIP, int clientPort,
                                      SSL* trackerSSLIfAvailable);

// for p2p communication 
void runPeerServer(int listenPort); // starts blocking server loop (call in a detached thread)
bool fetchChunkFromPeer(const std::string &peerIp, int peerPort, const std::string &fileName, int chunkIndex,
                        const std::string &localDestPath, size_t chunkSize, std::vector<char> &outChunkData); // returns chunk bytes in outChunkData

int isPeerOnline(const std::string &userId);
void notifyTracker(SSL* trackerSSL, const std::string& line);

struct DownloadStatus {
    std::string fileName;
    std::string gid;
    int numChunks;
    std::vector<int> chunkDone;
    bool completed = false;
    bool failed = false;
};
extern std::map<std::string, DownloadStatus> downloads;

extern std::string g_currentUsername;
extern std::unordered_map<std::string, std::string> g_groupKeys;

// TLS utilities (Fix 2)
extern SSL_CTX* g_clientSSLCtx;      // for outgoing connections (tracker, peers)
extern SSL_CTX* g_peerServerSSLCtx;  // for accepting peer chunk requests
void initOpenSSL();
SSL_CTX* initClientSSLCtx(const std::string& caPath);
SSL_CTX* initPeerServerSSLCtx(const std::string& certPath, const std::string& keyPath);
SSL* acceptSSL(SSL_CTX* ctx, int clientFd);
SSL* connectSSL(SSL_CTX* ctx, int sockFd);

#endif
