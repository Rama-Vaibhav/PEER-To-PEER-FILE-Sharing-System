#ifndef TRACKER_H
#define TRACKER_H

#include <string>
#include <unordered_map>
#include <set>
#include <mutex>
#include <openssl/ssl.h>

// this struct will store all the basic meta data information related to the user
struct User {
    std::string userId;
    std::string passwordHash;  // SHA-256 hash of (salt + password) — NEVER store plaintext
    std::string salt;          // per-user random salt (hex-encoded, 32 chars)
    std::string publicKeyPEM;  // RSA public key (PEM format)
    bool loggedIn = false;
    std::string ip; // ip for peer communication
    int port; // port for peer communication
    int failedAttempts = 0;
    time_t lockTime = 0;
}; 

// this struct will have all the file metadata related to the file 
struct FileInfo {
    std::string fileName;  // basename only (e.g., "song.mp3")
    size_t fileSize = 0; // total size of the file in bytes
    int numChunks = 0;  // number of chunks
    std::unordered_map<int, std::set<std::string>> chunkToPeers;  // chunk to peerId {ip:port}
    std::unordered_map<std::string, std::set<int>> peerToChunks; // peerId {ip:port} to chunk 
    std::string fileShaHex;
    std::string uploaderId;
    std::string fileSignature; // Signature of fileShaHex signed by uploader
};

// Data structures which will be used globally, and changes can be made parallely hence we need to protect them with the lock
extern std::mutex usersInfoMutex;
extern std::unordered_map<std::string, User> usersInfo; // userid -> User struct

// this mutex will be used for all the groups maps
extern std::mutex groupsMutex;
extern std::unordered_map<std::string, std::string> groupOwners;  // groupid -> ownerUserId
extern std::unordered_map<std::string, std::set<std::string>> groupMembers; // groupid -> members ids
extern std::unordered_map<std::string, std::set<std::string>> groupJoinRequests; // groupid -> pending user id
extern std::unordered_map<std::string, std::unordered_map<std::string, std::string>> groupKeys; // groupid -> (userid -> encrypted_key_hex)

// this mutex will be used for the activeSessions
extern std::mutex sessionMutex;
extern std::unordered_map<int, std::string> activeSessions;  // socket fd -> userid
extern std::unordered_map<int, std::string> pendingChallenges; // socket fd -> challenge_hex

// Important functions for connection with the tracker and handling commands which we will receive from the tracker 
void handleClientCommands(SSL* ssl);
bool extractTrackerInfo(const std::string &tracker_info, int &trackerNumber, std::string &currTrackerIP, int &currTrackerPort);
int startTrackerServer(const std::string &ip, int port);

// For tracker sync
extern SSL* peerTrackerSSL;
extern std::mutex peerSendMutex;
void keepPeerConnected(std::string peerIP, int peerPort);
bool connectToPeerTracker(const std::string &peerIP, int peerPort);
void forwardToPeer(const std::string &message);
void peerSyncListener();
void applyCommand(const std::string &message, SSL* ssl, bool isSync, const std::string &verifiedIP = "");

// Global file table: groupId -> (fileName -> FileInfo)
extern std::mutex fileTableMutex;
extern std::unordered_map<std::string, std::unordered_map<std::string, FileInfo>> fileTable;

// functions related to the files 
void handleDownload (std::string cmd, const std::string &message, SSL* ssl, bool isSync);
bool removePeerFromFile(const std::string& groupid, const std::string& fileName, const std::string& peerId);

// Password hashing utilities (Fix 1)
std::string generateSalt();
std::string hashPassword(const std::string& password, const std::string& salt);

// TLS utilities (Fix 2)
extern SSL_CTX* g_serverSSLCtx;
extern SSL_CTX* g_clientSSLCtx;
void initOpenSSL();
SSL_CTX* initServerSSLCtx(const std::string& certPath, const std::string& keyPath);
SSL_CTX* initClientSSLCtx(const std::string& caPath);
SSL* acceptSSL(SSL_CTX* ctx, int clientFd);
SSL* connectSSL(SSL_CTX* ctx, int sockFd);

#endif 