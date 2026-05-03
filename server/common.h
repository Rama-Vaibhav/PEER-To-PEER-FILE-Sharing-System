#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <algorithm>
#include <mutex>
#include <openssl/sha.h>
#include <openssl/rand.h>
using namespace std;
struct User {
    string username;
    string password;     // stores SHA-256 hash (not plaintext)
    string password_salt; // 16-byte random salt (hex-encoded)
    bool logged_in;
    string ip;
    int port;

    User() : logged_in(false),port(0) {}
    User(const string &uid, const string &pwd, const string &salt = "")
        : username(uid), password(pwd), password_salt(salt), logged_in(false),port(0) {}
};

struct FileMetadata{
    string group_id;
    string username;
    string filename;
    string local_path;
    size_t filesize;
    string file_hash; // SHA-256 of full file (64 chars hex)
    vector<string> piece_hashes; // SHA-256 per 512KB chunk
    string ip;
    int port;
    vector<string> seeders;
    // RSA-2048 digital signature fields
    string signature;         // hex-encoded RSA signature of metadata
    string uploader_pubkey;   // hex-encoded PEM public key of uploader
};

struct Group {
    string group_id;
    string owner; // username
    vector<string> members;
    vector<string> pending_requests;
    map<string,FileMetadata> files;
};
// ----------------------
// Global State
// ----------------------
extern unordered_map<string, User> users;
extern unordered_map<string, Group> groups;
extern mutex state_mutex; // protects users & groups

// Sync socket fd (set once connected to peer tracker)
extern int sync_sockfd;
extern mutex sync_mutex;

// ----------------------
// Utility
// ----------------------
vector<string> split(const string &s, char delimiter);
void send_sync_update(const string &msg);
void process_sync_message(const string &msg);
string generate_salt();
string hash_password(const string &password, const string &salt);

#endif // COMMON_H
