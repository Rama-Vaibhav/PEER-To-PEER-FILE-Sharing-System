#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <bits/stdc++.h>
#include <mutex>
using namespace std;
struct User {
    string username;
    string password;
    bool logged_in;
    string ip;
    int port;

    User() : logged_in(false),port(0) {}
    User(const string &uid, const string &pwd)
        : username(uid), password(pwd), logged_in(false),port(0) {}
};

struct FileMetadata{
    string group_id;
    string username;
    string filename;
    string local_path;
    size_t filesize;
    string file_hash; //sha1 of full file(40 chars hex)
    vector<string> piece_hashes; //sha1 per 512kb chunk
    string ip;
    int port;
    vector<string> seeders;
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

#endif // COMMON_H
