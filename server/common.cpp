#include "common.h"
#include <sstream>
#include <unistd.h>
#include <iostream>
#include <algorithm>
#include <iomanip>
using namespace std;
// Global variables
unordered_map<string, User> users;
mutex state_mutex;
int sync_sockfd = -1;
mutex sync_mutex;
string read_line_from_socket(int sockfd);

vector<string> split(const string &s, char delimiter) {
    vector<string> tokens;
    string token;
    istringstream tokenStream(s);
    while (getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

string generate_salt() {
    unsigned char buf[16];
    RAND_bytes(buf, 16);
    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < 16; ++i)
        ss << setw(2) << (int)buf[i];
    return ss.str();
}

string hash_password(const string &password, const string &salt) {
    string salted = salt + password;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(salted.c_str()), salted.size(), hash);
    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        ss << setw(2) << (int)hash[i];
    return ss.str();
}

void send_sync_update(const string &msg) {
    lock_guard<mutex> lock(sync_mutex);
    if (sync_sockfd!=-1) {
        // Ensure newline framing for the receiver
        string framed = msg;
        if (framed.empty() || framed.back()!='\n') framed.push_back('\n');
        int n = write(sync_sockfd, framed.c_str(), framed.size());
        if (n < 0) 
        {
            cerr << "Error: failed to write sync message\n";
        }
    }
}

void process_sync_message(const string &msg) {
    auto parts = split(msg, '|');
    if(parts.size()<2 || parts[0]!="SYNC") return;

    if(parts[1]=="CREATE_USER") {
        if(parts.size() < 4) return;
        string uid = parts[2];
        string pwd_or_hash = parts[3];
        string salt = (parts.size() >= 5) ? parts[4] : "";
        lock_guard<mutex> lock(state_mutex);
        if (users.find(uid) == users.end()) {
            User u(uid, pwd_or_hash, salt);
            users[uid] = u;
            cout << "[SYNC] Created user " << uid << " from peer\n";
        }
    }
    else if (parts[1] == "CREATE_GROUP") {
        if (parts.size() < 4) return;
        string gid = parts[2];
        string owner = parts[3];

        lock_guard<mutex> lock(state_mutex);
        if (groups.find(gid) == groups.end()) {
            Group g;
            g.group_id=gid;
            g.owner=owner;
            g.members.push_back(owner);
            groups[gid]=std::move(g);
            cout << "[SYNC] Created group " << gid << " with owner " << owner << " from peer\n";
        }
    }
    else if(parts[1]=="JOIN_GROUP") {
        if(parts.size() < 4) return;
        string gid=parts[2];
        string user=parts[3];
        lock_guard<mutex> lock(state_mutex);
        auto it=groups.find(gid);
        if(it!=groups.end()) {
            Group &g=it->second;
            if(find(g.pending_requests.begin(),g.pending_requests.end(),user)==g.pending_requests.end()) {
                g.pending_requests.push_back(user);
                cout << "[SYNC] User " << user << " requested to join group " << gid << " from peer\n";
            }
        }
    }
    else if(parts[1]=="ACCEPT_REQUEST" && parts.size()==4) {
        string gid=parts[2];
        string uid=parts[3];
        // BUG FIX: was missing state_mutex lock — data race on groups map
        lock_guard<mutex> lock(state_mutex);
        auto it=groups.find(gid);
        if(it!=groups.end()) {
            Group &g=it->second;
            auto pit=find(g.pending_requests.begin(),g.pending_requests.end(),uid);
            if(pit!=g.pending_requests.end()) {
                g.members.push_back(uid);
                g.pending_requests.erase(pit);
                cout<<"[SYNC] Accepted request of "<<uid<<" for group "<<gid<<" from peer\n";
            }
        }
    }
    else if (parts[1] == "LEAVE_GROUP" && parts.size() == 4) {
        string gid = parts[2];
        string uid = parts[3];
        lock_guard<mutex> lock(state_mutex);
        auto git = groups.find(gid);
        if (git != groups.end()) {
            Group &g = git->second;
            auto mit = find(g.members.begin(), g.members.end(), uid);
            if (mit != g.members.end()) {
                g.members.erase(mit);
                cout << "[SYNC] User " << uid << " left group " << gid << "\n";
            }
        }
    }
    // BUG FIX: DELETE_GROUP sync was sent but never handled
    else if (parts[1] == "DELETE_GROUP" && parts.size() == 3) {
        string gid = parts[2];
        lock_guard<mutex> lock(state_mutex);
        auto it = groups.find(gid);
        if (it != groups.end()) {
            groups.erase(it);
            cout << "[SYNC] Deleted group " << gid << " from peer\n";
        }
    }
    // BUG FIX: CHOWN sync was sent but never handled
    else if (parts[1] == "CHOWN" && parts.size() == 4) {
        string gid = parts[2];
        string new_owner = parts[3];
        lock_guard<mutex> lock(state_mutex);
        auto it = groups.find(gid);
        if (it != groups.end()) {
            it->second.owner = new_owner;
            cout << "[SYNC] Ownership of group " << gid << " transferred to " << new_owner << " from peer\n";
        }
    }
    else if(parts[1] == "UPLOAD_FILE")
    {
        if(parts.size()<8)
        return ;
        string groupid=parts[2];
        string filename = parts[3];
        long long filesize = stoll(parts[4]);
        string file_hash = parts[5];
        string initial_seeder = parts.back();
        vector<string> piece_hashes;
        for(size_t i=6;i<parts.size()-1;++i)
        {
            piece_hashes.push_back(parts[i]);
        }
        lock_guard<mutex> lock(state_mutex);
        auto group_it=groups.find(groupid);
        if(group_it!=groups.end() &&!group_it->second.files.count(filename))
        {
            FileMetadata new_file;
            new_file.filesize=filesize;
            new_file.file_hash=file_hash;
            new_file.piece_hashes=piece_hashes;
            new_file.seeders.push_back(initial_seeder);

            group_it->second.files[filename]=new_file;
            cout << "[SYNC] Received metadata for file '" << filename << "' in group '" << groupid << "'\n";
        }
    }
    else if (parts[1] == "ADD_SEEDER" && parts.size() == 5) {
        string group_id = parts[2];
        string filename = parts[3];
        string new_seeder = parts[4];

        lock_guard<mutex> lock(state_mutex);

        // Find the group and then the file
        auto group_it = groups.find(group_id);
        if (group_it != groups.end()) {
            auto file_it = group_it->second.files.find(filename);
            if (file_it != group_it->second.files.end()) {
                
                // Add the new seeder to the list if they aren't already there
                auto& seeders = file_it->second.seeders;
                if (find(seeders.begin(), seeders.end(), new_seeder) == seeders.end()) {
                    seeders.push_back(new_seeder);
                    cout << "[SYNC] Added '" << new_seeder << "' as a seeder for file '" << filename << "'\n";
                }
            }
        }
    }
    // STOP_SEEDING sync handler
    else if (parts[1] == "STOP_SEEDING" && parts.size() == 5) {
        string group_id = parts[2];
        string filename = parts[3];
        string seeder = parts[4];
        lock_guard<mutex> lock(state_mutex);
        auto group_it = groups.find(group_id);
        if (group_it != groups.end()) {
            auto file_it = group_it->second.files.find(filename);
            if (file_it != group_it->second.files.end()) {
                auto& seeders = file_it->second.seeders;
                auto sit = find(seeders.begin(), seeders.end(), seeder);
                if (sit != seeders.end()) {
                    seeders.erase(sit);
                    cout << "[SYNC] Removed '" << seeder << "' as seeder for '" << filename << "'\n";
                }
            }
        }
    }
}
