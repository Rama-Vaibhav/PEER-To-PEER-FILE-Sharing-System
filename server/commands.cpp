#include "commands.h"
#include "common.h"
// Helper function to read a line from a socket (simple implementation)
#include <unistd.h>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <iostream>

using namespace std;

// This map definition should be in common.cpp, but leaving it here if your structure needs it.
// Consider moving it if you haven't already.
unordered_map<string, Group> groups;

// Helper tokenize
static vector<string> tokenize(const string &s) {
    istringstream iss(s);
    vector<string> tokens{istream_iterator<string>{iss}, istream_iterator<string>{}};
    return tokens;
}

// Command implementations (Your original functions are preserved)
string cmd_create_user(const string &username, const string &password) {
    lock_guard<mutex> lock(state_mutex);
    if (users.find(username) != users.end()) {
        return "User already exists\n";
    }
    User u;
    u.username = username;
    u.password = password;
    u.logged_in = false;
    users[username] = std::move(u);
    send_sync_update("SYNC|CREATE_USER|"+username+"|"+password);
    cout<< "[server] User '" << username << "' created successfully\n";
    return "User created successfully\n";
}

static string cmd_login(const string &username, const string &password, const string &client_addr, string &current_user) {
    lock_guard<mutex> lock(state_mutex);
    auto it = users.find(username);
    if (it == users.end()) return "No such user\n";
    if (it->second.password != password) return "Incorrect password\n";
    if (it->second.logged_in) return "User already logged in elsewhere\n";
    
    size_t colon_pos = client_addr.find(':');
    if (colon_pos == string::npos) {
        return "ERROR: Invalid client address format from client.\n";
    }
    string ip = client_addr.substr(0, colon_pos);
    int port = stoi(client_addr.substr(colon_pos + 1));

    it->second.ip = ip;
    it->second.port = port;
    it->second.logged_in = true;
    current_user = username;
    cout << "[SERVER] User '" << username << "' logged in from " << ip << ":" << port << "\n";
    return "Login successful\n";
}

static string cmd_logout(string &current_user) {
    if (current_user.empty()) return "No user logged in\n";
    lock_guard<mutex> lock(state_mutex);
    auto it = users.find(current_user);
    if (it != users.end()) it->second.logged_in = false;
    current_user.clear();
    return "Logout successful\n";
}

static string cmd_create_group(const string &group_id, const string &current_user) {
    if (current_user.empty()) return "Please login first\n";
    lock_guard<mutex> lock(state_mutex);
    if (groups.find(group_id) != groups.end()) return "Group already exists\n";
    Group g;
    g.group_id = group_id;
    g.owner = current_user;
    g.members.push_back(current_user);
    groups[group_id] = std::move(g);
    cout<<"[server] Group '" << group_id << "' created by user '" << current_user << "'\n";
    string sync_msg="SYNC|CREATE_GROUP|" +group_id+"|"+current_user+"\n";
    send_sync_update(sync_msg);
    return "Group created successfully\n";
}

static string cmd_join_group(const string &group_id, const string &current_user) {
    if (current_user.empty()) return "Please login first\n";
    lock_guard<mutex> lock(state_mutex);
    auto git = groups.find(group_id);
    if (git == groups.end()) return "Group not found\n";
    Group &g = git->second;
    if (find(g.members.begin(), g.members.end(), current_user) != g.members.end())
        return "Already a member\n";
    if (find(g.pending_requests.begin(), g.pending_requests.end(), current_user) != g.pending_requests.end())
        return "Join request already pending\n";
    g.pending_requests.push_back(current_user);
    send_sync_update("SYNC|JOIN_GROUP|" + group_id + "|" + current_user);
    return "Join request sent\n";
}

static string cmd_leave_group(const string &group_id, const string &current_user) {
    if (current_user.empty()) return "Please login first\n";
    lock_guard<mutex> lock(state_mutex);
    auto git = groups.find(group_id);
    if (git == groups.end()) return "Group not found\n";
    Group &g = git->second;

    auto mit = find(g.members.begin(), g.members.end(), current_user);
    if (mit == g.members.end()) return "You are not a member of this group\n";

    if (g.owner == current_user) {
        g.members.erase(mit); 
        if (g.members.empty()) {
            groups.erase(git);
            send_sync_update("SYNC|DELETE_GROUP|" + group_id);
            return "You were the last member. Group deleted.\n";
        } else {
            string new_owner = g.members[0];
            g.owner = new_owner;
            send_sync_update("SYNC|CHOWN|" + group_id + "|" + new_owner);
            send_sync_update("SYNC|LEAVE_GROUP|" + group_id + "|" + current_user);
            return "You have left the group. Ownership transferred to user '" + new_owner + "'.\n";
        }
    } else {
        g.members.erase(mit);
        send_sync_update("SYNC|LEAVE_GROUP|" + group_id + "|" + current_user);
        return "Left group\n";
    }
}

static string cmd_list_groups() {
    lock_guard<mutex> lock(state_mutex);
    if (groups.empty()) return "No groups\n";
    string out;
    for (const auto &p : groups) {
        out += p.first + " (owner: " + p.second.owner + ")\n";
    }
    return out;
}

static string cmd_list_requests(const string &group_id, const string &current_user) {
    if (current_user.empty()) return "Please login first\n";
    lock_guard<mutex> lock(state_mutex);
    auto git = groups.find(group_id);
    if (git == groups.end()) return "Group not found\n";
    Group &g = git->second;
    if (g.owner != current_user) return "Only the owner can view requests\n";
    if (g.pending_requests.empty()) return "No pending requests\n";
    string out;
    for (auto &u : g.pending_requests) out += u + "\n";
    return out;
}

static string cmd_accept_request(const string &group_id, const string &user_id, const string &current_user) {
    if (current_user.empty()) return "Please login first\n";
    lock_guard<mutex> lock(state_mutex);
    auto git = groups.find(group_id);
    if (git == groups.end()) return "Group not found\n";
    Group &g = git->second;
    if (g.owner != current_user) return "Only the owner can accept requests\n";
    auto pit = find(g.pending_requests.begin(), g.pending_requests.end(), user_id);
    if (pit == g.pending_requests.end()) return "No pending request from that user\n";
    g.members.push_back(user_id);
    g.pending_requests.erase(pit);
    send_sync_update("SYNC|ACCEPT_REQUEST|"+group_id+"|"+user_id);
    return "Request accepted\n";
}

// The main command processing function
string process_command(const string &cmd_line, string &current_user, int newsockfd) {
    auto tokens = tokenize(cmd_line);
    if (tokens.empty()) return "Invalid command\n";

    string cmd = tokens[0];
    
    if (cmd == "create_user" && tokens.size() == 3) {
        return cmd_create_user(tokens[1], tokens[2]);
    }
    else if (cmd == "login" && tokens.size() == 4) {
        return cmd_login(tokens[1], tokens[2], tokens[3], current_user);
    }
    else if (cmd == "logout") {
        return cmd_logout(current_user);
    }
    else if (cmd == "create_group" && tokens.size() == 2) {
        return cmd_create_group(tokens[1], current_user);
    }
    else if (cmd == "join_group" && tokens.size() == 2) {
        return cmd_join_group(tokens[1], current_user);
    }
    else if (cmd == "leave_group" && tokens.size() == 2) {
        return cmd_leave_group(tokens[1], current_user);
    }
    else if (cmd == "list_groups" && tokens.size() == 1) {
        return cmd_list_groups();
    }
    else if (cmd == "list_requests" && tokens.size() == 2) {
        return cmd_list_requests(tokens[1], current_user);
    }
    else if (cmd == "accept_request" && tokens.size() == 3) {
        return cmd_accept_request(tokens[1], tokens[2], current_user);
    }
    
    else if (cmd == "UPLOAD_FILE") {
        // BUG FIX: Added login check
        if (current_user.empty()) {
            return "ERROR: You must be logged in to upload a file.\n";
        }
        if (tokens.size() != 6) {
            return "ERROR: Invalid UPLOAD_FILE command format.\n";
        }
        string groupid = tokens[1];
        string filename = tokens[2];
        long long filesize = stoll(tokens[3]);
        string file_hash = tokens[4];
        string all_hashes_str = tokens[5];

        lock_guard<mutex> lock(state_mutex);
        auto group_it = groups.find(groupid);
        if (group_it == groups.end()) {
            return "ERROR: Group not found.\n";
        }
        Group& group = group_it->second;

        auto member_it = find(group.members.begin(), group.members.end(), current_user);
        if (member_it == group.members.end()) {
            return "ERROR: You are not a member of this group.\n";
        }

        if (group.files.count(filename)) {
            return "ERROR: A file with this name already exists in the group.\n";
        }

        FileMetadata new_file;
        new_file.filesize = filesize;
        new_file.file_hash = file_hash;
        new_file.seeders.push_back(current_user);

        // Parse the pipe-separated hashes from the single token
        stringstream hash_stream(all_hashes_str);
        string piece_hash;
        while(getline(hash_stream, piece_hash, '|')) {
            if (!piece_hash.empty()) {
                new_file.piece_hashes.push_back(piece_hash);
            }
        }

        group.files[filename] = new_file;
        cout << "[SERVER] User '" << current_user << "' uploaded metadata for file '" << filename << "'\n";

        // Synchronize the update with the other tracker
        string sync_data = groupid + "|" + filename + "|" + to_string(filesize) + "|" + file_hash;
        for (const auto& hash : new_file.piece_hashes) {
            sync_data += "|" + hash;
        }
        sync_data += "|" + current_user; // Add the first seeder
        send_sync_update("SYNC|UPLOAD_FILE|" + sync_data);

        return "SUCCESS: File metadata uploaded successfully.\n";
    }
    else if (cmd == "DOWNLOAD_FILE") {
        if (current_user.empty()) {
            return "ERROR: You must be logged in to download a file.\n";
        }
        if (tokens.size() != 3) {
            return "ERROR: Invalid download_file format.\n";
        }
        string groupid = tokens[1];
        string filename = tokens[2];
        lock_guard<mutex> lock(state_mutex);

        auto group_it = groups.find(groupid);
        if (group_it == groups.end()) {
            return "ERROR: Group not found.\n";
        }
        auto file_it = group_it->second.files.find(filename);
        if (file_it == group_it->second.files.end()) {
            return "ERROR: File not found in this group.\n";
        }
        if (file_it->second.seeders.empty()) {
            return "ERROR: No seeders currently available for this file.\n";
        }

        FileMetadata& meta = file_it->second;
        
        // BUG FIX: Send ALL online seeders, not just the first one
        // Build comma-separated list of online seeder addresses
        string seeder_addrs;
        for (const auto& seeder_username : meta.seeders) {
            auto user_it = users.find(seeder_username);
            if (user_it != users.end() && user_it->second.logged_in) {
                if (!seeder_addrs.empty()) seeder_addrs += ",";
                seeder_addrs += user_it->second.ip + ":" + to_string(user_it->second.port);
            }
        }
        
        if (seeder_addrs.empty()) {
            return "ERROR: No online seeders available.\n";
        }
        
        string response = "DOWNLOAD_INFO " + to_string(meta.filesize) + " " + seeder_addrs + " ";
        
        for (const auto& hash: meta.piece_hashes) {
            response += "|" + hash;
        }
        response += "\n";
        return response;
    }
    else if (cmd == "UPDATE_SEEDER") {
        if (current_user.empty()) return "ERROR: Not logged in.\n";
        if (tokens.size() != 3) return "ERROR: Invalid update_seeder format.\n";

        string group_id = tokens[1];
        string filename = tokens[2];
        lock_guard<mutex> lock(state_mutex);

        auto group_it = groups.find(group_id);
        if (group_it != groups.end()) {
            auto file_it = group_it->second.files.find(filename);
            if (file_it != group_it->second.files.end()) {
                auto& seeders = file_it->second.seeders;
                if (find(seeders.begin(), seeders.end(), current_user) == seeders.end()) {
                    seeders.push_back(current_user);
                    cout << "[SERVER] User '" << current_user << "' is now a new seeder for file '" << filename << "'.\n";
                    send_sync_update("SYNC|ADD_SEEDER|" + group_id + "|" + filename + "|" + current_user);
                }
            }
        }
        // BUG FIX: Return "OK" instead of empty string to avoid protocol desync
        return "OK\n";
    }
    else if (cmd == "LIST_FILES") {
        if (tokens.size() != 2) return "Usage: LIST_FILES <group_id>\n";
        string group_id = tokens[1];
        string response = "";

        lock_guard<mutex> lock(state_mutex);
        auto it = groups.find(group_id);
        if (it != groups.end()) {
            if (it->second.files.empty()) {
                response = "No files in this group.\n";
            }
            for (const auto& file_pair : it->second.files) {
                response += file_pair.first + " (" + to_string(file_pair.second.filesize) + " bytes)\n";
            }
        } else {
            response = "Group not found.\n";
        }
        response += "END_OF_LIST\n";
        return response;
    }
    else if (cmd == "STOP_SEEDING") {
        if (tokens.size() != 3) return "Usage: STOP_SEEDING <group_id> <filename>\n";
        if (current_user.empty()) return "Not logged in.\n";

        string group_id = tokens[1];
        string filename = tokens[2];
        string response = "Could not stop sharing file.\n";

        lock_guard<mutex> lock(state_mutex);
        auto group_it = groups.find(group_id);
        if (group_it != groups.end()) {
            auto file_it = group_it->second.files.find(filename);
            if (file_it != group_it->second.files.end()) {
                auto& seeders = file_it->second.seeders;
                auto seeder_it = std::find(seeders.begin(), seeders.end(), current_user);
                if (seeder_it != seeders.end()) {
                    seeders.erase(seeder_it);
                    response = "Tracker updated. You are no longer listed as a seeder.\n";
                    send_sync_update("SYNC|STOP_SEEDING|" + group_id + "|" + filename + "|" + current_user);
                }
            }
        }
        return response;
    }

    return "Unknown command or incorrect usage.\n";
}