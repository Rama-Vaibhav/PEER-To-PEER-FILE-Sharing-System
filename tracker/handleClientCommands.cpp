#include "tracker.h"
#include "../common/cryptoUtil.h"
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <regex>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <cstring>

using namespace std;

// Helper: SSL_write wrapper matching old send() pattern
static void sslSend(SSL* ssl, const string &msg) {
    if (ssl) SSL_write(ssl, msg.c_str(), msg.size());
}

void applyCommand(const string &message, SSL* ssl, bool isSync, const string &verifiedIP) {
    stringstream ss(message);
    string cmd;
    ss >> cmd;

    /********************************************************************************************************
                                            Create User Command
    ********************************************************************************************************/   
    if (cmd == "create_user") {
        string userid, password, pubkeyHex;
        ss >> userid >> password;

        {
            lock_guard<mutex> lock(usersInfoMutex);
            if (usersInfo.find(userid) != usersInfo.end()) {
                // User already exists
                if (!isSync) {
                    sslSend(ssl, "User already exists: " + userid + "\n");
                }
            } 
            else {
                User newUser;
                newUser.userId   = userid;

                if (isSync) {
                    // Sync message carries pre-hashed credentials: create_user <userid> <hash> <salt> <pubkey_hex>
                    string salt;
                    ss >> salt >> pubkeyHex;
                    newUser.passwordHash = password;  // already hashed
                    newUser.salt = salt;
                    newUser.publicKeyPEM = fromHex(pubkeyHex);
                } else {
                    ss >> pubkeyHex;
                    // Fresh registration: hash the plaintext password (Fix 1)
                    string salt = generateSalt();
                    string hash = hashPassword(password, salt);
                    newUser.passwordHash = hash;
                    newUser.salt = salt;
                    newUser.publicKeyPEM = fromHex(pubkeyHex);
                    cout << "\033[36m[Security] Password hashed & public key registered for user: " << userid << "\033[0m" << endl;
                }

                newUser.loggedIn = false;
                newUser.ip       = "";
                newUser.port     = 0;
                newUser.failedAttempts = 0;
                newUser.lockTime = 0;

                usersInfo[userid] = newUser;

                if (!isSync) {
                    sslSend(ssl, "User created successfully: " + userid + "\n");
                    // Forward the HASHED form to peer tracker (never forward plaintext)
                    forwardToPeer("create_user " + userid + " " + newUser.passwordHash + " " + newUser.salt + " " + toHex(newUser.publicKeyPEM));
                }
            }
        }
    }
    
    /********************************************************************************************************
                                            Login Challenge
    ********************************************************************************************************/
    else if (cmd == "login_challenge") {
        string userid;
        ss >> userid;

        bool isLocked = false;
        int remainingTime = 0;
        {
            lock_guard<mutex> lock(usersInfoMutex);
            auto it = usersInfo.find(userid);
            if (it != usersInfo.end()) {
                if (it->second.failedAttempts >= 5 && time(nullptr) - it->second.lockTime < 30) {
                    isLocked = true;
                    remainingTime = 30 - (time(nullptr) - it->second.lockTime);
                }
            } else {
                sslSend(ssl, "ERROR User does not exist\n");
                return;
            }
        }

        if (isLocked) {
            sslSend(ssl, "ERROR Account locked. Try again in " + to_string(remainingTime) + " seconds.\n");
            return;
        }

        // Generate challenge
        unsigned char challBytes[32];
        if (RAND_bytes(challBytes, 32) <= 0) {
            sslSend(ssl, "ERROR Failed to generate challenge\n");
            return;
        }
        string challengeHex = toHex(string((char*)challBytes, 32));

        {
            int sslFd = SSL_get_fd(ssl);
            lock_guard<mutex> lock(sessionMutex);
            pendingChallenges[sslFd] = challengeHex;
        }

        sslSend(ssl, "CHALLENGE " + challengeHex + "\n");
    }

    /********************************************************************************************************
                                            Login Response (Challenge-Response Verification)
    ********************************************************************************************************/
    else if (cmd == "login_response") {
        string userid, signatureHex, clientIp, clientPortStr;
        ss >> userid >> signatureHex >> clientIp >> clientPortStr;

        if (!isSync) {
            if (!verifiedIP.empty()) {
                clientIp = verifiedIP;
            }
            // Check active session
            {
                int sslFd = SSL_get_fd(ssl);
                lock_guard<mutex> lock(sessionMutex);
                auto sessionIt = activeSessions.find(sslFd);
                if (sessionIt != activeSessions.end()) {
                    sslSend(ssl, "You are already logged in as " + sessionIt->second + ". Please logout first.\n");
                    return;
                }
            }
        }

        // Check lock status
        bool isLocked = false;
        int remainingTime = 0;
        {
            lock_guard<mutex> lock(usersInfoMutex);
            auto it = usersInfo.find(userid);
            if (it != usersInfo.end()) {
                if (it->second.failedAttempts >= 5 && time(nullptr) - it->second.lockTime < 30) {
                    isLocked = true;
                    remainingTime = 30 - (time(nullptr) - it->second.lockTime);
                }
            }
        }

        if (isLocked) {
            sslSend(ssl, "ERROR Account locked. Try again in " + to_string(remainingTime) + " seconds.\n");
            return;
        }

        // Retrieve challenge
        string challengeHex;
        int sslFd = SSL_get_fd(ssl);
        if (!isSync) {
            lock_guard<mutex> lock(sessionMutex);
            auto it = pendingChallenges.find(sslFd);
            if (it != pendingChallenges.end()) {
                challengeHex = it->second;
            }
        } else {
            challengeHex = "SYNC_PLACEHOLDER";
        }

        if (!isSync && challengeHex.empty()) {
            sslSend(ssl, "ERROR No pending challenge found\n");
            return;
        }

        // Verify signature
        bool loginSuccessful = false;
        {
            lock_guard<mutex> lock(usersInfoMutex);
            auto it = usersInfo.find(userid);
            if (it == usersInfo.end()) {
                if (!isSync) sslSend(ssl, "User does not exist: " + userid + "\n");
            } else {
                bool sigVerified = false;
                if (isSync) {
                    sigVerified = true;
                } else {
                    sigVerified = verifySignature(challengeHex, signatureHex, it->second.publicKeyPEM);
                }

                if (!sigVerified) {
                    it->second.failedAttempts++;
                    it->second.lockTime = time(nullptr);
                    if (!isSync) {
                        sslSend(ssl, "ERROR Invalid challenge signature. Attempts: " + to_string(it->second.failedAttempts) + "/5\n");
                    }
                } else {
                    // Success
                    it->second.failedAttempts = 0;
                    it->second.lockTime = 0;
                    it->second.loggedIn = true;
                    it->second.ip = clientIp;
                    it->second.port = stoi(clientPortStr);
                    loginSuccessful = true;
                }
            }
        }

        if (loginSuccessful) {
            if (!isSync) {
                {
                    lock_guard<mutex> lock(sessionMutex);
                    activeSessions[sslFd] = userid;
                    pendingChallenges.erase(sslFd);
                }
                sslSend(ssl, "Login successful: " + userid + "\n");
                forwardToPeer(message);
            }
        }
    }

    /********************************************************************************************************
                                                Legacy Login (Fallback with Brute Force)
    ********************************************************************************************************/
    else if (cmd == "login") {
        string userid, password, clientIp, clientPortStr;
        ss >> userid >> password >> clientIp >> clientPortStr;

        bool loginSuccessful = false;

        if (!isSync) {
            if (!verifiedIP.empty()) {
                clientIp = verifiedIP;
            }

            // First check if this socket already has an active session
            {
                int sslFd = SSL_get_fd(ssl);
                lock_guard<mutex> lock(sessionMutex);
                auto sessionIt = activeSessions.find(sslFd);
                if (sessionIt != activeSessions.end()) {
                    string reply = "You are already logged in as " + sessionIt->second +
                                        ". Please logout first before logging in again.\n";
                    sslSend(ssl, reply);
                    return; // stop here
                }
            }
        }

        {
            lock_guard<mutex> lock(usersInfoMutex);
            auto it = usersInfo.find(userid);

            if (it == usersInfo.end()) {
                if (!isSync) {
                    sslSend(ssl, "User does not exist: " + userid + "\n");
                }
            } 
            else if (it->second.failedAttempts >= 5 && time(nullptr) - it->second.lockTime < 30) {
                if (!isSync) {
                    int remaining = 30 - (time(nullptr) - it->second.lockTime);
                    sslSend(ssl, "ERROR Account locked. Try again in " + to_string(remaining) + " seconds.\n");
                }
            }
            // Fix 1: Verify password by hashing with stored salt and comparing hashes
            else if (hashPassword(password, it->second.salt) != it->second.passwordHash) {
                it->second.failedAttempts++;
                it->second.lockTime = time(nullptr);
                if (!isSync) {
                    sslSend(ssl, "Invalid password for user: " + userid + ". Attempts: " + to_string(it->second.failedAttempts) + "/5\n");
                }
            } 
            else if (it->second.loggedIn) {
                if (!isSync) {
                    // User is already logged in, but allow rebind on new socket (failover case)
                    {
                        int sslFd = SSL_get_fd(ssl);
                        lock_guard<mutex> lock(sessionMutex);
                        activeSessions[sslFd] = userid;  // bind this new socket to user and add it to the activeSessions
                    }
                    sslSend(ssl, "Login successful: " + userid + " (reconnected)\n");
                }
            }
            else {
                // success: update user info
                it->second.failedAttempts = 0;
                it->second.lockTime = 0;
                it->second.loggedIn = true;
                it->second.ip = clientIp;
                it->second.port = stoi(clientPortStr);
                loginSuccessful = true;
            }
        }

        if (loginSuccessful) {
            if (!isSync) {
                // Only add to activeSessions on client (not sync)
                {
                    int sslFd = SSL_get_fd(ssl);
                    lock_guard<mutex> lock(sessionMutex);
                    activeSessions[sslFd] = userid;
                }
                sslSend(ssl, "Login successful: " + userid + "\n");

                // replicate successful login to peer tracker
                forwardToPeer(message);
            }
        }
    }

    /********************************************************************************************************
                                              Create group
    ********************************************************************************************************/
    else if (cmd == "create_group") {
        string groupid, encKey;
        ss >> groupid >> encKey;

        string currentUserId;

        if (!isSync) {
            // find the current user tied to this socket
            {
                int sslFd = SSL_get_fd(ssl);
                lock_guard<mutex> lock(sessionMutex);
                auto it = activeSessions.find(sslFd);
                if (it == activeSessions.end()) {
                    sslSend(ssl, "You must be logged in to create a group\n");
                    return;
                }
                currentUserId = it->second;
            }
        } 
        else {
            string ownerFromMsg;
            if (!(ss >> ownerFromMsg)) {
                return; 
            }
            currentUserId = ownerFromMsg;
        }

        {
            lock_guard<mutex> lock(groupsMutex);

            if (groupOwners.find(groupid) != groupOwners.end()) {
                if (!isSync) {
                    sslSend(ssl, "Group already exists: " + groupid + "\n");
                }
            } 
            else {
                // we will give ownership to this user and then add it as the member of this group as well
                groupOwners[groupid] = currentUserId;
                groupMembers[groupid].insert(currentUserId);
                groupKeys[groupid][currentUserId] = encKey;

                if (!isSync) {
                    sslSend(ssl, "Group created successfully: " + groupid +
                                        " (Owner: " + currentUserId + ")\n");

                    // forward with explicit owner for peer sync
                    forwardToPeer("create_group " + groupid + " " + encKey + " " + currentUserId);
                }
            }
        }
    }

    /********************************************************************************************************
                                                List groups
    ********************************************************************************************************/
    else if (cmd == "list_groups") {
        if (!isSync) {
            string currentUserId;
            {
                int sslFd = SSL_get_fd(ssl);
                lock_guard<mutex> lock(sessionMutex);
                auto it = activeSessions.find(sslFd);
                if (it == activeSessions.end()) {
                    sslSend(ssl, "You must be logged in to use list_groups\n");
                    return;
                }
                currentUserId = it->second;
            }

            {
                lock_guard<mutex> lock(groupsMutex);

                stringstream reply;
                if (groupOwners.empty()) {
                    reply << "No groups available\n";
                } 
                else {
                    reply << "\nAvailable groups:\n";
                    for (const auto &g : groupOwners) {
                        reply << g.first << "\n";
                    }
                }

                sslSend(ssl, reply.str());
            }
        }
    }

    /********************************************************************************************************
                                                join_group
    ********************************************************************************************************/
    else if (cmd == "join_group") {
        string groupid;
        ss >> groupid;

        string currentUserId;

        if (!isSync) {
            // user must be logged in
            {
                int sslFd = SSL_get_fd(ssl);
                lock_guard<mutex> lock(sessionMutex);
                auto it = activeSessions.find(sslFd);
                if (it == activeSessions.end()) {
                    sslSend(ssl, "You must be logged in to join a group\n");
                    return;
                }
                currentUserId = it->second;
            }
        } 
        else {
            // in sync mode, we expect "<groupid> <userId>" in message
            if (!(ss >> currentUserId)) {
                return; // malformed sync message
            }
        }

        {
            lock_guard<mutex> lock(groupsMutex);

            // check if the group exists
            if (groupOwners.find(groupid) == groupOwners.end()) {
                if (!isSync) {
                    sslSend(ssl, "Group does not exist: " + groupid + "\n");
                }
                return;
            }

            // check if the user is already a member
            if (groupMembers[groupid].count(currentUserId)) {
                if (!isSync) {
                    sslSend(ssl, "You are already a member of group: " + groupid + "\n");
                }
                return;
            }

            // check if it has been already requested
            if (groupJoinRequests[groupid].count(currentUserId)) {
                if (!isSync) {
                    sslSend(ssl, "You already requested to join group: " + groupid + "\n");
                }
                return;
            }

            // add request
            groupJoinRequests[groupid].insert(currentUserId);

            if (!isSync) {
                sslSend(ssl, "Join request sent for group: " + groupid + "\n");

                // forward with explicit userId included
                forwardToPeer("join_group " + groupid + " " + currentUserId);
            }
        }
    }

    /********************************************************************************************************
                                                leave_group
    ********************************************************************************************************/
    else if (cmd == "leave_group") {
        string groupid;
        ss >> groupid;

        string currentUserId;

        if (!isSync) {
            // must be logged in
            {
                int sslFd = SSL_get_fd(ssl);
                lock_guard<mutex> lock(sessionMutex);
                auto it = activeSessions.find(sslFd);
                if (it == activeSessions.end()) {
                    sslSend(ssl, "You must be logged in to leave a group\n");
                    return;
                }
                currentUserId = it->second;
            }
        } 
        else {
            // in sync mode, we expect "<groupid> <userId>"
            if (!(ss >> currentUserId)) {
                return; // malformed sync message
            }
        }

        {
            lock_guard<mutex> lock(groupsMutex);

            auto ownerIt = groupOwners.find(groupid);
            if (ownerIt == groupOwners.end()) {
                if (!isSync) {
                    sslSend(ssl, "Group does not exist: " + groupid + "\n");
                }
                return;
            }

            // check membership
            if (!groupMembers[groupid].count(currentUserId)) {
                if (!isSync) {
                    sslSend(ssl, "You are not a member of group: " + groupid + "\n");
                }
                return;
            }

            // erase user from members
            groupMembers[groupid].erase(currentUserId);

            if (ownerIt->second != currentUserId) {
                // normal member leaves
                if (!isSync) {
                    sslSend(ssl, "You left the group: " + groupid + "\n");
                    forwardToPeer("leave_group " + groupid + " " + currentUserId);
                }
            } 
            else {
                // owner leaving
                if (!groupMembers[groupid].empty()) {
                    string newOwner = *groupMembers[groupid].begin();
                    groupOwners[groupid] = newOwner;

                    if (!isSync) {
                        sslSend(ssl, "You left the group: " + groupid +
                                            ". Ownership transferred to " + newOwner + "\n");
                        forwardToPeer("leave_group " + groupid + " " + currentUserId);
                    }
                } 
                else {
                    // no members left, delete group
                    groupOwners.erase(groupid);
                    groupMembers.erase(groupid);
                    groupJoinRequests.erase(groupid);

                    if (!isSync) {
                        sslSend(ssl, "You left the group: " + groupid +
                                            ". Group has been deleted as no members remain.\n");
                        forwardToPeer("leave_group " + groupid + " " + currentUserId);
                    }
                }
            }
        }
    }

    /********************************************************************************************************
                                                list_requests
    ********************************************************************************************************/
    else if (cmd == "list_requests") {
        if (!isSync) {
            string groupid;
            ss >> groupid;

            string currentUserId;
            {
                int sslFd = SSL_get_fd(ssl);
                lock_guard<mutex> lock(sessionMutex);
                auto it = activeSessions.find(sslFd);
                if (it == activeSessions.end()) {
                    sslSend(ssl, "You must be logged in to list requests\n");
                    return;
                }
                currentUserId = it->second;
            }

            {
                lock_guard<mutex> lock(groupsMutex);

                // check if group exists
                if (groupOwners.find(groupid) == groupOwners.end()) {
                    sslSend(ssl, "Group does not exist: " + groupid + "\n");
                    return;
                }

                // only the owner can view requests
                if (groupOwners[groupid] != currentUserId) {
                    sslSend(ssl, "Only the owner of group " + groupid + " can view join requests\n");
                    return;
                }

                auto currRequests = groupJoinRequests.find(groupid);
                if (currRequests == groupJoinRequests.end() || currRequests->second.empty()) {
                    sslSend(ssl, "No pending join requests for group: " + groupid + "\n");
                    return;
                }

                // build reply
                stringstream reply;
                reply << "\nPending requests for group " << groupid << ":\n";
                for (const auto &user : currRequests->second) {
                    reply << user << "\n";
                }

                sslSend(ssl, reply.str());
            }
        }
    }

    /********************************************************************************************************
                                                 accept_request
    ********************************************************************************************************/
    else if (cmd == "accept_request") {
        string groupid, targetUser, encKey;
        ss >> groupid >> targetUser >> encKey;

        string currentUserId;

        if (!isSync) {
            // must be logged in
            {
                int sslFd = SSL_get_fd(ssl);
                lock_guard<mutex> lock(sessionMutex);
                auto it = activeSessions.find(sslFd);
                if (it == activeSessions.end()) {
                    sslSend(ssl, "You must be logged in to accept requests\n");
                    return;
                }
                currentUserId = it->second;
            }
        } 
        else {
            if (!(ss >> currentUserId)) {
                return; // malformed sync message
            }
        }

        {
            lock_guard<mutex> lock(groupsMutex);

            auto owner = groupOwners.find(groupid);
            if (owner == groupOwners.end()) {
                if (!isSync) {
                    sslSend(ssl, "Group does not exist: " + groupid + "\n");
                }
                return;
            }

            // only owner can accept requests
            if (owner->second != currentUserId) {
                if (!isSync) {
                    sslSend(ssl, "Only group owner can accept requests\n");
                }
                return;
            }

            // check if targetUser has requested
            auto request = groupJoinRequests.find(groupid);
            if (request == groupJoinRequests.end() || !request->second.count(targetUser)) {
                if (!isSync) {
                    sslSend(ssl, "No join request from user " + targetUser +
                                        " for group " + groupid + "\n");
                }
                return;
            }

            // accept request
            request->second.erase(targetUser);
            groupMembers[groupid].insert(targetUser);
            groupKeys[groupid][targetUser] = encKey;

            if (!isSync) {
                sslSend(ssl, "User " + targetUser + " added to group " + groupid + "\n");

                // forward with explicit owner for peer sync
                forwardToPeer("accept_request " + groupid + " " + targetUser + " " + encKey + " " + currentUserId);
            }
        }
    }

    /********************************************************************************************************
                                            Get Group Key
    ********************************************************************************************************/
    else if (cmd == "get_group_key") {
        string groupid;
        ss >> groupid;

        string currentUserId;
        int sslFd = SSL_get_fd(ssl);
        {
            lock_guard<mutex> lock(sessionMutex);
            auto it = activeSessions.find(sslFd);
            if (it == activeSessions.end()) {
                sslSend(ssl, "ERROR You must be logged in to get group keys\n");
                return;
            }
            currentUserId = it->second;
        }

        {
            lock_guard<mutex> lock(groupsMutex);
            auto memberIt = groupMembers.find(groupid);
            if (memberIt == groupMembers.end() || memberIt->second.count(currentUserId) == 0) {
                sslSend(ssl, "ERROR You are not a member of group " + groupid + "\n");
                return;
            }

            auto keyGroupIt = groupKeys.find(groupid);
            if (keyGroupIt != groupKeys.end()) {
                auto keyUserIt = keyGroupIt->second.find(currentUserId);
                if (keyUserIt != keyGroupIt->second.end()) {
                    sslSend(ssl, "GROUPKEY " + keyUserIt->second + "\n");
                    return;
                }
            }
            sslSend(ssl, "ERROR Group key not found for you\n");
        }
    }

    /********************************************************************************************************
                                            Get User Public Key
    ********************************************************************************************************/
    else if (cmd == "get_user_pubkey") {
        string targetUser;
        ss >> targetUser;

        {
            lock_guard<mutex> lock(usersInfoMutex);
            auto it = usersInfo.find(targetUser);
            if (it == usersInfo.end()) {
                sslSend(ssl, "ERROR User not found\n");
            } else {
                if (it->second.publicKeyPEM.empty()) {
                    sslSend(ssl, "ERROR User has no registered public key\n");
                } else {
                    sslSend(ssl, "PUBKEY " + toHex(it->second.publicKeyPEM) + "\n");
                }
            }
        }
    }

    /********************************************************************************************************
                                                upload_file
    ********************************************************************************************************/
    else if (cmd == "upload_file") {
        // this is the non-sync message, so this goes on the primary tracker and not the peer tracker
        // upload_file <groupid> <fileName> <fileSize> <numChunks> <clientIP> <clientPort>
        // when forwarded for sync we append the owner: "upload_file <groupid> <fileName> <fileSize> <numChunks> <clientIP> <clientPort> <owner>"
        string groupid, fileName, clientIP;
        long long fileSize = 0;
        int numChunks = 0;
        int clientPort = 0;

        string currentUserId;

        if (!isSync) {
            // must be logged in
            {
                int sslFd = SSL_get_fd(ssl);
                lock_guard<mutex> lock(sessionMutex);
                auto it = activeSessions.find(sslFd);
                if (it == activeSessions.end()) {
                    sslSend(ssl, "You must be logged in to upload files\n");
                    return;
                }
                currentUserId = it->second;
            }

            // parse remaining args from client
            if (!(ss >> groupid >> fileName >> fileSize >> numChunks >> clientIP >> clientPort)) {
                sslSend(ssl, "Usage: upload_file <group_id> <file_name> <file_size> <num_chunks> <client_ip> <client_port>\n");
                return;
            }

            // Fix 3: Override client-provided IP with the verified IP from getpeername()
            if (!verifiedIP.empty()) {
                clientIP = verifiedIP;
            }
        } else {
            if (!(ss >> groupid >> fileName >> fileSize >> numChunks >> clientIP >> clientPort >> currentUserId)) {
                return;
            }
        }

        // Validate group exists and user is a member (or owner)
        {
            lock_guard<mutex> lock(groupsMutex);
            if (groupOwners.find(groupid) == groupOwners.end()) {
                if (!isSync) {
                    sslSend(ssl, "Group does not exist: " + groupid + "\n");
                }
                return;
            }
            // Verify membership for non-sync requests
            if (!isSync) {
                if (groupMembers[groupid].count(currentUserId) == 0) {
                    sslSend(ssl, "You are not a member of group: " + groupid + "\n");
                    return;
                }
            }
        }

        // Register / update FileInfo in fileTable
        {
            lock_guard<mutex> lock(fileTableMutex);
            FileInfo &fi = fileTable[groupid][fileName];
            fi.fileName = fileName;
            fi.fileSize = static_cast<size_t>(fileSize);
            fi.numChunks = numChunks;
            fi.uploaderId = currentUserId;

            // Mark that the uploader (peer) has all chunks.
            string peerId = clientIP + ":" + to_string(clientPort);
            for (int i = 0; i < numChunks; ++i) {
                fi.chunkToPeers[i].insert(peerId);
                fi.peerToChunks[peerId].insert(i);
            }
        }

        if (!isSync) {
            sslSend(ssl, "Upload registered for file: " + fileName + "\n");

            // forward to peer tracker for sync with explicit owner appended
            // Format forwarded: upload_file <groupid> <fileName> <fileSize> <numChunks> <clientIP> <clientPort> <owner>
            forwardToPeer("upload_file " + groupid + " " + fileName + " " + to_string(fileSize)
                        + " " + to_string(numChunks) + " " + clientIP + " " + to_string(clientPort)
                        + " " + currentUserId);
        }
    }

    /********************************************************************************************************
                                                    list_files
    ********************************************************************************************************/
    else if (cmd == "list_files") {
        string groupid;
        ss >> groupid;

        string currentUserId;
        if (!isSync) {
            // must be logged in
            {
                int sslFd = SSL_get_fd(ssl);
                lock_guard<mutex> lock(sessionMutex);
                auto it = activeSessions.find(sslFd);
                if (it == activeSessions.end()) {
                    sslSend(ssl, "You must be logged in to list files\n");
                    return;
                }
                currentUserId = it->second;
            }
        } else {
            // in sync mode, we don't expect list_files normally; if you ever forward it,
            // the owner/user can be included. We'll try to read it but it's optional.
            if (!(ss >> currentUserId)) {
                // not fatal for listing; proceed without an explicit owner
                currentUserId.clear();
            }
        }

        if (groupid.empty()) {
            if (!isSync) {
                sslSend(ssl, "Usage: list_files <group_id>\n");
            }
            return;
        }

        // Verify group membership for non-sync requests
        {
            lock_guard<mutex> lock(groupsMutex);
            if (groupOwners.find(groupid) == groupOwners.end()) {
                sslSend(ssl, "Group does not exist: " + groupid + "\n");
                return;
            }
            if (!isSync && groupMembers[groupid].count(currentUserId) == 0) {
                sslSend(ssl, "You are not a member of group: " + groupid + "\n");
                return;
            }
        }

        // Build reply from fileTable
        {
            lock_guard<mutex> lock(fileTableMutex);
            auto it = fileTable.find(groupid);
            if (it == fileTable.end() || it->second.empty()) {
                sslSend(ssl, "No files available in group: " + groupid + "\n");
                return;
            }

            ostringstream out;
            out << "Files in group " << groupid << ":\n";
            for (const auto &kv : it->second) {
                const FileInfo &fi = kv.second;
                out << fi.fileName << "\t" << fi.fileSize << " bytes\t" << fi.numChunks << " pieces\n";
            }
            sslSend(ssl, out.str());
        }
    }

    /********************************************************************************************************
                                                    download_file
    ********************************************************************************************************/
    else if (cmd == "download_file") {
        handleDownload(cmd, message, ssl, isSync);
        return;
    }

    else if (cmd == "is_peer_online") {
        string peerId;
        ss >> peerId;

        if (peerId.empty()) {
            sslSend(ssl, "ERROR missing ip:port\n");
            return;
        }

        // 1. Split ip and port
        size_t pos = peerId.find(':');
        if (pos == string::npos) {
            sslSend(ssl, "ERROR invalid format, Expected ip:port\n");
            return;
        }
        string ip = peerId.substr(0, pos);
        int port = stoi(peerId.substr(pos + 1));

        // 2. Snapshot logged-in users
        vector<string> loggedInUsers;
        {
            lock_guard<mutex> sLock(sessionMutex);
            for (auto &kv : activeSessions) {
                loggedInUsers.push_back(kv.second); // username
            }
        }

        // 3. Check usersInfo for matching ip:port
        bool online = false;
        {
            lock_guard<mutex> uLock(usersInfoMutex);
            for (const auto &uname : loggedInUsers) {
                auto it = usersInfo.find(uname);
                if (it != usersInfo.end() && it->second.ip == ip && it->second.port == port) {
                    online = true;
                    break;
                }
            }
        }

        sslSend(ssl, online ? "ONLINE\n" : "OFFLINE\n");
    }

    /********************************************************************************************************
                                                stop_share
    ********************************************************************************************************/
    else if (cmd == "stop_share") {
        string groupid, fileName;
        ss >> groupid >> fileName;
        if (groupid.empty() || fileName.empty()) {
            if (!isSync) sslSend(ssl, "Usage: stop_share <group_id> <file_name>\n");
            return;
        }

        // Determine user + peerId (unified)
        string userId, ip; int port = 0;
        if (!isSync) {
            // must be logged in
            {
                int sslFd = SSL_get_fd(ssl);
                lock_guard<mutex> s(sessionMutex);
                auto it = activeSessions.find(sslFd);
                if (it == activeSessions.end()) { sslSend(ssl, "You must be logged in to stop_share\n"); return; }
                userId = it->second;
            }
            // fetch ip:port from usersInfo
            {
                lock_guard<mutex> u(usersInfoMutex);
                auto uit = usersInfo.find(userId);
                if (uit == usersInfo.end() || !uit->second.loggedIn) { sslSend(ssl, "You are not logged in\n"); return; }
                ip   = uit->second.ip; port = uit->second.port;
            }
            // (optional) membership check
            {
                lock_guard<mutex> g(groupsMutex);
                if (groupOwners.find(groupid) == groupOwners.end()) { sslSend(ssl, "Group does not exist\n"); return; }
                if (!groupMembers[groupid].count(userId)) { sslSend(ssl, "You are not a member of this group\n"); return; }
            }
        } else {
            // SYNC form: stop_share <groupid> <fileName> <userId> <ip> <port>
            if (!(ss >> userId >> ip >> port)) return;
        }

        const string peerId = ip + ":" + to_string(port);
        bool removed = removePeerFromFile(groupid, fileName, peerId);

        if (!isSync) {
            // reply to client
            ostringstream r; 
            r << (removed ? "Stopped sharing " : "No changes")
            << fileName << " in " << groupid << "\n";
            sslSend(ssl, r.str());

            // replicate to peers
            ostringstream fwd;
            fwd << "stop_share " << groupid << " " << fileName << " " << userId << " " << ip << " " << port;
            forwardToPeer(fwd.str());
        }
    }

    /********************************************************************************************************
                                                Logout
    ********************************************************************************************************/   
    else if (cmd == "logout") {
        string currentUserId;
        int sslFd = ssl ? SSL_get_fd(ssl) : -1;

        // identify who exactly is logging out 
        if (!isSync) {
            lock_guard<mutex> lock(sessionMutex);
            auto it = activeSessions.find(sslFd);
            if (it == activeSessions.end()) {
                sslSend(ssl, "You are not logged in.\n");
                return;
            }
            currentUserId = it->second;
            activeSessions.erase(it);
        } else {
            if (!(ss >> currentUserId)) return; // malformed sync message
            lock_guard<mutex> lock(sessionMutex);
            for (auto it = activeSessions.begin(); it != activeSessions.end();) {
                if (it->second == currentUserId) it = activeSessions.erase(it);
                else ++it;
            }
        }

        // mark the user as logged out and capture their ip:port before clearing
        string loggedOutIp;
        int loggedOutPort = 0;
        {
            lock_guard<mutex> lock(usersInfoMutex);
            auto it = usersInfo.find(currentUserId);
            if (it != usersInfo.end()) {
                loggedOutIp   = it->second.ip;
                loggedOutPort = it->second.port;
                it->second.loggedIn = false;
                it->second.ip = "";
                it->second.port = 0;
            }
        }

        // remove this peer from all file entries in fileTable
        if (!loggedOutIp.empty() && loggedOutPort > 0) {
            string peerId = loggedOutIp + ":" + to_string(loggedOutPort);
            lock_guard<mutex> lock(fileTableMutex);
            for (auto& [gid, files] : fileTable) {
                vector<string> toRemove;
                for (auto& [fname, fi] : files) {
                    auto it = fi.peerToChunks.find(peerId);
                    if (it == fi.peerToChunks.end()) continue;
                    for (int ch : it->second) fi.chunkToPeers[ch].erase(peerId);
                    fi.peerToChunks.erase(it);
                    if (fi.peerToChunks.empty()) toRemove.push_back(fname);
                }
                for (const auto& fname : toRemove) files.erase(fname);
            }
        }

        // if the user was owner of some other group then transfer the ownership
        {
            lock_guard<mutex> lock(groupsMutex);
            vector<string> ownedGroups;

            // Find all groups where this user is the owner
            for (const auto &kv : groupOwners) {
                if (kv.second == currentUserId) ownedGroups.push_back(kv.first);
            }

            for (const auto &gid : ownedGroups) {
                auto &members = groupMembers[gid];
                members.erase(currentUserId); // remove them from members

                if (!members.empty()) {
                    // Transfer ownership to the first remaining member
                    groupOwners[gid] = *members.begin();
                    sslSend(ssl, "Ownership transferred to " + *members.begin());
                } else {
                    // No members left — delete the group entirely
                    groupOwners.erase(gid);
                    groupMembers.erase(gid);
                    groupJoinRequests.erase(gid);
                }
            }
        }

        if (!isSync) {
            sslSend(ssl, "User " + currentUserId + " logged out successfully.\n");
            forwardToPeer("logout " + currentUserId);
        }
    } 

    else if (cmd == "upload_filehash") {
        // Format: upload_filehash <groupid> <fileName> <hex> <signature>
        string gid, fname, hex, sig;
        ss >> gid >> fname >> hex >> sig;

        // Store the hash (create entry if needed)
        {
            lock_guard<std::mutex> lock(fileTableMutex);
            FileInfo &fi = fileTable[gid][fname];
            fi.fileName = fname;                 
            fi.fileShaHex = hex;       
            fi.fileSignature = sig;
        }

        if (!isSync) {
            forwardToPeer("upload_filehash " + gid + " " + fname + " " + hex + " " + sig);
        }
    }

    else {
        sslSend(ssl, "Unknown command\n");
    }
}

void handleClientCommands(SSL* ssl) {
    char buffer[4096];
    bool isSyncConnection = false;

    // Fix 3: Extract verified client IP from the socket using getpeername()
    string verifiedIP;
    int underlyingFd = SSL_get_fd(ssl);
    if (underlyingFd >= 0) {
        struct sockaddr_in peerAddr{};
        socklen_t peerLen = sizeof(peerAddr);
        if (getpeername(underlyingFd, (struct sockaddr*)&peerAddr, &peerLen) == 0) {
            char ipBuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &peerAddr.sin_addr, ipBuf, sizeof(ipBuf));
            verifiedIP = string(ipBuf);
            cout << "\033[36m[Security] Verified client IP from socket: " << verifiedIP << "\033[0m" << endl;
        }
    }

    while (true) {
        int bytesReceived = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytesReceived <= 0) {
            cout << "Connection closed on SSL fd " << underlyingFd << endl;
            break;
        }

        string message(buffer, bytesReceived);

        // First check whether this is the SYNC command or the actual tracker command
        if (message.rfind("SYNC ", 0) == 0) {
            isSyncConnection = true;
            std::string forwarded = message.substr(5);  // if it is sync command then trim the SYNC and send it to the tracker
            applyCommand(forwarded, nullptr, true);
            continue;
        }

        // If it is not a sync command then, its the actual tracker command
        cout << "\033[35m[Client Command]\033[0m " << message << endl;
        applyCommand(message, ssl, false, verifiedIP); // Pass verified IP (Fix 3)
    }

    // Clean up: remove session and close SSL
    {
        lock_guard<mutex> lock(sessionMutex);
        activeSessions.erase(underlyingFd);
    }

    if (!isSyncConnection) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(underlyingFd);
    }
}