#include "tracker.h"
#include "../common/cryptoUtil.h"
#include <iostream>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>
#include <regex>
#include <openssl/ssl.h>

using namespace std;

// Helper: SSL_write wrapper
static void sslSend(SSL* ssl, const string &msg) {
    if (ssl) SSL_write(ssl, msg.c_str(), msg.size());
}

// Remove a single peerId from a group's file entry.
// Returns true if something was actually removed.
bool removePeerFromFile(const string& groupid, const string& fileName, const string& peerId) {
    lock_guard<mutex> lock(fileTableMutex);

    auto groupIt = fileTable.find(groupid);
    if (groupIt == fileTable.end()) return false;

    auto fileIt = groupIt->second.find(fileName);
    if (fileIt == groupIt->second.end()) return false;

    FileInfo& fi = fileIt->second;

    auto ptc = fi.peerToChunks.find(peerId);
    if (ptc == fi.peerToChunks.end()) return false;

    for (int ch : ptc->second) fi.chunkToPeers[ch].erase(peerId);
    fi.peerToChunks.erase(ptc);

    // optional cleanup: drop file if no seeders left; drop group entry if now empty
    if (fi.peerToChunks.empty()) {
        groupIt->second.erase(fileIt);
        if (groupIt->second.empty()) fileTable.erase(groupIt);
    }
    return true;
}


// when this function received command for getting the file details then it will build the response and send it to the tracker
void handleDownload (string cmd, const string &message, SSL* ssl, bool isSync) {
    std::smatch m;
    static const std::regex rx(R"(^\s*download_file\s+(\S+)\s+(".*?"|\S+)\s*(.*?)\s*$)");
    // Groups:
    // 1 = groupId
    // 2 = fileName (may be quoted)
    // 3 = destPath

    if (!std::regex_search(message, m, rx) || m.size() < 3) {
        // Send usage message back to client and return from applyCommand
        if (!isSync) sslSend(ssl, "Usage: download_file <group_id> <file_name> <destination_path>\n");
        return;
    }

    string groupId = m[1].str();
    string requestFileName = m[2].str();
    string destPathOptional = ""; // groupId and filename are what tracker needs
    if (m.size() >= 4) destPathOptional = m[3].str();

    // Strip surrounding quotes from filename if present
    if (requestFileName.size() >= 2 && requestFileName.front() == '"' && requestFileName.back() == '"') {
        requestFileName = requestFileName.substr(1, requestFileName.size() - 2);
    }

    // ensure logged in and a member (for non-sync)
    string currentUserId;
    if (!isSync) {
        int sslFd = SSL_get_fd(ssl);
        lock_guard<mutex> sl(sessionMutex);
        auto sessionIt = activeSessions.find(sslFd);
        if (sessionIt == activeSessions.end()) {
            sslSend(ssl, "You must be logged in to download files\n");
            return;
        }
        currentUserId = sessionIt->second;
    }

    // validate group and membership
    {
        lock_guard<mutex> gl(groupsMutex);
        if (groupOwners.find(groupId) == groupOwners.end()) {
            sslSend(ssl, "Group does not exist: " + groupId + "\n");
            return;
        }
        if (!isSync && groupMembers[groupId].count(currentUserId) == 0) {
            sslSend(ssl, "You are not a member of group: " + groupId + "\n");
            return;
        }
    }

    // find file
    FileInfo fileInfoCopy;
    {
        lock_guard<mutex> fl(fileTableMutex);
        auto groupIt = fileTable.find(groupId);
        if (groupIt == fileTable.end()) {
            sslSend(ssl, "ERROR FILE_NOT_FOUND " + requestFileName + "\nEND\n");
            return;
        }
        auto fileIt = groupIt->second.find(requestFileName);
        if (fileIt == groupIt->second.end()) {
            sslSend(ssl, "ERROR FILE_NOT_FOUND " + requestFileName + "\nEND\n");
            return;
        }
        fileInfoCopy = fileIt->second;
    }

    // Build structured response for client
    // FILEINFO movie.mp4 104857600 205
    // PEER 192.168.1.10 5000 0,1,2,3,4,5
    // PEER 192.168.1.20 6000 6,7,8,9,10
    // PEER 127.0.0.1 7000 11,12,13,14
    // END

    string uploaderPubKeyHex = "";
    if (!fileInfoCopy.uploaderId.empty()) {
        lock_guard<mutex> ul(usersInfoMutex);
        auto userIt = usersInfo.find(fileInfoCopy.uploaderId);
        if (userIt != usersInfo.end()) {
            uploaderPubKeyHex = toHex(userIt->second.publicKeyPEM);
        }
    }

    ostringstream resp;
    resp << "FILEINFO " << fileInfoCopy.fileName << " " << fileInfoCopy.fileSize << " " << fileInfoCopy.numChunks << " " << fileInfoCopy.fileShaHex
         << " " << fileInfoCopy.uploaderId << " " << (fileInfoCopy.fileSignature.empty() ? "NONE" : fileInfoCopy.fileSignature) << "\n";
    if (!uploaderPubKeyHex.empty()) {
        resp << "UPLOADER_PUBKEY " << uploaderPubKeyHex << "\n";
    }

    // Emit PEER lines from peerToChunks mapping
    for (const auto &peerEntry : fileInfoCopy.peerToChunks) {
        const string &peerId = peerEntry.first; // "ip:port"
        const auto &chunks = peerEntry.second;  // set<int>
        // convert chunk set to comma separated list
        ostringstream chunkList;
        bool first = true;
        for (int idx : chunks) {
            if (!first) chunkList << ",";
            chunkList << idx;
            first = false;
        }
        // split peerId to ip and port:
        string peerIP = "0.0.0.0";
        int peerPort = 0;
        size_t cpos = peerId.find(':');
        if (cpos != string::npos) {
            peerIP = peerId.substr(0, cpos);
            try { peerPort = stoi(peerId.substr(cpos + 1)); } catch(...) { peerPort = 0; }
        }
        resp << "PEER " << peerIP << " " << peerPort << " " << chunkList.str() << "\n";
    }

    resp << "END\n";
    string respStr = resp.str();
    if (!isSync) {
        sslSend(ssl, respStr);
    }
}