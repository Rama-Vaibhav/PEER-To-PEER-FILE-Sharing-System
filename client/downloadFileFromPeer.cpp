#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <fcntl.h>
#include "client.h"
#include <cerrno>
#include <openssl/err.h>
#include "../common/cryptoUtil.h"

using namespace std;

static const size_t CHUNK_SIZE = 512 * 1024; 

// creating the same file info data structure like it is stored on the tracker side so we can parse the command and store
// the information of the file 
struct TrackerFileInfo {
    string fileName;
    size_t fileSize = 0;
    int numChunks = 0;
    vector<set<string>> chunkToPeers;  // chunk index -> set of peerId ("ip:port")
    map<string, set<int>> peerToChunks; // peerId -> set of chunk indices
    string fileShaHex;
    string uploaderId;
    string fileSignature;
    string uploaderPubKey;
};

/********************************************************************************************************
 It will notify the tracker that the full file has been downloaded successfully and now it can act as tracker
********************************************************************************************************/
void notifyTracker(SSL* trackerSSL, const string& message) {
    if (!trackerSSL) return;
    string msg = message;
    if (msg.empty() || msg.back() != '\n') msg.push_back('\n');
    if (SSL_write(trackerSSL, msg.c_str(), msg.size()) <= 0) {
        cerr << "[Planner] SSL_write to tracker failed" << endl;
        return;
    }
    char buf[1024];
    int n = SSL_read(trackerSSL, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
    }
}

/*
Format of the response from the tracker : 
    FILEINFO video.mp4 12710019 25
    PEER 127.0.0.1 1234 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24
    END
*/

/********************************************************************************************************
        Function to parse the response and enter the required details into tracker file info 
********************************************************************************************************/
bool parseTrackerFileInfoResponse(const string &trackerResponse, TrackerFileInfo &parsedFileInfo) {
    istringstream in(trackerResponse);
    string line;
    bool foundFileInfoHeader = false;
    parsedFileInfo = TrackerFileInfo();

    while (getline(in, line)) {
        if (line.empty()) continue;
        if (!line.empty() && line.back() == '\r') line.pop_back();

        istringstream ls(line);
        string tag;
        ls >> tag;
        // from this header we will get the filename, filesize and number of chunks 
        if (tag == "FILEINFO") {
            ls >> parsedFileInfo.fileName >> parsedFileInfo.fileSize >> parsedFileInfo.numChunks >> parsedFileInfo.fileShaHex >> parsedFileInfo.uploaderId >> parsedFileInfo.fileSignature;
            parsedFileInfo.chunkToPeers.assign(parsedFileInfo.numChunks, set<string>());
            foundFileInfoHeader = true;
        } 
        else if (tag == "UPLOADER_PUBKEY") {
            string pubkeyHex;
            ls >> pubkeyHex;
            parsedFileInfo.uploaderPubKey = fromHex(pubkeyHex);
        }
        // from this we will get the information about the peer that is its ip, port and list of chunks
        else if (tag == "PEER") {
            string ip; 
            int port; 
            string chunkList;
            ls >> ip >> port >> chunkList;
            string peerId = ip + ":" + to_string(port);
            istringstream cs(chunkList);
            string token;
            while (getline(cs, token, ',')) {
                if (token.empty()) continue;
                int idx = stoi(token);
                if (idx >= 0 && idx < parsedFileInfo.numChunks) {
                    parsedFileInfo.chunkToPeers[idx].insert(peerId);
                    parsedFileInfo.peerToChunks[peerId].insert(idx);
                }
            }
        } 

        else if (tag == "END") {
            break;
        } 
    }
    return foundFileInfoHeader;
}

/********************************************************************************************************
                Function to check whether particular peer is online or not
********************************************************************************************************/
int isPeerOnline(const string &userId) {
    // finding the tracker ip and port numbers to connect to the tracker
    int fd = open("tracker_info.txt", O_RDONLY);
    if (fd < 0) return -1;

    char buffer[256];
    ssize_t n1 = read(fd, buffer, sizeof(buffer)-1);
    close(fd);
    if (n1 <= 0) return -1;
    buffer[n1] = '\0';

    // 2. Split lines manually
    string ip1, ip2, p1s, p2s;
    vector<string> lines;
    string cur;
    for (int i = 0; i < n1; i++) {
        if (buffer[i] == '\n' || buffer[i] == '\r') {
            if (!cur.empty()) { lines.push_back(cur); cur.clear(); }
        } else {
            cur.push_back(buffer[i]);
        }
    }
    if (!cur.empty()) lines.push_back(cur);

    if (lines.size() < 4) return -1;

    string TrackerIP1 = lines[0];
    int TrackerPort1 = stoi(lines[1]);
    string TrackerIP2 = lines[2];
    int TrackerPort2 = stoi(lines[3]);

    // connecting to the tracker to check whether the peer is online or not using TLS
    SSL* tkSSL = connectToTrackerSSL(TrackerIP1, TrackerPort1, TrackerIP2, TrackerPort2);
    if (!tkSSL) {
        return -1;
    }

    string q = "is_peer_online " + userId + "\n";
    if (SSL_write(tkSSL, q.c_str(), q.size()) <= 0) { 
        int rawSock = SSL_get_fd(tkSSL);
        SSL_shutdown(tkSSL);
        SSL_free(tkSSL);
        if (rawSock >= 0) close(rawSock);
        return -1; 
    }

    char buf[128];
    int n = SSL_read(tkSSL, buf, sizeof(buf)-1);
    int rawSock = SSL_get_fd(tkSSL);
    SSL_shutdown(tkSSL);
    SSL_free(tkSSL);
    if (rawSock >= 0) close(rawSock);

    if (n <= 0) {
        cout << "not received anything" << endl;
        return -1;
    }

    buf[n] = '\0';
    string reply(buf);
    if (reply.find("ONLINE") != string::npos) return 1;
    if (reply.find("OFFLINE") != string::npos) return 0;
    return -1;
}

pair<string,int> splitPeer(const string& peerId) {
    size_t p = peerId.find(':');
    if (p == string::npos)
        return {peerId, 0};   // no port found → return 0
    return {peerId.substr(0, p), atoi(peerId.substr(p + 1).c_str())};
}

/********************************************************************************************************
                            Rarest first scheduling strategy
********************************************************************************************************/
bool static comp(const pair<int,int> &a, const pair<int,int> &b) {
    if(a.first!=b.first) return a.first < b.first;  // rarest first 
    return a.second < b.second;
}

static vector<int> chooseRarestFirstOrder(const TrackerFileInfo &info) {
    int n = info.numChunks;
    vector<pair<int,int>> order; // (peerCount, chunkIndex) that is how many peers have this chunk and what is the chunk index
    order.reserve(n);

    for (int i = 0; i < n; ++i) {
        int count = (int)info.chunkToPeers[i].size();

        order.push_back({count, i});
    }
    sort(order.begin(), order.end(), comp);
    vector<int> rarestOrder;
    for (auto value : order) rarestOrder.push_back(value.second);
    return rarestOrder;
}


/********************************************************************************************************
                                    Main downloading logic
********************************************************************************************************/
void startDownloadFromTrackerResponse(const string &trackerResponse, const string &groupId, const string &fileName, const string &destPath,
                                      const string &clientIP, int clientPort, SSL* trackerSSLIfAvailable) {
    // trackerSocketIfAvailabe is used : to notify the tracker about the chunk
    TrackerFileInfo fileInfoFromTracker;
    // Parse the tracker response into structured format
    parseTrackerFileInfoResponse(trackerResponse, fileInfoFromTracker);

    // Fetch and decrypt the Group Key if not already cached
    if (g_groupKeys.find(groupId) == g_groupKeys.end()) {
        if (trackerSSLIfAvailable) {
            string getkeyCmd = "get_group_key " + groupId + "\n";
            if (SSL_write(trackerSSLIfAvailable, getkeyCmd.c_str(), getkeyCmd.size()) > 0) {
                char kbuf[2048];
                int kn = SSL_read(trackerSSLIfAvailable, kbuf, sizeof(kbuf) - 1);
                if (kn > 0) {
                    kbuf[kn] = '\0';
                    string getkeyReply(kbuf);
                    if (getkeyReply.rfind("GROUPKEY ", 0) == 0) {
                        string encKeyHex = getkeyReply.substr(9);
                        if (!encKeyHex.empty() && encKeyHex.back() == '\n') encKeyHex.pop_back();

                        // Decrypt group key
                        string privPath = "keys/" + g_currentUsername + "_private.pem";
                        FILE* f = fopen(privPath.c_str(), "r");
                        if (f) {
                            string privateKeyPEM;
                            char keyBuf[256];
                            while (fgets(keyBuf, sizeof(keyBuf), f)) {
                                privateKeyPEM += keyBuf;
                            }
                            fclose(f);

                            string decryptedKey = rsaDecrypt(encKeyHex, privateKeyPEM);
                            if (!decryptedKey.empty()) {
                                g_groupKeys[groupId] = decryptedKey;
                                cout << "\033[32m[Security] Retrieved and decrypted group key for " << groupId << "\033[0m" << endl;
                            } else {
                                cerr << "[Security] Failed to decrypt group key using local private key." << endl;
                            }
                        } else {
                            cerr << "[Security] Private key file not found at " << privPath << endl;
                        }
                    }
                }
            }
        }
    }

    // make entry for this file in the downloads, this will be helpful for show_downloads
    downloads[fileName] = {
        fileName,
        groupId,
        fileInfoFromTracker.numChunks,
        vector<int>(fileInfoFromTracker.numChunks, 0),
        false,  // download failed
        false   // download completed
    };

    cout << "Destination: " << destPath << "\n";

    // ---------------- collect unique peers, check each exactly once ----------------
    set<string> allPeerIds;
    for (int i = 0; i < fileInfoFromTracker.numChunks; ++i)
        for (const auto& pid : fileInfoFromTracker.chunkToPeers[i])
            allPeerIds.insert(pid);

    set<string> onlinePeers;
    for (const auto& pid : allPeerIds) {
        if (isPeerOnline(pid) == 1)
            onlinePeers.insert(pid);
    }

    // Build filtered chunk→peer map using only online peers
    vector<set<string>> filteredChunkToPeers(fileInfoFromTracker.numChunks);
    for (int i = 0; i < fileInfoFromTracker.numChunks; ++i)
        for (const auto& pid : fileInfoFromTracker.chunkToPeers[i])
            if (onlinePeers.count(pid))
                filteredChunkToPeers[i].insert(pid);

    // Abort if any chunk has no online seeder
    for (int i = 0; i < fileInfoFromTracker.numChunks; ++i) {
        if (filteredChunkToPeers[i].empty()) {
            cerr << "\033[31m[Error] chunk " << i << " has no online peers, aborting download.\033[0m\n";
            downloads[fileName].failed = true;
            return;
        }
    }
    fileInfoFromTracker.chunkToPeers.swap(filteredChunkToPeers);

    // ---------------- prepare the destination file at the given location ----------------
    int outFd = open(destPath.c_str(), O_CREAT | O_RDWR, 0644);
    if (outFd < 0) {
        perror("Error while opening the destination file");
        downloads[fileName].failed = true;
        return;
    }
    // here we are allocating the file size because we are writing into the file at certain offset and there should be that much size so that we access that location
    if (ftruncate(outFd, fileInfoFromTracker.fileSize) != 0) {
        perror("ftruncate");
    }

    // ---------------- we are scheduling according to rareness of that chunk ----------------
    auto rarestOrder = chooseRarestFirstOrder(fileInfoFromTracker);

    // ---------------- for every chunk we need to decide from which peer we need to download it from ----------------
    struct Task { 
        int chunkIndex; 
        string peerId; 
    };
    vector<Task> tasks;   // this will contain chunkInddex, peerId for all the chunks that is all the tasks which needs to be performed by the worker thread pool
    tasks.reserve(rarestOrder.size());
    for (auto index : rarestOrder) {
        const auto peerset = fileInfoFromTracker.chunkToPeers[index];
        // we are taking peers in round robin fashion so that there is illusion of load balancing
        auto pickIndex = tasks.size() % peerset.size();
        auto it = peerset.begin();
        advance(it, pickIndex);
        tasks.push_back({index,*it});
    }

    // ---------------- THREAD POOLING WITH MAXIMUM 4 WORKER THREADS ----------------
    const int WORKER_COUNT = min(4, fileInfoFromTracker.numChunks); // if number of chunks are less than 4 then don't spawn more threads
    atomic<size_t> nextTask{0};   // this is just to know which is the next task for which we need to allocate to the worker
    vector<int> chunkDone(fileInfoFromTracker.numChunks, 0);  // this marks each chunk finished once it is written
    mutex coutMutex;    // keeps log lines from overlapping when multiple threads print.
 
    // this is the lambda function for what one worker will do
    auto worker = [&]() {
        while (true) {
            size_t i = nextTask.fetch_add(1);
            if (i >= tasks.size()) break;

            int chunkIndex = tasks[i].chunkIndex;

            // Try every peer that has this chunk, not just the one pre-assigned
            const auto& peerset = fileInfoFromTracker.chunkToPeers[chunkIndex];
            bool fetchingSuccessful = false;
            vector<char> chunkData;

            for (const auto& candidatePeer : peerset) {
                auto [peerIp, peerPort] = splitPeer(candidatePeer);
                chunkData.clear();
                fetchingSuccessful = fetchChunkFromPeer(peerIp, peerPort, fileInfoFromTracker.fileName,
                                                        chunkIndex, destPath, CHUNK_SIZE, chunkData);
                if (fetchingSuccessful) break;  // got it, stop trying other peers

                lock_guard<mutex> lg(coutMutex);
                cerr << "\033[31m[Downloader] failed chunk " << chunkIndex
                     << " from " << candidatePeer << ", trying next peer\033[0m\n";
            }

            if (!fetchingSuccessful) {
                lock_guard<mutex> lg(coutMutex);
                cerr << "\033[31m[Downloader] all peers failed for chunk " << chunkIndex << "\033[0m\n";
                continue;
            }

            // Write successfully fetched chunk to file
            off_t offset = (off_t)chunkIndex * (off_t)CHUNK_SIZE;
            ssize_t bytesWritten = pwrite(outFd, chunkData.data(), chunkData.size(), offset);
            if (bytesWritten != (ssize_t)chunkData.size()) {
                lock_guard<mutex> lg(coutMutex);
                cerr << "\033[31mWrite failed for chunk " << chunkIndex << "\033[0m\n";
                continue;
            }

            chunkDone[chunkIndex] = 1;
            {
                lock_guard<mutex> lg(coutMutex);
                downloads[fileName].chunkDone[chunkIndex] = 1;
                cout << "\033[34m[Downloader]\033[0m Wrote chunk: " << chunkIndex << "\n";
            }
        }
    };

    // Launch the thread pool and allocate start the workers
    vector<thread> pool;
    pool.reserve(WORKER_COUNT);
    // As soon we write thread(worker), the thread is created and immediately starts running the worker function in parallel
    for (int i = 0; i < WORKER_COUNT; ++i) pool.push_back(thread(worker));
    // after starting all the worker threads we reach here and then here we will ensure that we wait for all worker threads to finish 
    for (auto &t : pool) if (t.joinable()) t.join();

    // ---------------- Downloading either completed or it failed ----------------
    close(outFd);  // close the output file as writing has been done

    // check if all the chunks were successfully downloaded
    bool allDone = true;
    for (auto value : chunkDone) {
        if (value == 0) { 
            allDone = false;
            break;
        }
    }

    if (!allDone) {
        cerr << "\033[31m[Planner] Download incomplete: some chunks downloading failed\033[0m\n";
        downloads[fileName].failed = true;
        return;
    }

    downloads[fileName].completed = true;

    // -------- Digital Signature Verification (if uploader signed it) --------
    if (!fileInfoFromTracker.fileSignature.empty() && fileInfoFromTracker.fileSignature != "NONE" && !fileInfoFromTracker.uploaderPubKey.empty()) {
        bool sigOk = verifySignature(fileInfoFromTracker.fileShaHex, fileInfoFromTracker.fileSignature, fileInfoFromTracker.uploaderPubKey);
        if (!sigOk) {
            cerr << "\033[31m[Verifier] Digital signature verification failed! Rejecting file.\033[0m\n";
            downloads[fileName].failed = true;
            return;
        } else {
            cout << "\033[32m[Verifier] Digital signature verified successfully!\033[0m\n";
        }
    }

    // Register file locally so peer-server can serve it, like if some other file wants this file then we should know where this file was stored
    addLocalFilePath(fileInfoFromTracker.fileName, destPath);
    {
        lock_guard<mutex> lock(localPathMutex);
        fileNameToGroupId[fileInfoFromTracker.fileName] = groupId;
    }

    // -------- Full-file integrity check (if tracker provided a hash) --------
    string actual;
    if (!fileInfoFromTracker.fileShaHex.empty()) {
        // Compute SHA-1 of the file we just wrote at destPath
        string actualHex = sha1_hex_of_file(destPath);

        // Normalize case (defensive)
        auto toLower = [](string s){ for (auto& c : s) c = (char)tolower((unsigned char)c); return s; };
        string expected = toLower(fileInfoFromTracker.fileShaHex);
        actual = toLower(actualHex);

        if (actual.empty() || actual != expected) {
            cerr << "\033[31m[Verifier] File hash mismatch for '" << fileName
                    << "'. Expected " << expected << " got " << actual << "\033[0m\n";
            downloads[fileName].failed = true;

            return; // do NOT mark completed, do NOT register, do NOT notify tracker
        } else {
            cout << "\033[32m[Verifier]\033[0m File hash OK: " << actual << "\n";
        }
    } else {
        cout << "\033[32m[Verifier]\033[0m Did not receive any file hash from tracker: " << actual << "\n";
    }


    // Inform tracker that we have all chunks by sending upload_file
    if (trackerSSLIfAvailable != nullptr) {
        ostringstream ss;
        ss << "upload_file " << groupId << " " << fileInfoFromTracker.fileName << " "
        << (long long)fileInfoFromTracker.fileSize << " " << fileInfoFromTracker.numChunks << " "
        << clientIP << " " << clientPort;

        notifyTracker(trackerSSLIfAvailable, ss.str()); 
        {
            lock_guard<mutex> lg(coutMutex);
            cout << "Notified tracker about " << ss.str() << "\n";
        }
    }
}