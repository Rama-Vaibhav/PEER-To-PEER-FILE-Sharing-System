#include <iostream>
#include <sstream>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>
#include <set>
#include <openssl/ssl.h>
#include "client.h"
#include "../common/cryptoUtil.h"

using namespace std;

// this will be used for show_downloads as that part will be handled from the peer and not the tracker side
map<string, DownloadStatus> downloads;

/********************************************************************************************************
                Function to handle the sending of command from the client
********************************************************************************************************/
void sendCommands(SSL* trackerSSL, const string &clientIP, int clientPort, const string &trackerIP1, int trackerPort1, const string &trackerIP2, int trackerPort2) {
    string command;
    bool pendingFilehash = false;
    string pendingHashCmd;
    while (true) {
        cout << "\033[33m>>\033[0m " << flush;
        if (!getline(cin, command)) {
            break;
        }

        // Check if command is empty or only whitespace
        stringstream test_ss(command);
        string first_word;
        test_ss >> first_word;
        if (first_word.empty()) {
            continue;
        }

        // --- Normalize two-word commands to underscore form ---
        // PDF uses "create user", "join group" etc. Internally we use underscores.
        {
            stringstream norm(command);
            string w1, w2;
            norm >> w1;
            // These first words always precede a second command word
            static const set<string> twoWordPrefixes = {
                "create", "join", "leave", "list", "accept",
                "upload", "download", "show", "stop"
            };
            if (twoWordPrefixes.count(w1)) {
                norm >> w2;
                string rest;
                getline(norm, rest);  // everything after the two words
                // Trim leading space from rest
                if (!rest.empty() && rest[0] == ' ') rest.erase(0, 1);
                command = w1 + "_" + w2;
                if (!rest.empty()) command += " " + rest;
            }
        }

        stringstream ss(command);
        string cmd;
        ss >> cmd;

        if (cmd == "create_user") {
            string userid, password;
            ss >> userid >> password;

            if (userid.empty() || password.empty()) {
                cout << "Usage: create user <user_id> <password>" << endl;
                continue;
            }

            // Generate RSA Key Pair
            string privateKeyPEM, publicKeyPEM;
            if (!generateRSAKeyPair(privateKeyPEM, publicKeyPEM)) {
                cout << "Error: Failed to generate RSA key pair for user" << endl;
                continue;
            }

            // Ensure directory keys/ exists
            system("mkdir -p keys");

            // Save private key locally
            string privPath = "keys/" + userid + "_private.pem";
            FILE* f = fopen(privPath.c_str(), "w");
            if (f) {
                fputs(privateKeyPEM.c_str(), f);
                fclose(f);
            } else {
                cout << "Error: Failed to save private key locally" << endl;
                continue;
            }

            // Send command with public key hex: create_user <userid> <password> <pubkey_hex>
            string regCmd = "create_user " + userid + " " + password + " " + toHex(publicKeyPEM);
            if (SSL_write(trackerSSL, regCmd.c_str(), regCmd.size()) <= 0) {
                cerr << "SSL_write failed" << endl;
                continue;
            }

            char buf[4096];
            int bytes = SSL_read(trackerSSL, buf, sizeof(buf) - 1);
            if (bytes > 0) {
                string reply(buf, bytes);
                cout << "\033[34m[Tracker]\033[0m " << reply << flush;
            }
            continue;
        }

        else if (cmd == "login") {
            string userid, password;
            ss >> userid >> password;

            if (userid.empty() || password.empty()) {
                cout << "Usage: login <user_id> <password>" << endl;
                continue;
            }

            // Step A: Send login_challenge <userid>
            string challengeCmd = "login_challenge " + userid;
            if (SSL_write(trackerSSL, challengeCmd.c_str(), challengeCmd.size()) <= 0) {
                cerr << "SSL_write failed" << endl;
                continue;
            }

            char buf[4096];
            int bytes = SSL_read(trackerSSL, buf, sizeof(buf) - 1);
            if (bytes <= 0) {
                cerr << "[Client] Lost connection to tracker" << endl;
                continue;
            }
            string challReply(buf, bytes);
            
            if (challReply.rfind("CHALLENGE ", 0) != 0) {
                cout << "\033[34m[Tracker]\033[0m " << challReply << flush;
                continue;
            }

            string challengeHex = challReply.substr(10);
            if (!challengeHex.empty() && challengeHex.back() == '\n') challengeHex.pop_back();

            // Step B: Load private key
            string privPath = "keys/" + userid + "_private.pem";
            FILE* f = fopen(privPath.c_str(), "r");
            if (!f) {
                cout << "Error: Private key not found at " << privPath << ". Did you register on this machine?" << endl;
                continue;
            }
            string privateKeyPEM;
            char keyBuf[256];
            while (fgets(keyBuf, sizeof(keyBuf), f)) {
                privateKeyPEM += keyBuf;
            }
            fclose(f);

            // Step C: Sign challenge
            string signatureHex = signMessage(challengeHex, privateKeyPEM);
            if (signatureHex.empty()) {
                cout << "Error: Failed to sign the login challenge" << endl;
                continue;
            }

            // Step D: Send login_response <userid> <signature_hex> <ip> <port>
            string respCmd = "login_response " + userid + " " + signatureHex + " " + clientIP + " " + to_string(clientPort);
            if (SSL_write(trackerSSL, respCmd.c_str(), respCmd.size()) <= 0) {
                cerr << "SSL_write failed" << endl;
                continue;
            }

            bytes = SSL_read(trackerSSL, buf, sizeof(buf) - 1);
            if (bytes > 0) {
                string reply(buf, bytes);
                cout << "\033[34m[Tracker]\033[0m " << reply << flush;
                if (reply.find("Login successful") != string::npos) {
                    g_currentUsername = userid; // Save current logged in user
                }
            }
            continue;
        }

        else if (cmd == "create_group") {
            string groupid;
            ss >> groupid;
            if (groupid.empty()) {
                cout << "Usage: create group <group_id>" << endl;
                continue;
            }

            if (g_currentUsername.empty()) {
                cout << "Error: You must be logged in to create a group" << endl;
                continue;
            }

            // Step A: Generate AES Key (the group key)
            string groupKey = generateAESKey();

            // Step B: Get current user's public key from tracker
            string pubkeyCmd = "get_user_pubkey " + g_currentUsername;
            if (SSL_write(trackerSSL, pubkeyCmd.c_str(), pubkeyCmd.size()) <= 0) {
                cerr << "SSL_write failed" << endl;
                continue;
            }
            char buf[4096];
            int bytes = SSL_read(trackerSSL, buf, sizeof(buf) - 1);
            if (bytes <= 0) continue;
            string pubkeyReply(buf, bytes);
            if (pubkeyReply.rfind("PUBKEY ", 0) != 0) {
                cout << "\033[34m[Tracker]\033[0m " << pubkeyReply << flush;
                continue;
            }
            string pubkeyHex = pubkeyReply.substr(7);
            if (!pubkeyHex.empty() && pubkeyHex.back() == '\n') pubkeyHex.pop_back();

            // Step C: Encrypt group key with public key
            string encGroupKey = rsaEncrypt(groupKey, fromHex(pubkeyHex));
            if (encGroupKey.empty()) {
                cout << "Error: Failed to encrypt group key" << endl;
                continue;
            }

            // Step D: Send create_group <groupid> <encGroupKey>
            string createCmd = "create_group " + groupid + " " + encGroupKey;
            if (SSL_write(trackerSSL, createCmd.c_str(), createCmd.size()) <= 0) {
                cerr << "SSL_write failed" << endl;
                continue;
            }
            bytes = SSL_read(trackerSSL, buf, sizeof(buf) - 1);
            if (bytes > 0) {
                string reply(buf, bytes);
                cout << "\033[34m[Tracker]\033[0m " << reply << flush;
                if (reply.find("Group created successfully") != string::npos) {
                    g_groupKeys[groupid] = groupKey; // Cache the group key
                }
            }
            continue;
        }

        else if (cmd == "join_group") {
            string groupid;
            ss >> groupid;
            if (groupid.empty()) {
                cout << "Usage: join group <group_id>" << endl;
                continue;
            }
        }

        else if (cmd == "leave_group") {
            string groupid;
            ss >> groupid;
            if (groupid.empty()) {
                cout << "Usage: leave group <group_id>" << endl;
                continue;
            }
        }

        else if (cmd == "list_requests") {
            string groupid;
            ss >> groupid;
            if (groupid.empty()) {
                cout << "Usage: list requests <group_id>" << endl;
                continue;
            }
        }

        else if (cmd == "accept_request") {
            string groupid, userid;
            ss >> groupid >> userid;
            if (groupid.empty() || userid.empty()) {
                cout << "Usage: accept request <group_id> <user_id>" << endl;
                continue;
            }

            // Step A: Fetch target user's public key
            string pubkeyCmd = "get_user_pubkey " + userid;
            if (SSL_write(trackerSSL, pubkeyCmd.c_str(), pubkeyCmd.size()) <= 0) {
                cerr << "SSL_write failed" << endl;
                continue;
            }
            char buf[4096];
            int bytes = SSL_read(trackerSSL, buf, sizeof(buf) - 1);
            if (bytes <= 0) continue;
            string pubkeyReply(buf, bytes);
            if (pubkeyReply.rfind("PUBKEY ", 0) != 0) {
                cout << "\033[34m[Tracker]\033[0m " << pubkeyReply << flush;
                continue;
            }
            string targetPubkeyHex = pubkeyReply.substr(7);
            if (!targetPubkeyHex.empty() && targetPubkeyHex.back() == '\n') targetPubkeyHex.pop_back();

            // Step B: Get group key (either from cache, or retrieve from tracker and decrypt)
            string groupKey = "";
            auto kit = g_groupKeys.find(groupid);
            if (kit != g_groupKeys.end()) {
                groupKey = kit->second;
            } else {
                // Fetch encrypted group key for current user
                string getkeyCmd = "get_group_key " + groupid;
                if (SSL_write(trackerSSL, getkeyCmd.c_str(), getkeyCmd.size()) <= 0) {
                    cerr << "SSL_write failed" << endl;
                    continue;
                }
                bytes = SSL_read(trackerSSL, buf, sizeof(buf) - 1);
                if (bytes <= 0) continue;
                string getkeyReply(buf, bytes);
                if (getkeyReply.rfind("GROUPKEY ", 0) != 0) {
                    cout << "\033[34m[Tracker]\033[0m " << getkeyReply << flush;
                    continue;
                }
                string encKeyHex = getkeyReply.substr(9);
                if (!encKeyHex.empty() && encKeyHex.back() == '\n') encKeyHex.pop_back();

                // Decrypt group key
                string privPath = "keys/" + g_currentUsername + "_private.pem";
                FILE* f = fopen(privPath.c_str(), "r");
                if (!f) {
                    cout << "Error: Private key not found at " << privPath << endl;
                    continue;
                }
                string privateKeyPEM;
                char keyBuf[256];
                while (fgets(keyBuf, sizeof(keyBuf), f)) {
                    privateKeyPEM += keyBuf;
                }
                fclose(f);

                groupKey = rsaDecrypt(encKeyHex, privateKeyPEM);
                if (groupKey.empty()) {
                    cout << "Error: Failed to decrypt group key" << endl;
                    continue;
                }
                g_groupKeys[groupid] = groupKey; // Cache it
            }

            // Step C: Encrypt group key with target user's public key
            string encGroupKeyForTarget = rsaEncrypt(groupKey, fromHex(targetPubkeyHex));
            if (encGroupKeyForTarget.empty()) {
                cout << "Error: Failed to encrypt group key for target user" << endl;
                continue;
            }

            // Step D: Send accept_request <groupid> <userid> <encGroupKeyForTarget>
            string acceptCmd = "accept_request " + groupid + " " + userid + " " + encGroupKeyForTarget;
            if (SSL_write(trackerSSL, acceptCmd.c_str(), acceptCmd.size()) <= 0) {
                cerr << "SSL_write failed" << endl;
                continue;
            }
            bytes = SSL_read(trackerSSL, buf, sizeof(buf) - 1);
            if (bytes > 0) {
                string reply(buf, bytes);
                cout << "\033[34m[Tracker]\033[0m " << reply << flush;
            }
            continue;
        }

        else if (cmd == "upload_file") {
            string groupid, filePath;
            ss >> groupid;
            getline(ss, filePath);
            if (!filePath.empty() && filePath[0] == ' ') filePath.erase(0, 1);

            if (!filePath.empty() && filePath.front() == '"' && filePath.back() == '"')
                filePath = filePath.substr(1, filePath.size() - 2);

            if (groupid.empty()) {
                cout << "Usage: upload file <group_id> <file_path>" << endl;
                continue;
            }

            size_t pos = filePath.find_last_of('/');
            string fileName = (pos == string::npos) ? filePath : filePath.substr(pos + 1);

            struct stat st;
            if (stat(filePath.c_str(), &st) != 0) {
                perror("stat failed");
                cout << "Cannot access file: " << filePath << endl;
                continue;
            }
            long long fileSize = st.st_size;
            const int chunkSize = 512 * 1024;
            int numChunks = (fileSize + chunkSize - 1) / chunkSize;

            addLocalFilePath(fileName, filePath);
            {
                lock_guard<mutex> lock(localPathMutex);
                fileNameToGroupId[fileName] = groupid;
            }

            command = "upload_file " + groupid + " " + fileName + " " + to_string(fileSize)
                    + " " + to_string(numChunks) + " " + clientIP + " " + to_string(clientPort);

            string fullHex = sha1_hex_of_file(filePath);
            if (!fullHex.empty()) {
                string signatureHex = "";
                string privPath = "keys/" + g_currentUsername + "_private.pem";
                FILE* f = fopen(privPath.c_str(), "r");
                if (f) {
                    string privateKeyPEM;
                    char keyBuf[256];
                    while (fgets(keyBuf, sizeof(keyBuf), f)) {
                        privateKeyPEM += keyBuf;
                    }
                    fclose(f);
                    signatureHex = signMessage(fullHex, privateKeyPEM);
                } else {
                    cerr << "\033[33m[Client] Warning: Private key not found at " << privPath << ", file won't be digitally signed\033[0m\n";
                }

                if (signatureHex.empty()) {
                    signatureHex = "NONE";
                }

                pendingHashCmd  = "upload_filehash " + groupid + " " + fileName + " " + fullHex + " " + signatureHex;
                pendingFilehash = true;
            } else {
                pendingHashCmd.clear();
                pendingFilehash = false;
                cerr << "\033[33m[Client] Warning: could not compute SHA1 for " << filePath << "\033[0m\n";
            }
        }

        else if (cmd == "download_file") {
            string groupid, fileName, destPath;
            ss >> groupid >> fileName;
            getline(ss, destPath);
            if (!destPath.empty() && destPath[0] == ' ') destPath.erase(0, 1);

            if (!destPath.empty() && destPath.front() == '"' && destPath.back() == '"')
                destPath = destPath.substr(1, destPath.size() - 2);

            if (groupid.empty() || fileName.empty() || destPath.empty()) {
                cout << "Usage: download file <group_id> <file_name> <destination_path>\n";
                continue;
            }

            string trackerCmd = "download_file " + groupid + " " + fileName;
            if (SSL_write(trackerSSL, trackerCmd.c_str(), trackerCmd.size()) <= 0) {
                cerr << "SSL_write failed" << endl;
                continue;
            }

            string trackerResponse;
            char buffer[1024];
            while (true) {
                int n = SSL_read(trackerSSL, buffer, sizeof(buffer));
                if (n <= 0) {
                    cerr << "Lost connection to tracker\n";
                    trackerResponse.clear();
                    break;
                }
                trackerResponse.append(buffer, n);
                if (trackerResponse.find("END\n") != string::npos) break;
            }
            if (trackerResponse.find("FILEINFO") != string::npos) {
                startDownloadFromTrackerResponse(trackerResponse, groupid, fileName, destPath,
                                                 clientIP, clientPort, trackerSSL);
            }
            continue;
        }

        else if (cmd == "show_downloads") {
            if (downloads.empty()) {
                cout << "There are no downloads to show yet\n";
            } else {
                for (auto file : downloads) {
                    auto value = file.second;
                    int done = 0;
                    for (int val : value.chunkDone) { if (val) ++done; }
                    char tag = value.completed ? 'C' : (value.failed ? 'F' : 'I');
                    cout << "[" << tag << "] "
                         << "[" << (value.gid.empty() ? "-" : value.gid) << "] "
                         << value.fileName;
                    if (!value.completed && !value.failed) {
                        double progress = (value.numChunks > 0) ? (100.0 * done / value.numChunks) : 0.0;
                        cout << " - " << done << "/" << value.numChunks
                             << " (" << progress << "%)";
                    }
                    cout << "\n";
                }
            }
            continue;
        }

        else if (cmd == "stop_share") {
            string groupid, fileName;
            ss >> groupid >> fileName;
            if (groupid.empty() || fileName.empty()) {
                cout << "Usage: stop share <group_id> <file_name>\n";
                continue;
            }
            command = "stop_share " + groupid + " " + fileName;
        }

        else if (command == "logout") {
            SSL_write(trackerSSL, command.c_str(), command.size());
            char buffer[4096];
            int bytes = SSL_read(trackerSSL, buffer, sizeof(buffer));
            if (bytes > 0) {
                string reply(buffer, bytes);
                cout << "\033[34m[Tracker]\033[0m " << reply << flush;
            }
            cout << "Logging out. You can login again or exit." << endl;
            continue;
        }

        // Send command to tracker via TLS
        if (SSL_write(trackerSSL, command.c_str(), command.size()) <= 0) {
            cerr << "SSL_write failed" << endl;
        }

        char buffer[4096];
        int bytes = SSL_read(trackerSSL, buffer, sizeof(buffer));
        if (bytes <= 0) {
            cerr << "\033[31m[Client] Lost connection to tracker\033[0m" << endl;
            // Try to reconnect with TLS
            int fd = SSL_get_fd(trackerSSL);
            SSL_shutdown(trackerSSL);
            SSL_free(trackerSSL);
            close(fd);
            trackerSSL = connectToTrackerSSL(trackerIP1, trackerPort1, trackerIP2, trackerPort2);
            if (!trackerSSL) {
                cerr << "\033[31m[Client] Could not reconnect to any tracker, exiting\033[0m" << endl;
                break;
            } else {
                cout << "\033[32m[Client] Reconnected to tracker (TLS)!\033[0m" << endl;
                continue;
            }
        }

        string reply(buffer, bytes);
        cout << "\033[34m[Tracker]\033[0m " << reply << flush;

        if (pendingFilehash && !pendingHashCmd.empty()) {
            if (reply.find("ERROR") == std::string::npos) {
                if (SSL_write(trackerSSL, pendingHashCmd.c_str(), pendingHashCmd.size()) <= 0) {
                    cerr << "SSL_write failed (upload_filehash)" << endl;
                } else {
                    // Try non-blocking read for the hash upload response
                    // Set socket to non-blocking temporarily
                    int fd = SSL_get_fd(trackerSSL);
                    int flags = fcntl(fd, F_GETFL, 0);
                    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
                    int n2 = SSL_read(trackerSSL, buffer, sizeof(buffer));
                    fcntl(fd, F_SETFL, flags);  // restore blocking mode
                    if (n2 > 0) {
                        std::string r2(buffer, n2);
                        cout << "\033[34m[Tracker]\033[0m " << r2 << flush;
                    }
                }
            }
            pendingFilehash = false;
            pendingHashCmd.clear();
        }
    }
}