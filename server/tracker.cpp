// server/tracker.cpp — Secure P2P File Sharing Tracker with TLS
// Build: make (see Makefile)

#include "commands.h"
#include "common.h"
#include "tls_utils.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <string>
#include <atomic>
#include <sstream>
#include <chrono>
#include <map>
#include <cstring>
using namespace std;

// === Global sync socket descriptor ===
int g_sync_sock = -1;
mutex g_sync_sock_mutex;

// === Global SSL contexts ===
static SSL_CTX* g_server_ctx = nullptr;  // for accepting client connections
static string g_ca_cert_path;
static string g_ca_key_path;

// ---- Tracker info parsing ----

struct TrackerInfo {
    int id;
    string ip;
    int main_port;
    int sync_port;
};

string cmd_create_user(const string&, const string&);

static bool parse_tracker_info_file(const string &path, map<int, TrackerInfo> &out_map) {
    ifstream ifs(path);
    if (!ifs.is_open()) return false;
    out_map.clear();
    string line;
    while (getline(ifs, line)) {
        if (line.empty()) continue;
        istringstream iss(line);
        TrackerInfo t;
        if (!(iss >> t.id >> t.ip >> t.main_port >> t.sync_port)) continue;
        out_map[t.id] = t;
    }
    return true;
}

// ---- Client handler (TLS) ----

void client_thread_func(SSL* ssl) {
    string current_user;
    cout << "[TLS] Client connected — secure channel established\n";

    while (true) {
        string line = tls_read_line(ssl);
        if (line.empty()) break;

        string response = process_command(line, current_user, SSL_get_fd(ssl));

        // Check if this is a login success — if so, generate & send client cert
        if (line.rfind("login ", 0) == 0 && response.find("Login successful") != string::npos) {
            // Generate on-the-fly client certificate for mTLS P2P
            string cert_pem, key_pem;
            if (generate_client_cert(g_ca_cert_path.c_str(), g_ca_key_path.c_str(),
                                     current_user, cert_pem, key_pem)) {
                // Encode cert and key as hex to send in single line (no newlines)
                string cert_hex, key_hex;
                for (char c : cert_pem) {
                    char buf[3];
                    snprintf(buf, 3, "%02x", (unsigned char)c);
                    cert_hex += buf;
                }
                for (char c : key_pem) {
                    char buf[3];
                    snprintf(buf, 3, "%02x", (unsigned char)c);
                    key_hex += buf;
                }
                response = "Login successful CERT " + cert_hex + " KEY " + key_hex + "\n";
                cout << "[TLS] Issued X.509 certificate for user '" << current_user << "'\n";
            }
        }

        if (!tls_write_line(ssl, response)) break;
    }

    // Ensure logout
    if (!current_user.empty()) {
        lock_guard<mutex> lock(state_mutex);
        auto it = users.find(current_user);
        if (it != users.end()) it->second.logged_in = false;
        cout << "[SERVER] User '" << current_user << "' disconnected\n";
    }

    SSL_shutdown(ssl);
    close(SSL_get_fd(ssl));
    SSL_free(ssl);
}

// ---- Sync connection handler (TLS) ----

static void handle_sync_connection(SSL* ssl, atomic<bool> &global_running, bool initiated_by_me) {
    string peer_label = initiated_by_me ? "peer(client-mode)" : "peer(listener-mode)";
    cout << "[SYNC-TLS] Connection established (" << peer_label << ")\n";

    {
        lock_guard<mutex> lk(sync_mutex);
        sync_sockfd = SSL_get_fd(ssl);
    }

    if (initiated_by_me) {
        tls_write_line(ssl, "HELLO_FROM_INITIATOR");
    }

    while (global_running.load()) {
        string line = tls_read_line_timeout(ssl, 5);
        if (line.empty()) {
            cout << "[SYNC-TLS] Connection closed by peer or error\n";
            break;
        }
        if (line == "__TIMEOUT__") {
            if (!tls_write_line(ssl, "HEARTBEAT")) {
                cout << "[SYNC-TLS] Failed to send heartbeat\n";
                break;
            }
            continue;
        }
        if (line != "HEARTBEAT" && line.rfind("ACK:", 0) != 0) {
            cout << "[SYNC-TLS recv] " << line << "\n";
            process_sync_message(line);
            string ack = "ACK:" + line;
            if (!tls_write_line(ssl, ack)) break;
        }
    }

    {
        lock_guard<mutex> lk(sync_mutex);
        if (sync_sockfd == SSL_get_fd(ssl)) sync_sockfd = -1;
    }

    SSL_shutdown(ssl);
    close(SSL_get_fd(ssl));
    SSL_free(ssl);
    cout << "[SYNC-TLS] Connection handler exiting\n";
}

// ---- Sync listener thread (TLS) ----

static void sync_listener_thread(const TrackerInfo &self_info, atomic<bool> &global_running) {
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) { perror("[sync listener] socket"); return; }

    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(self_info.sync_port);

    if (::bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("[sync listener] bind"); close(listenfd); return;
    }
    if (listen(listenfd, 1) < 0) {
        perror("[sync listener] listen"); close(listenfd); return;
    }

    cout << "[SYNC-TLS] Listening on port " << self_info.sync_port << "\n";

    while (global_running.load()) {
        struct sockaddr_in cli;
        socklen_t clilen = sizeof(cli);
        int newsock = accept(listenfd, (struct sockaddr*)&cli, &clilen);
        if (newsock < 0) {
            this_thread::sleep_for(chrono::seconds(1));
            continue;
        }

        // Wrap with TLS
        SSL* ssl = SSL_new(g_server_ctx);
        SSL_set_fd(ssl, newsock);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(newsock);
            SSL_free(ssl);
            continue;
        }

        thread t(handle_sync_connection, ssl, ref(global_running), false);
        t.detach();
    }
    close(listenfd);
}

// ---- Sync connector thread (TLS) ----

static void sync_connector_thread(const TrackerInfo &peer_info, atomic<bool> &global_running) {
    // Create client context for connecting to peer tracker
    SSL_CTX* sync_ctx = create_client_tls_ctx(g_ca_cert_path.c_str());
    if (!sync_ctx) {
        cerr << "[SYNC-TLS] Failed to create sync client context\n";
        return;
    }
    // Also load our tracker cert for mutual auth
    SSL_CTX_use_certificate_file(sync_ctx, (g_ca_cert_path.substr(0, g_ca_cert_path.rfind('/')) + "/tracker.crt").c_str(), SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(sync_ctx, (g_ca_cert_path.substr(0, g_ca_cert_path.rfind('/')) + "/tracker.key").c_str(), SSL_FILETYPE_PEM);

    while (global_running.load()) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            this_thread::sleep_for(chrono::seconds(2));
            continue;
        }

        struct sockaddr_in serv_addr{};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(peer_info.sync_port);
        if (inet_pton(AF_INET, peer_info.ip.c_str(), &serv_addr.sin_addr) <= 0) {
            close(sockfd); return;
        }

        cout << "[SYNC-TLS] Connecting to " << peer_info.ip << ":" << peer_info.sync_port << "...\n";
        if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == 0) {
            SSL* ssl = SSL_new(sync_ctx);
            SSL_set_fd(ssl, sockfd);
            if (SSL_connect(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                close(sockfd);
                SSL_free(ssl);
                this_thread::sleep_for(chrono::seconds(3));
                continue;
            }
            cout << "[SYNC-TLS] Connected to peer tracker (TLS encrypted)\n";
            handle_sync_connection(ssl, const_cast<atomic<bool>&>(global_running), true);
            cout << "[SYNC-TLS] Connection closed; will retry\n";
            this_thread::sleep_for(chrono::seconds(3));
        } else {
            close(sockfd);
            this_thread::sleep_for(chrono::seconds(3));
        }
    }
    SSL_CTX_free(sync_ctx);
}

// ---- Main ----

int main(int argc, char *argv[]) {
    if (argc < 3) {
        cerr << "Usage: " << argv[0] << " <tracker_info.txt> <my_id> [certs_dir]\n";
        return 1;
    }

    string info_path = argv[1];
    int my_id = atoi(argv[2]);
    string certs_dir = (argc >= 4) ? argv[3] : "certs";

    g_ca_cert_path = certs_dir + "/ca.crt";
    g_ca_key_path = certs_dir + "/ca.key";
    string tracker_cert = certs_dir + "/tracker.crt";
    string tracker_key = certs_dir + "/tracker.key";

    // Initialize OpenSSL
    init_openssl();

    cout << "╔══════════════════════════════════════════════════╗\n";
    cout << "║     SECURE P2P FILE SHARING — TRACKER SERVER     ║\n";
    cout << "║          TLS 1.2+ | SHA-256 | RSA-2048           ║\n";
    cout << "╚══════════════════════════════════════════════════╝\n";

    // Create server TLS context
    g_server_ctx = create_server_tls_ctx(tracker_cert.c_str(), tracker_key.c_str(), g_ca_cert_path.c_str());
    if (!g_server_ctx) {
        cerr << "FATAL: Failed to create TLS context. Check cert files in " << certs_dir << "/\n";
        return 1;
    }
    cout << "[TLS] Server context initialized (cert: " << tracker_cert << ")\n";

    map<int, TrackerInfo> trackers;
    if (!parse_tracker_info_file(info_path, trackers)) {
        cerr << "Failed to open or parse " << info_path << "\n"; return 1;
    }
    if (trackers.find(my_id) == trackers.end()) {
        cerr << "No entry for id " << my_id << " in " << info_path << "\n"; return 1;
    }

    TrackerInfo self = trackers[my_id];

    TrackerInfo peer;
    bool found_peer = false;
    for (auto &p : trackers) {
        if (p.first != my_id) { peer = p.second; found_peer = true; break; }
    }

    if (found_peer) {
        cout << "[SYNC] Peer tracker: id=" << peer.id << " ip=" << peer.ip
             << " sync_port=" << peer.sync_port << "\n";
    }

    atomic<bool> global_running(true);

    // Start sync threads
    thread listener_t(sync_listener_thread, cref(self), ref(global_running));
    listener_t.detach();

    thread connector_t;
    if (found_peer) {
        connector_t = thread(sync_connector_thread, cref(peer), ref(global_running));
        connector_t.detach();
    }

    // Main client-facing server socket (TLS)
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(self.main_port);

    if (::bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(sockfd, 16) < 0) { perror("listen"); return 1; }

    cout << "[SERVER] Tracker (id=" << self.id << ") listening on port " << self.main_port
         << " (TLS encrypted)\n";
    cout << "─────────────────────────────────────────────────────\n";

    while (global_running.load()) {
        sockaddr_in cli_addr;
        socklen_t clilen = sizeof(cli_addr);
        int newsockfd = accept(sockfd, (struct sockaddr*)&cli_addr, &clilen);
        if (newsockfd < 0) {
            this_thread::sleep_for(chrono::milliseconds(100));
            continue;
        }

        // Wrap with TLS
        SSL* ssl = SSL_new(g_server_ctx);
        SSL_set_fd(ssl, newsockfd);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(newsockfd);
            SSL_free(ssl);
            continue;
        }

        thread t(client_thread_func, ssl);
        t.detach();
    }

    close(sockfd);
    SSL_CTX_free(g_server_ctx);
    cleanup_openssl();
    cout << "Tracker shutting down\n";
    return 0;
}
