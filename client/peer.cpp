#include "peer.h"
#include <iostream>
#include <map>
#include <set>
#include <mutex>
#include <thread>
#include <vector>
#include <sstream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

using namespace std;

#define CHUNK_SIZE 524288 // 512KB

// Single definitions (others should declare 'extern')
map<string,string> seeded_files;
map<string,string> local_partial_files;  // filename -> dest_path for active downloads
map<string,set<int>> local_pieces;       // filename -> set of completed piece indices
mutex seeded_files_mutex;

/* ---------- helpers ---------- */

static bool send_all(int sock, const char* buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

static bool recv_line(int sock, string& out) {
    out.clear();
    char c;
    while (true) {
        ssize_t n = read(sock, &c, 1);
        if (n <= 0) return false;
        if (c == '\n') break;
        out.push_back(c);
    }
    return true;
}

/* ---------- handler ---------- */

static void handle_peer_request(int peer_socket) {
    // Serve multiple requests on the same connection
    while (true) {
        string request;
        if (!recv_line(peer_socket, request)) {
            break;
        }

        stringstream ss(request);
        string command, filename;
        long long piece_index = -1;
        ss >> command >> filename >> piece_index;

        if (command == "GET_PIECE") {
            if (filename.empty() || piece_index < 0) {
                break;
            }

            string local_path;
            bool has_piece = false;
            {
                lock_guard<mutex> lock(seeded_files_mutex);
                // Check fully seeded files first
                auto it = seeded_files.find(filename);
                if (it != seeded_files.end()) {
                    local_path = it->second;
                    has_piece = true;
                } else {
                    // Check partial downloads — serve pieces we already have
                    auto pit = local_partial_files.find(filename);
                    if (pit != local_partial_files.end()) {
                        auto lit = local_pieces.find(filename);
                        if (lit != local_pieces.end() && lit->second.count((int)piece_index)) {
                            local_path = pit->second;
                            has_piece = true;
                        }
                    }
                }
            }

            if (!has_piece || local_path.empty()) {
                const string hdr = "PIECE_LEN 0\n";
                send_all(peer_socket, hdr.c_str(), hdr.size());
                continue;
            }

            int fd = open(local_path.c_str(), O_RDONLY);
            if (fd < 0) {
                const string hdr = "PIECE_LEN 0\n";
                send_all(peer_socket, hdr.c_str(), hdr.size());
                continue;
            }

            off_t offset = static_cast<off_t>(piece_index) * static_cast<off_t>(CHUNK_SIZE);
            if (lseek(fd, offset, SEEK_SET) < 0) {
                close(fd);
                const string hdr = "PIECE_LEN 0\n";
                send_all(peer_socket, hdr.c_str(), hdr.size());
                continue;
            }

            vector<char> buffer(CHUNK_SIZE);
            ssize_t bytes_read = read(fd, buffer.data(), CHUNK_SIZE);
            close(fd);

            if (bytes_read < 0) {
                const string hdr = "PIECE_LEN 0\n";
                send_all(peer_socket, hdr.c_str(), hdr.size());
                continue;
            }

            string hdr = "PIECE_LEN " + to_string(bytes_read) + "\n";
            if (!send_all(peer_socket, hdr.c_str(), hdr.size())) {
                break;
            }

            if (bytes_read > 0) {
                if (!send_all(peer_socket, buffer.data(), (size_t)bytes_read)) {
                    break;
                }
            }
        }
        else if (command == "GET_BITMAP") {
            // GET_BITMAP <filename> <total_pieces>
            // piece_index variable holds total_pieces here (reusing the parsed int)
            int total_pieces = (int)piece_index;
            if (filename.empty() || total_pieces <= 0) {
                string resp = "BITMAP_ERROR\n";
                send_all(peer_socket, resp.c_str(), resp.size());
                continue;
            }

            string bitmap;
            {
                lock_guard<mutex> lock(seeded_files_mutex);
                if (seeded_files.count(filename)) {
                    // Full seeder — has all pieces
                    bitmap = string(total_pieces, '1');
                } else if (local_pieces.count(filename)) {
                    // Partial downloader — has some pieces
                    bitmap.resize(total_pieces, '0');
                    for (int p : local_pieces[filename]) {
                        if (p < total_pieces) bitmap[p] = '1';
                    }
                } else {
                    // Don't have this file at all
                    bitmap = string(total_pieces, '0');
                }
            }
            string resp = "BITMAP " + bitmap + "\n";
            send_all(peer_socket, resp.c_str(), resp.size());
        }
        else {
            // Unknown command
            break;
        }
    }

    close(peer_socket);
}


/* ---------- server thread ---------- */

void peer_server_thread(string my_ip, int my_port) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("[Peer Server] socket() failed");
        return;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(my_ip.c_str());
    addr.sin_port = htons(my_port);

    if (bind(listen_fd, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[Peer Server] bind() failed");
        close(listen_fd);
        return;
    }

    if (listen(listen_fd, 16) < 0) {
        perror("[Peer Server] listen() failed");
        close(listen_fd);
        return;
    }

    cout << "[Peer Server] Listening on " << my_ip << ":" << my_port << endl;

    while (true) {
        int peer_socket = accept(listen_fd, nullptr, nullptr);
        if (peer_socket < 0) {
            perror("[Peer Server] accept() failed");
            continue;
        }
        thread t(handle_peer_request, peer_socket);
        t.detach();
    }

    close(listen_fd);
}