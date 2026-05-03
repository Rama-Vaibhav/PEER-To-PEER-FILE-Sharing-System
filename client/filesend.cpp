#include "filesend.h"
#include "peer.h"
#include <openssl/sha.h>
#include<cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>
#include <string>
#include <iostream>
#include <cstring>
#include <map>
#include <set>
#include <mutex>
#include <memory>
#include <thread>
#include <chrono>
#include <algorithm>
#include <cstdlib>
using namespace std;

#define CHUNK_SIZE 524288 // 512KB

// These are defined in peer.cpp (single definition). We only reference them here.
extern map<string,string> seeded_files;
extern map<string,string> local_partial_files;
extern map<string,set<int>> local_pieces;
extern mutex seeded_files_mutex;

// these are for the show_downloads command
map<string,shared_ptr<DownloadState>>active_downloads;
mutex active_downloads_mutex;

/* ---------- helpers ---------- */
static string sha1_to_hex(const unsigned char* hash) {
    stringstream ss;
    ss << hex << setfill('0');
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        ss << setw(2) << static_cast<unsigned int>(hash[i]);
    }
    return ss.str();
}

// read one \n-terminated line from a socket
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

// read exactly len bytes into buf
static bool recv_exact(int sock, char* buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(sock, buf + got, len - got, 0);
        if (n <= 0) return false;
        got += (size_t)n;
    }
    return true;
}

// helper to read a line from the tracker socket (used in client.cpp too)
static string read_line_tracker(int sock) {
    string line;
    char c;
    while(read(sock, &c, 1) > 0) {
        if(c == '\n') break;
        line += c;
    }
    return line;
}

/* ---------- metadata for upload ---------- */

FileMetadata prepare_file_metadata(const string &file_path,const string &group_id,const string &username,const string &ip,int port)
{
    struct stat st;
    if (stat(file_path.c_str(), &st) != 0) {
        throw runtime_error("File not found or cannot be accessed: " + file_path);
    }
    if (!S_ISREG(st.st_mode)) {
        throw runtime_error("Not a regular file: " + file_path);
    }
    if (st.st_size == 0) {
        throw runtime_error("cannot upload an empty file: " + file_path);
    }

    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd < 0) throw runtime_error("Permission denied or cannot open file: " + file_path);

    FileMetadata meta;
    meta.group_id = group_id;
    meta.username = username;
    meta.local_path = file_path;
    meta.filesize = st.st_size;

    char* path_copy = strdup(file_path.c_str());
    meta.filename = basename(path_copy);
    free(path_copy);
    meta.ip = ip;
    meta.port = port;

    vector<char> buffer(CHUNK_SIZE);
    SHA_CTX sha_ctx;
    SHA1_Init(&sha_ctx);
    while (true) {
        ssize_t bytes_read = read(fd, buffer.data(), CHUNK_SIZE);
        if (bytes_read < 0) {
            close(fd);
            throw runtime_error("Error reading file: " + file_path);
        }
        if (bytes_read == 0) 
        break;
        SHA1_Update(&sha_ctx, buffer.data(), bytes_read);
        unsigned char piece_hash_raw[SHA_DIGEST_LENGTH];
        SHA1(reinterpret_cast<unsigned char*>(buffer.data()), bytes_read, piece_hash_raw);
        meta.piece_hashes.push_back(sha1_to_hex(piece_hash_raw));
    }
    close(fd);
    unsigned char full_file_hash_raw[SHA_DIGEST_LENGTH];
    SHA1_Final(full_file_hash_raw, &sha_ctx);
    meta.file_hash = sha1_to_hex(full_file_hash_raw);
    return meta;
}

// ======================================================================
// MULTI-SEEDER DOWNLOAD WITH RAREST PIECE FIRST
// ======================================================================

// Connect to a seeder and query its bitmap for a given file
static string query_seeder_bitmap(const string& seeder_addr, const string& filename, int total_pieces) {
    size_t colon_pos = seeder_addr.find(':');
    if (colon_pos == string::npos) return "";
    string ip = seeder_addr.substr(0, colon_pos);
    int port = stoi(seeder_addr.substr(colon_pos + 1));

    hostent* host = gethostbyname(ip.c_str());
    if (!host) return "";

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr.s_addr, host->h_addr_list[0], host->h_length);
    addr.sin_port = htons(port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return "";
    }

    string request = "GET_BITMAP " + filename + " " + to_string(total_pieces) + "\n";
    if (send(sock, request.c_str(), request.size(), 0) <= 0) {
        close(sock);
        return "";
    }

    string response;
    if (!recv_line(sock, response)) {
        close(sock);
        return "";
    }
    close(sock);

    // Parse: "BITMAP 110101..."
    if (response.rfind("BITMAP ", 0) == 0) {
        return response.substr(7);
    }
    return "";
}

// Build piece availability maps by querying all seeders
static void build_piece_availability(DownloadState* state) {
    state->piece_rarity.assign(state->total_pieces, 0);
    state->piece_seeder_map.resize(state->total_pieces);

    for (int s = 0; s < (int)state->seeder_addresses.size(); ++s) {
        string bitmap = query_seeder_bitmap(state->seeder_addresses[s], state->filename, state->total_pieces);

        if (bitmap.empty() || (int)bitmap.size() != state->total_pieces) {
            // If bitmap query fails, assume seeder has all pieces (optimistic fallback)
            for (int p = 0; p < state->total_pieces; ++p) {
                state->piece_rarity[p]++;
                state->piece_seeder_map[p].push_back(s);
            }
        } else {
            for (int p = 0; p < state->total_pieces; ++p) {
                if (bitmap[p] == '1') {
                    state->piece_rarity[p]++;
                    state->piece_seeder_map[p].push_back(s);
                }
            }
        }
    }
}

// Download a single piece from a specific seeder
static bool download_single_piece(DownloadState* state, int piece_index, int seeder_index) {
    if (seeder_index < 0 || seeder_index >= (int)state->seeder_addresses.size()) return false;

    const string& addr = state->seeder_addresses[seeder_index];
    size_t colon_pos = addr.find(':');
    if (colon_pos == string::npos) return false;
    string seeder_ip = addr.substr(0, colon_pos);
    int seeder_port = stoi(addr.substr(colon_pos + 1));

    hostent* peer_server = gethostbyname(seeder_ip.c_str());
    if (!peer_server) return false;

    sockaddr_in peer_serv_addr{};
    peer_serv_addr.sin_family = AF_INET;
    memcpy(&peer_serv_addr.sin_addr.s_addr, peer_server->h_addr_list[0], peer_server->h_length);
    peer_serv_addr.sin_port = htons(seeder_port);

    int peer_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (peer_sock < 0) return false;

    if (connect(peer_sock, (sockaddr*)&peer_serv_addr, sizeof(peer_serv_addr)) < 0) {
        close(peer_sock);
        return false;
    }

    string request = "GET_PIECE " + state->filename + " " + to_string(piece_index) + "\n";
    if (send(peer_sock, request.c_str(), request.size(), 0) <= 0) {
        close(peer_sock);
        return false;
    }

    string header;
    if (!recv_line(peer_sock, header) || header.rfind("PIECE_LEN ", 0) != 0) {
        close(peer_sock);
        return false;
    }

    size_t payload_len = stoul(header.substr(10));
    if (payload_len == 0) {
        close(peer_sock);
        return false;
    }

    vector<char> piece_buffer(payload_len);
    if (!recv_exact(peer_sock, piece_buffer.data(), payload_len)) {
        close(peer_sock);
        return false;
    }
    close(peer_sock);

    // Verify SHA1 hash
    unsigned char hashbuf[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<unsigned char*>(piece_buffer.data()), payload_len, hashbuf);
    string received_hash = sha1_to_hex(hashbuf);
    if (received_hash != state->piece_hashes[piece_index]) {
        cout << "Piece " << piece_index << " hash mismatch from seeder " << seeder_index << ". Retrying..." << endl;
        return false;
    }

    // Write piece to file at correct offset
    off_t offset = (off_t)piece_index * CHUNK_SIZE;
    ssize_t bytes_written = pwrite(state->output_file_descriptor, piece_buffer.data(), payload_len, offset);
    if (bytes_written <= 0 || (size_t)bytes_written != payload_len) {
        return false;
    }

    // Register this piece as available for other peers
    {
        lock_guard<mutex> lk(seeded_files_mutex);
        local_pieces[state->filename].insert(piece_index);
    }

    return true;
}

// Worker thread: picks rarest pieces and downloads them
static void download_worker(shared_ptr<DownloadState> state) {
    while (state->pieces_completed < state->total_pieces && !state->failed) {
        int piece_to_download = -1;
        int seeder_to_use = -1;

        {
            lock_guard<mutex> lock(state->mtx);
            // Rarest piece first: find NEEDED piece with lowest rarity (but > 0)
            int best_piece = -1;
            int lowest_rarity = INT_MAX;
            for (int i = 0; i < state->total_pieces; ++i) {
                if (state->piece_status[i] == PieceStatus::NEEDED) {
                    int rarity = (int)state->piece_seeder_map[i].size();
                    if (rarity > 0 && rarity < lowest_rarity) {
                        lowest_rarity = rarity;
                        best_piece = i;
                    }
                }
            }

            if (best_piece >= 0) {
                state->piece_status[best_piece] = PieceStatus::IN_FLIGHT;
                piece_to_download = best_piece;
                // Pick a random seeder from those that have this piece
                auto& seeders_for_piece = state->piece_seeder_map[best_piece];
                seeder_to_use = seeders_for_piece[rand() % seeders_for_piece.size()];
            }
        }

        if (piece_to_download == -1) {
            if (state->pieces_completed < state->total_pieces && !state->failed) {
                this_thread::sleep_for(chrono::milliseconds(100));
                continue;
            } else {
                break;
            }
        }

        cout << "Thread " << this_thread::get_id() << " downloading piece " << piece_to_download
             << " from seeder " << seeder_to_use << " (rarity=" << state->piece_rarity[piece_to_download] << ")" << endl;

        bool success = download_single_piece(state.get(), piece_to_download, seeder_to_use);

        {
            lock_guard<mutex> lock(state->mtx);
            if (success) {
                state->piece_status[piece_to_download] = PieceStatus::HAVE;
                state->pieces_completed++;
                cout << "Progress: " << state->pieces_completed << "/" << state->total_pieces << " pieces downloaded." << endl;
                state->cv.notify_all();
            } else {
                state->piece_retry_count[piece_to_download]++;
                if (state->piece_retry_count[piece_to_download] >= MAX_PIECE_RETRIES) {
                    cerr << "FATAL: Piece " << piece_to_download << " failed after " << MAX_PIECE_RETRIES << " retries. Aborting download." << endl;
                    state->failed = true;
                    state->cv.notify_all();
                } else {
                    state->piece_status[piece_to_download] = PieceStatus::NEEDED;
                }
            }
        }
    }
}

// The Manager: start_download with multi-seeder and rarest-piece-first
void start_download(const string& tracker_response, const string& dest_path, const string& filename,
                    const string& group_id, int sockfd, mutex& tracker_mutex) 
{
    // 1. Parse tracker response: DOWNLOAD_INFO <filesize> <seeder1,seeder2,...> |hash1|hash2|...
    stringstream ss(tracker_response);
    string command, filesize_str, seeders_str, hashes_str;
    ss >> command >> filesize_str >> seeders_str >> hashes_str;
    
    if (!hashes_str.empty() && hashes_str[0] == '|') {
        hashes_str.erase(0, 1);
    }
    long long filesize = stoll(filesize_str);

    auto state = make_shared<DownloadState>();

    state->filename = filename;
    state->group_id = group_id;
    state->destination_path = dest_path;
    state->pieces_completed = 0;
    state->completed = false;
    state->failed = false;
    
    // Parse comma-separated seeder addresses
    {
        stringstream seeder_stream(seeders_str);
        string single_seeder;
        while (getline(seeder_stream, single_seeder, ',')) {
            if (!single_seeder.empty())
                state->seeder_addresses.push_back(single_seeder);
        }
    }
    
    if (state->seeder_addresses.empty()) {
        cerr << "Error: No seeder addresses received from tracker." << endl;
        return;
    }
    cout << "Seeders available: " << state->seeder_addresses.size() << endl;

    // Parse piece hashes
    stringstream hash_stream(hashes_str);
    string single_hash;
    while (getline(hash_stream, single_hash, '|')) {
        if (!single_hash.empty())
            state->piece_hashes.push_back(single_hash);
    }
    state->total_pieces = state->piece_hashes.size();
    state->piece_status.assign(state->total_pieces, PieceStatus::NEEDED);
    state->piece_retry_count.assign(state->total_pieces, 0);

    if (state->total_pieces == 0) {
        cerr << "Error: No piece hashes received from tracker. Aborting." << endl;
        return;
    }

    // If dest_path is a directory, append the filename to it
    string final_dest = dest_path;
    struct stat dest_stat;
    if (stat(dest_path.c_str(), &dest_stat) == 0 && S_ISDIR(dest_stat.st_mode)) {
        // dest_path is an existing directory — append filename
        final_dest = dest_path;
        if (!final_dest.empty() && final_dest.back() != '/') final_dest += '/';
        final_dest += filename;
        cout << "Destination is a directory. Saving as: " << final_dest << endl;
    }
    state->destination_path = final_dest;

    // Create destination file
    state->output_file_descriptor = open(final_dest.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0666);
    if (state->output_file_descriptor < 0) {
        perror("Failed to create destination file");
        return;
    }
    ftruncate(state->output_file_descriptor, filesize);

    // Register as partial download so peer server can serve our completed pieces
    {
        lock_guard<mutex> lk(seeded_files_mutex);
        local_partial_files[filename] = dest_path;
        local_pieces[filename].clear();
    }

    // Track this download for 'show_downloads'
    {
        lock_guard<mutex> lock(active_downloads_mutex);
        active_downloads[group_id + ":" + filename] = state;
    }

    // 2. Query seeders for piece bitmaps (rarest piece first)
    cout << "Querying seeders for piece availability..." << endl;
    build_piece_availability(state.get());

    // Check if any piece has zero availability
    bool can_download = true;
    for (int i = 0; i < state->total_pieces; ++i) {
        if (state->piece_seeder_map[i].empty()) {
            cerr << "Warning: Piece " << i << " is not available from any seeder." << endl;
            can_download = false;
        }
    }
    if (!can_download) {
        cerr << "Error: Some pieces are unavailable. Aborting download." << endl;
        close(state->output_file_descriptor);
        return;
    }

    // 3. Launch worker threads
    int num_threads = min((int)thread::hardware_concurrency(), state->total_pieces);
    if (num_threads <= 0) num_threads = 1;
    cout << "Starting download with " << num_threads << " worker threads (rarest piece first)." << endl;
    
    vector<thread> workers;
    for (int i = 0; i < num_threads; ++i) {
        workers.emplace_back(download_worker, state);
    }

    // 4. Wait for download to complete or fail
    {
        unique_lock<mutex> lock(state->mtx);
        state->cv.wait(lock, [&]{ 
            return state->pieces_completed == state->total_pieces || state->failed; 
        });
    }

    // 5. Cleanup
    for (auto& worker : workers) {
        worker.join();
    }
    close(state->output_file_descriptor);

    // Remove partial download tracking
    {
        lock_guard<mutex> lk(seeded_files_mutex);
        local_partial_files.erase(filename);
        local_pieces.erase(filename);
    }

    if (state->failed) {
        cerr << "Download failed. The destination file may be corrupt." << endl;
        state->completed = false;
        return;
    }

    cout << "Download Completed Successfully!" << endl;
    state->completed = true;

    // Add to seeded files
    {
        lock_guard<mutex> lock(seeded_files_mutex);
        seeded_files[filename] = state->destination_path;
        save_seeded_files(seeded_files);
    }

    // Inform tracker we are now a seeder (thread-safe socket access)
    cout << "Informing tracker that you are now a seeder..." << endl;
    {
        lock_guard<mutex> lock(tracker_mutex);
        string update_msg = "UPDATE_SEEDER " + group_id + " " + filename + "\n";
        send(sockfd, update_msg.c_str(), update_msg.size(), 0);
        // BUG FIX: Read the "OK" response to avoid protocol desync
        string resp = read_line_tracker(sockfd);
        // resp should be "OK" — discard it
    }
}