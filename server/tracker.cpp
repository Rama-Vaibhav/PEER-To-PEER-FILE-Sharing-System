// server/tracker.cpp
// Build: g++ -std=c++17 server/commands.cpp server/tracker.cpp -pthread -o server/tracker

#include "commands.h"
#include "common.h"
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

// ---------------- Tracker info parsing ----------------

struct TrackerInfo {
    int id;
    string ip;
    int main_port;
    int sync_port;
};
string cmd_create_user(const string&,const string&);
static bool parse_tracker_info_file(const string &path, map<int, TrackerInfo> &out_map) {
    ifstream ifs(path);
    if (!ifs.is_open()) return false;
    out_map.clear();
    string line;
    while (getline(ifs, line)) {
        if (line.empty()) continue;
        istringstream iss(line);
        TrackerInfo t;
        if (!(iss >> t.id >> t.ip >> t.main_port >> t.sync_port)) {
            // malformed line, skip
            continue;
        }
        out_map[t.id] = t;
    }
    return true;
}

// ---------------- Simple framed read/write helpers (newline-terminated) ----------------

static string read_line_from_socket_with_timeout(int sockfd, int timeout_seconds) {
    string line;
    char ch;
    while (true) {
        // use select to wait with timeout
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        struct timeval tv;
        tv.tv_sec = timeout_seconds;
        tv.tv_usec = 0;
        int rv = select(sockfd + 1, &readfds, nullptr, nullptr, &tv);
        if (rv == 0) {
            // timeout
            return string("__TIMEOUT__"); // special sentinel
        } else if (rv < 0) {
            // error
            return string();
        }
        ssize_t n = recv(sockfd, &ch, 1, 0);
        if (n <= 0) {
            // closed or error
            return string();
        }
        if (ch == '\n') break;
        line.push_back(ch);
    }
    return line;
}

static bool write_line_to_socket_blocking(int sockfd, const string &s) {
    string out = s;
    if (out.empty() || out.back() != '\n') out.push_back('\n');
    const char *buf = out.c_str();
    size_t left = out.size();
    while (left > 0) {
        ssize_t n = send(sockfd, buf, left, 0);
        if (n <= 0) return false;
        buf += n;
        left -= n;
    }
    return true;
}

//--------------------
// Handle Client commands
//--------------------



void handle_client(int sockfd)
{
    char buffer[1024];
    int n=read(sockfd,buffer,1023);
    if(n>0)
    {
        buffer[n]='\0';
        string input(buffer);
        auto parts=split(input,' ');
        string response;
        if(parts[0]=="create_user" && parts.size()==3)
        {
            response=cmd_create_user(parts[1],parts[2]);
        }
        else
        {
            response="ERROR: Unknown command or wrong number of arguments";
        }
        write(sockfd,response.c_str(),response.size());
    }
    close(sockfd);
}
void sync_listener(int port)
{
    int sockfd,newsockfd;
    struct sockaddr_in serv_addr{},cli_addr{};
    socklen_t clilen=sizeof(cli_addr);
    sockfd=socket(AF_INET,SOCK_STREAM,0);
    serv_addr.sin_family=AF_INET;
    serv_addr.sin_addr.s_addr=INADDR_ANY;
    serv_addr.sin_port=htons(port);
    ::bind(sockfd,(struct sockaddr*)&serv_addr,sizeof(serv_addr));
    listen(sockfd,5);
    newsockfd=accept(sockfd,(struct sockaddr*)&cli_addr,&clilen);
    {
        lock_guard<mutex> lock(sync_mutex);
        sync_sockfd=newsockfd;
    }
    char buffer[1024];
    while(true)
    {
        int n=read(newsockfd,buffer,1023);
        if(n<=0) break;
        buffer[n]='\0';
        process_sync_message(string(buffer));  
    }
    close(newsockfd);
    close(sockfd);
}
void sync_connector(const string &peer_ip,int peer_port)
{
    int sockfd;
    struct sockaddr_in serv_addr{};
    while(true)
    {
        sockfd=socket(AF_INET,SOCK_STREAM,0);
        serv_addr.sin_family=AF_INET;
        serv_addr.sin_port=htons(peer_port);
        inet_pton(AF_INET,peer_ip.c_str(),&serv_addr.sin_addr);
        if(connect(sockfd,(struct sockaddr*)&serv_addr,sizeof(serv_addr))==0)
        {
            lock_guard<mutex> lock(sync_mutex);
            sync_sockfd=sockfd;
            break;
        }
        close(sockfd);
        sleep(5); //retry after 5 second if connection lost
    }
    char buffer[1024];
    while(true)
    {
        int n=read(sockfd,buffer,1023);
        if(n<=0) break;
        buffer[n]='\0';
        process_sync_message(string(buffer));  
    }
    close(sockfd);
    
}

// ---------------- Sync connection handler ----------------
// This function handles bidirectional communication on a sync socket.
// It will read newline-terminated messages and print/ack them.
// Important: do NOT hold global locks while blocking on socket I/O.
// Use select-based timeout to keep it responsive.

static void handle_sync_connection(int sockfd, atomic<bool> &global_running, bool initiated_by_me) {
    string peer_label = initiated_by_me ? "peer(client-mode)" : "peer(listener-mode)";
    cout << "[sync] connection established (" << peer_label << ")\n";

    // Expose this active sync socket to send_sync_update()
    {
        lock_guard<mutex> lk(sync_mutex);
        sync_sockfd = sockfd;
    }

    // send an initial HELLO if this side initiated
    if (initiated_by_me) {
        write_line_to_socket_blocking(sockfd, "HELLO_FROM_INITIATOR");
    }

    while (global_running.load()) {
        // read with a 5-second timeout so we can check global_running periodically
        string line = read_line_from_socket_with_timeout(sockfd, 5);
        if (line.empty()) {
            cout << "[sync] connection closed by peer or error\n";
            break;
        }
        if (line == "__TIMEOUT__") {
            // send a heartbeat
            if (!write_line_to_socket_blocking(sockfd, "HEARTBEAT")) {
                cout << "[sync] failed to send heartbeat, breaking\n";
                break;
            }
            continue;
        }
        if (line != "HEARTBEAT" && line.rfind("ACK:", 0) != 0) {
            cout << "[sync recv] " << line << "\n";
            process_sync_message(line);

            // Send ACK
            string ack = "ACK:" + line;
            if (!write_line_to_socket_blocking(sockfd, ack)) {
                cout << "[sync] failed to send ACK\n";
                break;
            }
        }
    }

    close(sockfd);
    // Clear global sync socket when connection closes
    {
        lock_guard<mutex> lk(sync_mutex);
        if (sync_sockfd == sockfd) {
            sync_sockfd = -1;
        }
    }
    cout << "[sync] connection handler exiting\n";
}

// ---------------- Sync listener thread ----------------
// Binds to this tracker's sync_port and accepts one connection from peer.
// After accept, calls handle_sync_connection.

static void sync_listener_thread(const TrackerInfo &self_info, atomic<bool> &global_running) {
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        perror("[sync listener] socket");
        return;
    }

    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(self_info.sync_port);

    if (::bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("[sync listener] bind");
        close(listenfd);
        return;
    }
    if (listen(listenfd, 1) < 0) {
        perror("[sync listener] listen");
        close(listenfd);
        return;
    }

    cout << "[sync listener] listening on port " << self_info.sync_port << "\n";

    while (global_running.load()) {
        struct sockaddr_in cli;
        socklen_t clilen = sizeof(cli);
        int newsock = accept(listenfd, (struct sockaddr*)&cli, &clilen);
        if (newsock < 0) {
            perror("[sync listener] accept");
            // avoid busy loop, sleep briefly
            this_thread::sleep_for(chrono::seconds(1));
            continue;
        }

        // Spawn a handler thread for this sync connection
        thread t(handle_sync_connection, newsock, ref(global_running), false);
        t.detach();

        // BUG FIX: Removed break so listener keeps accepting reconnections
        // after a sync connection drops. Each connection gets its own handler thread.
    }

    close(listenfd);
    cout << "[sync listener] exiting\n";
}

// ---------------- Sync connector thread ----------------
// Attempts to connect to peer's sync_port. If connection fails, retries with backoff.
// On successful connect, calls handle_sync_connection.

static void sync_connector_thread(const TrackerInfo &peer_info, atomic<bool> &global_running) {
    while (global_running.load()) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("[sync connector] socket");
            this_thread::sleep_for(chrono::seconds(2));
            continue;
        }

        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(peer_info.sync_port);

        if (inet_pton(AF_INET, peer_info.ip.c_str(), &serv_addr.sin_addr) <= 0) {
            cerr << "[sync connector] invalid peer ip: " << peer_info.ip << "\n";
            close(sockfd);
            return;
        }

        cout << "[sync connector] attempting to connect to " << peer_info.ip << ":" << peer_info.sync_port << "...\n";
        if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == 0) {
            cout << "[sync connector] connected to peer sync port\n";
            // Once connected, hand off to handler (this will block inside handler but inside its own loop/select)
            handle_sync_connection(sockfd, const_cast<atomic<bool>&>(global_running), true);
            // If handle_sync_connection returns, connection closed. Try reconnect after short sleep.
            cout << "[sync connector] connection closed; will retry\n";
            this_thread::sleep_for(chrono::seconds(3));
            continue;
        } else {
            // connect failed; sleep and retry
            perror("[sync connector] connect");
            close(sockfd);
            this_thread::sleep_for(chrono::seconds(3));
            continue;
        }
    }
}

// ---------------- Client server loop (accept clients and spawn threads) ----------------
// This reuses client_thread_func from earlier commands implementation.
// We declare it extern here (it was defined in commands.cpp earlier).
extern void client_thread_func(int newsockfd);

static string read_line_from_socket(int sockfd) {
    // Read until newline. This is simple and OK for demo.
    string line;
    char ch;
    ssize_t n;
    while (true) {
        n = recv(sockfd, &ch, 1, 0);
        if (n <= 0) {
            // connection closed or error
            return string();
        }
        if (ch == '\n') break;
        line.push_back(ch);
    }
    return line;
}

static bool write_line_to_socket(int sockfd, const string &s) {
    string out = s;
    if (!out.empty() && out.back() != '\n') out.push_back('\n');
    const char *buf = out.c_str();
    size_t left = out.size();
    while (left > 0) {
        ssize_t n = send(sockfd, buf, left, 0);
        if (n <= 0) return false;
        buf += n;
        left -= n;
    }
    return true;
}
void client_thread_func(int newsockfd) {
    string current_user; // per-connection session
    while (true) {
        string line = read_line_from_socket(newsockfd);
        if (line.empty()) break; // client disconnected or error
        string response = process_command(line, current_user,newsockfd);
        if (!write_line_to_socket(newsockfd, response)) break;
    }
    // ensure logout if user logged in
    if (!current_user.empty()) {
        lock_guard<mutex> lock(state_mutex);
        auto it = users.find(current_user);
        if (it != users.end()) it->second.logged_in = false;
    }
    close(newsockfd);
}
// Initialize global sync socket (nothing fancy for now)
void init_sync_socket() {
    lock_guard<mutex> lock(g_sync_sock_mutex);
    g_sync_sock = -1;   // no active connection yet
}

// Close and cleanup global sync socket
void close_sync_socket() {
    lock_guard<mutex> lock(g_sync_sock_mutex);
    if (g_sync_sock != -1) {
        close(g_sync_sock);
        g_sync_sock = -1;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        cerr << "Usage: " << argv[0] << " <tracker_info.txt> <my_id>\n";
        return 1;
    }

    string info_path = argv[1];
    int my_id = atoi(argv[2]);

    map<int, TrackerInfo> trackers;
    if (!parse_tracker_info_file(info_path, trackers)) {
        cerr << "Failed to open or parse " << info_path << "\n";
        return 1;
    }
    if (trackers.find(my_id) == trackers.end()) {
        cerr << "No entry for id " << my_id << " in " << info_path << "\n";
        return 1;
    }

    TrackerInfo self = trackers[my_id];

    // find a peer (any other entry)
    TrackerInfo peer;
    bool found_peer = false;
    for (auto &p : trackers) {
        if (p.first != my_id) { peer = p.second; found_peer = true; break; }
    }

    if (!found_peer) {
        cerr << "No peer tracker found in " << info_path << "\n";
        // It's okay to continue, but sync threads won't run.
    } else {
        cout << "Peer tracker: id=" << peer.id << " ip=" << peer.ip
                  << " sync_port=" << peer.sync_port << "\n";
    }

    atomic<bool> global_running(true);

    // === NEW: init global sync socket ===
    init_sync_socket();

    // Start sync listener thread
    thread listener_thread(sync_listener_thread, cref(self), ref(global_running));
    listener_thread.detach();

    // Start sync connector thread (only if there's a peer)
    thread connector_thread;
    if (found_peer) {
        connector_thread = thread(sync_connector_thread, cref(peer), ref(global_running));
        connector_thread.detach();
    }

    // Start main client-facing server socket (like before)
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(self.main_port);

    if (::bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) { perror("bind"); return 1; }
    if (listen(sockfd, 16) < 0) { perror("listen"); return 1; }

    cout << "Tracker (id=" << self.id << ") listening for clients on port " << self.main_port << "\n";

    // Accept loop (spawns detached client threads)
    while (global_running.load()) {
        sockaddr_in cli_addr;
        socklen_t clilen = sizeof(cli_addr);
        int newsockfd = accept(sockfd, (struct sockaddr*)&cli_addr, &clilen);
        if (newsockfd < 0) {
            perror("accept");
            this_thread::sleep_for(chrono::milliseconds(100));
            continue;
        }
        thread t(client_thread_func, newsockfd);
        t.detach();
    }

    close(sockfd);
    global_running.store(false);

    // === NEW: close global sync socket ===
    close_sync_socket();

    cout << "Tracker shutting down\n";
    return 0;
}
