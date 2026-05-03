#include "filesend.h"
#include "peer.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <thread>
using namespace std;

extern map<string,shared_ptr<DownloadState>>active_downloads;
extern mutex active_downloads_mutex;

// BUG FIX: Tracker socket mutex to prevent protocol desync when
// background download threads send UPDATE_SEEDER while main thread sends commands
static mutex tracker_sock_mutex;

// BUG FIX: Track the logged-in username on the client side (was hardcoded "myUsername")
static string current_user_client;

// Port-specific seeding log to avoid corruption when multiple clients run from same directory
static string seeding_log_file;

void load_seeded_files(map<string,string>& seeded_files)
{
    ifstream log_file(seeding_log_file);
    if(!log_file.is_open())
    {
        return ; //file doesnt exist yet, which is fine
    }
    string line;
    while(getline(log_file,line))
    {
        stringstream ss(line);
        string filename,filepath;
        if(getline(ss,filename,'\t') && getline(ss,filepath))
        {
            seeded_files[filename]=filepath;
        }
    }
    log_file.close();
    cout<<"Loaded "<<seeded_files.size()<<" previously seeded files."<<endl;
}
void save_seeded_files(const map<string,string>& seeded_files)
{
    ofstream log_file(seeding_log_file, ofstream::trunc);
    if(!log_file.is_open())
    {
        cerr<<"Error:Could not save seeding state. "<<endl;
        return ;
    }
    for(const auto& pair:seeded_files)
    {
        log_file<<pair.first<<"\t"<<pair.second<<"\n";
    }
    log_file.close();
}

static string read_line(int sock)
{
    string line;
    char c;
    while(read(sock, &c, 1) > 0)
    {
        if(c == '\n')
            break;
        line += c;
    }
    return line;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        cerr << "Usage: " << argv[0] <<" <MY_IP:MY_PORT> <tracker_info.txt>\n";
        return 1;
    }

    string client_addr_str = argv[1];
    size_t colon_pos = client_addr_str.find(':');
    if(colon_pos == string::npos)
    {
        cerr << "Invalid format for <MY_IP:MY_PORT>\n";
        return 1;
    }
    string my_ip = client_addr_str.substr(0, colon_pos);
    int my_port = stoi(client_addr_str.substr(colon_pos + 1));

    // BUG FIX: Per-port seeding log to avoid corruption with multiple clients
    seeding_log_file = "seeding_" + to_string(my_port) + ".log";

    // === Load Persistence ===
    {
        lock_guard<mutex> lock(seeded_files_mutex);
        load_seeded_files(seeded_files);
    }

    thread server(peer_server_thread, my_ip, my_port);
    server.detach();

    string tracker_info_path = argv[2];
    string tracker_ip;
    int tracker_port;
    ifstream tracker_file(tracker_info_path);
    if (!tracker_file.is_open()) {
        cerr << "Error: Could not open tracker info file: " << tracker_info_path << "\n";
        return 1;
    }
    int temp_id, temp_sync_port;
    if (!(tracker_file >> temp_id >> tracker_ip >> tracker_port >> temp_sync_port)) {
        cerr << "Error: Invalid format in tracker info file.\n";
        return 1;
    }
    tracker_file.close();

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); return 1; }
    hostent *server_host = gethostbyname(tracker_ip.c_str());
    if (server_host == nullptr) { cerr << "No such host\n"; return 1; }
    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server_host->h_addr_list[0], server_host->h_length);
    serv_addr.sin_port = htons(tracker_port);
    if (connect(sockfd, (sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) 
    { 
        perror("connect"); 
        return 1; 
    }

    string line;
    while (cout << "> " && getline(cin, line)) {
        if (line.empty()) continue;
        stringstream ss(line);
        string cmd;
        ss >> cmd;

        if (cmd == "upload_file") {
            string group_id, file_path;
            if (!(ss >> group_id >> file_path)) {
                cout << "Usage: upload_file <group_id> <file_path>\n";
                continue;
            }

            // BUG FIX: Check login before upload
            if (current_user_client.empty()) {
                cout << "Error: Please login first.\n";
                continue;
            }

            try {
                // BUG FIX: Use actual logged-in username instead of hardcoded "myUsername"
                FileMetadata meta = prepare_file_metadata(file_path, group_id, current_user_client, my_ip, my_port);

                {
                    lock_guard<mutex> lock(seeded_files_mutex);
                    seeded_files[meta.filename] = meta.local_path;
                    save_seeded_files(seeded_files);
                }
                // Combine all piece hashes into a single string, separated by a pipe '|'
                string all_hashes_str;
                for (const string& piece_hash : meta.piece_hashes) {
                    all_hashes_str += piece_hash + "|";
                }
                if (!all_hashes_str.empty()) {
                    all_hashes_str.pop_back(); // Remove the trailing '|'
                }
                // Send all information in a single line
                string request = "UPLOAD_FILE " + meta.group_id + " " + meta.filename + " " +to_string(meta.filesize) + " " + meta.file_hash + " " +all_hashes_str + "\n";
                
                // Thread-safe tracker communication
                lock_guard<mutex> tlock(tracker_sock_mutex);
                send(sockfd, request.c_str(), request.size(), 0);
                string resp = read_line(sockfd);
                cout << "Tracker: " << resp << endl;
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << '\n';
            }
        } 
        else if (cmd == "download_file") 
        {
            string group_id, filename, destination_path;
            if (!(ss >> group_id >> filename >> destination_path)) {
                cout << "Usage: download_file <group_id> <filename> <destination_path>\n";
                continue;
            }

            if (current_user_client.empty()) {
                cout << "Error: Please login first.\n";
                continue;
            }

            string request = "DOWNLOAD_FILE " + group_id + " " + filename + "\n";
            string response;
            {
                // Thread-safe tracker communication
                lock_guard<mutex> tlock(tracker_sock_mutex);
                send(sockfd, request.c_str(), request.size(), 0);
                response = read_line(sockfd);
            }

            if (response.rfind("DOWNLOAD_INFO", 0) == 0) {
                cout << "Tracker sent seeder info. Starting download in background..." << endl;
                // BUG FIX: Run download in a BACKGROUND THREAD so the client doesn't block
                thread download_thread(start_download, response, destination_path, filename, group_id, sockfd, ref(tracker_sock_mutex));
                download_thread.detach();
            } else {
                cout << "Tracker Response: " << response << endl;
            }
        }
        else if(cmd=="list_files")
        {
            string group_id;
            if(!(ss>>group_id))
            {
                cout<<"Usage: list_files <group_id>\n";
                continue;
            }
            string request="LIST_FILES "+group_id+"\n";
            
            // Thread-safe tracker communication
            lock_guard<mutex> tlock(tracker_sock_mutex);
            send(sockfd,request.c_str(),request.size(),0);
            cout<<"Files in the group "<<group_id<<":"<<endl;
            while(true)
            {
                string file_info=read_line(sockfd);
                if(file_info=="END_OF_LIST")
                {
                    break;
                }
                cout<<"- "<<file_info<<endl;
            }
        }
        else if(cmd=="show_downloads")
        {
            // BUG FIX: Format matches assignment spec: [C] [group_id] filename / [D] [group_id] filename
            lock_guard<mutex> lock(active_downloads_mutex);
            if(active_downloads.empty())
            {
                cout<<"No downloads."<<endl;
                continue;
            }
            for(const auto& pair:active_downloads)
            {
                auto state=pair.second;
                if (state->completed) {
                    cout<<"[C] ["<<state->group_id<<"] "<<state->filename<<endl;
                } else if (state->failed) {
                    cout<<"[F] ["<<state->group_id<<"] "<<state->filename<<" (FAILED)"<<endl;
                } else {
                    cout<<"[D] ["<<state->group_id<<"] "<<state->filename
                        <<" ("<<state->pieces_completed<<"/"<<state->total_pieces<<" pieces)"<<endl;
                }
            }
        }
        else if(cmd=="stop_share")
        {
            string group_id,filename;
            if(!(ss>>group_id>>filename))
            {
                cout<<"Usage: stop_share <group_id> <filename>\n";
                continue;
            }
            {
                lock_guard<mutex> lock(seeded_files_mutex);
                if(seeded_files.erase(filename)>0)
                {
                    save_seeded_files(seeded_files);
                    cout<<"Stopped sharing ' "<<filename<<"' locally."<<endl;
                }
                else
                {
                    cout<<"You were not sharing '"<<filename<<"'."<<endl;
                }
            }
            string request="STOP_SEEDING "+group_id+" "+filename+"\n";
            
            // Thread-safe tracker communication
            lock_guard<mutex> tlock(tracker_sock_mutex);
            send(sockfd,request.c_str(),request.size(),0);
            string response=read_line(sockfd);
            cout<<"Tracker: "<<response<<endl;
        }
        else if (cmd == "login") {
            string user_id, password;
            if (!(ss >> user_id >> password)) {
                cout << "Usage: login <user_id> <password>\n";
                continue;
            }
            string out = "login " + user_id + " " + password + " " + my_ip + ":" + to_string(my_port) + "\n";
            
            string resp;
            {
                lock_guard<mutex> tlock(tracker_sock_mutex);
                send(sockfd, out.c_str(), out.size(), 0);
                resp = read_line(sockfd);
            }
            cout << resp << endl;
            // BUG FIX: Track the logged-in username on client side
            if (resp.find("Login successful") != string::npos) {
                current_user_client = user_id;
            }
        }
        else if (cmd == "logout") {
            string out = "logout\n";
            string resp;
            {
                lock_guard<mutex> tlock(tracker_sock_mutex);
                send(sockfd, out.c_str(), out.size(), 0);
                resp = read_line(sockfd);
            }
            cout << resp << endl;
            if (resp.find("Logout successful") != string::npos) {
                current_user_client.clear();
            }
        }
        else {
            // All other commands (create_user, create_group, join_group, etc.)
            string out = line + "\n";
            string resp;
            {
                lock_guard<mutex> tlock(tracker_sock_mutex);
                send(sockfd, out.c_str(), out.size(), 0);
                resp = read_line(sockfd);
            }
            cout << resp << endl;
        }
    }
    close(sockfd);
    return 0;
}