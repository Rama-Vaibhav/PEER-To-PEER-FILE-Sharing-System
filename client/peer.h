#ifndef PEER_H
#define PEER_H
#include<bits/stdc++.h>
using namespace std;
void peer_server_thread(string my_ip,int my_port);

extern map<string,string> seeded_files;
// Track partially downloaded files: filename -> destination path
extern map<string,string> local_partial_files;
// Track which pieces we have for partial downloads: filename -> set of piece indices
extern map<string,set<int>> local_pieces;
extern mutex seeded_files_mutex;

// Declares the persistence function so other files can use it.
void save_seeded_files(const map<string, string>& seeded_files);
#endif