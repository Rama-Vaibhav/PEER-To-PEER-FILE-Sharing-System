#ifndef FILESEND_H
#define FILESEND_H
#include<string>
#include<vector>
#include <mutex>
#include <condition_variable>
#include <atomic>
using namespace std;

#define MAX_PIECE_RETRIES 5

enum class PieceStatus{
    NEEDED,     // The piece has not been downloaded yet
    IN_FLIGHT,  // A worker thread is currently downloading this piece
    HAVE        // The piece has been successfully downloaded and saved
};

struct DownloadState
{
    mutex mtx;
    condition_variable cv;
    // --- Progress Tracking ---
    vector<PieceStatus> piece_status;
    atomic<int> pieces_completed;
    int total_pieces;
    // --- File & Network Info ---
    vector<string> seeder_addresses;  // BUG FIX: Changed from single string to support multi-seeder
    string filename;
    string group_id;                  // BUG FIX: Added to track group for show_downloads
    vector<string> piece_hashes;
    string destination_path;
    int output_file_descriptor;
    // --- Status ---
    bool completed;                   // BUG FIX: Track completion for show_downloads [C] format
    bool failed;                      // BUG FIX: Track failure to break out of infinite retry loops
    // --- Rarest Piece First ---
    vector<int> piece_rarity;         // Number of seeders that have each piece
    vector<vector<int>> piece_seeder_map; // piece_index -> list of seeder indices that have it
    vector<int> piece_retry_count;    // BUG FIX: Per-piece retry counter to avoid infinite loops
};

struct FileMetadata{
    string group_id;
    string username;
    string filename;
    string local_path;
    size_t filesize;
    string file_hash; //sha1 of full file(40 chars hex)
    vector<string> piece_hashes; //sha1 per 512kb chunk
    string ip;
    int port;
    vector<string> seeders;
};

FileMetadata prepare_file_metadata(const string &file_path,const string &group_id,const string &username,const string &ip,int port);
void start_download(const string& tracker_response,const string& dest_path,const string& filename,const string& group_id, int sockfd, mutex& tracker_mutex);
#endif
