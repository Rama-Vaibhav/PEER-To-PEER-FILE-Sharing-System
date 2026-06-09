#include "tracker.h"
#include <unordered_map>   // for unordered_map
#include <set>             // for =set
#include <mutex>           // for =mutex, =lock_guard

using namespace std;

// Define global variables
mutex usersInfoMutex;
unordered_map<string, User> usersInfo; // userid and userInfo

mutex groupsMutex;  // this will be used for groupOwners and groupMembers map
unordered_map<string, string> groupOwners;  // groupId and owner_userid
unordered_map<string, set<string>> groupMembers;  // groupId and groupMembers
unordered_map<string, set<string>> groupJoinRequests;  // used for join_group and list_reqeuests command, group id and the pending requests


mutex sessionMutex;
// clientSocket and userId, this will have currently active login sessions, because socket gives you fd which will be unique for each session
unordered_map<int, string> activeSessions;  

// this is for the files
mutex fileTableMutex;
unordered_map<string, unordered_map<string, FileInfo>> fileTable;

unordered_map<string, unordered_map<string, string>> groupKeys;
unordered_map<int, string> pendingChallenges;