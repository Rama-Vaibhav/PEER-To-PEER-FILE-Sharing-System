# Secure Peer-to-Peer Distributed File Sharing System

A distributed peer-to-peer file sharing system built in C++ with dual-tracker redundancy, chunked parallel downloads, rarest-first scheduling, and SHA-1 integrity verification.

## Architecture

![Architecture](architecture.png)

The system consists of two components:

- **Tracker** — A centralized metadata server that manages users, groups, and file-to-peer mappings. Two trackers run simultaneously for fault tolerance, synchronizing state via SYNC messages.
- **Client** — A peer node that communicates with the tracker for metadata and directly with other peers for file transfers. Each client runs two threads: one for tracker communication and one as a peer server to serve file chunks to other peers.

---

## Project Structure

```
client/
  peer.cpp                  # Client main entry point
  client.h                  # Client header with shared declarations
  handleCommands.cpp        # Command parsing and dispatch (user input → tracker)
  connectionWithTracker.cpp # Tracker connection with dual-tracker failover
  downloadFileFromPeer.cpp  # Parallel chunked download engine
  peerDownloadHelpers.cpp   # Peer-to-peer download helpers (chunk fetching)
  peerUploadHelpers.cpp     # Peer-to-peer upload helpers (chunk serving)
  fileStorage.cpp           # Local file path registry
  shaUtil.cpp               # SHA-1 hash utilities (per-chunk and full-file)
  makefile                  # Builds the `client` binary

tracker/
  tracker.cpp               # Tracker main entry point
  tracker.h                 # Tracker header with shared data structures
  handleClientCommands.cpp  # Command dispatcher (create_user, upload_file, etc.)
  handleDownload.cpp        # Download request handler (builds FILEINFO response)
  trackerConnection.cpp     # Peer-tracker sync connection management
  trackerData.cpp           # Global data structure definitions
  makefile                  # Builds the `tracker` binary
```

---

## Getting Started

### Prerequisites

- **C++17** compatible compiler (g++ / clang++)
- **OpenSSL** (for SHA-1 hashing) — install via `brew install openssl@3` on macOS
- **POSIX** system (Linux / macOS)

### tracker_info.txt

Both the tracker and client directories should contain a `tracker_info.txt` file with the following format:

```
<tracker1_ip>
<tracker1_port>
<tracker2_ip>
<tracker2_port>
```

Example:
```
127.0.0.1
8001
127.0.0.1
9001
```

### Starting the Trackers

```bash
# Terminal 1 — Tracker 1
cd tracker
make
./tracker tracker_info.txt 1

# Terminal 2 — Tracker 2
cd tracker
make
./tracker tracker_info.txt 2
```

### Starting the Clients

```bash
# Terminal 3 — Client 1
cd client
make
./client 127.0.0.1:1234 tracker_info.txt

# Terminal 4 — Client 2
cd client
make
./client 127.0.0.1:2357 tracker_info.txt

# Terminal 5 — Client 3
cd client
make
./client 127.0.0.1:1313 tracker_info.txt
```

---

## Supported Commands

All commands use **space-separated** syntax as specified in the assignment:

| Command | Description |
|---------|-------------|
| `create user <user_id> <password>` | Register a new user |
| `login <user_id> <password>` | Log in to the system |
| `create group <group_id>` | Create a new sharing group |
| `join group <group_id>` | Request to join a group |
| `leave group <group_id>` | Leave a group |
| `list groups` | List all available groups |
| `list requests <group_id>` | List pending join requests (owner only) |
| `accept request <group_id> <user_id>` | Accept a join request (owner only) |
| `upload file <group_id> <file_path>` | Share a file with a group |
| `list files <group_id>` | List all files in a group |
| `download file <group_id> <file_name> <dest_path>` | Download a file from peers |
| `show downloads` | Show download progress and status |
| `stop share <group_id> <file_name>` | Stop sharing a file |
| `logout` | Log out (client keeps running) |

### Example Usage

```bash
>> create user alice pass123
>> login alice pass123
>> create group g1
>> upload file g1 /path/to/myfile.mp4

# On another client:
>> create user bob pass456
>> login bob pass456
>> join group g1

# Back on alice's client:
>> list requests g1
>> accept request g1 bob

# On bob's client:
>> download file g1 myfile.mp4 /path/to/destination/myfile.mp4
>> show downloads
```

---

## Edge Cases Handled

### 1. `create user <user_id> <password>`
- If **userId already exists** → `"User already exists"`.
- If **new user** → creates user, initializes fields, stores in `usersInfo`.

### 2. `login <user_id> <password>`
- If **socket already has a logged-in user** → `"You are already logged in as ... Please logout first"`.
- If **user does not exist** → `"User does not exist"`.
- If **invalid password** → `"Invalid password for user"`.
- If **user already logged in elsewhere** → allows rebind (reconnected).
- On success → marks user logged in, updates `ip` and `port`, maps socket → user in `activeSessions`.

### 3. `create group <group_id>`
- If **not logged in** → `"You must be logged in to create a group"`.
- If **group already exists** → `"Group already exists"`.
- On success → assigns current user as owner, inserts them into `groupMembers`.

### 4. `list groups`
- If **not logged in** → `"You must be logged in to use list_groups"`.
- If **no groups exist** → `"No groups available"`.
- On success → lists all group IDs.

### 5. `join group <group_id>`
- If **not logged in** → `"You must be logged in to join a group"`.
- If **group does not exist** → `"Group does not exist"`.
- If **already a member** → `"You are already a member"`.
- If **already requested** → `"You already requested to join group"`.
- On success → adds user to `groupJoinRequests`, sends `"Join request sent"`.

### 6. `leave group <group_id>`
- If **not logged in** → `"You must be logged in to leave a group"`.
- If **group does not exist** → `"Group does not exist"`.
- If **user is not a member** → `"You are not a member of group"`.
- If **user is a normal member** → simply removed.
- If **user is the owner**:
  - If other members exist → transfers ownership to first remaining member.
  - If no members remain → deletes group entirely.

### 7. `list requests <group_id>`
- If **not logged in** → `"You must be logged in to list requests"`.
- If **group does not exist** → `"Group does not exist"`.
- If **user is not the owner** → `"Only the owner of group ... can view join requests"`.
- If **no pending requests** → `"No pending join requests"`.
- On success → lists all pending users.

### 8. `accept request <group_id> <user_id>`
- If **not logged in** → `"You must be logged in to accept requests"`.
- If **group does not exist** → `"Group does not exist"`.
- If **user is not the owner** → `"Only group owner can accept requests"`.
- If **target user has not requested** → `"No join request from user"`.
- On success → removes from `groupJoinRequests`, adds to `groupMembers`.

### 9. `upload file <group_id> <file_path>`
- If **not logged in** → `"You must be logged in to upload files"`.
- If **group does not exist** → `"Group does not exist"`.
- If **user is not a member** → `"You are not a member of this group"`.
- If **file does not exist** → `"Cannot access file"`.
- On success → registers file metadata and SHA-1 hash with tracker.

### 10. `list files <group_id>`
- If **not logged in** → `"You must be logged in to list files"`.
- If **group does not exist** → `"Group does not exist"`.
- If **user is not a member** → `"You are not a member of this group"`.
- If **no files available** → `"No files available in group"`.
- On success → displays all shared files with sizes and chunk count.

### 11. `download file <group_id> <file_name> <destination_path>`
- If **not logged in** → `"You must be logged in to download files"`.
- If **group does not exist** → `"Group does not exist"`.
- If **user is not a member** → `"You are not a member of this group"`.
- If **file not found** → `"File not found in group"`.
- If **no online seeders for any chunk** → aborts download.
- On success → begins parallel chunked download with retry across all available peers.

### 12. `show downloads`
- If **no downloads** → `"There are no downloads to show yet"`.
- Displays list with status tags: `[C]` Completed, `[I]` In-progress, `[F]` Failed.

### 13. `stop share <group_id> <file_name>`
- If **not logged in** → `"You must be logged in to stop_share"`.
- If **group does not exist** → `"Group does not exist"`.
- If **not sharing** → `"No changes"`.
- On success → `"Stopped sharing <fileName>"`.

### 14. `logout`
- **Client side**: Sends logout to tracker. The peer program does **not** exit — it continues running, allowing the user to log in again.
- **Tracker side**: Removes the user from `activeSessions`, marks `loggedIn = false`, clears IP/port, and **removes the peer from all file entries** in `fileTable` so stale seeders are not advertised.

---

## Design Details

### Global Data Structures (Tracker)

| Data Structure | Type | Purpose |
|---------------|------|---------|
| `usersInfo` | `unordered_map<string, User>` | userId → User struct (credentials, login state, IP/port) |
| `groupOwners` | `unordered_map<string, string>` | groupId → owner userId |
| `groupMembers` | `unordered_map<string, set<string>>` | groupId → set of member userIds |
| `groupJoinRequests` | `unordered_map<string, set<string>>` | groupId → pending join request userIds |
| `activeSessions` | `unordered_map<int, string>` | socket FD → userId (logged-in sessions) |
| `fileTable` | `unordered_map<string, unordered_map<string, FileInfo>>` | groupId → (fileName → FileInfo with chunk-to-peer mappings) |

All maps are protected by dedicated `std::mutex` locks for thread safety.

### FileInfo Structure

```cpp
struct FileInfo {
    std::string fileName;
    size_t fileSize = 0;
    int numChunks = 0;
    std::unordered_map<int, std::set<std::string>> chunkToPeers;  // chunk → set of "ip:port"
    std::unordered_map<std::string, std::set<int>> peerToChunks;  // "ip:port" → set of chunks
    std::string fileShaHex;
};
```

### Threading Model

| Thread | Component | Purpose |
|--------|-----------|---------|
| Tracker thread (per client) | `handleClientCommands` | Listens to and executes client commands |
| Peer sync thread | `keepPeerConnected` + `peerSyncListener` | Maintains inter-tracker sync connection |
| Console thread | Tracker main | Allows admin to type `exit` for graceful shutdown |
| Tracker comm thread | Client | Sends commands to the tracker |
| Peer server thread | `runPeerServer` | Serves file chunks to other peers |
| Worker pool (4 threads) | `startDownloadFromTrackerResponse` | Parallel chunk downloads |

### Synchronization Approach

- State-changing commands (`create_user`, `login`, `upload_file`, etc.) are forwarded to the peer tracker via `forwardToPeer()` as `SYNC` messages.
- The peer tracker applies these commands through `applyCommand()` with `isSync = true` to replicate state.
- All accesses to `peerTrackerSocket` are protected under `peerSendMutex` to prevent data races.

### Dual-Tracker Failover

- The client always tries **Tracker 1 first**, then falls back to **Tracker 2** on every connection attempt.
- If the active tracker goes down mid-session, the client automatically reconnects to the other tracker.
- No permanent "dead" flag — a tracker that recovers can be reconnected to.

### Download Engine

1. **Peer online check** — Collects all unique peers from the tracker response, checks each exactly once (single-pass), then filters the chunk-to-peer map.
2. **Rarest-first scheduling** — Chunks with fewer available peers are scheduled first to minimize the risk of losing access.
3. **Round-robin peer assignment** — Peers are assigned to chunks in round-robin order for load balancing.
4. **Parallel worker pool** — Up to 4 worker threads download chunks concurrently using `pwrite()` for safe concurrent writes.
5. **Retry across peers** — If a chunk download fails from one peer, the worker automatically tries all other available peers before giving up.
6. **Integrity verification** — Per-chunk SHA-1 verification during download, plus full-file SHA-1 verification after completion.

### Wire Protocol (Download)

```
Tracker response format:
  FILEINFO <fileName> <fileSize> <numChunks> <fileShaHex>
  PEER <ip> <port> <chunk0>,<chunk1>,...
  PEER <ip> <port> <chunk0>,<chunk1>,...
  END

Peer-to-peer chunk request:
  REQUEST_CHUNK <fileName> <chunkIndex>

Peer-to-peer chunk response:
  CHUNK <size> <shaHex>\n<raw chunk data>
```

---

## Building

```bash
# Build tracker
cd tracker && make

# Build client
cd client && make

# Clean
cd tracker && make clean
cd client && make clean
```

The chunk size is **512 KB**. Files are split into chunks and reassembled at the destination using `pwrite()` for concurrent, offset-based writes.

---