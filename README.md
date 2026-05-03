# Peer-to-Peer File Sharing System

**Roll Number:** 2025201067  
**Course:** Advanced Operating Systems — Assignment 3, Monsoon 2025  
**Institute:** IIIT Hyderabad

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Directory Structure](#directory-structure)
4. [Compilation](#compilation)
5. [Execution](#execution)
6. [Supported Commands](#supported-commands)
7. [Network Protocol Design](#network-protocol-design)
8. [Key Algorithms](#key-algorithms)
9. [Data Structures](#data-structures)
10. [Tracker Synchronization](#tracker-synchronization)
11. [File Integrity & Piece Management](#file-integrity--piece-management)
12. [Error Handling](#error-handling)
13. [Assumptions & Limitations](#assumptions--limitations)
14. [Testing Procedures](#testing-procedures)

---

## Overview

A distributed peer-to-peer file sharing system inspired by BitTorrent. The system consists of two main components:

- **Tracker (Server):** A centralized coordination server that manages user accounts, groups, file metadata, and seeder information. Supports a two-tracker redundant deployment with automatic state synchronization.
- **Client:** A peer application that uploads, downloads, and shares files within groups. Each client runs an embedded peer server to serve file pieces to other clients.

Key features:
- Multi-threaded concurrent piece downloads using **rarest-piece-first** selection
- SHA1 integrity verification at both piece-level and full-file level
- Multi-seeder support — downloads different pieces from different peers
- Partial file serving — peers can serve pieces they've already downloaded even before completing the full file
- Two-tracker synchronization with automatic reconnection
- Persistent seeding state across client restarts

---

## Architecture

```
                    ┌──────────────────┐
                    │   Tracker 1      │◄──── Sync ────►┌──────────────────┐
                    │  (Main: 6000)    │                 │   Tracker 2      │
                    │  (Sync: 6100)    │                 │  (Main: 6001)    │
                    └────────┬─────────┘                 │  (Sync: 6101)    │
                             │                           └────────┬─────────┘
                    TCP (persistent)                               │
                             │                           TCP (persistent)
              ┌──────────────┼──────────────┐                     │
              ▼              ▼              ▼                     ▼
      ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
      │   Client A   │ │   Client B   │ │   Client C   │
      │ (Peer: 5001) │ │ (Peer: 5002) │ │ (Peer: 5003) │
      └──────┬───────┘ └──────┬───────┘ └──────────────┘
             │                │
             └──── P2P ───────┘
           (GET_PIECE / GET_BITMAP)
```

**Communication flows:**
1. **Client ↔ Tracker:** Persistent TCP connection for user/group management, file metadata upload, seeder discovery
2. **Client ↔ Client (P2P):** Short-lived TCP connections for piece transfer and bitmap queries
3. **Tracker ↔ Tracker:** Persistent TCP connection for state synchronization with heartbeat keep-alive

---

## Directory Structure

```
2025201067_A3/
├── README.md                    # This file
├── Report.pdf                   # Technical report
├── tracker_info.txt             # Tracker configuration (id, ip, main_port, sync_port)
├── server/                      # Tracker source files
│   ├── tracker.cpp              # Main tracker: networking, sync threads, client accept loop
│   ├── commands.cpp             # Command processing: user/group/file operations
│   ├── commands.h               # Command handler declarations
│   ├── common.cpp               # Global state, sync message processing, utilities
│   └── common.h                 # Shared data structures (User, Group, FileMetadata)
└── client/                      # Client source files
    ├── client.cpp               # Main client: CLI loop, tracker communication
    ├── filesend.cpp             # File hashing, multi-threaded download engine
    ├── filesend.h               # Download state, file metadata structures
    ├── peer.cpp                 # Embedded peer server: serves pieces and bitmaps
    └── peer.h                   # Peer server declarations, shared state externs
```

---

## Compilation

### Prerequisites
- **Compiler:** `g++` with C++17 support (GCC 7+ recommended)
- **Libraries:** OpenSSL (`libssl-dev` / `openssl-devel`) for SHA1 hashing
- **Threading:** POSIX threads (`-pthread`)

### Build the Tracker
```bash
g++ -std=c++17 server/tracker.cpp server/common.cpp server/commands.cpp \
    -o server/tracker -pthread
```

### Build the Client
```bash
g++ -std=c++17 client/client.cpp client/filesend.cpp client/peer.cpp \
    -o client/client -I/opt/homebrew/opt/openssl/include -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto -pthread -Wno-deprecated-declarations
```

> **Note:** The `-Wno-deprecated-declarations` flag suppresses OpenSSL 3.0 deprecation warnings for the legacy SHA1 API. The functions remain fully functional.

---

## Execution

### Step 1: Configure Trackers

Edit `tracker_info.txt` with one line per tracker:
```
<tracker_id> <ip> <main_port> <sync_port>
```

Example (`tracker_info.txt`):
```
1 127.0.0.1 6000 6100
2 127.0.0.1 6001 6101
```

### Step 2: Start Trackers (2 terminals)

```bash
# Terminal 1 — Start Tracker 1
./server/tracker tracker_info.txt 1

# Terminal 2 — Start Tracker 2
./server/tracker tracker_info.txt 2
```

Both trackers will automatically establish a sync connection with each other.

### Step 3: Start Clients (1+ terminals)

```bash
# Terminal 3 — Start Client A
./client/client 127.0.0.1:5001 tracker_info.txt

# Terminal 4 — Start Client B
./client/client 127.0.0.1:5002 tracker_info.txt

# Terminal 5 — Start Client C (optional)
./client/client 127.0.0.1:5003 tracker_info.txt
```

**Format:** `./client/client <MY_IP:MY_PORT> <tracker_info.txt>`

- `<MY_IP:MY_PORT>` — The IP and port this client's peer server will listen on for incoming piece requests.
- `<tracker_info.txt>` — Path to the tracker configuration file.

---

## Supported Commands

All commands use underscore-separated format.

### User Management
| Command | Description |
|---------|-------------|
| `create_user <user_id> <password>` | Register a new user account |
| `login <user_id> <password>` | Authenticate and start a session |
| `logout` | End current session and stop sharing files |

### Group Management
| Command | Description |
|---------|-------------|
| `create_group <group_id>` | Create a new group (you become the owner) |
| `join_group <group_id>` | Request to join an existing group |
| `leave_group <group_id>` | Leave a group you're a member of |
| `list_groups` | Display all available groups |
| `list_requests <group_id>` | Show pending join requests (owner only) |
| `accept_request <group_id> <user_id>` | Accept a join request (owner only) |

### File Operations
| Command | Description |
|---------|-------------|
| `upload_file <group_id> <file_path>` | Share a file with a group |
| `download_file <group_id> <file_name> <dest_path>` | Download a file from a group |
| `list_files <group_id>` | Show all files available in a group |
| `show_downloads` | Display current download progress |
| `stop_share <group_id> <file_name>` | Stop sharing a specific file |

### Download Status Format
```
[D] [group_id] filename (X/Y pieces)    — Download in progress
[C] [group_id] filename                 — Download completed
[F] [group_id] filename (FAILED)        — Download failed
```

---

## Network Protocol Design

### Client ↔ Tracker Protocol

All messages are newline-terminated (`\n`). The client maintains a persistent TCP connection to the tracker.

| Request | Response | Notes |
|---------|----------|-------|
| `create_user <uid> <pwd>\n` | `User created successfully\n` | |
| `login <uid> <pwd> <ip:port>\n` | `Login successful\n` | Client appends its peer address |
| `logout\n` | `Logout successful\n` | |
| `create_group <gid>\n` | `Group created successfully\n` | |
| `join_group <gid>\n` | `Join request sent\n` | |
| `leave_group <gid>\n` | `Left group\n` | |
| `list_groups\n` | `gid1 (owner: user1)\ngid2...\n` | Single response |
| `list_requests <gid>\n` | `user1\nuser2\n` | |
| `accept_request <gid> <uid>\n` | `Request accepted\n` | |
| `UPLOAD_FILE <gid> <fname> <size> <filehash> <h1\|h2\|...>\n` | `SUCCESS: File metadata uploaded successfully.\n` | Single-line protocol |
| `DOWNLOAD_FILE <gid> <fname>\n` | `DOWNLOAD_INFO <size> <ip1:port1,ip2:port2,...> \|h1\|h2\|...\n` | Multi-seeder response |
| `UPDATE_SEEDER <gid> <fname>\n` | `OK\n` | Sent after download completes |
| `LIST_FILES <gid>\n` | `file1 (size bytes)\n...\nEND_OF_LIST\n` | Multi-line, terminated |
| `STOP_SEEDING <gid> <fname>\n` | `Tracker updated...\n` | |

### Client ↔ Client (P2P) Protocol

Each peer runs an embedded TCP server. Connections are short-lived (one request per connection).

| Request | Response | Notes |
|---------|----------|-------|
| `GET_PIECE <filename> <piece_index>\n` | `PIECE_LEN <bytes>\n` + raw binary data | Downloads one 512KB piece |
| `GET_BITMAP <filename> <total_pieces>\n` | `BITMAP <bit_string>\n` | e.g., `BITMAP 11010` — `1` = have, `0` = don't have |

**Error handling:**
- `PIECE_LEN 0\n` — Piece not available (file not found, piece index out of range, or partial download doesn't have this piece yet)
- `BITMAP_ERROR\n` — Invalid request parameters

### Tracker ↔ Tracker Sync Protocol

Pipe-delimited (`|`) messages over a persistent TCP connection with heartbeat keep-alive.

| Sync Message | Description |
|--------------|-------------|
| `SYNC\|CREATE_USER\|uid\|pwd` | New user registered |
| `SYNC\|CREATE_GROUP\|gid\|owner` | New group created |
| `SYNC\|JOIN_GROUP\|gid\|uid` | Join request submitted |
| `SYNC\|ACCEPT_REQUEST\|gid\|uid` | Join request accepted |
| `SYNC\|LEAVE_GROUP\|gid\|uid` | Member left group |
| `SYNC\|DELETE_GROUP\|gid` | Group deleted (last member left) |
| `SYNC\|CHOWN\|gid\|new_owner` | Ownership transferred |
| `SYNC\|UPLOAD_FILE\|gid\|fname\|size\|hash\|ph1\|ph2\|...\|seeder` | File metadata uploaded |
| `SYNC\|ADD_SEEDER\|gid\|fname\|uid` | New seeder registered |
| `SYNC\|STOP_SEEDING\|gid\|fname\|uid` | Seeder removed |

---

## Key Algorithms

### Rarest Piece First (Download Strategy)

Before starting a download, the client queries all seeders for their piece availability using the `GET_BITMAP` protocol:

1. **Bitmap Query:** For each seeder, send `GET_BITMAP <filename> <total_pieces>`. The seeder responds with a binary string (e.g., `"110101"`) indicating which pieces it has.
2. **Rarity Computation:** For each piece, count how many seeders have it. This is the piece's "rarity score."
3. **Piece Selection:** Worker threads select the **NEEDED** piece with the **lowest rarity** (fewest sources). This ensures that rare pieces are downloaded first, maximizing overall piece availability across the swarm.
4. **Seeder Selection:** For the chosen piece, a random seeder is selected from those that have it, distributing load across peers.
5. **Fallback:** If a bitmap query fails (seeder offline), the system optimistically assumes the seeder has all pieces.

**Why rarest first?**
- Improves swarm health: rare pieces get replicated faster
- Prevents the "last piece" problem in multi-peer scenarios
- Enables partial seeders (still-downloading peers) to contribute effectively

### Multi-threaded Download Engine

- Worker thread count = `min(hardware_concurrency, total_pieces)`
- Each worker independently claims a piece (under mutex), downloads it, verifies its hash, and writes it to disk at the correct offset using `pwrite()`
- On failure: piece is retried up to `MAX_PIECE_RETRIES` (5) times before aborting the entire download
- A `condition_variable` coordinates completion notification between workers and the manager thread

### Partial File Serving

- As soon as a piece is downloaded and verified, it's registered in `local_pieces[filename]`
- Other peers can immediately query `GET_BITMAP` and see the newly available piece
- Other peers can download that piece via `GET_PIECE` — even while our download is still in progress
- This is critical for swarm efficiency: a peer with 50% of a file can already help others

---

## Data Structures

### Tracker Side

```
User {
    username, password, logged_in,
    ip, port                           // Peer server address (set on login)
}

Group {
    group_id, owner,
    members[],                         // List of member usernames
    pending_requests[],                // Join requests awaiting approval
    files: map<filename, FileMetadata> // Shared files in this group
}

FileMetadata {
    filesize, file_hash,               // Full file SHA1
    piece_hashes[],                    // Per-piece SHA1 (512KB chunks)
    seeders[]                          // Usernames of users who have the complete file
}
```

**Concurrency:** All shared state is protected by `state_mutex`. Sync socket writes are protected by `sync_mutex`.

### Client Side

```
DownloadState {
    piece_status[]:    NEEDED / IN_FLIGHT / HAVE
    pieces_completed:  atomic<int>
    seeder_addresses:  vector<string>        // All available seeders
    piece_hashes:      vector<string>        // Expected SHA1 per piece
    piece_rarity:      vector<int>           // Seeder count per piece
    piece_seeder_map:  vector<vector<int>>   // piece → seeder indices
    piece_retry_count: vector<int>           // Retry counter per piece
    completed, failed: bool                  // Terminal states
}
```

**Persistence:**
- `seeding_<port>.log` — Tab-separated file mapping `filename → filepath` for files this client is seeding. Per-port to avoid corruption when multiple clients run from the same directory.

---

## Tracker Synchronization

### Design

The two-tracker system uses a **bidirectional persistent TCP connection** for state synchronization:

1. **Listener Thread:** Each tracker listens on its `sync_port` for incoming connections from the peer tracker.
2. **Connector Thread:** Each tracker actively attempts to connect to the peer tracker's `sync_port` with automatic retry (3-second backoff).
3. **Heartbeat:** If no data is received for 5 seconds, a `HEARTBEAT` message is sent. This detects dead connections.
4. **ACK:** Each received sync message is acknowledged with `ACK:<original_message>`.

### Failure Handling

- If a tracker goes offline, the remaining tracker continues serving clients normally.
- When the offline tracker comes back online, the connector thread re-establishes the sync connection automatically.
- Sync messages sent while the peer is offline are lost (no queue/WAL). However, the system remains functional with single-tracker operation.
- All sync operations are idempotent — duplicate messages are safely ignored.

### Consistency Model

- **Eventual consistency:** Both trackers will converge to the same state as long as they can communicate. There is no strict ordering guarantee.
- **No split-brain protection:** If both trackers accept conflicting operations while disconnected (e.g., same group name created on both), the first write wins when sync reconnects.

---

## File Integrity & Piece Management

### Piece Size
- Fixed chunk size: **512 KB** (524,288 bytes)
- Last piece may be smaller than 512 KB

### Hashing Strategy
1. **Piece-level SHA1:** Each 512KB chunk is independently hashed during upload. The hash is stored in `piece_hashes[]`.
2. **Full-file SHA1:** The entire file is hashed using a streaming `SHA_CTX` (processes chunks sequentially without loading the full file into memory).
3. **Download verification:** Each received piece is immediately verified against its expected SHA1 hash. Corrupted pieces are discarded and re-requested (up to 5 retries, potentially from a different seeder).

### Write Strategy
- The destination file is pre-allocated to full size using `ftruncate()`.
- Pieces are written at their exact byte offset using `pwrite()` — enabling concurrent writes from multiple threads without seek conflicts.

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Seeder goes offline during download | Piece download fails, retries with backoff. If all retries exhausted, download aborts. |
| Tracker connection lost | Client exits gracefully. Re-run the client to reconnect. |
| File deleted while seeding | Peer server returns `PIECE_LEN 0` for that file's pieces. |
| Hash mismatch on downloaded piece | Piece is discarded and re-requested from a (potentially different) seeder. |
| All seeders offline | Tracker returns `ERROR: No online seeders available.` |
| Duplicate user/group creation | Returns error message, no state change. |
| Non-member tries to upload/download | Returns `ERROR: You are not a member of this group.` |
| Owner leaves group | Ownership transferred to the next member. If last member, group is deleted. |
| Multiple clients same directory | Per-port seeding log files (`seeding_<port>.log`) prevent state corruption. |

---

## Assumptions & Limitations

### Assumptions
1. Clients and trackers run on the same local network (or `127.0.0.1` for testing).
2. File names are unique within a group (no versioning).
3. `tracker_info.txt` is available and correctly formatted before starting any component.
4. The file system has sufficient disk space for pre-allocating downloaded files.

### Limitations
1. **No persistent tracker state:** Tracker state (users, groups, files) is in-memory only. Restarting both trackers loses all data.
2. **Single tracker connection:** Each client connects to the first tracker listed in `tracker_info.txt`. There is no automatic failover to the second tracker.
3. **No resume:** If a download is interrupted (client killed), it starts from scratch on restart.
4. **No NAT traversal:** Peers must be directly reachable by IP:port.
5. **No encryption:** All communication is plaintext TCP.

### Implemented Features
- [x] User registration and authentication
- [x] Group creation, joining, leaving with ownership transfer
- [x] File upload (metadata + SHA1 hashing)
- [x] Multi-threaded file download with rarest-piece-first
- [x] Multi-seeder support
- [x] Partial file serving (serve pieces while still downloading)
- [x] Piece-level SHA1 integrity verification
- [x] Two-tracker synchronization with heartbeat
- [x] Download progress tracking (`show_downloads`)
- [x] Stop sharing (`stop_share`)
- [x] Persistent seeding state across client restarts

---

## Testing Procedures

### Basic End-to-End Test (5 terminals)

```bash
# T1: Start Tracker 1
./server/tracker tracker_info.txt 1

# T2: Start Tracker 2
./server/tracker tracker_info.txt 2

# T3: Start Client A (seeder)
./client/client 127.0.0.1:5001 tracker_info.txt
> create_user alice pass123
> login alice pass123
> create_group g1
> upload_file g1 /path/to/testfile.pdf

# T4: Start Client B (downloader)
./client/client 127.0.0.1:5002 tracker_info.txt
> create_user bob pass456
> login bob pass456
> join_group g1

# T3 (Client A): Accept Bob's request
> list_requests g1
> accept_request g1 bob

# T4 (Client B): Download the file
> list_files g1
> download_file g1 testfile.pdf /tmp/downloaded_testfile.pdf
> show_downloads

# T5: Start Client C (second downloader — tests multi-seeder)
./client/client 127.0.0.1:5003 tracker_info.txt
> create_user charlie pass789
> login charlie pass789
> join_group g1
# (Accept from T3)
> download_file g1 testfile.pdf /tmp/downloaded_testfile_c.pdf
```

### Verify File Integrity
```bash
sha1sum /path/to/testfile.pdf /tmp/downloaded_testfile.pdf
# Both hashes should match
```

### Test Tracker Sync
```bash
# Create a user on Tracker 1 (via Client A)
> create_user synctest pass

# Kill Tracker 1 (Ctrl+C in T1)
# Start a new client connecting to Tracker 2
./client/client 127.0.0.1:5004 tracker_info.txt
> login synctest pass
# Should succeed — user was synced to Tracker 2
```

### Test Large Files
```bash
# Create a ~100MB test file
dd if=/dev/urandom of=bigfile.bin bs=1M count=100

# Upload and download — should create ~200 pieces (100MB / 512KB)
> upload_file g1 bigfile.bin
> download_file g1 bigfile.bin /tmp/downloaded_bigfile.bin
```