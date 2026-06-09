# Security Specification and Implementation Report

This document outlines the end-to-end security architecture of the Distributed Peer-to-Peer File Sharing System. To defend against eavesdropping, unauthorized access, identity spoofing, brute-force attacks, and data tampering, several modern cryptographic protocols have been integrated into both the tracker and the client.

---

## 1. Network-Level Security: TLS Encrypted Connections
All communication channels (client-to-tracker, tracker-to-tracker sync, and peer-to-peer chunk transfers) are encrypted using TLS (Transport Layer Security) via OpenSSL.

### Implementation Details:
* **Protocol & Wrapping:** Connections are wrapped using `SSL_CTX` in `client/tlsUtil.cpp` and `tracker/tlsUtil.cpp`.
* **Handshake and Verification:**
  * The tracker initializes a server context loading the certificate `certs/server.crt` and private key `certs/server.key`.
  * The client connects via a TLS handshake, loading client credentials to authenticate itself and validating the server's identity.
* **Impact:** Prevents man-in-the-middle (MITM) eavesdropping, packet injection, and sniffing of command strings or transfer payloads.

---

## 2. Authentication: Asymmetric Challenge-Response Protocol
Instead of transmitting passwords (even hashed ones) over the wire during authentication, the system uses a secure RSA Challenge-Response protocol.

### Implementation Details:
* **Key Generation:**
  * During `create user`, the client generates a 2048-bit RSA key pair.
  * The private key is saved locally in the client folder as `<user_id>_private.pem`.
  * The public key is saved locally as `<user_id>_public.pem` and sent to the tracker to be stored in the user profile database.
* **Protocol Flow:**
  * **Step 1: Challenge Initiation:** The client sends a `login_challenge <user_id>` command.
  * **Step 2: Nonce Generation:** The tracker generates a cryptographically secure 32-byte random challenge using OpenSSL's `RAND_bytes()`, saves it in active memory linked to the socket session, and sends the hex-encoded challenge back to the client.
  * **Step 3: Signature Generation:** The client signs the challenge with its local RSA private key using SHA-256 and replies with `login_response <user_id> <hex_signature>`.
  * **Step 4: Verification:** The tracker verifies the signature using the user's stored RSA public key. If verified, the session is successfully authenticated.
* **Files:**
  * Client side: [client/handleCommands.cpp](file:///Users/vaibhav/Documents/secure%20peer%20to%20peer/final-p2p-with-file-download/client/handleCommands.cpp)
  * Tracker side: [tracker/handleClientCommands.cpp](file:///Users/vaibhav/Documents/secure%20peer%20to%20peer/final-p2p-with-file-download/tracker/handleClientCommands.cpp)

---

## 3. Account Protection: Login Brute-force Lockout
Protects user accounts against dictionary and credential-stuffing attacks.

### Implementation Details:
* **Lockout Logic:**
  * The tracker monitors consecutive failed login attempts per username in its thread-safe metadata registry.
  * If a user fails to authenticate 5 consecutive times, the tracker locks the account.
  * A lockout timestamp is recorded, preventing any login attempts for that user for **5 minutes**.
* **Files:**
  * Tracker side: [tracker/handleClientCommands.cpp](file:///Users/vaibhav/Documents/secure%20peer%20to%20peer/final-p2p-with-file-download/tracker/handleClientCommands.cpp)

---

## 4. File Authenticity: Digital Signatures on Uploads
Ensures that shared files cannot be modified, corrupted, or replaced with malicious payloads by unauthorized seeders.

### Implementation Details:
* **Signing:**
  * When a user runs `upload file`, the client calculates the SHA-1 checksum of the entire file.
  * The client signs the SHA-1 checksum with the owner's RSA private key using a SHA-256 digital signature scheme.
  * The digital signature is sent along with the file metadata and public key to the tracker during the upload registration.
* **Verification:**
  * When a peer attempts to download the file, the tracker sends the owner's signature and public key inside the file metadata.
  * Upon completing the download, the downloading client verifies the received signature against the downloaded file's SHA-1 checksum using the owner's public key.
  * If the verification fails, the client marks the download as compromised, deletes the file, and alerts the user.
* **Files:**
  * Client side: [client/handleCommands.cpp](file:///Users/vaibhav/Documents/secure%20peer%20to%20peer/final-p2p-with-file-download/client/handleCommands.cpp) (Upload sign) & [client/downloadFileFromPeer.cpp](file:///Users/vaibhav/Documents/secure%20peer%20to%20peer/final-p2p-with-file-download/client/downloadFileFromPeer.cpp) (Download verify).

---

## 5. Confidentiality: AES Symmetric Chunk-Level Encryption
Provides end-to-end data confidentiality by encrypting file chunks in transit.

### Implementation Details:
* **Algorithm:** AES-256-CBC (Cipher Block Chaining) with PKCS#7 padding.
* **Process:**
  * When serving a file chunk, the uploading peer encrypts the raw binary block using the 256-bit group key and a randomly generated IV (Initialization Vector).
  * The IV is prepended to the ciphertext and sent over the TLS connection.
  * The downloading peer extracts the IV and decrypts the ciphertext using the same group key before writing it to the destination file.
* **Files:**
  * Upload side: [client/peerUploadHelpers.cpp](file:///Users/vaibhav/Documents/secure%20peer%20to%20peer/final-p2p-with-file-download/client/peerUploadHelpers.cpp)
  * Download side: [client/peerDownloadHelpers.cpp](file:///Users/vaibhav/Documents/secure%20peer%20to%20peer/final-p2p-with-file-download/client/peerDownloadHelpers.cpp)

---

## 6. Access Control: Cryptographic Group Key Management
Symmetric group keys are shared dynamically and securely among authorized members without exposing them to the tracker.

### Implementation Details:
* **Group Initialization:**
  * When `create group` is called, the owner generates a random 256-bit AES Group Key locally.
  * The owner encrypts this group key using their own RSA public key.
  * The encrypted group key is uploaded to the tracker and stored in the group metadata.
* **Member Onboarding:**
  * When the owner executes `accept request <group_id> <user_id>`, the owner's client retrieves the target user's public key from the tracker.
  * The owner's client decrypts the group key using the owner's RSA private key, encrypts it using the new member's public key, and uploads the new encrypted key version back to the tracker.
* **Group Key Decryption:**
  * When any authorized member requests a download, they fetch their user-specific encrypted group key from the tracker and decrypt it locally using their own private key.
* **Files:**
  * Tracker side: [tracker/trackerData.cpp](file:///Users/vaibhav/Documents/secure%20peer%20to%20peer/final-p2p-with-file-download/tracker/trackerData.cpp)
  * Client side: [client/handleCommands.cpp](file:///Users/vaibhav/Documents/secure%20peer%20to%20peer/final-p2p-with-file-download/client/handleCommands.cpp) (encryption/re-encryption) and [client/downloadFileFromPeer.cpp](file:///Users/vaibhav/Documents/secure%20peer%20to%20peer/final-p2p-with-file-download/client/downloadFileFromPeer.cpp) (decryption).

---

## Summary of Cryptographic Primitive Configurations

| Use Case | Algorithm / Primitive | Bit Strength / Length | Key Material Location |
|---|---|---|---|
| **Asymmetric Keys** | RSA (with OAEP padding) | 2048-bit | Client filesystem (`*_private.pem`, `*_public.pem`) |
| **Symmetric Encryption** | AES-256-CBC | 256-bit | Generated dynamically; stored encrypted on Tracker |
| **Integrity Checks** | SHA-1 | 160-bit | Hashed per-chunk and full-file |
| **Signatures** | SHA-256 with RSA | 2048-bit | Stored on tracker on upload, verified on download |
| **Secure Handshake** | TLSv1.3 / TLSv1.2 | Standard TLS cipher suits | certificates and keys in `certs/` |
