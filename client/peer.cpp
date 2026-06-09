#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>
#include <fcntl.h> 
#include <unistd.h>  
#include <thread>
#include <openssl/ssl.h>
#include "client.h"

using namespace std;

string g_currentUsername;
unordered_map<string, string> g_groupKeys;
unordered_map<string, string> fileNameToGroupId;

/********************************************************************************************************
                                                MAIN FUNCTION
********************************************************************************************************/
int main(int argc, char* argv[]) {
    cout << "\033[32m*********************************PEER-STARTED*********************************\033[0m" << endl;

    /********************************************************************************************************
                        Extracting the client info from the command line args
    ********************************************************************************************************/
    if (argc != 3) {
        cout << "Command usage: ./client <IP>:<PORT> tracker_info.txt" << endl;
        return -1;
    }

    string peerAddr = argv[1];
    size_t colonPos = peerAddr.find(":");
    if (colonPos == string::npos) {
        cerr << "Invalid format for peer IP:Port" << endl;
        return -1;
    }

    string clientIP = peerAddr.substr(0, colonPos);
    int clientPort = stoi(peerAddr.substr(colonPos + 1));

    /********************************************************************************************************************
      Extracting the tracker info from tracker_info.txt, connecting to the tracker and sending commands to the tracker
    *********************************************************************************************************************/
    // we will read the details of the first tracker from the file names tracker_info.txt
    string trackerIP1;
    string trackerIP2;
    int trackerPort1 = 0;
    int trackerPort2 = 0;

    string tracker_info = argv[2];
    if (!extractTrackerInfo(tracker_info, trackerIP1, trackerPort1, trackerIP2, trackerPort2)) {
        cerr << "Failed to load tracker info" << endl;
        return -1;
    }

    /********************************************************************************************************
                        Initialize OpenSSL and load TLS certificates (Fix 2)
    ********************************************************************************************************/
    initOpenSSL();

    // Certs are expected in ../certs/ relative to the client directory
    string caPath   = "../certs/ca.crt";
    string certPath = "../certs/server.crt";
    string keyPath  = "../certs/server.key";

    g_clientSSLCtx     = initClientSSLCtx(caPath);
    g_peerServerSSLCtx = initPeerServerSSLCtx(certPath, keyPath);

    // Connect to tracker with TLS
    SSL* trackerSSL = connectToTrackerSSL(trackerIP1, trackerPort1, trackerIP2, trackerPort2);
    if (!trackerSSL) {
        cerr << "\033[31mFailed to establish TLS connection to any tracker!\033[0m" << endl;
        return -1;
    }

    // Thread 1 - Peer as client (talk to tracker)
    // this will send the commands from client to the tracker and this is its complete task of just sending the commands
    // this thread is for client to communicate with the client
    thread trackerThread(sendCommands, trackerSSL, clientIP, clientPort, trackerIP1, trackerPort1, trackerIP2, trackerPort2);

    // Thread 2 - Peer as server (serve files to other peers)
    // this will listen to the connections from other clients 
    thread peerServerThread(runPeerServer, clientPort);

    trackerThread.join();
    peerServerThread.join();

    return 0;
}