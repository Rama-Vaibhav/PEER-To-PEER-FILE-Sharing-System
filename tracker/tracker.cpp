#include <iostream>
#include <sys/socket.h>
#include <thread>
#include <mutex>
#include <unistd.h> 
#include <csignal> // this is for SIGINT
#include "tracker.h"

using namespace std;

/********************************************************************************************************
                                    Thread to listen for quit command
********************************************************************************************************/
// this function will always listen to the input console of the tracker and whenever it detects quit then it will terminate the process
void consoleListener() {
    string command;
    while (true) {
        cin >> command;
        if (command == "quit") {
            cout << "\033[31m[Tracker shutting down...]\033[0m" << endl;
            raise(SIGINT);  // send Ctrl+C signal to self
            break;
        }
    }
}

/********************************************************************************************************
                                                MAIN FUNCTION
********************************************************************************************************/
int main(int argc, char *argv[]) {
    cout << "\033[32m*********************************TRACKER-STARTED*********************************\033[0m" << endl;

    /********************************************************************************************************
                        Extracting the tracker info from the command line args
    ********************************************************************************************************/
    if (argc != 3) {
        cout << "Command usage: ./tracker tracker_info_filename.txt <tracker_number>\n";
        return -1;
    }
    
    string tracker_info = argv[1];
    int trackerNumber = stoi(argv[2]);

    /********************************************************************************************************
                        Extracting the tracker info from tracker_info.txt
    ********************************************************************************************************/
    string currentTrackerIP;
    int currentTrackerPort;
    if (!extractTrackerInfo(tracker_info, trackerNumber, currentTrackerIP, currentTrackerPort)) {
        cerr << "Failed to load tracker info" << endl;
        return -1;
    }


    // This will look into the file and figure out which is the peer client, anyways the client will first try to connect with tracker 1
    // and if it is down then only it will move to the other tracker
    string peerIP;
    int peerPort;
    int peerTrackerNumber;

    if (trackerNumber == 1) peerTrackerNumber = 2;
    else if (trackerNumber == 2) peerTrackerNumber = 1;

    if (!extractTrackerInfo(tracker_info, peerTrackerNumber, peerIP, peerPort)) {
        cerr << "Failed to load peer tracker info" << endl;
        return -1;
    } 

    /********************************************************************************************************
                        Initialize OpenSSL and load TLS certificates (Fix 2)
    ********************************************************************************************************/
    initOpenSSL();

    // Determine certs path relative to executable location
    // Certs are expected in ../certs/ relative to the tracker directory
    string certPath = "../certs/server.crt";
    string keyPath  = "../certs/server.key";
    string caPath   = "../certs/ca.crt";

    g_serverSSLCtx = initServerSSLCtx(certPath, keyPath);
    g_clientSSLCtx = initClientSSLCtx(caPath);

    /********************************************************************************************************
                    Thread for listening to QUIT and connection between peer trackers
    ********************************************************************************************************/
    // We are creating a thread to listen for quit command so that tracker can shut down
    thread consoleThread(consoleListener);
    consoleThread.detach();

    /********************************************************************************************************
                             Thread for connecting to the peer tracker
    ********************************************************************************************************/
    // Connect to the peer tracker, means one will connect to other to start syncing
    thread keepPeerConnectedThread(keepPeerConnected, peerIP, peerPort);
    keepPeerConnectedThread.detach();


    /********************************************************************************************************
                          Start the current tracker for listening to the requests 
    ********************************************************************************************************/
    // here we are telling that the tracker is now open to accept the incoming connections
    int listenSocket = startTrackerServer(currentTrackerIP, currentTrackerPort);

    /********************************************************************************************************
           Create new thread for each client, like this loop run infinitely waiting for new clients
    ********************************************************************************************************/
    // A new thread is spawned for each incoming peer connection, and that thread is responsible for handling that peer's 
    // commands for the entire duration of its session.
    while (true) {
        // using tracker socket we will communicate with the tracker, this will be a fd
        // in listen() we just say we are open for accepting the incoming connections, but here we are actually handling those 
        // incoming connections
        int newClientFd = accept(listenSocket, nullptr, nullptr);
        if (newClientFd >= 0) {
            // Wrap the accepted socket in TLS (Fix 2)
            SSL* clientSSL = acceptSSL(g_serverSSLCtx, newClientFd);
            if (clientSSL) {
                thread clientHandlingThread(handleClientCommands, clientSSL);
                clientHandlingThread.detach();
            } else {
                cerr << "\033[31m[TLS] SSL_accept failed for client fd " << newClientFd << "\033[0m" << endl;
                close(newClientFd);
            }
        }
    }

    close(listenSocket);
    return 0;
}