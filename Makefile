CXX = g++
CXXFLAGS = -std=c++17 -pthread -Wno-deprecated-declarations
LDFLAGS = -lssl -lcrypto
INCLUDES = -I/opt/homebrew/opt/openssl/include
LIB_DIRS = -L/opt/homebrew/opt/openssl/lib

# Target executables
SERVER_BIN = server/tracker
CLIENT_BIN = client/client

# Source files
SERVER_SRCS = server/tracker.cpp server/common.cpp server/commands.cpp
CLIENT_SRCS = client/client.cpp client/filesend.cpp client/peer.cpp

all: $(SERVER_BIN) $(CLIENT_BIN)

$(SERVER_BIN): $(SERVER_SRCS)
	$(CXX) $(CXXFLAGS) $^ -o $@

$(CLIENT_BIN): $(CLIENT_SRCS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(LIB_DIRS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(SERVER_BIN) $(CLIENT_BIN)
