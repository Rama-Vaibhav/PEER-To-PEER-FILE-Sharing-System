CXX = g++
CXXFLAGS = -std=c++17 -pthread -Wno-deprecated-declarations
LDFLAGS = -lssl -lcrypto
INCLUDES = -I/opt/homebrew/opt/openssl/include
LIB_DIRS = -L/opt/homebrew/opt/openssl/lib

# Target executables
SERVER_BIN = server/tracker
CLIENT_BIN = client/client

# Source files
SERVER_SRCS = server/tracker.cpp server/common.cpp server/commands.cpp server/tls_utils.cpp
CLIENT_SRCS = client/client.cpp client/filesend.cpp client/peer.cpp client/tls_utils.cpp client/crypto_utils.cpp

all: $(SERVER_BIN) $(CLIENT_BIN)

$(SERVER_BIN): $(SERVER_SRCS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(LIB_DIRS) $^ -o $@ $(LDFLAGS)

$(CLIENT_BIN): $(CLIENT_SRCS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(LIB_DIRS) $^ -o $@ $(LDFLAGS)

certs:
	cd certs && bash generate_certs.sh

clean:
	rm -f $(SERVER_BIN) $(CLIENT_BIN)

.PHONY: all clean certs
