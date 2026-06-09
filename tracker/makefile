# Makefile (macOS-friendly; auto-detects Homebrew OpenSSL prefix)

CXX = g++
CXXFLAGS = -Wall -pthread -std=c++17

# Try to detect Homebrew OpenSSL prefix (openssl@3 preferred)
OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null || echo "")

ifeq ($(OPENSSL_PREFIX),)
$(warning "Could not detect OpenSSL via brew. If you haven't installed it run: brew install openssl@3")
else
CXXFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS  += -L$(OPENSSL_PREFIX)/lib
endif

LDLIBS = -lssl -lcrypto

# Sources and objects
SRCS = tracker.cpp handleClientCommands.cpp trackerData.cpp trackerConnection.cpp handleDownload.cpp passwordUtil.cpp tlsUtil.cpp ../common/cryptoUtil.cpp
OBJS = $(SRCS:.cpp=.o)

# Target executable
TARGET = tracker

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS) $(LDLIBS)

# Compile rule for .cpp to .o
%.o: %.cpp tracker.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

../common/cryptoUtil.o: ../common/cryptoUtil.cpp ../common/cryptoUtil.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean
clean:
	rm -f $(OBJS) ../common/cryptoUtil.o $(TARGET)

.PHONY: all clean