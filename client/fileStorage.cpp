#include "client.h"
#include <map>
#include <mutex>
#include <string>

using namespace std;

mutex localPathMutex;
unordered_map<string, string> fileNameToPath;

void addLocalFilePath(const string &fileName, const string &filePath) {
    lock_guard<mutex> l(localPathMutex);
    fileNameToPath[fileName] = filePath;
}

string getLocalFilePath(const string &fileName) {
    lock_guard<mutex> l(localPathMutex);
    auto it = fileNameToPath.find(fileName);
    return it == fileNameToPath.end() ? string() : it->second;
}
void removeLocalFilePath(const string &fileName) {
    lock_guard<mutex> l(localPathMutex);
    fileNameToPath.erase(fileName);
}
