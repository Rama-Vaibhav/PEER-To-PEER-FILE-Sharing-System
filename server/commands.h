#ifndef COMMANDS_H
#define COMMANDS_H

#include <string>
using namespace std;
string process_command(const string &cmd_line, string &current_user,int newsockfd);
string cmd_create_user(const string &username, const string &password);
#endif // COMMANDS_H
