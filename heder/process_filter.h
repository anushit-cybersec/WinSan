
#ifndef PROCESS_FILTER_H
#define PROCESS_FILTER_H

#include <string>

void setTargetProcessName(const std::string& name);
std::string getTargetProcessName();
bool processNameMatches(const std::string& name);

#endif
