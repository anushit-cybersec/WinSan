#ifndef LOGGER_H
#define LOGGER_H

#include <minwindef.h>
#include <string>

struct Event
{
    std::string timestamp;
    std::string eventType;

    DWORD pid;
    DWORD parentPid;

    std::string name;
    std::string path;

    unsigned long long size;

    std::string sha256;
    
    // Network information
    std::string localIP;
    DWORD localPort;

    std::string remoteIP;
    DWORD remotePort;

    std::string state;
};

void logEvent(const Event& event);

#endif