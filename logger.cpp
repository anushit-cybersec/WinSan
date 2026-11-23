#include "logger.h"
#include "behavior_engine.h"
#include "process_filter.h"

#include <fstream>
#include <iostream>

using namespace std;


// ----------------------------------------
// JSON escaping
// ----------------------------------------

string jsonEscape(const string& input)
{
    string output;

    for (char c : input)
    {
        switch (c)
        {
            case '\\':
                output += "\\\\";
                break;

            case '"':
                output += "\\\"";
                break;

            case '\n':
                output += "\\n";
                break;

            case '\r':
                output += "\\r";
                break;

            case '\t':
                output += "\\t";
                break;

            default:
                output += c;
        }
    }

    return output;
}


// ----------------------------------------
// Write event
// ----------------------------------------

void logEvent(const Event& event)
{

    if (!getTargetProcessName().empty())
    {
        bool supportedEvent =
            event.eventType == "PROCESS_CREATED" ||
            event.eventType == "PROCESS_TERMINATED" ||
            event.eventType == "NETWORK_CONNECTION";

        bool matches =
            event.pid != 0 &&
            processNameMatches(event.name);

        if (!supportedEvent || !matches)
            return;
    }
    ofstream file("events.jsonl", ios::app);

    if (!file.is_open())
    {
        cout << "[!] Could not open events.jsonl\n";
        return;
    }

    file << "{";

    file << "\"timestamp\":\""
         << jsonEscape(event.timestamp)
         << "\",";

    file << "\"event\":\""
         << jsonEscape(event.eventType)
         << "\",";

    file << "\"pid\":"
         << event.pid
         << ",";

    file << "\"parent_pid\":"
         << event.parentPid
         << ",";

    file << "\"name\":\""
         << jsonEscape(event.name)
         << "\",";

    file << "\"path\":\""
         << jsonEscape(event.path)
         << "\",";

    file << "\"size\":"
         << event.size
         << ",";

    file << "\"sha256\":\""
         << jsonEscape(event.sha256)
         << "\",";

    file << "\"local_ip\":\""
         << jsonEscape(event.localIP)
         << "\",";

    file << "\"local_port\":"
         << event.localPort
         << ",";

    file << "\"remote_ip\":\""
         << jsonEscape(event.remoteIP)
         << "\",";

    file << "\"remote_port\":"
         << event.remotePort
         << ",";

    file << "\"state\":\""
         << jsonEscape(event.state)
         << "\"";

    file << "}\n";

    file.close();
    analyzeEvent(event);
}