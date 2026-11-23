#include "network_monitor.h"
#include "hash.h"
#include "logger.h"
#include "utils.h"
#include "process_filter.h"

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <iostream>
#include <string>
#include <map>
#include <thread>
#include <chrono>

using namespace std;
string getProcessPath(DWORD pid);

#pragma comment(lib, "iphlpapi.lib")

struct TcpConnection
{
    DWORD pid;
    DWORD localAddr;
    DWORD localPort;
    DWORD remoteAddr;
    DWORD remotePort;
    DWORD state;
};

string tcpStateToString(DWORD state)
{
    switch (state)
    {
        case MIB_TCP_STATE_CLOSED:
            return "CLOSED";

        case MIB_TCP_STATE_LISTEN:
            return "LISTEN";

        case MIB_TCP_STATE_SYN_SENT:
            return "SYN_SENT";

        case MIB_TCP_STATE_SYN_RCVD:
            return "SYN_RECEIVED";

        case MIB_TCP_STATE_ESTAB:
            return "ESTABLISHED";

        case MIB_TCP_STATE_FIN_WAIT1:
            return "FIN_WAIT1";

        case MIB_TCP_STATE_FIN_WAIT2:
            return "FIN_WAIT2";

        case MIB_TCP_STATE_CLOSE_WAIT:
            return "CLOSE_WAIT";

        case MIB_TCP_STATE_CLOSING:
            return "CLOSING";

        case MIB_TCP_STATE_LAST_ACK:
            return "LAST_ACK";

        case MIB_TCP_STATE_TIME_WAIT:
            return "TIME_WAIT";

        case MIB_TCP_STATE_DELETE_TCB:
            return "DELETE_TCB";

        default:
            return "UNKNOWN";
    }
}


string ipToString(DWORD ip)
{
    struct in_addr address;

    address.S_un.S_addr = ip;

    return string(inet_ntoa(address));
}


map<string, TcpConnection> getTcpConnections()
{
    map<string, TcpConnection> connections;

    DWORD size = 0;

    DWORD result = GetExtendedTcpTable(
        nullptr,
        &size,
        FALSE,
        AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0
    );

    if (result != ERROR_INSUFFICIENT_BUFFER)
    {
        return connections;
    }

    auto* table =
        reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(
            new BYTE[size]
        );

    result = GetExtendedTcpTable(
        table,
        &size,
        FALSE,
        AF_INET,
        TCP_TABLE_OWNER_PID_ALL,
        0
    );

    if (result != NO_ERROR)
    {
        delete[] reinterpret_cast<BYTE*>(table);
        return connections;
    }


    for (DWORD i = 0;
         i < table->dwNumEntries;
         i++)
    {
        MIB_TCPROW_OWNER_PID& row =
            table->table[i];


        // Ignore LISTEN sockets.
        if (row.dwState == MIB_TCP_STATE_LISTEN)
        {
            continue;
        }


        // Only monitor useful connection states.
        if (row.dwState != MIB_TCP_STATE_ESTAB &&
            row.dwState != MIB_TCP_STATE_SYN_SENT &&
            row.dwState != MIB_TCP_STATE_SYN_RCVD)
        {
            continue;
        }


        TcpConnection connection;

        connection.pid = row.dwOwningPid;
        connection.localAddr = row.dwLocalAddr;
        connection.localPort = row.dwLocalPort;
        connection.remoteAddr = row.dwRemoteAddr;
        connection.remotePort = row.dwRemotePort;
        connection.state = row.dwState;


        string key =
            to_string(connection.pid) + ":" +
            to_string(connection.localAddr) + ":" +
            to_string(connection.localPort) + ":" +
            to_string(connection.remoteAddr) + ":" +
            to_string(connection.remotePort);


        connections[key] = connection;
    }


    delete[] reinterpret_cast<BYTE*>(table);

    return connections;
}

string getProcessNameFromPath(const string& path)
{
    size_t position =
        path.find_last_of("\\/");

    if (position == string::npos)
        return path;

    return path.substr(position + 1);
}

void printConnection(
    const TcpConnection& connection
)
{

    string processPath = getProcessPath(connection.pid);
    string processName = getProcessNameFromPath(processPath);
    if (!processNameMatches(processName)) return;
    string sha256 = "NOT_AVAILABLE";
    if (processPath != "ACCESS_DENIED" &&
        processPath != "UNKNOWN")
    {
        sha256 =
            calculateSHA256(processPath);
    }

    cout << "[NEW NETWORK CONNECTION]\n";

    cout << "    PID        : "
         << connection.pid
         << "\n";

    cout << "    Process    : "
         << processName
         << "\n";

    cout << "    Path       : "
         << processPath
         << "\n";

    cout << "    SHA-256    : "
         << sha256
         << "\n";

    cout << "    Local      : "
         << ipToString(connection.localAddr)
         << ":"
         << ntohs(
                static_cast<u_short>(
                    connection.localPort
                )
            )
         << "\n";

    cout << "    Remote     : "
         << ipToString(connection.remoteAddr)
         << ":"
         << ntohs(
                static_cast<u_short>(
                    connection.remotePort
                )
            )
         << "\n";

    cout << "    State      : "
         << tcpStateToString(
                connection.state
            )
         << "\n\n";
          Event event;

        event.timestamp = getTimestamp();
        event.eventType = "NETWORK_CONNECTION";

        event.pid = connection.pid;
        event.parentPid = 0;

        event.name = processName;
        event.path = processPath;

        event.size = 0;
        event.sha256 = sha256;

        event.localIP =
            ipToString(connection.localAddr);

        event.localPort =
            ntohs(
                static_cast<u_short>(
                    connection.localPort
                )
            );

        event.remoteIP =
            ipToString(connection.remoteAddr);

        event.remotePort =
            ntohs(
                static_cast<u_short>(
                    connection.remotePort
                )
            );

        event.state =
            tcpStateToString(connection.state);

        logEvent(event);
}



void startNetworkMonitor()
{
    cout << "[*] Network monitor started\n";

    map<string, TcpConnection> previousConnections =
        getTcpConnections();


    while (true)
    {
        this_thread::sleep_for(
            chrono::seconds(2)
        );


        map<string, TcpConnection> currentConnections =
            getTcpConnections();


        // Detect NEW connections.
        for (const auto& entry : currentConnections)
        {
            const string& key = entry.first;

            const TcpConnection& connection =
                entry.second;


            if (previousConnections.find(key)
                == previousConnections.end())
            {
                printConnection(connection);
            }
        }


        // Replace old snapshot.
        previousConnections =
            currentConnections;
    }
}