#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>

#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <chrono>
#include <ctime>
#include <winspool.h>

#include "file_monitor.h"
#include "hash.h"
#include "logger.h"
#include "utils.h"
#include "registry_monitor.h"
#include "network_monitor.h"
#include "process_filter.h"
#include "target_process.h"
#include "target_file_etw.h"


using namespace std;

struct ProcessInfo
{
    DWORD pid;
    DWORD parentPid;
    string name;
    string path;
    string sha256;
};


string getProcessPath(DWORD pid) // Geting Process Path
{
    string path;

    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        pid
    );

    if (hProcess == NULL)
    {
        return "ACCESS DENIED";
    }

    char buffer[MAX_PATH];
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameA(
            hProcess,
            0,
            buffer,
            &size))
    {
        path = string(buffer, size);
    }
    else
    {
        path = "UNKNOWN";
    }

    CloseHandle(hProcess);

    return path;
}

map<DWORD, ProcessInfo> getProcesses()
{
    map<DWORD, ProcessInfo> processes;

    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,
        0
    );

    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return processes;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe))
    {
        do
        {
            ProcessInfo info;

            info.pid = pe.th32ProcessID;
            info.parentPid = pe.th32ParentProcessID;
            info.name = pe.szExeFile;
            info.path = getProcessPath(info.pid);

            if (info.path != "ACCESS DENIED" && info.path != "UNKNOWN")
              {
                info.sha256 = calculateSHA256(info.path);
              }
            else
             {
              info.sha256 = "NOT_AVAILABLE";
             }
            processes[info.pid] = info;

        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);

    return processes;
}


void printHelp(const char* program)
{
    std::cout
        << "\nMini Windows Sandbox\n\n"
        << "Usage:\n"
        << "  " << program << " [options]\n\n"
        << "Options:\n"
        << "  -h, --help              Show help\n"
        << "  -p, --process <name>    Select target process\n\n"
        << "Examples:\n"
        << "  " << program << " --help\n"
        << "  " << program << " --process curl.exe\n"
        << "  " << program << " -p notepad.exe\n"
        << "  " << program << "\n\n";
}


int main(int argc, char* argv[])
{
    cout << "====================================\n";
    cout << "     Mini Malware Behavior Monitor\n";
    cout << "====================================\n\n";

    std::string targetProcess;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h")
        {
            printHelp(argv[0]);
            return 0;
        }
        else if (arg == "--process" || arg == "-p")
        {
            if (i + 1 >= argc)
            {
                std::cerr << "[!] Missing process name.\n";
                printHelp(argv[0]);
                return 1;
            }

            targetProcess = argv[++i];

            if (targetProcess.empty() ||
                targetProcess[0] == '-')
            {
                std::cerr << "[!] Invalid process name.\n";
                printHelp(argv[0]);
                return 1;
            }
        }
        else
        {
            std::cerr << "[!] Unknown argument: "
                      << arg << "\n";

            printHelp(argv[0]);
            return 1;
        }
    }

    setTargetProcessName(targetProcess);

    if (targetProcess.empty())
    {

        cout << "[*] Starting process monitor...\n";
        cout << "[*] Press Ctrl+C to stop.\n\n";
        std::cout << "[*] Monitoring: ALL PROCESSES\n\n";

    }
    else
    {
        cout << "[*] Starting process monitor...\n";
        cout << "[*] Press Ctrl+C to stop.\n\n";
        std::cout << "[*] Monitoring target: "

                  << getTargetProcessName() << "\n";
    }
    if (!targetProcess.empty())
{
    set<DWORD> targetPIDs = getTargetPIDs();

    cout << "[*] Matching process instances:\n";

    for (DWORD pid : targetPIDs)
    {
        cout << "    PID: " << pid << "\n";
    }
}

    if(getTargetProcessName().empty()){


    thread fileThread( startFileMonitor, "C:\\" );

    fileThread.detach();

    thread registryThread(startRegistryMonitor,"Software\\MiniSandbox");

    thread registryThread2( startRegistryMonitor,"Software\\Microsoft\\Windows\\CurrentVersion\\Run");

    thread registryThread3(startRegistryMonitor,"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" );

    registryThread.detach();
    registryThread2.detach();
    registryThread3.detach();

    }

    else{
    thread targetFileThread(startTargetFileETW);
    targetFileThread.detach();

    cout << "[*] Registry monitoring remains disabled in target mode "
            "until process attribution is implemented.\n";
    }
    thread networkThread(startNetworkMonitor);
    networkThread.detach();


    // Initial process list
    map<DWORD, ProcessInfo> oldProcesses = getProcesses();

    while (true)
    {
        // Get current processes
        map<DWORD, ProcessInfo> currentProcesses = getProcesses();

        // --------------------------------
        // Detect NEW processes
        // --------------------------------

        for (auto const& [pid, process] : currentProcesses)
        {
            if (oldProcesses.find(pid) == oldProcesses.end() && processNameMatches(process.name))
            {
                cout << "[+] PROCESS CREATED\n";
                cout << "    PID        : " << process.pid << "\n";
                cout << "    Parent PID : " << process.parentPid << "\n";
                cout << "    Name       : " << process.name << "\n";
                cout << "    Path       : " << getProcessPath(process.pid)<< "\n";
                cout << "    SHA-256    : " << process.sha256 << "\n";
                cout << "\n";

                Event event;

                event.timestamp = getTimestamp();

                event.eventType = "PROCESS_CREATED";

                event.pid = process.pid;

                event.parentPid = process.parentPid;

                event.name = process.name;

                event.path = process.path;

                event.size = 0;

                event.sha256 = process.sha256;

                logEvent(event);
            }
        }

        // --------------------------------
        // Detect TERMINATED processes
        // --------------------------------

        for (auto const& [pid, process] : oldProcesses)
        {
            if (currentProcesses.find(pid) == currentProcesses.end() && processNameMatches(process.name))
            {
                cout << "[-] PROCESS TERMINATED\n";
                cout << "    PID        : " << process.pid << "\n";
                cout << "    Parent PID : " << process.parentPid << "\n";
                cout << "    Name       : " << process.name << "\n";
                cout << "    Path       : " <<process.path << " \n" ; 
                cout << "    SHA-256    : " << process.sha256 << "\n";
                cout << "\n";

                Event event;

                event.timestamp = getTimestamp();

                event.eventType = "PROCESS_TERMINATED";

                event.pid = process.pid;

                event.parentPid = process.parentPid;

                event.name = process.name;

                event.path = process.path;

                event.size = 0;

                event.sha256 = process.sha256;

                logEvent(event);
            }
        }

        // Current state becomes old state
        oldProcesses = currentProcesses;

        // Check every 500 ms
        this_thread::sleep_for(
            chrono::milliseconds(500)
        );
    }

    return 0;
}