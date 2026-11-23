#include "target_file_etw.h"
#include "target_process.h"
#include "process_filter.h"

#include <windows.h>
#include <initguid.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tlhelp32.h>
#include <string>
#include <initguid.h>


using namespace std;

set<DWORD> getTargetPIDs()
{
    set<DWORD> pids;

    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,
        0
    );

    if (snapshot == INVALID_HANDLE_VALUE)
        return pids;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            // Convert the process name from wide string to std::string.
            wstring wideName(entry.szExeFile);

            string processName(
                wideName.begin(),
                wideName.end()
            );

            if (processNameMatches(processName))
            {
                pids.insert(entry.th32ProcessID);
            }

        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    return pids;
}

bool isTargetPID(DWORD pid)
{
    if (getTargetProcessName().empty())
        return true;

    set<DWORD> pids = getTargetPIDs();

    return pids.find(pid) != pids.end();
}
