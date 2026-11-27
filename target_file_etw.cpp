
#include "heder/target_file_etw.h"
#include "heder/target_process.h"
#include "heder/process_filter.h"

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include <iostream>
#include <vector>

using namespace std;

static TRACEHANDLE sessionHandle = 0;

static VOID WINAPI fileEventCallback(
    PEVENT_RECORD record
)
{
    if (record == nullptr)
        return;

    DWORD pid = record->EventHeader.ProcessId;

    // Only accept events from the selected process.
    if (!isTargetPID(pid))
        return;

    cout << "[TARGET FILE I/O]\n";
    cout << "    PID       : " << pid << "\n";
    cout << "    Event ID  : "
         << record->EventHeader.EventDescriptor.Id << "\n";
    cout << "    Opcode    : "
         << static_cast<unsigned int>(
                record->EventHeader.EventDescriptor.Opcode
            ) << "\n\n";
}

void startTargetFileETW()
{
    if (getTargetProcessName().empty())
    {
        cout << "[!] Select a process before starting target ETW.\n";
        return;
    }

    const ULONG propertiesSize =
        sizeof(EVENT_TRACE_PROPERTIES) +
        sizeof(KERNEL_LOGGER_NAMEW);

    vector<BYTE> buffer(propertiesSize, 0);

    auto* properties =
        reinterpret_cast<EVENT_TRACE_PROPERTIES*>(
            buffer.data()
        );

    properties->Wnode.BufferSize = propertiesSize;
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.Guid = SystemTraceControlGuid;
    properties->Wnode.ClientContext = 1;

    properties->LogFileMode =
        EVENT_TRACE_REAL_TIME_MODE |
        EVENT_TRACE_SYSTEM_LOGGER_MODE;

    properties->EnableFlags =
        EVENT_TRACE_FLAG_PROCESS |
        EVENT_TRACE_FLAG_FILE_IO |
        EVENT_TRACE_FLAG_FILE_IO_INIT;

    properties->LoggerNameOffset =
        sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(
        &sessionHandle,
        KERNEL_LOGGER_NAMEW,
        properties
    );

    if (status != ERROR_SUCCESS)
    {
        cout << "[!] StartTraceW failed. Error: "
             << status << "\n";

        cout << "[!] Run as Administrator and check whether "
                "the kernel logger is already active.\n";
        return;
    }

    EVENT_TRACE_LOGFILEW logfile{};

    logfile.LoggerName =
        const_cast<LPWSTR>(KERNEL_LOGGER_NAMEW);

    logfile.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME |
        PROCESS_TRACE_MODE_EVENT_RECORD;

    logfile.EventRecordCallback = fileEventCallback;

    TRACEHANDLE traceHandle = OpenTraceW(&logfile);

    if (traceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        cout << "[!] OpenTraceW failed. Error: "
             << GetLastError() << "\n";

        ControlTraceW(
            sessionHandle,
            KERNEL_LOGGER_NAMEW,
            properties,
            EVENT_TRACE_CONTROL_STOP
        );

        return;
    }

    cout << "[*] Target file-I/O ETW started for: "
         << getTargetProcessName() << "\n";

    ULONG processStatus = ProcessTrace(
        &traceHandle,
        1,
        nullptr,
        nullptr
    );

    if (processStatus != ERROR_SUCCESS)
    {
        cout << "[!] ProcessTrace returned: "
             << processStatus << "\n";
    }

    CloseTrace(traceHandle);

    ControlTraceW(
        sessionHandle,
        KERNEL_LOGGER_NAMEW,
        properties,
        EVENT_TRACE_CONTROL_STOP
    );
}
