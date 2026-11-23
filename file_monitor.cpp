#include "file_monitor.h"
#include "hash.h"
#include "logger.h"
#include "utils.h"

#include <windows.h>

#include <iostream>
#include <string>
#include <map>
#include <chrono>
#include <thread>

using namespace std;
unsigned long long getFileSize(const string& path)
{
    WIN32_FILE_ATTRIBUTE_DATA data;

    if (!GetFileAttributesExA(
            path.c_str(),
            GetFileExInfoStandard,
            &data))
    {
        return 0;
    }

    ULARGE_INTEGER size;

    size.HighPart = data.nFileSizeHigh;
    size.LowPart = data.nFileSizeLow;

    return size.QuadPart;
}

struct FileEventState
{
    string action;
    chrono::steady_clock::time_point lastEvent;
};

void startFileMonitor(const string& directory)
{
    HANDLE hDirectory = CreateFileA(
        directory.c_str(),

        FILE_LIST_DIRECTORY,

        FILE_SHARE_READ |
        FILE_SHARE_WRITE |
        FILE_SHARE_DELETE,

        NULL,

        OPEN_EXISTING,

        FILE_FLAG_BACKUP_SEMANTICS,

        NULL
    );

    if (hDirectory == INVALID_HANDLE_VALUE)
    {
        cout << "[!] Could not open directory: "
             << directory << "\n";

        return;
    }

    cout << "[*] File monitor started: "
         << directory << "\n";

    BYTE buffer[64 * 1024];

    DWORD bytesReturned;

    map<string, FileEventState> recentEvents;

    const auto debounceTime =
        chrono::milliseconds(500);

    while (true)
    {
        BOOL result = ReadDirectoryChangesW(
            hDirectory,

            buffer,

            sizeof(buffer),

            TRUE,

            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_ATTRIBUTES |
            FILE_NOTIFY_CHANGE_SIZE |
            FILE_NOTIFY_CHANGE_LAST_WRITE,

            &bytesReturned,

            NULL,

            NULL
        );

        if (!result)
        {
            cout << "[!] ReadDirectoryChangesW failed\n";
            break;
        }

        DWORD offset = 0;

        while (offset < bytesReturned)
        {
            FILE_NOTIFY_INFORMATION* info =
                reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                    buffer + offset
                );

            string action;

            switch (info->Action)
            {
                case FILE_ACTION_ADDED:
                    action = "CREATED";
                    break;

                case FILE_ACTION_REMOVED:
                    action = "DELETED";
                    break;

                case FILE_ACTION_MODIFIED:
                    action = "MODIFIED";
                    break;

                case FILE_ACTION_RENAMED_OLD_NAME:
                    action = "RENAMED_FROM";
                    break;

                case FILE_ACTION_RENAMED_NEW_NAME:
                    action = "RENAMED_TO";
                    break;

                default:
                    action = "UNKNOWN";
                    break;
            }

            // Convert Windows wide string to normal string
            int length = WideCharToMultiByte(
                CP_UTF8,
                0,
                info->FileName,
                info->FileNameLength / sizeof(WCHAR),
                NULL,
                0,
                NULL,
                NULL
            );

            string fileName(length, '\0');

            WideCharToMultiByte(
                CP_UTF8,
                0,
                info->FileName,
                info->FileNameLength / sizeof(WCHAR),
                &fileName[0],
                length,
                NULL,
                NULL
            );

           string fullPath = directory + "\\" + fileName;
           auto now =chrono::steady_clock::now();

            auto existing =
                recentEvents.find(fullPath);

            if (existing != recentEvents.end())
            {
                auto elapsed =
                    chrono::duration_cast<
                        chrono::milliseconds
                    >(
                        now - existing->second.lastEvent
                    );

                if (elapsed < debounceTime &&
                    existing->second.action == action)
                {
                    existing->second.lastEvent = now;

                    if (info->NextEntryOffset == 0)
                        break;

                    offset += info->NextEntryOffset;

                    continue;
                }
            }

            recentEvents[fullPath] =
            {
                action,
                now
            };

            cout << "[FILE " << action << "]\n";

            cout << "    Path : "
                 << fullPath
                 << "\n";

             unsigned long long size = 0;

            string sha256 = "NOT_AVAILABLE";


            if (action == "CREATED" ||
                action == "MODIFIED")
            {
                size = getFileSize(fullPath);
                if (size == 0) {
                        this_thread::sleep_for(
                            chrono::milliseconds(100) );

                        size = getFileSize(fullPath);
                    }

                sha256 =
                    calculateSHA256(fullPath);

                cout << "    Size : "
                     << size
                     << " bytes\n";

                cout << "    SHA-256 : "
                     << sha256
                     << "\n";
            }


                cout << "\n";
                // ----------------------------------------
                // Create unified event
                // ----------------------------------------

                Event event;

                event.timestamp = getTimestamp();

                event.eventType =
                    "FILE_" + action;

                event.pid = 0;

                event.parentPid = 0;

                event.name = fileName;

                event.path = fullPath;

                event.size = size;

                event.sha256 = sha256;


                // Send to logger

                logEvent(event);



            if (info->NextEntryOffset == 0)
                break;

            offset += info->NextEntryOffset;
        }
    }

    CloseHandle(hDirectory);
}