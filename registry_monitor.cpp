#include "heder/registry_monitor.h"
#include "heder/logger.h"
#include "heder/utils.h"

#include <windows.h>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>

using namespace std;


// Store information about one registry value
struct RegistryValue
{
    DWORD type;
    vector<BYTE> data;
};


// Convert registry type to readable name
string getRegistryTypeName(DWORD type)
{
    switch (type)
    {
        case REG_SZ:
            return "REG_SZ";

        case REG_EXPAND_SZ:
            return "REG_EXPAND_SZ";

        case REG_DWORD:
            return "REG_DWORD";

        case REG_QWORD:
            return "REG_QWORD";

        case REG_BINARY:
            return "REG_BINARY";

        case REG_MULTI_SZ:
            return "REG_MULTI_SZ";

        default:
            return "UNKNOWN";
    }
}


// Convert registry data to readable string
string registryDataToString(const RegistryValue& value)
{
    if (value.type == REG_SZ ||
        value.type == REG_EXPAND_SZ)
    {
        if (value.data.empty())
            return "";

        return string(
            reinterpret_cast<const char*>(value.data.data())
        );
    }


    if (value.type == REG_DWORD)
    {
        if (value.data.size() < sizeof(DWORD))
            return "INVALID_DWORD";

        DWORD number;

        memcpy(
            &number,
            value.data.data(),
            sizeof(DWORD)
        );

        return to_string(number);
    }


    if (value.type == REG_QWORD)
    {
        if (value.data.size() < sizeof(ULONGLONG))
            return "INVALID_QWORD";

        ULONGLONG number;

        memcpy(
            &number,
            value.data.data(),
            sizeof(ULONGLONG)
        );

        return to_string(number);
    }


    // Binary / unknown data
    stringstream ss;

    for (BYTE byte : value.data)
    {
        ss << hex
           << setw(2)
           << setfill('0')
           << static_cast<int>(byte);
    }

    return ss.str();
}


// Read all values from a registry key
map<string, RegistryValue> readRegistryValues(HKEY hKey)
{
    map<string, RegistryValue> values;

    DWORD index = 0;

    while (true)
    {
        char valueName[16384];
        BYTE data[65536];

        DWORD valueNameSize = sizeof(valueName);
        DWORD dataSize = sizeof(data);
        DWORD type = 0;

        LONG result = RegEnumValueA(
            hKey,
            index,
            valueName,
            &valueNameSize,
            NULL,
            &type,
            data,
            &dataSize
        );

        if (result == ERROR_NO_MORE_ITEMS)
            break;

        if (result == ERROR_SUCCESS)
        {
            RegistryValue value;

            value.type = type;

            value.data.assign(
                data,
                data + dataSize
            );

            values[string(valueName, valueNameSize)] = value;
        }

        index++;
    }

    return values;
}
bool isPersistenceKey(const string& keyPath)
{
    if (keyPath ==
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run")
    {
        return true;
    }

    if (keyPath ==
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce")
    {
        return true;
    }

    return false;
}
void checkPersistence(
    const string& keyPath,
    const string& valueName,
    const RegistryValue& value
)
{
    if (!isPersistenceKey(keyPath))
        return;

    cout << "[!] SUSPICIOUS REGISTRY PERSISTENCE\n";
    cout << "    Key        : HKCU\\" << keyPath << "\n";
    cout << "    Value Name : " << valueName << "\n";
    cout << "    Type       : "
         << getRegistryTypeName(value.type) << "\n";
    cout << "    Data       : "
         << registryDataToString(value) << "\n\n";
}


// Compare two registry snapshots
void compareRegistryValues(
    const map<string, RegistryValue>& oldValues,
    const map<string, RegistryValue>& newValues,
    const string& keyPath
)
{
    // Check for new or modified values
    for (const auto& entry : newValues)
    {
        const string& valueName = entry.first;
        const RegistryValue& newValue = entry.second;

        auto old = oldValues.find(valueName);

        // New value
        if (old == oldValues.end())
        {
            cout << "[REGISTRY VALUE SET]\n";
            cout << "    Key        : HKCU\\" << keyPath << "\n";
            cout << "    Value Name : " << valueName << "\n";
            cout << "    Type       : "
                 << getRegistryTypeName(newValue.type) << "\n";
            cout << "    Data       : "
                 << registryDataToString(newValue)
                 << "\n\n";

            Event event;

            event.timestamp = getTimestamp();
            event.eventType = "REGISTRY_VALUE_SET";
            event.pid = 0;
            event.parentPid = 0;
            event.name = valueName;
            event.path = "HKCU\\" + keyPath;
            event.size = newValue.data.size();
            event.sha256 =
            registryDataToString(newValue);

            logEvent(event);
            checkPersistence(keyPath, valueName, newValue );

            continue;
        }


        // Existing value - check whether it changed
        const RegistryValue& oldValue = old->second;

        if (oldValue.type != newValue.type ||
            oldValue.data != newValue.data)
        {
            cout << "[REGISTRY VALUE CHANGED]\n";
            cout << "    Key        : HKCU\\" << keyPath << "\n";
            cout << "    Value Name : " << valueName << "\n";
            cout << "    Type       : "
                 << getRegistryTypeName(newValue.type) << "\n";
            cout << "    Data       : "
                 << registryDataToString(newValue)
                 << "\n\n";

            Event event;

            event.timestamp = getTimestamp();
            event.eventType = "REGISTRY_VALUE_CHANGED";
            event.pid = 0;
            event.parentPid = 0;
            event.name = valueName;
            event.path = "HKCU\\" + keyPath;
            event.size = newValue.data.size();
            event.sha256 =
            registryDataToString(newValue);

            logEvent(event);
            checkPersistence(keyPath, valueName, newValue );
        }
    }


    // Check for deleted values
    for (const auto& entry : oldValues)
    {
        const string& valueName = entry.first;

        if (newValues.find(valueName) == newValues.end())
        {
            cout << "[REGISTRY VALUE DELETED]\n";
            cout << "    Key        : HKCU\\" << keyPath << "\n";
            cout << "    Value Name : " << valueName << "\n\n";

            Event event;

            event.timestamp = getTimestamp();
            event.eventType = "REGISTRY_VALUE_DELETED";
            event.pid = 0;
            event.parentPid = 0;
            event.name = valueName;
            event.path = "HKCU\\" + keyPath;
            event.size = 0;
            event.sha256 = "NOT_APPLICABLE";

            logEvent(event);
        }
    }
}


void startRegistryMonitor(const string& keyPath)
{
    HKEY hKey;

    LONG result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        keyPath.c_str(),
        0,
        KEY_READ | KEY_NOTIFY,
        &hKey
    );

    if (result != ERROR_SUCCESS)
    {
        cout << "[!] Could not open registry key\n";
        cout << "    HKCU\\" << keyPath << "\n";
        return;
    }


    cout << "[*] Registry monitor started\n";
    cout << "    HKCU\\" << keyPath << "\n";


    // Take initial snapshot
    map<string, RegistryValue> previousValues =
        readRegistryValues(hKey);


    while (true)
    {
        result = RegNotifyChangeKeyValue(
            hKey,
            TRUE,
            REG_NOTIFY_CHANGE_NAME |
            REG_NOTIFY_CHANGE_LAST_SET,
            NULL,
            FALSE
        );


        if (result != ERROR_SUCCESS)
        {
            cout << "[!] RegNotifyChangeKeyValue failed\n";
            break;
        }


        // Registry changed.
        // Take a new snapshot.
        map<string, RegistryValue> currentValues =
            readRegistryValues(hKey);


        // Compare old and new snapshots
        compareRegistryValues(
            previousValues,
            currentValues,
            keyPath
        );


        // New snapshot becomes the old snapshot
        previousValues = currentValues;
    }


    RegCloseKey(hKey);
}