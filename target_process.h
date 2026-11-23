
#ifndef TARGET_PROCESS_H
#define TARGET_PROCESS_H

#include <windows.h>
#include <set>

std::set<DWORD> getTargetPIDs();
bool isTargetPID(DWORD pid);

#endif
