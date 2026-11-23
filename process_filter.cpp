
#include "process_filter.h"

#include <algorithm>
#include <cctype>

using namespace std;

static string targetProcessName;

static string normalizeProcessName(string name)
{
    // Allow a process name or a full executable path.
    size_t pos = name.find_last_of("\\/");

    if (pos != string::npos)
        name = name.substr(pos + 1);

    transform(
        name.begin(),
        name.end(),
        name.begin(),
        [](unsigned char c)
        {
            return static_cast<char>(tolower(c));
        }
    );

    return name;
}

void setTargetProcessName(const string& name)
{
    targetProcessName = normalizeProcessName(name);
}

string getTargetProcessName()
{
    return targetProcessName;
}

bool processNameMatches(const string& name)
{
    if (targetProcessName.empty())
        return true;

    return normalizeProcessName(name) == targetProcessName;
}
