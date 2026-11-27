#include "heder/utils.h"

#include <ctime>

using namespace std;

string getTimestamp()
{
    time_t now = time(nullptr);

    tm localTime;

    localtime_s(
        &localTime,
        &now
    );

    char buffer[32];

    strftime(
        buffer,
        sizeof(buffer),
        "%Y-%m-%d %H:%M:%S",
        &localTime
    );

    return string(buffer);
}