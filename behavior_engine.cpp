
#include "behavior_engine.h"

#include <iostream>

using namespace std;

void analyzeEvent(const Event& event)
{
    cout << "[BEHAVIOR ENGINE] Event received: "
         << event.eventType
         << " | PID: "
         << event.pid
         << "\n";
}
