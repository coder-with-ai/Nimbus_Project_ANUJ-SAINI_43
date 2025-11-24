#ifndef REPORTS_H
#define REPORTS_H

#include "logentry.h"

void reportByUser(LogEntry *logs, int logCount);
void reportByIP(LogEntry *logs, int logCount);

#endif
