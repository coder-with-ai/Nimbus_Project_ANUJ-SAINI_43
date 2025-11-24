//contain user ip and reports only

#include <stdio.h>
#include <string.h>
#include "reports.h"

void reportByUser(LogEntry *logs, int logCount) {
    printf("\n=== Login Summary By User ===\n");

    for (int i = 0; i < logCount; i++) {
        int success = 0, failed = 0;

        for (int j = 0; j < logCount; j++) {
            if (strcmp(logs[i].username, logs[j].username) == 0) {
                if (strcmp(logs[j].status, "SUCCESS") == 0)
                    success++;
                else
                    failed++;
            }
        }

        printf("User: %-10s Success: %d Failed: %d\n",
               logs[i].username, success, failed);
    }
}

void reportByIP(LogEntry *logs, int logCount) {
    printf("\n=== Login Summary By IP Address ===\n");

    for (int i = 0; i < logCount; i++) {
        int success = 0, failed = 0;

        for (int j = 0; j < logCount; j++) {
            if (strcmp(logs[i].ip, logs[j].ip) == 0) {
                if (strcmp(logs[j].status, "SUCCESS") == 0)
                    success++;
                else
                    failed++;
            }
        }

        printf("IP: %-15s Success: %d Failed: %d\n",
               logs[i].ip, success, failed);
    }
}
