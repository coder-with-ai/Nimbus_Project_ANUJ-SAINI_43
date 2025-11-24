#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>          // For abs()
#include "logentry.h"      // Contains LogEntry structure
#include "suspicious.h"    // Function declaration

#define TIME_WINDOW 60     // Seconds for brute-force detection

void detectSuspicious(LogEntry *logs, int logCount) {
    printf("\n=== Suspicious Activity Detected ===\n");

    for (int i = 0; i < logCount; i++) {
        if (strcmp(logs[i].status, "FAILED") == 0) {

            int attempts = 1;

            for (int j = i + 1; j < logCount; j++) {
                if (strcmp(logs[i].username, logs[j].username) == 0 &&
                    strcmp(logs[j].status, "FAILED") == 0 &&
                    abs(logs[j].seconds - logs[i].seconds) <= TIME_WINDOW)
                {
                    attempts++;
                }
            }

            if (attempts >= 3) {
                printf("WARNING: User '%s' has %d failed logins in %d seconds!\n",
                       logs[i].username, attempts, TIME_WINDOW);
            }
        }
    }
}
