#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LEN 200
#define TIME_WINDOW 60  // seconds

// Structure for storing log entry
typedef struct {
    char timestamp[30];
    char username[50];
    char ip[20];
    char status[10];
    int seconds; // converted timestamp (for detection)
} LogEntry;

// Convert HH:MM:SS → seconds
int convertToSeconds(char *timeStr) {
    int h, m, s;
    sscanf(timeStr, "%d:%d:%d", &h, &m, &s);
    return h * 3600 + m * 60 + s;
}

// Detect suspicious failed login attempts
void detectSuspicious(LogEntry *logs, int n) {
    printf("\n=== Suspicious Activity Detected ===\n");

    for (int i = 0; i < n; i++) {
        if (strcmp(logs[i].status, "FAILED") == 0) {
            int count = 1;

            for (int j = i + 1; j < n; j++) {
                if (strcmp(logs[i].username, logs[j].username) == 0 &&
                    strcmp(logs[j].status, "FAILED") == 0 &&
                    abs(logs[j].seconds - logs[i].seconds) <= TIME_WINDOW) {

                    count++;
                }
            }

            if (count >= 3) {
                printf("User %s has %d failed attempts within %d seconds\n",
                       logs[i].username, count, TIME_WINDOW);
            }
        }
    }
}

// Summary by user
void reportByUser(LogEntry *logs, int n) {
    printf("\n=== Login Summary by User ===\n");

    for (int i = 0; i < n; i++) {
        int success = 0, failed = 0;

        for (int j = 0; j < n; j++) {
            if (strcmp(logs[i].username, logs[j].username) == 0) {
                if (strcmp(logs[j].status, "SUCCESS") == 0)
                    success++;
                else
                    failed++;
            }
        }

        printf("User: %s | Success: %d | Failed: %d\n",
               logs[i].username, success, failed);
    }
}

// Summary by IP
void reportByIP(LogEntry *logs, int n) {
    printf("\n=== Login Summary by IP ===\n");

    for (int i = 0; i < n; i++) {
        int success = 0, failed = 0;

        for (int j = 0; j < n; j++) {
            if (strcmp(logs[i].ip, logs[j].ip) == 0) {
                if (strcmp(logs[j].status, "SUCCESS") == 0)
                    success++;
                else
                    failed++;
            }
        }

        printf("IP: %s | Success: %d | Failed: %d\n",
               logs[i].ip, success, failed);
    }
}

int main() {
    FILE *fp = fopen("logs.txt", "r");
    if (!fp) {
        printf("Error opening log file.\n");
        return 1;
    }

    char line[MAX_LEN];
    int count = 0;

    // Step 1: Count lines
    while (fgets(line, sizeof(line), fp))
        count++;

    rewind(fp);

    // Step 2: Allocate memory
    LogEntry *logs = (LogEntry *)malloc(count * sizeof(LogEntry));
    if (!logs) {
        printf("Memory allocation failed.\n");
        return 1;
    }

    // Step 3: Read and parse logs
    int index = 0;
    while (fgets(line, sizeof(line), fp)) {
        char date[15], time[15];

        sscanf(line, "%s %s %s %s %s",
               date,
               time,
               logs[index].username,
               logs[index].ip,
               logs[index].status);

        sprintf(logs[index].timestamp, "%s %s", date, time);
        logs[index].seconds = convertToSeconds(time);

        index++;
    }

    fclose(fp);

    // Step 4: Analysis and Reports
    detectSuspicious(logs, count);
    reportByUser(logs, count);
    reportByIP(logs, count);

    // Step 5: Free memory
    free(logs);
    return 0;
}
