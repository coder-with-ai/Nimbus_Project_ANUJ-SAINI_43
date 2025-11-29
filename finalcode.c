#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LEN 200
#define TIME_WINDOW 60

typedef struct {
    char timestamp[30];
    char username[50];
    char ip[20];
    char status[10];
    int seconds;
} LogEntry;

// Convert HH:MM:SS → seconds
int convertToSecond(char *timeStr) {
    int h, m, s;
    sscanf(timeStr, "%d:%d:%d", &h, &m, &s);
    return h * 3600 + m * 60 + s;
}

// Check if string is unique in 2D array
int isUnique(char arr[][50], int size, const char *value) {
    for (int i = 0; i < size; i++)
        if (strcmp(arr[i], value) == 0)
            return 0;
    return 1;
}

// Detect suspicious login attempts
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
                printf("User: %-10s | Failed Attempts: %d | Time Window: %d sec\n",
                       logs[i].username, count, TIME_WINDOW);
                break;
            }
        }
    }
}

// Summary by user
void reportByUser(LogEntry *logs, int n) {
    printf("\n=== Login Summary by User ===\n");
    printf("+------------+----------+---------+\n");
    printf("| Username   | Success  | Failed  |\n");
    printf("+------------+----------+---------+\n");

    char uniqueUsers[100][50];
    int uCount = 0;

    for (int i = 0; i < n; i++) {
        if (isUnique(uniqueUsers, uCount, logs[i].username)) {
            strcpy(uniqueUsers[uCount++], logs[i].username);

            int success = 0, failed = 0;

            for (int j = 0; j < n; j++) {
                if (strcmp(logs[i].username, logs[j].username) == 0) {
                    if (strcmp(logs[j].status, "SUCCESS") == 0)
                        success++;
                    else
                        failed++;
                }
            }

            printf("| %-10s | %-8d | %-7d |\n",
                   logs[i].username, success, failed);
        }
    }

    printf("+------------+----------+---------+\n");
}

// Summary by IP
void reportByIP(LogEntry *logs, int n) {
    printf("\n=== Login Summary by IP ===\n");
    printf("+---------------+----------+---------+\n");
    printf("| IP Address    | Success  | Failed  |\n");
    printf("+---------------+----------+---------+\n");

    char uniqueIPs[100][20];
    int ipCount = 0;

    for (int i = 0; i < n; i++) {
        if (strcmp(logs[i].ip, "") != 0 && isUnique((char (*)[50])uniqueIPs, ipCount, logs[i].ip)) {

            strcpy(uniqueIPs[ipCount++], logs[i].ip);

            int success = 0, failed = 0;

            for (int j = 0; j < n; j++) {
                if (strcmp(logs[i].ip, logs[j].ip) == 0) {
                    if (strcmp(logs[j].status, "SUCCESS") == 0)
                        success++;
                    else
                        failed++;
                }
            }

            printf("| %-13s | %-8d | %-7d |\n",
                   logs[i].ip, success, failed);
        }
    }

    printf("+---------------+----------+---------+\n");
}

int main() {
    FILE *fp = fopen("logs.txt", "r");
    if (!fp) {
        printf("Error opening log file.\n");
        return 1;
    }

    char line[MAX_LEN];
    int count = 0;

    while (fgets(line, sizeof(line), fp))
        count++;

    rewind(fp);

    LogEntry *logs = malloc(count * sizeof(LogEntry));
    if (!logs) return 1;

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
        logs[index].seconds = convertToSecond(time);

        index++;
    }

    fclose(fp);

    detectSuspicious(logs, count);
    reportByUser(logs, count);
    reportByIP(logs, count);

    free(logs);
    return 0;
}

