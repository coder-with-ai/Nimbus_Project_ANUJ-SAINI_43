#ifndef LOGENTRY_H
#define LOGENTRY_H

typedef struct {
    char timestamp[30];
    char username[50];
    char ip[20];
    char status[10];
    int seconds;
} LogEntry;

int convertToSeconds(char *timeStr);
LogEntry* readLogs(const char *fn, int *tlogs);
#endif
