#include <stdio.h>
#include <stdlib.h>
#include "logentry.h"
LogEntry* readLogs(const char *fn,int *tlogs);
int main(){
    int tl=0;
    LogEntry *logs=readLogs("input.txt",&tl);
    if
    (logs==NULL){
        printf("Failed to read logs.\n");
        return 1;
    }
    printf("\nTotal Logs read: %d\n",tl);
    printf("----------------------------------------------------\n");
    for(int i=0;i<tl;i++)
        printf("%s  %s  %s  %s\n",logs[i].timestamp,logs[i].username,logs[i].ip,logs[i].status);
    free(logs);
    return 0;
}