#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "logentry.h"
#define maxlim 200
LogEntry* readLogs(const char *fn,int *tlogs){
    FILE *fp=fopen(fn, "r");
    if (!fp){
        printf("ERROR! Can't open file: '%s'\n",fn);
        *tlogs=0;
        return NULL;
    }
    LogEntry *arr = NULL;
    char line[maxlim];
    int c=0;
    while(fgets(line,sizeof(line),fp)){
        LogEntry *temp=realloc(arr,(c + 1)*sizeof(LogEntry));
        if(!temp){
            printf("Memory allocation failed\n");
            free(arr);
            fclose(fp);
            *tlogs = 0;
            return NULL;
        }
        arr=temp;
        line[strcspn(line,"\r\n")] = 0;
        char date[15],time[15];
        int sc=sscanf(line,"%14s %14s %49s %19s %9s",date,time,arr[c].username,arr[c].ip,arr[c].status);
if(sc==5){            
snprintf(arr[c].timestamp,sizeof(arr[c].timestamp),"%s %s",date,time);
c++;
        }
    }
    fclose(fp);
    *tlogs=c;
    return arr;
}
