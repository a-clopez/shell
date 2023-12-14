#ifndef JOBS_H
#define JOBS_H

#include <sys/types.h>
#include <time.h>
#include <sys/resource.h>

#define MAX_LINE 256
#define MAX_USERNAME 50

struct job {
    pid_t pid;
    uid_t uid;
    char username[MAX_USERNAME]; 
    time_t time;
    int out; 
    char state[MAX_LINE];
    char process[MAX_LINE];
    int exit_status;
    char waiting[MAX_USERNAME];
};

struct Node {
    struct job *data;
    struct Node *next;
};

struct LinkedList {
    struct Node *head;
};

struct context {
    struct LinkedList jobs;
};

struct Node *createNode(pid_t pid, uid_t uid, const char *username, const char *process, const char *waiting);
void insertJob(struct LinkedList *list, pid_t pid, uid_t uid, const char *username, const char *process, const char *waiting);
void freeList(struct LinkedList *list);
void listJobs(struct LinkedList *list);
void updateJobStatus(struct LinkedList *list);
void removeJob(struct LinkedList *list, pid_t pid);

#endif

