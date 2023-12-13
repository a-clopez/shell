#include "jobs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define EXIT_EXECVP_FAILURE 255

struct SEN {
    const char *nombre;
    int senal;
};

static struct SEN sigstrnum[]={
        {"HUP", SIGHUP},
        {"INT", SIGINT},
        {"QUIT", SIGQUIT},
        {"ILL", SIGILL},
        {"TRAP", SIGTRAP},
        {"ABRT", SIGABRT},
        {"IOT", SIGIOT},
        {"BUS", SIGBUS},
        {"FPE", SIGFPE},
        {"KILL", SIGKILL},
        {"USR1", SIGUSR1},
        {"SEGV", SIGSEGV},
        {"USR2", SIGUSR2},
        {"PIPE", SIGPIPE},
        {"ALRM", SIGALRM},
        {"TERM", SIGTERM},
        {"CHLD", SIGCHLD},
        {"CONT", SIGCONT},
        {"STOP", SIGSTOP},
        {"TSTP", SIGTSTP},
        {"TTIN", SIGTTIN},
        {"TTOU", SIGTTOU},
        {"URG", SIGURG},
        {"XCPU", SIGXCPU},
        {"XFSZ", SIGXFSZ},
        {"VTALRM", SIGVTALRM},
        {"PROF", SIGPROF},
        {"WINCH", SIGWINCH},
        {"IO", SIGIO},
        {"SYS", SIGSYS},
#ifdef SIGPOLL
        {"POLL", SIGPOLL},
#endif
#ifdef SIGPWR
        {"PWR", SIGPWR},
#endif
#ifdef SIGEMT
        {"EMT", SIGEMT},
#endif
#ifdef SIGINFO
        {"INFO", SIGINFO},
#endif
#ifdef SIGSTKFLT
        {"STKFLT", SIGSTKFLT},
#endif
#ifdef SIGCLD
        {"CLD", SIGCLD},
#endif
#ifdef SIGLOST
        {"LOST", SIGLOST},
#endif
#ifdef SIGCANCEL
        {"CANCEL", SIGCANCEL},
#endif
#ifdef SIGTHAW
        {"THAW", SIGTHAW},
#endif
#ifdef SIGFREEZE
        {"FREEZE", SIGFREEZE},
#endif
#ifdef SIGLWP
        {"LWP", SIGLWP},
#endif
#ifdef SIGWAITING
        {"WAITING", SIGWAITING},
#endif
        {NULL,-1},
};


int ValorSenal(char * sen)
{
    int i;
    for (i=0; sigstrnum[i].nombre!=NULL; i++)
        if (!strcmp(sen, sigstrnum[i].nombre))
            return sigstrnum[i].senal;
    return -1;
}


const char *NombreSenal(int sen)
{
    int i;
    for (i = 0; sigstrnum[i].nombre != NULL; i++)
        if (sen == sigstrnum[i].senal)
            return sigstrnum[i].nombre;
    return "SIGUNKNOWN";
}

struct Node *createNode(pid_t pid, uid_t uid, const char *username, const char *process, const char *waiting) {
    struct Node *newNode = (struct Node *)malloc(sizeof(struct Node));
    if (!newNode) {
        perror("Memory allocation error");
        exit(EXIT_FAILURE);
    }

    newNode->data = (struct job *)malloc(sizeof(struct job));
    if (!newNode->data) {
        perror("Memory allocation error");
        free(newNode);
        exit(EXIT_FAILURE);
    }

    newNode->data->pid = pid;
    newNode->data->uid = uid;
    strncpy(newNode->data->username, username, MAX_USERNAME); 
    newNode->data->time = time(NULL);
    newNode->data->out = 0;
    strncpy(newNode->data->state, "ACTIVE", MAX_LINE);
    strncpy(newNode->data->process, process, MAX_LINE);
    strncpy(newNode->data->waiting, waiting, MAX_USERNAME);
    newNode->next = NULL;

    return newNode;
}

void insertJob(struct LinkedList *list, pid_t pid, uid_t uid, const char *username, const char *process, const char *waiting) {
    struct Node *newNode = createNode(pid, uid, username, process, waiting);

    if (list->head == NULL) {
        list->head = newNode;
    } else {
        struct Node *temp = list->head;
        while (temp->next != NULL) {
            temp = temp->next;
        }
        temp->next = newNode;
    }
}

void freeList(struct LinkedList *list) {
    struct Node *current = list->head;
    struct Node *next;

    while (current != NULL) {
        next = current->next;
        free(current->data);
        free(current);
        current = next;
    }

    list->head = NULL;
}

void listJobs(struct LinkedList *list) {
    int which = PRIO_PROCESS;
    printf("List of jobs:\n");
    struct Node *current = list->head;
    while (current != NULL) {
        char datetime[100];
        strftime(datetime, 100, "%d/%m/%Y, %H:%M:%S", localtime(&current->data->time));

        printf("%7d%10s    p=%d %25s%12s(%03d) %10s%6s\n", 
        	current->data->pid, 
        	current->data->username, 
        	getpriority(which, current->data->pid),
        	datetime, 
        	current->data->state,
        	current->data->out,
        	current->data->process,
        	current->data->waiting
        );
        current = current->next;
    }
}

void listJobDetails(struct LinkedList *list, pid_t pid) {
    int which = PRIO_PROCESS;
    struct Node *current = list->head;
    while (current != NULL) {
        if (current->data->pid == pid) {
            char datetime[100];
            strftime(datetime, 100, "%d/%m/%Y, %H:%M:%S", localtime(&current->data->time));

            printf("%7d%10s    p=%d %25s%12s(%03d) %10s%6s\n", 
                current->data->pid, 
                current->data->username, 
                getpriority(which, current->data->pid), 
                datetime, 
                current->data->state,
                current->data->out,
                current->data->process,
                current->data->waiting
            );
            return;
        }
        current = current->next;
    }

    printf("Error: Process with PID %d not found\n", pid);
}


void updateJobStatus(struct LinkedList *list) {
    struct Node *current = list->head;
    while (current != NULL) {
        pid_t pid = current->data->pid;
        int status;

        if (waitpid(pid, &status, WNOHANG | WUNTRACED | WCONTINUED) > 0) {
            if (WIFEXITED(status)) {
                if (WEXITSTATUS(status) == EXIT_EXECVP_FAILURE) {
                    strcpy(current->data->state, "TERMINADO");
                    current->data->out = 255;
                } else {
                    strcpy(current->data->state, "TERMINADO");
                    current->data->out = WEXITSTATUS(status);
                }
            } else if (WIFSIGNALED(status)) {
                strcpy(current->data->state, "SENALADO");
                current->data->out = WTERMSIG(status);
            } else if (WIFSTOPPED(status)) {
                strcpy(current->data->state, "STOPPED");
                current->data->out = WSTOPSIG(status);
            } else if (WIFCONTINUED(status)) {
                strcpy(current->data->state, "ACTIVO");
            }
        }
        current = current->next;
    }
}

void removeJob(struct LinkedList *list, pid_t pid) {
    struct Node *current = list->head;
    struct Node *prev = NULL;

    while (current != NULL && current->data->pid != pid) {
        prev = current;
        current = current->next;
    }

    if (current == NULL) {
        return;
    }

    if (prev == NULL) {
        list->head = current->next;
    } else {
        prev->next = current->next;
    }

    free(current->data);
    free(current);
}

