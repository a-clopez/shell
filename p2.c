//student 1: Calin Lupascu calin.lupascu@udc.es
//student 2: Antón Calviño a.clopez@udc.es
//student 3: Pablo Seoane pablo.seoane.vazquez@udc.es

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <ctype.h>
#include <fcntl.h>
#include <pwd.h>  
#include <grp.h>  
#include <dirent.h>
#include "dynamic_list.c"
#include <errno.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>


#define MAX_HISTORY_SIZE 100
#define MAX_OPEN_FILES 10
#define MAX_FILENAME_LENGTH 256
#define TAMANO 2048


#define name1 "Calin Lupascu"
#define name2 "Pablo Seoane"
#define name3 "Antón Calviño"

#define login1 "calin.lupascu@udc.es"
#define login2 "pablo.seoane.vazquez@udc.es"
#define login3 "a.clopez@udc.es"

tList mem;
char ** env;

struct OpenFile {
    int descriptor;
    int mode;
    char filename[MAX_FILENAME_LENGTH];
    int original_descriptor;
};


struct OpenFile open_files[MAX_OPEN_FILES];
int main();


void print_prompt() {
    printf("--> ");
}

char LetraTF (mode_t m)
{
     switch (m&S_IFMT) { /*and bit a bit con los bits de formato,0170000 */
        case S_IFSOCK: return 's'; /*socket */
        case S_IFLNK: return 'l'; /*symbolic link*/
        case S_IFREG: return '-'; /* fichero normal*/
        case S_IFBLK: return 'b'; /*block device*/
        case S_IFDIR: return 'd'; /*directorio */ 
        case S_IFCHR: return 'c'; /*char device*/
        case S_IFIFO: return 'p'; /*pipe*/
        default: return '?'; /*desconocido, no deberia aparecer*/
     }
}

char *ConvierteModo(mode_t m, char *permisos) {
    strcpy(permisos, "---------- "); // Initialize the string with dashes

    permisos[0] = LetraTF(m); // Set the file type character (e.g., '-', 'd', 'l')

    // Check and set owner (user) permissions
    if (m & S_IRUSR) permisos[1] = 'r';
    if (m & S_IWUSR) permisos[2] = 'w';
    if (m & S_IXUSR) permisos[3] = 'x';

    // Check and set group permissions
    if (m & S_IRGRP) permisos[4] = 'r';
    if (m & S_IWGRP) permisos[5] = 'w';
    if (m & S_IXGRP) permisos[6] = 'x';

    // Check and set other (rest) permissions
    if (m & S_IROTH) permisos[7] = 'r';
    if (m & S_IWOTH) permisos[8] = 'w';
    if (m & S_IXOTH) permisos[9] = 'x';

    // Check and set special permissions
    if (m & S_ISUID) permisos[3] = 's'; // Setuid
    if (m & S_ISGID) permisos[6] = 's'; // Setgid
    if (m & S_ISVTX) permisos[9] = 't'; // Sticky bit

    return permisos;
}

int TrocearCadena(char *cadena, char *trozos[]) {
    int i = 1;
    if ((trozos[0] = strtok(cadena, " \n\t")) == NULL)
        return 0;
    while ((trozos[i] = strtok(NULL, " \n\t")) != NULL)
        i++;
    return i;
}

bool isNum(const char *str) {
    if (str == NULL || *str == '\0') return false;
    while (*str >= '0' && *str <= '9') {
        str++;
    }
    return *str == '\0';
}

void Cmd_pid(char *args[], int num_args) {
    if (num_args == 1) {
        pid_t shell_pid = getpid();
        printf("Shell PID: %d\n", shell_pid);
    } else if (num_args == 2 && strcmp(args[1], "-p") == 0) {
        pid_t parent_pid = getppid();
        printf("Parent PID: %d\n", parent_pid);
    }
}

void Cmd_authors(char *args[], int num_args) {
    if (num_args == 1 || (num_args == 2 && (strcmp(args[1], "-n") == 0 || strcmp(args[1], "-l") == 0))) {
        printf("Authors:\n");
        if (num_args == 1 || strcmp(args[1], "-n") == 0) {
            printf("Name1: %s\n", name1);
            printf("Name2: %s\n", name2);
            printf("Name3: %s\n",name3);
        }
        if (num_args == 1 || strcmp(args[1], "-l") == 0) {
            printf("Login1: %s\n", login1);
            printf("Login2: %s\n", login2);
            printf("Login3: %s\n", login3);
        }
    }
}

void Cmd_chdir(char *args[], int num_args) {
    if (num_args == 1) {
        char cwd[1024];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            printf("Current dir: %s\n", cwd);
        } else {
            perror("getcwd");
        }
    } else if (num_args == 2) {
        if (chdir(args[1]) == 0) {
            printf("Changed dir to: %s\n", args[1]);
        } else {
            perror("chdir");
        }
    }
}

void Cmd_date(char *args[], int num_args) {
    if (num_args == 1) {
        time_t t;
        struct tm *tm_info;

        time(&t);
        tm_info = localtime(&t);

        char buffer[80];
        strftime(buffer, 80, "%d/%m/%Y", tm_info);

        printf("Current date: %s\n", buffer);
    }
}

void Cmd_time(char *args[], int num_args) {
    if (num_args == 1) {
        time_t t;
        struct tm *tm_info;

        time(&t);
        tm_info = localtime(&t);

        char buffer[80];
        strftime(buffer, 80, "%H:%M:%S", tm_info);

        printf("Current time: %s\n", buffer);
    }
}

void Cmd_infosys() {
    struct utsname system_info;
    if (uname(&system_info) == 0) {
        printf("System Information:\n");
        printf("  OS Name: %s\n", system_info.sysname);
        printf("  Node Name: %s\n", system_info.nodename);
        printf("  Release: %s\n", system_info.release);
        printf("  Version: %s\n", system_info.version);
        printf("  Machine: %s\n", system_info.machine);
    } else {
        perror("uname");
    }
}

void Cmd_hist(char *args[], int num_args, char *history[], int *history_count) {
    if (num_args == 1) {
        for (int i = 0; i < *history_count; i++) {
            printf("%d: %s", i + 1, history[i]);
        }
    } else if (num_args == 2 && strcmp(args[1], "-c") == 0) {
        for (int i = 0; i < *history_count; i++) {
            free(history[i]);
        }
        *history_count = 0;
        printf("Command history cleared.\n");
    } else if (num_args == 2 && args[1][0] == '-' && isdigit(args[1][1])) {
        if (*history_count == 0) {
            printf("Command history is empty.\n");
        } else {
            int N = atoi(args[1] + 1);
            if (N <= 0) {
                printf("Invalid argument. Please provide a positive integer.\n");
                return;
            }
            if (N > *history_count) {
                printf("Not enough commands in history. Displaying all %d previous commands:\n", *history_count);
                N = *history_count;
            }
            for (int i = 0; i < N; i++) {
                printf("%d: %s", i + 1, history[i]);
            }
        }
    } else {
        printf("Invalid arguments for hist command.\n");
    }
}

void Cmd_listopen() {
    printf("Open files:\n");
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (open_files[i].descriptor != -1) {
            printf("Descriptor: %d", open_files[i].descriptor);
            
            if (open_files[i].original_descriptor != -1) {
                printf(" (Dup from Descriptor: %d)", open_files[i].original_descriptor);
            } else {
                printf(", Mode: %d, Filename: %s", open_files[i].mode, open_files[i].filename);
            }
            
            printf("\n");
        }
    }
}


void Cmd_open(char *tr[]) {
    int i, df, mode = 0;

    if (tr[1] == NULL) {

        return;
    }

    for (i = 2; tr[i] != NULL; i++) {
        if (!strcmp(tr[i], "cr")) mode |= O_CREAT;
        else if (!strcmp(tr[i], "ex")) mode |= O_EXCL;
        else if (!strcmp(tr[i], "ro")) mode |= O_RDONLY;
        else if (!strcmp(tr[i], "wo")) mode |= O_WRONLY;
        else if (!strcmp(tr[i], "rw")) mode |= O_RDWR;
        else if (!strcmp(tr[i], "ap")) mode |= O_APPEND;
        else if (!strcmp(tr[i], "tr")) mode |= O_TRUNC;
        else break;
    }

    if ((df = open(tr[1], mode, 0777)) == -1) {
        perror("Impossible to open the file");
    } else {
        int added = 0;
        for (i = 0; i < MAX_OPEN_FILES; i++) {
            if (open_files[i].descriptor == -1) {
                open_files[i].descriptor = df;
                open_files[i].mode = mode;
                strncpy(open_files[i].filename, tr[1], sizeof(open_files[i].filename) - 1);
                open_files[i].filename[sizeof(open_files[i].filename) - 1] = '\0';
                added = 1;
                printf("Added entry to the list of open files.\n");
                break;
            }
        }
        if (!added) {
            printf("Maximum number of open files reached.\n");
            close(df);
        }
    }
}

void Cmd_close(char *tr[]) {
    int df;

    if (tr[1] == NULL || (df = atoi(tr[1])) < 0) {
        return;
    }

    int found = 0;
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (open_files[i].descriptor == df) {
            close(df);
            open_files[i].descriptor = -1;
            open_files[i].mode = 0;
            open_files[i].filename[0] = '\0';
            found = 1;
            printf("Closed descriptor %d and removed from the list of open files.\n", df);
            break;
        }
    }

    if (!found) {
        printf("Descriptor %d not found in the list of open files.\n", df);
    }
}

void Cmd_dup(char *tr[]) {
    int df, new_descriptor;

    if (tr[1] == NULL || (df = atoi(tr[1])) < 0) {
        printf("Invalid file descriptor.\n");
        return;
    }

    new_descriptor = dup(df);

    if (new_descriptor == -1) {
        perror("dup");
        printf("Failed to duplicate file descriptor %d.\n", df);
    } else {
        int added = 0;
        for (int i = 0; i < MAX_OPEN_FILES; i++) {
            if (open_files[i].descriptor == -1) {
                open_files[i].descriptor = new_descriptor;
                open_files[i].mode = open_files[df].mode;
                strncpy(open_files[i].filename, open_files[df].filename, sizeof(open_files[i].filename) - 1);
                open_files[i].filename[sizeof(open_files[i].filename) - 1] = '\0';
                open_files[i].original_descriptor = df; 
                added = 1;
                printf("Duplicated descriptor %d as descriptor %d.\n", df, new_descriptor);
                break;
            }
        }
        if (!added) {
            printf("Maximum number of open files reached.\n");
            close(new_descriptor);
        }
    }
}


void Cmd_command(char *args[], int num_args, char *history[], int *history_count) {
    if (num_args == 2) {
        int N = atoi(args[1]) - 1;  
        if (N >= 0 && N < *history_count) {
            char *command_to_repeat = history[N];
            printf("Repeating command %d: %s", N + 1, command_to_repeat);

            char *tr[100];
            int num_command_args = TrocearCadena(command_to_repeat, tr);

            if (num_command_args > 0) {
                if (!strcmp(tr[0], "quit") || !strcmp(tr[0], "exit") || !strcmp(tr[0], "bye")) {
                    printf("Exited the Shell.\n");
                    exit(0); 
                }
                else if (!strcmp(tr[0], "pid")) {
                    Cmd_pid(tr, num_command_args);
                } else if (!strcmp(tr[0], "authors")) {
                    Cmd_authors(tr, num_command_args);
                } else if (!strcmp(tr[0], "chdir")) {
                    Cmd_chdir(tr, num_command_args);
                } else if (!strcmp(tr[0], "date")) {
                    Cmd_date(tr, num_command_args);
                } else if (!strcmp(tr[0], "time")) {
                    Cmd_time(tr, num_command_args);
                } else if (!strcmp(tr[0], "infosys")) {
                    Cmd_infosys();
                } else if (!strcmp(tr[0], "hist")) {
                    Cmd_hist(tr, num_command_args, history, history_count);
                } else if (!strcmp(tr[0], "listopen")) {
                    Cmd_listopen();
                } else if (!strcmp(tr[0], "open")) {
                    Cmd_open(tr);
                } else if (!strcmp(tr[0], "close")) {
                    Cmd_close(tr);
                } else if (!strcmp(tr[0], "dup")) {
                    Cmd_dup(tr);
                } else {
                    printf("Invalid number");
                }
            }
        } else {
            printf("Invalid command number.\n");
        }
    } else {
        printf("Invalid arguments for command command.\n");
    }
}

void Cmd_create(char *args[], int num_args) {
    if (num_args == 2) {
        char *name = args[1];
        struct stat st;

        if (stat(name, &st) == 0) {
            printf("'%s' already exists\n", name);
        } else if (mkdir(name, 0777) == 0) {
            printf("Created directory '%s'\n", name);
        } else {
            perror("mkdir");
        }
        
    } else if (num_args == 3 && strcmp(args[1], "-f") == 0) {
        char *name = args[2];
        struct stat st;

        if (stat(name, &st) == 0) {
            printf("File '%s' already exists\n", name);
        } else {
            FILE *file = fopen(name, "w");
            if (file != NULL) {
                fclose(file);
                printf("Created file '%s'\n", name);
            } else {
                perror("fopen");
            }
        }
    }
}

void Cmd_stat(char *args[], int num_args) {
    struct stat st;
    int long_at = 0;
    int link_at = 0;
    int acc_at = 0;

    for (int i = 1; i < num_args; i++) {
        if (strcmp(args[i], "-long") == 0) {
            long_at = 1;
        } else if (strcmp(args[i], "-link") == 0) {
            link_at = 1;
        } else if (strcmp(args[i], "-acc") == 0) {
            acc_at = 1;
        }
    }

    for (int i = 1; i < num_args; i++) {
        if (args[i][0] == '-') {
            continue;
        }

        if (access(args[i], F_OK) != 0) {
            printf("File %s not found\n", args[i]);
            continue;
        }

        if (lstat(args[i], &st) == 0) {
            char time_buffer[30];
            struct tm *time;

            if (long_at) {
            	time = acc_at ? localtime(&st.st_atim.tv_sec) : localtime(&st.st_mtim.tv_sec);
            } else {
            	time = localtime(&st.st_mtim.tv_sec);
            }

            strftime(time_buffer, 30, "%Y/%m/%d-%H:%M", time);
            char permissions[30]; 

            ConvierteModo(st.st_mode, permissions);
            if (long_at){
	      printf("%5s%3ld ( %7ld)%7s%7s%13s%8ld%13s",
		    time_buffer,  
		    st.st_nlink,
		    (long) st.st_ino,
		    getpwuid(st.st_uid)->pw_name,
		    getgrgid(st.st_gid)->gr_name,
		    permissions,  
		    st.st_size,
		    args[i]);
	    } 
	      else{
	      	  printf("%8ld%13s", st.st_size, args[i]);
	      }
	      
            if (S_ISLNK(st.st_mode) && link_at) {
                char link[2048];
                ssize_t length = readlink(args[i], link, sizeof(link) - 1);
                if (length != -1) {
                    link[length] = '\0';
                    printf(" -> %s", link);
                }
            }
            printf("\n");
        } else {
            perror("lstat");
        }
    }
}

bool exist_directory(const char *path) {
    struct stat st;
    if (lstat(path, &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    return false;
}

bool has_access(const char *path, int permission) {
    return access(path, permission) == 0;
}

void Cmd_list(char *tr[], int num_args) {
    if (num_args > 1) {
        for (int i = 1; i < num_args; i++) {
            const char *name = tr[i];

            bool dir_exists = exist_directory(name);
            bool has_read_permission = has_access(name, R_OK);

            if (dir_exists && has_read_permission) {
                DIR *dir = opendir(name);
                if (dir) {
                    printf("************%s:\n", name);
                    struct dirent *data;
                    while ((data = readdir(dir)) != NULL) {
                        if (strcmp(data->d_name, ".") != 0 && strcmp(data->d_name, "..") != 0) {
                            struct stat st;
                            char path[2048];
                            snprintf(path, 2048, "%s/%s", name, data->d_name);
                            if (lstat(path, &st) == 0) {
                                printf("%6ld %s\n", st.st_size, data->d_name);
                            } else {
                                printf("%s\n", data->d_name);
                            }
                        }
                    }
                    closedir(dir);
                } else {
                    perror("opendir");
                }
            } else if (dir_exists && !has_read_permission) {
                fprintf(stderr, "Permission denied to read directory '%s'\n", name);
            } else {
                fprintf(stderr, "Directory '%s' does not exist\n", name);
            }
        }
    } else {
        fprintf(stderr, "Invalid arguments for list command.\n");
    }
}

void Cmd_delete(char *args[], int num_args) {
    for (int i = 1; i < num_args; i++) {
        if (access(args[i], F_OK) != 0) {
            printf("Item doesnt exist: %s\n", args[i]);
            continue;
        }
	if (has_access(args[i], W_OK)) {
            struct stat st;
            if (lstat(args[i], &st) == 0) {
                if (S_ISDIR(st.st_mode)) {
                    DIR *dir = opendir(args[i]);
                    struct dirent *entry;

                    if (dir == NULL) {
                        perror("opendir");
                        continue;
                    }
                    
                    int counter = 0;
                    while ((entry = readdir(dir)) != NULL) {
                        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
                            counter++;
                            break;
                        }
                    }
                    closedir(dir);

                    if (counter == 0) {
                        if (rmdir(args[i]) == 0) {
                            printf("Deleted directory: %s\n", args[i]);
                        } else {
                            perror("rmdir");
                        }
                    } else {
                        printf("Impossible to delete a not empty directory: %s\n", args[i]);
                    }
                } else if (S_ISREG(st.st_mode)) {
                    if (remove(args[i]) == 0) {
                        printf("Deleted file: %s\n", args[i]);
                    } else {
                        perror("remove");
                    }
                } else {
                    printf("Impossible to delete %s\n", args[i]);
                }
            } else {
                perror("stat");
            }
        } else {
            printf("Permission denied. You dont have permission for: %s\n", args[i]);
        }
    }
}

int recursive_delete(const char *path) {
    DIR *directory = opendir(path);
    size_t length = strlen(path);
    int count = -1;

    if (directory) {
        struct dirent *p;
        count = 0;
        while (!count && (p = readdir(directory))) {
            int count2 = -1;
            if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, "..")) {
                continue;
            }

            size_t len = length + strlen(p->d_name) + 2;
            char *buf = (char *)malloc(len);

            if (buf) {
                struct stat statbuf;
                snprintf(buf, len, "%s/%s", path, p->d_name);

                if (!lstat(buf, &statbuf)) {
                    if (S_ISDIR(statbuf.st_mode)) {
                        count2 = recursive_delete(buf);
                    } else {
                        count2 = remove(buf);
                    }
                }
                free(buf);
            }
            count = count2;
        }
        closedir(directory);
    }
    if (!count) {
        count = rmdir(path);
    }
    return count;
}

void Cmd_deltree(char *tr[], int num_args) {
    for (int i = 1; i < num_args; i++) {
        const char *path = tr[i];

        if (!exist_directory(path)) {
            fprintf(stderr, "The directory '%s' doesnt exist\n", path);
            continue; 
        }

        if (!has_access(path, R_OK | W_OK)) {
            fprintf(stderr, "You dont have permission for '%s'.\n", path);
            continue; 
        }

        if (recursive_delete(path) == 0) {
            printf("Directory '%s' has been deleted\n", path);
        } else {
            fprintf(stderr, "Failed to delete the directory '%s'.\n", path);
        }
    }
}//malloc aux functions

void readList(struct tNode node, char tr[], char size[]){
    char Size[MAX_FILENAME_LENGTH];
    struct tm tm = *localtime(&node.mem.date);
    sprintf(Size, "%d", node.mem.size);
    char funcNode[]={};
    strcpy(funcNode, node.data.text);
    strtok(funcNode, " ");
    if ((!strcmp(funcNode, tr) || !strcmp("all", tr)) && ((!strcmp(size, Size)) || !strcmp("all", size))) {
        printf("%p: size:%d B ", node.mem.address, node.mem.size);
        if (strlen(node.mem.data.text) > 0)
            printf("%s (fd:%d) ", node.mem.data.text, node.mem.key);
        else if (node.mem.key >= 0)
            printf("(key %d) ", node.mem.key);
        printf("%d-%d-%d %d:%d\n", tm.tm_mday,tm.tm_mon+1,tm.tm_year+1900,tm.tm_hour,tm.tm_min);
    }

}
void saveNode(char tr[], void * address, size_t size, char data[], int key, time_t date[]){
    struct tNode memNode;
    strcpy(memNode.data.text, tr);
    memNode.mem.address=address;
    memNode.mem.size=size;
    strcpy(memNode.mem.data.text,data);
    memNode.mem.key=key;
    memNode.mem.date=*date;
    insertItem(memNode,&mem);
}

void printMalloc(){
    if(isEmptyList((mem)))return;
    tPosL pos= first(mem);
    while (pos!=NULL){
        readList(getItem(pos,mem),"malloc","all");
        pos= next(pos,mem);
    }
}
void printMmap(){
    if(isEmptyList((mem)))return;
    tPosL pos= first(mem);
    while (pos!=NULL){
        readList(getItem(pos,mem),"mmap","all");
        pos= next(pos,mem);
    }
}
void printShared(){
    if(isEmptyList((mem)))return;
    tPosL pos= first(mem);
    while (pos!=NULL){
        readList(getItem(pos,mem),"shared","all");
        pos= next(pos,mem);
    }
}
void deleteMalloc(char size[]) {
    tPosL pos = first(mem);
    while (pos != NULL) {
        if (getItem(pos, mem).mem.size == strtol(size, NULL, 10)) {
            //free( getItem(pos, mem).mem.address );
            deleteAtPosition(pos, &mem);
            printf("Malloc in address %p was deallocated\n", pos);
            return;
        }
        pos = next(pos, mem);
    }
}

void deleteMmap(char name[]){
    tPosL pos= first(mem);
    while (pos!=NULL){
        if (!strcmp(name, getItem(pos,mem).mem.data.text)) {
            close(*name);
            deleteAtPosition(pos, &mem);
            printf("Mapped in address %p was deallocated\n", pos);
            return;
        }
        pos= next(pos,mem);
    }
}
void freeShare(char key[]) {
    tPosL pos = first(mem);
    while (pos != NULL) {
        if (getItem(pos, mem).mem.key == strtol(key, NULL, 10)) {
            if (shmdt(getItem(pos, mem).mem.address) == -1)
                printf("Couldn't detach shared memory : %s\n",strerror(errno));
            printf("Shared memory block at %p (key %d) was deallocated\n", getItem(pos,mem).mem.address, getItem(pos, mem).mem.key);
            deleteAtPosition(pos, &mem);
            return;
        }
        pos = next(pos, mem);
    }
}
void * ObtenerMemoriaShmget (key_t clave, size_t tam)
{
    void * p;
    int aux,id,flags=0777;
    struct shmid_ds s;

    if (tam)flags=flags | IPC_CREAT | IPC_EXCL;
    if (clave==IPC_PRIVATE)
    {errno=EINVAL; return NULL;}
    if ((id=shmget(clave, tam, flags))==-1)
        return (NULL);
    if ((p=shmat(id,NULL,0))==(void*) -1){
        aux=errno;
        if (tam)
            shmctl(id,IPC_RMID,NULL);
        errno=aux;
        return (NULL);
    }
    shmctl (id,IPC_STAT,&s);
    return (p);
}

void createShare(char *tr[]){
    key_t k;
    size_t s=0;
    void *pnt;
    time_t date;
    time(&date);
    if (tr[2]==NULL){
        printShared();
        return;
    }
    k=(key_t)strtol(tr[2],NULL,10);
    s=(size_t) strtol(tr[2],NULL,10);
    pnt=ObtenerMemoriaShmget(k,s);
    if (pnt==NULL) printf("Couldn't get memory : %s\n", strerror(errno));
    else{
        printf("Allocated %s bytes (key:%d) at %p\n",tr[2],k,pnt);
        saveNode("shared",pnt,s,"",k,&date);
    }
}
void delKeyShare(char *tr[]){
    key_t k;
    int id;
    char *key = tr[2];
    if (key==NULL || (k=(key_t) strtoul(key,NULL,10))==IPC_PRIVATE){
        printf("Shared -delkey valid key\n");
        return;
    }
    if ((id = shmget(k, 0, 0666)) == -1) {
        printf("Couldn't get shared memory : %s\n",strerror(errno));
        return;
    }
    if (shmctl(id, IPC_RMID, NULL) == -1)
        printf("Couldn't delete shared memory  : %s\n",strerror(errno));
    else
        printf("Key %s removed from the system\n", tr[2]);
}


void Cmd_malloc(char *tr[]){
    void *pointer;
    time_t date;
    size_t tam;
    date=time(NULL);
    struct tm tm= *localtime(&date);
    if (tr[1]==NULL){
        printf("******List of allocated malloc blocks for the process %d\n",getpid());
        printMalloc();
        return;
    }else if (!strcmp(tr[1],"-free")){
        if (tr[2] != NULL){
            deleteMalloc(tr[2]);
        }
    }else{
        tam=strtol(tr[1],NULL,10);
        pointer = malloc (tam);
        if(pointer==NULL){
            printf ("Error, memory wasn't allocated \n");
            return;
        }else {
            printf("Allocated %s bytes at %p\n",tr[1],pointer);
            saveNode("malloc",pointer, tam, "", 0,&date);
        }

    }
}
void * MapFile (char * file, int protection)
{
    int df, map=MAP_PRIVATE,modo=O_RDONLY;
    struct stat s;
    void *p;
    time_t date;
    time(&date);

    if (protection&PROT_WRITE)
        modo=O_RDWR;
    if (stat(file,&s)==-1 || (df=open(file, modo))==-1)
        return NULL;
    if ((p=mmap (NULL,s.st_size, protection,map,df,0))==MAP_FAILED)
        return NULL;
    saveNode("mmap",p,(int) s.st_size, file, df, &date);
    return p;
}


void Cmd_mmap(char *tr[], int num_args){
    char *perm="";
    void *p;
    int protection=0;
    if (tr[1]==NULL){
        printf("******List of allocated mmap blocks for the process %d\n",getpid());
        printMmap();
        return;
    }else if (!strcmp(tr[1],"-free")){
        if( tr[2] != NULL) {
            deleteMmap(tr[2]);
            return;
        }else {printMmap();return;}
    }
    if (tr[2]!=NULL && num_args<4) {
        if (strchr(perm,'r')!=NULL) protection|=PROT_READ;
        if (strchr(perm,'w')!=NULL) protection|=PROT_WRITE;
        if (strchr(perm,'x')!=NULL) protection|=PROT_EXEC;
    }
    if ((p=MapFile(tr[1],protection))==NULL) printf ("Couldn't map file %s\n", tr[1]);
    else printf ("File %s mapped en %p\n", tr[1], p);
}

void Cmd_shared(char *tr[]){
    if(tr[1]==NULL){
        printf("******List of allocated shared blocks for the process %d\n",getpid());
        printShared();
        return;
    }if( tr[2] != NULL) {
            if (!strcmp(tr[1],"-free")) freeShare(tr[2]);
            if (!strcmp(tr[1],"-create")) createShare(tr);
            if (!strcmp(tr[1],"-delkey")) delKeyShare(tr);
    }else {printMmap();return;}
}

ssize_t WriteFile(char* filename, void* address, size_t size, int overwrite) {
    ssize_t n;
    int df, aux, flags;

    if (overwrite) {
        flags = O_CREAT | O_WRONLY | O_TRUNC;
    } else {
        if (access(filename, F_OK) != -1) {
            fprintf(stderr, "Error: File '%s' already exists.\n", filename);
            return -1;
        }
        flags = O_CREAT | O_EXCL | O_WRONLY;
    }

    if ((df = open(filename, flags, 0777)) == -1) {
        perror("Error opening file");
        return -1;
    }

    if ((n = write(df, address, size)) == -1) {
        aux = errno;
        close(df);
        errno = aux;
        perror("Error writing to file");
        return -1;
    }

    close(df);
    return n;
}

void Cmd_write(char *tr[], int num_args){
    if (num_args != 4 && num_args != 5){
        printf("Not enough arguments\n");
        return;
    }

    int overwrite = 0;
    char* filename;
    void* address;
    size_t size;

    if (num_args == 5 && strcmp(tr[1], "-o") == 0){
        overwrite = 1;
        filename = tr[2];
        sscanf(tr[3], "%p", &address);
        size = strtoul(tr[4], NULL, 0);
    } else if (num_args == 4) {
        filename = tr[1];
        sscanf(tr[2], "%p", &address);
        size = strtoul(tr[3], NULL, 0);
    } else {
        printf("Error\n");
        return;
    }

    ssize_t result = WriteFile(filename, address, size, overwrite);
    if (result != -1) {
        printf("Has written %zd bytes in %s from %p\n", result, filename, address);
    }
}

void Recursiva (int n)
{
    char automatico[TAMANO];
    static char estatico[TAMANO];

    printf ("Parametro:%3d(%p) array %p, arr estatico %p\n",n,&n,automatico, estatico);

    if (n > 0)
        Recursiva(n - 1);
}

void Cmd_recurse(char *args[])
{
    if (args[1] != NULL){
        int number = atoi(args[1]);
        Recursiva(number);
    }
}

void Do_MemPmap (void)
{
    pid_t pid;
    char elpid[32];
    char *argv[4]={"pmap",elpid,NULL};

    sprintf (elpid,"%d", (int) getpid());
    if ((pid=fork())==-1){
        perror ("Unable to create process");
        return;
    }
    if (pid==0){
        if (execvp(argv[0],argv)==-1)
            perror("cannot execute pmap (linux, solaris)");

        argv[0]="vmmap"; argv[1]="-interleave"; argv[2]=elpid;argv[3]=NULL;
        if (execvp(argv[0],argv)==-1)
            perror("cannot execute vmmap (Mac-OS)");

        argv[0]="procstat"; argv[1]="vm"; argv[2]=elpid; argv[3]=NULL;
        if (execvp(argv[0],argv)==-1)
            perror("cannot execute procstat (FreeBSD)");

        argv[0]="procmap",argv[1]=elpid;argv[2]=NULL;
        if (execvp(argv[0],argv)==-1)
            perror("cannot execute procmap (OpenBSD)");

        exit(1);
    }
    waitpid(pid,NULL,0);
}

int global1 = 0;
char global2 = 'a';
long global3 = 0;

int globalNI1;
char globalNI2;
long globalNI3;

void Do_MemVars(void){
    int local1;
    char local2;
    long local3;
    static int static1 = 0;
    static char static2 = 'a';
    static long static3 = 1;
    static int staticNI1;
    static char staticNI2;
    static long staticNI3;

    printf("%23s%22p,%22p,%22p\n","Local Variables", &local1, &local2, &local3);
    printf("%23s%22p,%22p,%22p\n","Global Variables", &global1, &global2, &global3);
    printf("%23s%22p,%22p,%22p\n","Global N.I. Variables", &globalNI1, &globalNI2, &globalNI3);
    printf("%23s%22p,%22p,%22p\n","Static Variables", &static1, &static2, &static3);
    printf("%23s%22p,%22p,%22p\n","Static N.I. Variables", &staticNI1, &staticNI2, &staticNI3);
}

void Do_MemFuncs(void){
    printf("%17s%22p,%22p,%22p\n","Program Functions", &Do_MemFuncs, &main, &printf);
    printf("%17s%22p,%22p,%22p\n","Library Functions", &malloc, &free, &exit);
}

void Cmd_mem(char **tr, int num_args) {
    if (num_args == 1) {
        printf("******List of allocated blocks for the process %d\n",getpid());
        printMalloc();
        printMmap();
        printShared();
    } else {
        if (!strcmp(tr[1], "-vars")) {
            Do_MemVars();
        } else if (!strcmp(tr[1], "-funcs")) {
            Do_MemFuncs();
        } else if (!strcmp(tr[1], "-blocks")) {
            printf("******List of allocated blocks for the process %d\n",getpid());
            printMalloc();
            printMmap();
            printShared();
        } else if (!strcmp(tr[1], "-pmap")) {
            Do_MemPmap();
        } else if (!strcmp(tr[1], "-all")) {
            Do_MemVars();
            Do_MemFuncs();
        } else {
            printf("Invalid argument\n");
        }
    }
}

ssize_t ReadFile (char *f, void *p, size_t cont){
    struct stat s;
    ssize_t  n;
    int df,aux;

    if (stat (f,&s)==-1 || (df=open(f,O_RDONLY))==-1)
        return -1;
    if (cont==-1)   /* si pasamos -1 como bytes a leer lo leemos entero*/
        cont=s.st_size;
    if ((n=read(df,p,cont))==-1){
        aux=errno;
        close(df);
        errno=aux;
        return -1;
    }
    close (df);
    return n;
}

void Cmd_read (char *tr[], int num_args)
{
    void *p;
    size_t cont=-1;
    ssize_t n;
    if (tr[1] == NULL || tr[2] == NULL){
        printf ("faltan parametros\n");
        return;
    }
    p=(void *) strtoul(tr[2], NULL, 16);  /*convertimos de cadena a puntero*/
    if (tr[3] != NULL)
        cont=(size_t) atoll(tr[3]);

    if ((n= ReadFile(tr[1], p, cont)) == -1)
        perror ("Imposible leer fichero");
    else
        printf ("Read %lld bytes of %s from %p\n", (long long) n, tr[1], p);
}

void Cmd_memfill (char *tr[],int num_args)//Hecho
{
    if (tr[1]==NULL)
        return;
    void *p;
    p= (void *) strtoul(tr[1], NULL, 16); size_t cont=0; unsigned char byte = 65;

    if (tr[2]!=NULL)
        cont = atoi(tr[2]);

    if (tr[3]!=NULL) {
        byte = strtoul(tr[3], NULL, 10);
        if(tr[3][0]=='\''&&tr[3][2]=='\'')
            byte=tr[3][1];
    }
    unsigned char *arr=(unsigned char *) p;
    size_t i;

    for (i=0; i<cont;i++)
        arr[i]=byte;
    printf("Filling %li bytes of memory with byte %c(%.2X) from address %p\n",cont,byte,byte,p);
}


void Cmd_memdump(char *tr[], int num_args) {
    int i, j, k, len, l_len;
    len = l_len = 25;
    if(tr[1]==NULL)
        return;
    void * add = (void *) strtoul(tr[1], NULL, 16);
    char * txt = (char *) add;

    if (tr[2] != NULL) len =(int) strtol(tr[2], NULL, 10);

    for (i = 0; i < len && txt[i] != '\0'; i += l_len) {
        for (j = i; j < len && j - i < l_len && txt[j+1] != '\0'; j++) {
            if (txt[j] != '\n') printf(" %c ", txt[j]);
            else printf("   ");
        }
        printf("\n");
        for (k = i; k < len  && k - i < l_len  && txt[k+1] != '\0'; k++)
            printf("%.2x ", txt[k]);
        printf("\n");
    }
}
char * getUser(uid_t uid){
    struct passwd *p;
    if ((p= getpwuid(uid))==NULL) return "?????";
    return p->pw_name;
}

uid_t getUid(char *user){
    struct passwd *p;
    if ((p= getpwnam(user))==NULL) return (uid_t) - 1;
    return p->pw_uid;
}

void changeUid (char *login){
    uid_t uid;
    if ((uid= getUid(login))==(uid_t) - 1){
        printf("Login not valid: %s\n", login);
        return;
    }else if (setuid(uid)==-1) printf("Impossible to change credential: %s\n", strerror(errno));
}

void PrintIDs(void){
    uid_t real=getuid();
    uid_t effect=geteuid();
    printf("Real credential: %d, (%s)\n",real, getUser(real));
    printf("Effective credential: %d, (%s)\n",effect, getUser(effect));
}

void Cmd_uid(char *tr[]){
    if (tr[1]==NULL || tr[2]==NULL || !strcmp(tr[1],"-get")) PrintIDs();
    else if (!strcmp(tr[1],"-set")){
        if (!strcmp(tr[2],"-l")) {
            changeUid(tr[3]);
        }
        else if (isNum(tr[2])){
            char* user = getUser(atoi(tr[2]));
            changeUid(user);
        }else printf("Error: choose a valid option (-get|-set -l id)\n");
    }else printf("Error: choose a valid option (-get|-set -l id)\n");
}
int searchVar (char * var, char *e[]){
    int pos=0;
    char aux[FILENAME_MAX];
    strcpy (aux,var);
    strcat (aux,"=");
    while (e[pos]!=NULL)
        if (!strncmp(e[pos],aux,strlen(aux)))
             return (pos);
        else
            pos++;
            errno=ENOENT;
    return(-1);
}
void environment(char **e, char *e_name) {
    for (int i = 0; e[i] != NULL; i++)
        printf ("%p->%s[%d]=(%p) %s\n", &e[i], e_name, i, e[i], e[i]);
}

void showVariable ( char *var){
    int pos;
    char * getEnv = getenv(var);
    if ((pos= searchVar(var,__environ))!=-1) {
        printf("Con arg3 main %s(%p) @%p\n", __environ[pos], __environ[pos], &__environ[pos]);
        printf("Con environ %s(%p) @%p\n", __environ[pos], __environ[pos], &__environ[pos]);
        printf("Con getenv %s(%p)\n", getEnv, &getEnv);
    }
}

void Cmd_showvar(char *tr[]){
    if(tr[1]==NULL) environment(__environ, "main arg3");
    else showVariable(tr[1]);
}

void Cmd_fork (char *tr[])
{
    pid_t pid;

    if ((pid=fork())==0){
		//VaciarListaProcesos(&LP); Depende de la implementación de cada uno
        printf ("ejecutando proceso %d\n", getpid());
    }
    else if (pid!=-1)
        waitpid (pid,NULL,0);
}

void Cmd_execute (char *tr[], int num_args){
	pid_t pid = fork();
	
	if (pid==0){
	execvp(tr[0],tr);
	perror("Error");
	exit(EXIT_FAILURE);
	}else if (pid < 0){
	wait(NULL);
	}else{
	perror("Error");
	exit(EXIT_FAILURE);
	}
}

void Cmd_showenv(char *tr[], int num_args,char *envir[]) {


    if (num_args == 2) {
        if (strcmp(tr[1], "-environ") == 0) {
            environment(__environ,"environ");
            
        } else if (strcmp(tr[1], "-addr") == 0) {
            printf("Address of environ: %p (Stored in %p)\n", &__environ[0],&__environ);
            printf("Address of main arg3: %p (Stored in %p)\n", envir,&envir);
        } else {
            printf("Invalid option. Use -environ or -addr.\n");
        }
    } else {
    	environment(__environ,"main arg3");
        /*printf("Usage: showenv [-environ|-addr]\n");
        printf("-environ: Accesses the environment using environ.\n");
        printf("-addr: Shows the value and location of environ and the 3rd argument of main.\n");*/
    }
}

/* Help code:
*el siguiente codigo se da como ayuda por si se quiere utilizar
NO ES OBLIGATORIO USARLO
y pueden usarse funciones enteras o parte de funciones

Este fichero, ayudaP3.c no está pensado para ser compilado separadamente
, entre otras cosas, no contiene los includes necesarios
y las constantes utilizadas, no están definidas en él

void Cmd_fork (char *tr[])
{
    pid_t pid;

    if ((pid=fork())==0){
		VaciarListaProcesos(&LP); Depende de la implementación de cada uno
        printf ("ejecutando proceso %d\n", getpid());
    }
    else if (pid!=-1)
        waitpid (pid,NULL,0);
}

int BuscarVariable (char * var, char *e[])  /busca una variable en el entorno que se le pasa como parámetro
{
    int pos=0;
    char aux[MAXVAR];

    strcpy (aux,var);
    strcat (aux,"=");

    while (e[pos]!=NULL)
        if (!strncmp(e[pos],aux,strlen(aux)))
            return (pos);
        else
            pos++;
    errno=ENOENT;   /*no hay tal variable
    return(-1);
}


int CambiarVariable(char * var, char * valor, char *e[]) /cambia una variable en el entorno que se le pasa como parámetro
{                                                        /lo hace directamente, no usa putenv
    int pos;
    char *aux;

    if ((pos=BuscarVariable(var,e))==-1)
        return(-1);

    if ((aux=(char *)malloc(strlen(var)+strlen(valor)+2))==NULL)
        return -1;
    strcpy(aux,var);
    strcat(aux,"=");
    strcat(aux,valor);
    e[pos]=aux;
    return (pos);
}


/las siguientes funciones nos permiten obtener el nombre de una senal a partir
del número y viceversa
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
/senales que no hay en todas partes
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
};    /fin array sigstrnum


int ValorSenal(char * sen)  /devuelve el numero de senial a partir del nombre
{
    int i;
    for (i=0; sigstrnum[i].nombre!=NULL; i++)
        if (!strcmp(sen, sigstrnum[i].nombre))
            return sigstrnum[i].senal;
    return -1;
}


char *NombreSenal(int sen)  /devuelve el nombre senal a partir de la senal
{			/ para sitios donde no hay sig2str
    int i;
    for (i=0; sigstrnum[i].nombre!=NULL; i++)
        if (sen==sigstrnum[i].senal)
            return sigstrnum[i].nombre;
    return ("SIGUNKNOWN");
}
*/




void Cmd_help(char *args[], int num_args) {
    if (num_args == 1) {
        printf("Available commands:\n");
        printf("1. pid [-p] : Display the shell or parent PID\n");
        printf("2. authors [-n|-l] : Display author information\n");
        printf("3. chdir [directory] : Change current directory\n");
        printf("4. date : Display the current date\n");
        printf("5. time : Display the current time\n");
        printf("6. infosys : Display system information\n");
        printf("7. hist [-c|-N] : Display command history\n");
        printf("8. listopen : Display open files\n");
        printf("9. open [filename] [mode] : Open a file\n");
        printf("10. close [descriptor] : Close a file\n");
        printf("11. dup [descriptor] : Duplicate a file descriptor\n");
        printf("12. command N : Repeat a command by its history number\n");
        printf("13. create [-f] name: close files or directories\n");
        printf("14. stat [-long][-link][-acc]: gives information on files or directories\n");
        printf("15. list: lists directories contents\n");
        printf("16. delete [item1] [item2]: deletes files and/or empty directories\n");
        printf("17. deltree [dir1] [dir2]: deletes files and/or non empty directories recursively\n");
        printf("18. help [command] : Display command usage\n");
        printf("19. quit/exit/bye : Exit the shell\n");
        printf("20. write : Write cont bytes from address addr to file (-o overwrite)");
        printf("21. mem : Sample shows process memory details");
        printf("22. recurse : Invokes the recursive function n times)");
    } else if (num_args == 2) {
        if (strcmp(args[1], "pid") == 0) {
            printf("Usage: pid [-p]\n");
            printf("  -p : Display the parent PID\n");
        } else if (strcmp(args[1], "authors") == 0) {
            printf("Usage: authors [-n|-l]\n");
            printf("  -n : Display author names\n");
            printf("  -l : Display author login names\n");
        } else if (strcmp(args[1], "chdir") == 0) {
            printf("Usage: chdir [directory]\n");
            printf("  Change the current directory to the specified directory\n");
        } else if (strcmp(args[1], "date") == 0) {
            printf("Usage: date\n");
            printf("  Display the current date\n");
        } else if (strcmp(args[1], "time") == 0) {
            printf("Usage: time\n");
            printf("  Display the current time\n");
        } else if (strcmp(args[1], "infosys") == 0) {
            printf("Usage: infosys\n");
            printf("  Display system information\n");
        } else if (strcmp(args[1], "hist") == 0) {
            printf("Usage: hist [-c|-N]\n");
            printf("  -c : Clear command history\n");
            printf("  -N : Display the last N commands from history\n");
        } else if (strcmp(args[1], "listopen") == 0) {
            printf("Usage: listopen\n");
            printf("  Display open files\n");
        } else if (strcmp(args[1], "open") == 0) {
            printf("Usage: open [filename] [mode]\n");
            printf("  [filename] : Name of the file to open\n");
            printf("  [mode]     : Open mode (cr, ex, ro, wo, rw, ap, tr)\n");
        } else if (strcmp(args[1], "close") == 0) {
            printf("Usage: close [descriptor]\n");
            printf("  [descriptor] : File descriptor to close\n");
        } else if (strcmp(args[1], "dup") == 0) {
            printf("Usage: dup [descriptor]\n");
            printf("  [descriptor] : File descriptor to duplicate\n");
        } else if (strcmp(args[1], "command") == 0) {
            printf("Usage: command N\n");
            printf("  N : History number of the command to repeat\n");
        } else if (strcmp(args[1], "help") == 0) {
            printf("Usage: help [command]\n");
            printf("  Display a list of available commands or provide usage for a specific command\n");
        } else if (strcmp(args[1], "create") == 0) {
            printf("Usage: create [-f] [name]\n");
        } else if (strcmp(args[1], "stat") == 0) {
            printf("Usage: stat [-long][-link][-acc] item1 item2 ...\n");
        } else if (strcmp(args[1], "list") == 0) {
	    printf("Usage: list - lists directories contents\n");
        } else if (strcmp(args[1], "delete") == 0) {
	    printf("Usage: delete [item1] [item2] ...\n");
        } else if (strcmp(args[1], "deltree") == 0) {
            printf("Usage: deltree [dir1] [dir2] ...\n");
        } else if (!strcmp(args[1], "mem")){
            printf("Usage: mem [-blocks|-funcs|-vars|-all|-pmap] .. Sample shows process memory details\n");
            printf("\t\t-blocks: the allocated memory blocks\n");
            printf("\t\t-funcs: the addresses of the functions\n");
            printf("\t\t-vars: the addresses of the variables\n");
            printf("\t\t-all: everything\n");
            printf("\t\t-pmap: show the output of the pmap command (or similar)\n");
        } else if (!strcmp(args[1], "write")){
            printf("Usage: write [-o] file addr cont\n\t Write cont bytes from address addr to file (-o overwrite)\n");
        } else if (!strcmp(args[1], "recurse")){
            printf("Usage: recurse [n]\n\t Invokes the recursive function n times\n");
        } else if (!strcmp(args[1], "malloc")) {
            printf("Usage: allocates (or deallocates) a block malloc memory. Updates the list of memory blocks\n");
            printf("\t\t-free: deallocates the block\n");
        } else if (!strcmp(args[1], "mmap")) {
            printf("Usage: maps (or unmaps) a file in memory. Updates the list of memory blocks\n");
            printf("\t\t-free: deallocates the block");
        } else if (!strcmp(args[1], "shared")) {
            printf("Usage: allocates (or deallocates) a block shared memory. Updates the list of memory blocks identified by a number called key\n");
            printf("\t\t-free: deallocates the block");
            printf("\t\t-delkey: deletes the key");
            printf("\t\t-create: creates a key and allocates a block with it");
        }else if (!strcmp(args[1], "memfill")) {
            printf("memfill addr cont byte \tFills the memory with addr with byte");
        }else if (!strcmp(args[1], "memdump")) {
            printf("memdump addr cont \tDumps in screen the contents (cont bytes) of the position of memory addr");
        }else if (!strcmp(args[1], "read")) {
            printf("read file addr cont \tLee cont bytes desde fich a la direccion addr");
        }
        else {
            printf("Invalid command: %s\n", args[1]);
        }
    } else {
        printf("Invalid arguments for help command.\n");
    }
}


int main(int argc, char * argv[],char *envir[]) {
    char *tr[100];
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        open_files[i].descriptor = -1;
        open_files[i].original_descriptor = -1;
    }
    char *history[MAX_HISTORY_SIZE];
    int history_count = 0;
    createEmptyList(&mem);


    while (1) {
        print_prompt();
        char input[1048];
        fgets(input, sizeof(input), stdin);

        if (history_count < MAX_HISTORY_SIZE) {
            history[history_count++] = strdup(input);
        } else {
            free(history[0]);
            for (int i = 1; i < MAX_HISTORY_SIZE; i++) {
                history[i - 1] = history[i];
            }
            history[MAX_HISTORY_SIZE - 1] = strdup(input);
        }
        int num_args = TrocearCadena(input, tr);

        if (num_args > 0) {
            if (strcmp(tr[0], "quit") == 0 || strcmp(tr[0], "exit") == 0 || strcmp(tr[0], "bye") == 0) {
                printf("Exited the Shell.\n");
                break;
            } else if (!strcmp(tr[0], "pid")) {
                Cmd_pid(tr, num_args);
            } else if (!strcmp(tr[0], "authors")) {
                Cmd_authors(tr, num_args);
            } else if (!strcmp(tr[0], "chdir")) {
                Cmd_chdir(tr, num_args);
            } else if (!strcmp(tr[0], "date")) {
                Cmd_date(tr, num_args);
            } else if (!strcmp(tr[0], "time")) {
                Cmd_time(tr, num_args);
            } else if (!strcmp(tr[0], "infosys")) {
                Cmd_infosys();
            } else if (!strcmp(tr[0], "hist")) {
                Cmd_hist(tr, num_args, history, &history_count);
            } else if (!strcmp(tr[0], "listopen")) {
                Cmd_listopen();
            } else if (!strcmp(tr[0], "open")) {
                Cmd_open(tr);
            } else if (!strcmp(tr[0], "close")) {
                Cmd_close(tr);
            } else if (!strcmp(tr[0], "dup")) {
                Cmd_dup(tr);
            } else if (!strcmp(tr[0], "command")) {
                Cmd_command(tr, num_args, history, &history_count);
            } else if (!strcmp(tr[0], "create")) {
                Cmd_create(tr, num_args);
            } else if (!strcmp(tr[0], "stat")) {
                Cmd_stat(tr, num_args);
            } else if (!strcmp(tr[0], "help")) {
                Cmd_help(tr, num_args);
            } else if (!strcmp(tr[0], "delete")) {
                Cmd_delete(tr, num_args);
            } else if (!strcmp(tr[0], "list")) {
                Cmd_list(tr, num_args);
            } else if (!strcmp(tr[0], "deltree")) {
                Cmd_deltree(tr, num_args);
            } else if (!strcmp(tr[0], "write")) {
                Cmd_write(tr, num_args);
            } else if (!strcmp(tr[0], "malloc")) {
                Cmd_malloc(tr);
            } else if (!strcmp(tr[0], "mmap")) {
                Cmd_mmap(tr, num_args);
            } else if (!strcmp(tr[0], "shared")) {
                Cmd_shared(tr);
            }else if (!strcmp(tr[0], "read")) {
            Cmd_read(tr, num_args);
            } else if (!strcmp(tr[0], "memfill")) {
            Cmd_memfill(tr, num_args);
            } else if (!strcmp(tr[0], "memdump")) {
            Cmd_memdump(tr, num_args);
            } else if (!strcmp(tr[0], "recurse")) {
            Cmd_recurse(tr);
            } else if (!strcmp(tr[0], "mem")) {
            Cmd_mem(tr, num_args);
            } else if (!strcmp(tr[0], "uid")) {
            Cmd_uid(tr);
            } else if (!strcmp(tr[0], "showvar")) {
                Cmd_showvar(tr);
            } else if (!strcmp(tr[0], "showenv")) {
            Cmd_showenv(tr,num_args,envir);
        }
    }
    }
        for (int i = 0; i < history_count; i++) {
            free(history[i]);
    }
    free (mem);


    return 0;
}
