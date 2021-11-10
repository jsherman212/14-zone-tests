#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include "xnuspy_ctl.h"

void (*hookme_hook)(void *);

long SYS_xnuspy_ctl = 0;
uint64_t hookme_addr = 0;

void *(*kalloc_external)(vm_size_t sz);
uint64_t kernel_slide;
void (*kfree_ext)(void *kheap, void *addr, vm_size_t sz);
void (*kprintf)(const char *fmt, ...);
void *(*_memset)(void *s, int c, size_t n);
int (*_snprintf)(char *str, size_t size, const char *fmt, ...);
void *(*unified_kalloc)(size_t sz);
void (*unified_kfree)(void *ptr);

static bool offsets_init(void){
    int ret;
#define GET(a, b) \
    do { \
        ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, a, (void *)(b), 0); \
        if(ret){ \
            printf("%s: failed getting %s\n", __func__, #a); \
            return false; \
        } \
    } while (0) \

    GET(HOOKME, &hookme_addr);
    GET(KERNEL_SLIDE, &kernel_slide);
    GET(KALLOC_EXTERNAL, &kalloc_external);
    GET(KFREE_EXT, &kfree_ext);
    GET(KPRINTF, &kprintf);
    GET(MEMSET, &_memset);
    GET(SNPRINTF, &_snprintf);
    GET(UNIFIED_KALLOC, &unified_kalloc);
    GET(UNIFIED_KFREE, &unified_kfree);

    hookme_addr -= kernel_slide;

    return true;
}

static bool ztest(size_t allocsz){
    int res = syscall(SYS_xnuspy_ctl, XNUSPY_CALL_HOOKME,
            (void *)allocsz, NULL, NULL);

    if(res){
        printf("%s: calling hookme failed: %s\n", __func__,
                strerror(errno));
        return false;
    }

    return true;
}

int main(int argc, char **argv){
    if(argc < 2){
        printf("Need element size\n");
        return 1;
    }

    char *p = NULL;
    int elemsz = strtol(argv[1], &p, 0);

    if(*p){
        printf("Invalid element size '%s'\n", argv[1]);
        return 1;
    }

    size_t oldlen = sizeof(long);
    int res = sysctlbyname("kern.xnuspy_ctl_callnum", &SYS_xnuspy_ctl,
            &oldlen, NULL, 0);

    if(res == -1){
        printf("sysctlbyname with kern.xnuspy_ctl_callnum failed: %s\n",
                strerror(errno));
        return 1;
    }

    res = syscall(SYS_xnuspy_ctl, XNUSPY_CHECK_IF_PATCHED, 0, 0, 0);

    if(res != 999){
        printf("xnuspy_ctl isn't present?\n");
        return 1;
    }

    if(!offsets_init()){
        printf("Failed to get offsets\n");
        return 1;
    }

    res = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, hookme_addr,
            &hookme_hook, NULL);

    if(res){
        printf("Failed to hook hookme: %s\n", strerror(errno));
        return 1;
    }

    ztest(elemsz);

    return 0;
}
