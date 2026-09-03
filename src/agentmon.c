// SPDX-License-Identifier: GPL-2.0
/*
 * agentmon.c — userspace loader for the AgentCell eBPF audit monitor.
 *
 * Loads agentmon.bpf.o, points its cgroup filter at a sandbox cgroup,
 * attaches all probes, and pretty-prints the event stream.
 *
 * Needs root (CAP_BPF + CAP_PERFMON):  sudo ./agentmon --cgroup <path>
 * The path is printed by `sand` when it starts a sandbox.
 */
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "arch/syscalls.h"   /* AC_* syscall table */

static const struct ac_sys ac_syscalls[] = { AC_SYSCALL_TAB };

enum ev_type { EV_EXEC = 1, EV_OPEN = 2, EV_CONNECT = 3, EV_ATTEMPT = 4 };

struct ev {
    __u64 ts, cgid;
    __u32 tgid, tid, type, nr;
    char  comm[16];
    char  data[192];
};

static volatile sig_atomic_t g_stop;

static void on_sigint(int sig) { (void)sig; g_stop = 1; }

static const char *attempt_name(unsigned nr)
{
    for (size_t i = 0; i < sizeof ac_syscalls / sizeof ac_syscalls[0]; i++)
        if ((unsigned)ac_syscalls[i].nr == nr)
            return ac_syscalls[i].name;
    return "?";
}

static int handle_ev(void *ctx, void *data, size_t size)
{
    (void)ctx; (void)size;
    const struct ev *e = data;

    char when[32];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(when, sizeof when, "%H:%M:%S", &tm);

    switch (e->type) {
    case EV_EXEC:
        printf("%s \033[32mEXEC \033[0m %s[%d]  %s\n",
               when, e->comm, e->tgid, e->data);
        break;
    case EV_OPEN:
        printf("%s \033[34mOPEN \033[0m %s[%d]  %s\n",
               when, e->comm, e->tgid, e->data);
        break;
    case EV_CONNECT: {
        /* data = first 16 bytes of sockaddr */
        unsigned short fam;
        memcpy(&fam, e->data, 2);
        if (fam == 2 /* AF_INET */) {
            unsigned short port;
            memcpy(&port, e->data + 2, 2);
            unsigned char ip[4];
            memcpy(ip, e->data + 4, 4);
            printf("%s \033[35mNET  \033[0m %s[%d]  connect %u.%u.%u.%u:%u\n",
                   when, e->comm, e->tgid,
                   ip[0], ip[1], ip[2], ip[3], ntohs(port));
        } else {
            printf("%s \033[35mNET  \033[0m %s[%d]  connect family=%u\n",
                   when, e->comm, e->tgid, fam);
        }
        break;
    }
    case EV_ATTEMPT:
        printf("%s \033[31;1mTRIP \033[0m %s[%d] cgid=%llu blocked syscall: %s (%u)\n",
               when, e->comm, e->tgid, (unsigned long long)e->cgid,
               attempt_name(e->nr), e->nr);
        break;
    default:
        printf("%s ????  %s[%d] type=%u\n", when, e->comm, e->tgid, e->type);
    }
    fflush(stdout);
    return 0;
}

/*
 * --audit mode: seccomp denials are dropped by the kernel BEFORE the
 * sys_enter tracepoints fire, so eBPF probes can't see them. But the
 * sandbox installs its filter with SECCOMP_FILTER_FLAG_LOG, so every
 * denial lands in the kernel audit log (type=1326). This mode tails it.
 */
static int audit_mode(void)
{
    FILE *p = popen("journalctl -k -f -o cat --no-pager 2>/dev/null "
                    "|| dmesg -w --nopager", "r");
    if (!p) { perror("popen journalctl/dmesg"); return 1; }

    char line[2048];
    setbuf(stdout, NULL);
    printf("agentmon: audit mode — seccomp denials (type=1326), Ctrl-C to stop\n");

    while (fgets(line, sizeof line, p)) {
        if (!strstr(line, "type=1326"))
            continue;
        char comm[64] = "?", exe[256] = "?";
        long pid = 0, nr = -1;
        char *s;

        if ((s = strstr(line, "comm=\""))) {
            sscanf(s + 6, "%63[^\"]", comm);
        }
        if ((s = strstr(line, "exe=\""))) {
            sscanf(s + 5, "%255[^\"]", exe);
        }
        if ((s = strstr(line, "pid=")))  sscanf(s + 4, "%ld", &pid);
        if ((s = strstr(line, "syscall="))) sscanf(s + 8, "%ld", &nr);

        char when[32];
        time_t t = time(NULL);
        struct tm tm;
        localtime_r(&t, &tm);
        strftime(when, sizeof when, "%H:%M:%S", &tm);

        printf("%s \033[31;1mTRIP \033[0m %s[%ld] (audit) %s — %s\n",
               when, comm, pid, attempt_name(nr), exe);
    }
    pclose(p);
    return 0;
}

int main(int argc, char **argv)
{
    const char *cgroup = NULL;
    __u64 cgid = 0;
    int audit = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--audit"))
            audit = 1;
        else if (!strcmp(argv[i], "--cgroup") && i + 1 < argc)
            cgroup = argv[++i];
        else if (!strcmp(argv[i], "--cgid") && i + 1 < argc)
            cgid = strtoull(argv[++i], NULL, 0);
        else {
            fprintf(stderr, "usage: %s [--cgroup PATH | --cgid ID | --audit]\n"
                            "  --cgroup/--cgid : eBPF probes filtered to a sandbox cgroup\n"
                            "  --audit         : follow kernel audit log for seccomp denials\n",
                    argv[0]);
            return 2;
        }
    }
    if (audit)
        return audit_mode();
    if (cgroup) {
        struct stat st;
        if (stat(cgroup, &st) < 0) { perror(cgroup); return 1; }
        /* on cgroup v2 the kernfs inode number is the cgroup id */
        cgid = st.st_ino;
    }
    if (!cgid)
        fprintf(stderr, "agentmon: NO FILTER — will print events from all "
                        "processes (very noisy!)\n");
    if (geteuid() != 0)
        fprintf(stderr, "agentmon: warning: not root — loading will likely "
                        "fail (needs CAP_BPF + CAP_PERFMON)\n");

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    /* the BPF ELF is embedded via -include src/agentmon.bpf.h (xxd -i) */
    struct bpf_object *obj = bpf_object__open_mem(bpf_elf, bpf_elf_len, NULL);
    if (!obj) {
        fprintf(stderr, "agentmon: failed to open embedded BPF object "
                        "(run make in the agentcell dir)\n");
        return 1;
    }

    /* configure the cgroup filter before load */
    struct bpf_map *rodata = bpf_object__find_map_by_name(obj, ".rodata");
    if (!rodata || bpf_map__set_initial_value(rodata, &cgid, sizeof cgid)) {
        fprintf(stderr, "agentmon: cannot set target cgid\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "agentmon: load failed: %s\n"
                        "  (are you root? kernel BPF enabled?)\n",
                strerror(errno));
        return 1;
    }

    /* attach every program (section names carry their attach points) */
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link) {
            fprintf(stderr, "agentmon: attach %s failed: %s\n",
                    bpf_program__name(prog), strerror(errno));
            return 1;
        }
    }

    int ev_fd = bpf_object__find_map_fd_by_name(obj, "events");
    struct ring_buffer *rb = ring_buffer__new(ev_fd, handle_ev, NULL, NULL);
    if (!rb) { fprintf(stderr, "agentmon: ringbuf setup failed\n"); return 1; }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    setbuf(stdout, NULL);

    printf("agentmon: watching cgroup id %llu (0 = no filter) — Ctrl-C to stop\n",
           (unsigned long long)cgid);
    while (!g_stop) {
        int r = ring_buffer__poll(rb, 1000);
        if (r == -EINTR) break;
        if (r < 0) {
            fprintf(stderr, "agentmon: poll error: %s\n", strerror(-r));
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
