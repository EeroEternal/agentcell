/*
 * agentcell.h — C API for embedding AgentCell (RFC 0001, Gap 5).
 *
 * Link against libagentcell.a.  One jail per spawn: namespaces, mounts,
 * Landlock, seccomp and cgroup limits are identical to the `sand` CLI.
 *
 * Threading: NOT thread-safe — serialize agentcell_spawn() calls from
 * your own lock.  Each returned pid may be waitpid()ed exactly once and
 * should be followed by agentcell_release(pid) for teardown.
 */
#ifndef AGENTCELL_H
#define AGENTCELL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    AGENTCELL_NET_NONE = 0,     /* loopback only */
    AGENTCELL_NET_HOST = 1,     /* share the host stack */
    AGENTCELL_NET_VETH = 2,     /* own stack + NAT (needs agentlsm daemon) */
};

struct agentcell_config {
    /* everything optional unless noted */
    const char *workdir;        /* NULL = ~/agent-work */
    const char *rootfs;         /* NULL = host /usr /etc /opt view */
    uint64_t    mem_bytes;      /* 0 = 60% of RAM */
    double      cpu_cores;      /* 0 = default quota */
    uint32_t    pids;           /* 0 = 256 */
    int         net;            /* AGENTCELL_NET_* */
    const char *egress;         /* "host:port" — NET_VETH only: DNS +
                                 * this dst pass, all else DROPped; also
                                 * sets http_proxy inside the jail */
    int         secure;         /* agentlsm enforcement (deny /etc/shadow) */
    int         no_landlock;    /* debug */
    int         no_seccomp;     /* debug */
};

/*
 * Run argv[0] (with argv) inside a fresh jail.  Required: cfg, argv,
 * argv[0], out_pid.  stdio fds are dup2'd onto the payload's 0/1/2 —
 * pass -1 to inherit the caller's.  envp: NULL = sane defaults, else a
 * NULL-terminated "K=V" array used verbatim (HOME/PATH up to you).
 *
 * Returns 0 and stores the jail pid (the payload itself); waitpid() it
 * for the exit code, then agentcell_release().  On failure returns a
 * negative errno and prints a "sand:" diagnostic on stderr.
 */
int agentcell_spawn(const struct agentcell_config *cfg,
                    const char *argv[], const char *envp[],
                    int stdin_fd, int stdout_fd, int stderr_fd,
                    pid_t *out_pid);

/*
 * Teardown after the payload exits: veth + egress rules, LSM
 * registration, cgroup dir.  Call once per pid after waitpid().
 * Tolerates unknown pids (returns 0).
 */
int agentcell_release(pid_t pid);

const char *agentcell_version(void);

#ifdef __cplusplus
}
#endif
#endif /* AGENTCELL_H */
