// SPDX-License-Identifier: GPL-2.0
/*
 * agentlsm.c — loader/daemon for the AgentCell BPF LSM enforcement.
 *
 * One-shot modes (debugging / bisect):
 *   sudo ./agentlsm --cgroup PATH [--deny PREFIX]... [--audit]
 *   sudo ./agentlsm --any-cgroup [--deny PREFIX]...
 *   sudo ./agentlsm --block-all SECONDS [--cgroup PATH]
 *                     deny every open — scoped to PATH's cgroup when
 *                     given, system-wide otherwise (DANGER: EPERMs
 *                     every process, incl. your shell/agent harness)
 *
 * Daemon mode (the real thing):
 *   sudo ./agentlsm serve
 *
 *     Attaches lsm/file_open once and manages per-cell policies for
 *     many sandbox cgroups over a control socket, so unprivileged
 *     `sand --secure` can register its cell without any root helper
 *     per launch.  Protocol (one request per line, replies OK/ERR/END):
 *
 *       ADD <cgid> <prefix>    arm one deny rule for that cgroup id
 *       DEL <cgid> <prefix>    drop one rule
 *       CLR <cgid>             cell died: drop all its rules
 *       LIST                   "cgid prefix" lines, then END
 *       WATCH [classes]        from now on: "EV <cgid> <CLASS> <text>"
 *                              lines; classes: deny,exec,open,net,trip
 *                              (comma-separated, default all)
 *
 *       NETUP <pid> [EGRESS H1 P1 [EGRESS H2 P2 ...]]
 *                   [RESOLV NS1 [RESOLV NS2 ...]]
 *                              build a veth pair + NAT for the cell whose
 *                              jail pid is <pid>.  Each EGRESS pair adds
 *                              one destination to the cell's allowlist and
 *                              whitelists every A record of H, resolved
 *                              against the RESOLV nameservers the cell
 *                              actually uses (addr or addr:port) and
 *                              refreshed on TTL.  Replies
 *                              "OK <ifname> <cell-ip> <gw-ip> <hosts> <ips>"
 *                              or "ERR egress_unresolved <host>" /
 *                              "ERR egress_too_many_ips" /
 *                              "ERR egress_too_many_hosts".
 *       NETDOWN <pid>          tear it down (frees the /30)
 *
 *     Denials are enforced (-EPERM) AND reported to watchers.  The
 *     daemon also carries agentmon's tracepoint probes (exec / open /
 *     connect) plus a raw_syscalls/sys_exit probe for TRIP events —
 *     seccomp-denied syscalls never reach the entry tracepoints, but
 *     their -EPERM return is visible on the exit path.  One watcher
 *     stream for everything.
 *
 * Socket: /run/agentcell/lsm.sock (0666 — single-user trust model for
 * now: anyone local may register policy; document before sharing).
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <errno.h>
#include <netdb.h>
#include <resolv.h>
#include <stdarg.h>
#include "arch/syscalls.h"   /* AC_* syscall table */
#include "netup_reply.h"     /* reply policy + drain math (testable) */

static const struct ac_sys ac_syscalls[] = { AC_SYSCALL_TAB };
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* bpf_elf[] and bpf_elf_len come from the -include'd xxd header */

#define PLEN        64
#define ACT_DENY    2
#define LSM_SOCK    "/run/agentcell/lsm.sock"
#define MAX_WATCH   64

static volatile sig_atomic_t g_stop;
static void on_sig(int s) { (void)s; g_stop = 1; }

/* event classes — keep in sync with agentlsm.bpf.c */
#define EV_DENY    1
#define EV_EXEC    2
#define EV_OPEN    3
#define EV_CONNECT 4
#define EV_TRIP    5

struct evt {
    __u64 cgid;
    __u32 tgid;
    __u32 type;
    __u32 nr;
    char  comm[16];
    char  path[192];
};

static const char *attempt_name(unsigned nr)
{
    for (size_t i = 0; i < sizeof ac_syscalls / sizeof ac_syscalls[0]; i++)
        if ((unsigned)ac_syscalls[i].nr == nr)
            return ac_syscalls[i].name;
    return "?";
}

/* ---- shared bpf state ------------------------------------------------ */

static struct bpf_object *g_obj;
static int g_fd_policy, g_fd_cells, g_fd_cellpol, g_fd_events;

static int bpf_load_attach(__u64 target_cgid, int enforce,
                           __u64 block_until_ns, __u64 block_cgid, int mode)
{
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    struct bpf_object *obj = bpf_object__open_mem(bpf_elf, bpf_elf_len, NULL);
    if (!obj) { fprintf(stderr, "agentlsm: open failed\n"); return -1; }

    /* rodata layout: target_cgid@0, enforce@8, mode@12,
     * block_until@16, block_cgid@24 */
    struct {
        __u64 target_cgid;
        int  enforce;
        int  mode;
        __u64 block_until_ns;
        __u64 block_cgid;
    } __attribute__((packed)) cfg = { target_cgid, enforce, mode,
                                      block_until_ns, block_cgid };

    struct bpf_map *ro = bpf_object__find_map_by_name(obj, ".rodata");
    if (!ro || bpf_map__set_initial_value(ro, &cfg, sizeof cfg)) {
        fprintf(stderr, "agentlsm: cannot set config\n"); return -1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "agentlsm: load failed: %s\n", strerror(errno));
        return -1;
    }

    /* attach every program in the object: the lsm/file_open hook plus
     * the tracepoint probes (exec/open/connect/escape-attempts) */
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        if (!bpf_program__attach(prog)) {
            fprintf(stderr, "agentlsm: attach %s failed: %s\n"
                            "  (is 'bpf' in /sys/kernel/security/lsm?)\n",
                    bpf_program__name(prog), strerror(errno));
            return -1;
        }
    }

    g_obj        = obj;
    g_fd_policy  = bpf_object__find_map_fd_by_name(obj, "policy");
    g_fd_cells   = bpf_object__find_map_fd_by_name(obj, "cells");
    g_fd_cellpol = bpf_object__find_map_fd_by_name(obj, "cellpol");
    g_fd_events  = bpf_object__find_map_fd_by_name(obj, "events");
    if (g_fd_cells < 0 || g_fd_cellpol < 0) {
        fprintf(stderr, "agentlsm: serve maps missing\n"); return -1;
    }
    return 0;
}

static void bpf_detach(void)
{
    if (g_obj) bpf_object__close(g_obj);   /* takes all links with it */
    g_obj = NULL;
}

/* ---- serve mode ------------------------------------------------------- */

struct conn {
    int   fd;
    int   watcher;
    __u32 mask;                 /* event classes this watcher wants */
    char  buf[4096];
    size_t len;
    int   drain;                /* swallowing the tail of an over-long line */
};
static struct conn g_conn[MAX_WATCH];

static void conn_drop(int i)
{
    close(g_conn[i].fd);
    g_conn[i].fd = -1;
    g_conn[i].watcher = 0;
    g_conn[i].mask = 0;
    g_conn[i].drain = 0;
}

/* fan one formatted line out to all watchers (best effort); the
 * daemon's own log gets the high-signal classes only — the full
 * stream (OPEN especially) would flood it */
static void fanout(const char *line, __u32 classbit)
{
    if (classbit & ((1 << EV_DENY) | (1 << EV_TRIP))) {
        fputs(line, stdout);
        fflush(stdout);
    }
    for (int i = 0; i < MAX_WATCH; i++) {
        if (g_conn[i].fd < 0 || !g_conn[i].watcher) continue;
        if (!(g_conn[i].mask & classbit)) continue;
        if (write(g_conn[i].fd, line, strlen(line)) < 0)
            conn_drop(i);                   /* watcher went away */
    }
}

static int on_evt(void *ctx, void *data, size_t size)
{
    (void)ctx; (void)size;
    struct evt *e = data;
    char info[300], line[400];
    const char *cls;
    __u32 bit;

    switch (e->type) {
    case EV_DENY:
        cls = "DENY"; bit = 1 << EV_DENY;
        snprintf(info, sizeof info, "%s[%u] %s", e->comm, e->tgid, e->path);
        break;
    case EV_EXEC:
        cls = "EXEC"; bit = 1 << EV_EXEC;
        snprintf(info, sizeof info, "%s[%u] %s", e->comm, e->tgid, e->path);
        break;
    case EV_OPEN:
        cls = "OPEN"; bit = 1 << EV_OPEN;
        snprintf(info, sizeof info, "%s[%u] %s", e->comm, e->tgid, e->path);
        break;
    case EV_CONNECT: {
        cls = "NET"; bit = 1 << EV_CONNECT;
        unsigned short fam;                      /* e->path = sockaddr */
        memcpy(&fam, e->path, 2);
        if (fam == 2 /* AF_INET */) {
            unsigned short port;
            unsigned char ip[4];
            memcpy(&port, e->path + 2, 2);
            memcpy(ip, e->path + 4, 4);
            snprintf(info, sizeof info, "%s[%u] connect %u.%u.%u.%u:%u",
                     e->comm, e->tgid, ip[0], ip[1], ip[2], ip[3],
                     ntohs(port));
        } else {
            snprintf(info, sizeof info, "%s[%u] connect family=%u",
                     e->comm, e->tgid, fam);
        }
        break;
    }
    case EV_TRIP:
        cls = "TRIP"; bit = 1 << EV_TRIP;
        snprintf(info, sizeof info, "%s[%u] blocked syscall %s (%u)",
                 e->comm, e->tgid, attempt_name(e->nr), e->nr);
        break;
    default:
        return 0;
    }
    snprintf(line, sizeof line, "EV %llu %s %s\n",
             (unsigned long long)e->cgid, cls, info);
    fanout(line, bit);
    return 0;
}

/* ---- veth + NAT provisioning (sand --net veth) -----------------------
 * The sandbox is unprivileged; veth pairs and NAT are not.  The cell's
 * parent asks over the control socket: NETUP builds a pair, pushes one
 * end into the cell's netns, assigns a /30 out of 10.200.0.0/16 and
 * makes sure NAT exists; NETDOWN tears it down.  Everything the daemon
 * touches (veth ends, iptables rules, ip_forward) is reversed on exit.
 */
#define MAX_EGRESS 16                          /* --egress entries per cell */
#define MAX_EG_IPS 128                         /* resolved A records kept  */
#define MAX_NS 4                               /* per-cell resolvers       */
#define EG_TTL_CAP 60                          /* max seconds between refresh */

struct egpair { char ip[64]; char port[8]; };
struct eghost { char host[128]; char port[8]; };

static int  egress_accept(int idx, const char *ip, const char *port, int add);
static void net_recover_startup(void);

static __u64 g_netmap[256];                    /* 16384 /30s, one bit each */
static struct {
    pid_t pid;
    int   idx;
    int   n_eg;                                /* installed accept rules */
    struct egpair eg[MAX_EG_IPS];
    int   n_hosts;                             /* allowlisted destinations */
    struct eghost hosts[MAX_EGRESS];
    int   n_ns;                                /* resolvers the cell uses */
    char  ns[MAX_NS][64];
    time_t next_refresh;
} g_nets[64];

/* "addr" or "addr:port" -> sockaddr_in (AF_INET only). */
static int ns_addr(const char *spec, struct sockaddr_in *sa)
{
    char a[64];
    snprintf(a, sizeof a, "%s", spec);
    int port = 53;
    char *c = strrchr(a, ':');
    if (c && c[1] && strspn(c + 1, "0123456789") == strlen(c + 1)) {
        port = atoi(c + 1);
        *c = 0;
    }
    memset(sa, 0, sizeof *sa);
    sa->sin_family = AF_INET;
    sa->sin_port = htons((uint16_t)port);
    return inet_pton(AF_INET, a, &sa->sin_addr) == 1 ? 0 : -1;
}

/* Resolve one host against the cell's resolvers and append every A record
 * (deduped) to `want`.  Returns 0, -1 (no answer anywhere), or -2 (overflow).
 * Using res_nquery per NS catches single-resolver rotation across NS; the
 * TTL feeds the refresh loop.  Falls back to getaddrinfo when n_ns == 0. */
static int resolve_egress(const char *host, const char *port,
                          const struct sockaddr_in *ns, int n_ns,
                          struct egpair *want, int *n_want, int max,
                          int *ttl_min)
{
    int got_any = 0;
    if (n_ns > 0) {
        for (int k = 0; k < n_ns; k++) {
            struct __res_state st;
            memset(&st, 0, sizeof st);
            if (res_ninit(&st)) continue;
            st.nscount = 1;
            st.nsaddr_list[0] = ns[k];
            /* NETUP and the refresh loop resolve inline in serve_loop;
             * the 5s x retries defaults would stall every control client
             * for minutes when a nameserver is unreachable */
            st.retrans = 1;
            st.retry = 1;
            unsigned char buf[4096];
            int r = res_nquery(&st, host, C_IN, T_A, buf, sizeof buf);
            if (r > 0) {
                ns_msg h;
                if (!ns_initparse(buf, r, &h)) {
                    for (int i = 0; i < ns_msg_count(h, ns_s_an); i++) {
                        ns_rr rr;
                        if (ns_parserr(&h, ns_s_an, i, &rr)) continue;
                        if (ns_rr_type(rr) != ns_t_a) continue;
                        char ip[64];
                        if (!inet_ntop(AF_INET, ns_rr_rdata(rr), ip, sizeof ip))
                            continue;
                        got_any = 1;
                        if (ttl_min) {
                            unsigned t = ns_rr_ttl(rr);
                            if (t && (!*ttl_min || (int)t < *ttl_min))
                                *ttl_min = (int)t;
                        }
                        int dup = 0;
                        for (int j = 0; j < *n_want; j++)
                            if (!strcmp(want[j].ip, ip) &&
                                !strcmp(want[j].port, port)) { dup = 1; break; }
                        if (dup) continue;
                        if (*n_want >= max) { res_nclose(&st); return -2; }
                        snprintf(want[*n_want].ip, 64, "%s", ip);
                        snprintf(want[*n_want].port, 8, "%s", port);
                        (*n_want)++;
                    }
                }
            }
            res_nclose(&st);
        }
    }
    if (!got_any) {
        struct addrinfo hints = { .ai_family = AF_INET,
                                  .ai_socktype = SOCK_STREAM }, *ai = NULL;
        if (!getaddrinfo(host, NULL, &hints, &ai) && ai) {
            for (struct addrinfo *p = ai; p; p = p->ai_next) {
                char ip[64];
                struct sockaddr_in *sin = (void *)p->ai_addr;
                if (!inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof ip))
                    continue;
                got_any = 1;
                int dup = 0;
                for (int j = 0; j < *n_want; j++)
                    if (!strcmp(want[j].ip, ip) && !strcmp(want[j].port, port))
                        { dup = 1; break; }
                if (dup) continue;
                if (*n_want >= max) { freeaddrinfo(ai); return -2; }
                snprintf(want[*n_want].ip, 64, "%s", ip);
                snprintf(want[*n_want].port, 8, "%s", port);
                (*n_want)++;
            }
            freeaddrinfo(ai);
        }
        if (!got_any) return -1;
        return 0;
    }
    return 0;
}

/* Build the desired (ip,port) set for a cell. */
static int egress_want(int slot, struct egpair *want, int *n_want,
                       int *ttl_min, char *bad, size_t badn)
{
    struct sockaddr_in ns[MAX_NS];
    int n_ns = 0;
    for (int k = 0; k < g_nets[slot].n_ns; k++)
        if (!ns_addr(g_nets[slot].ns[k], &ns[n_ns])) n_ns++;
    *n_want = 0;
    *ttl_min = 0;
    for (int h = 0; h < g_nets[slot].n_hosts; h++) {
        int r = resolve_egress(g_nets[slot].hosts[h].host,
                               g_nets[slot].hosts[h].port,
                               ns, n_ns, want, n_want, MAX_EG_IPS, ttl_min);
        if (r == -2) return -2;
        if (r < 0) { snprintf(bad, badn, "%s", g_nets[slot].hosts[h].host);
                     return -1; }
    }
    return 0;
}

/* Diff the installed accept rules against `want` and apply the delta. */
static void egress_apply(int slot, const struct egpair *want, int n_want)
{
    for (int i = 0; i < g_nets[slot].n_eg; ) {
        int keep = 0;
        for (int j = 0; j < n_want; j++)
            if (!strcmp(g_nets[slot].eg[i].ip, want[j].ip) &&
                !strcmp(g_nets[slot].eg[i].port, want[j].port)) { keep = 1; break; }
        if (keep) { i++; continue; }
        egress_accept(g_nets[slot].idx, g_nets[slot].eg[i].ip,
                      g_nets[slot].eg[i].port, 0);
        g_nets[slot].eg[i] = g_nets[slot].eg[--g_nets[slot].n_eg];
    }
    for (int j = 0; j < n_want && g_nets[slot].n_eg < MAX_EG_IPS; j++) {
        int have = 0;
        for (int i = 0; i < g_nets[slot].n_eg; i++)
            if (!strcmp(g_nets[slot].eg[i].ip, want[j].ip) &&
                !strcmp(g_nets[slot].eg[i].port, want[j].port)) { have = 1; break; }
        if (have) continue;
        if (egress_accept(g_nets[slot].idx, want[j].ip, want[j].port, 1)) {
            fprintf(stderr, "agentlsm: egress: veth%d: ACCEPT %s:%s "
                            "failed to install\n",
                    g_nets[slot].idx, want[j].ip, want[j].port);
            continue;                       /* never count a missing rule */
        }
        g_nets[slot].eg[g_nets[slot].n_eg++] = want[j];
    }
}

/* Re-resolve every live cell that is due.  A transient failure keeps the
 * last good set; only a full cell teardown drops rules. */
static void egress_refresh(void)
{
    time_t now = time(NULL);
    for (int s = 0; s < 64; s++) {
        if (!g_nets[s].pid || g_nets[s].n_hosts == 0) continue;
        if (now < g_nets[s].next_refresh) continue;
        struct egpair want[MAX_EG_IPS];
        int n = 0, ttl = 0;
        char bad[128] = "";
        int r = egress_want(s, want, &n, &ttl, bad, sizeof bad);
        if (r == -2) {
            fprintf(stderr, "agentlsm: egress: %s: too many addresses\n", bad);
            g_nets[s].next_refresh = now + 10;
            continue;
        }
        if (r < 0 || n == 0) {
            fprintf(stderr, "agentlsm: egress: %s: transient resolve "
                            "failure; keeping last good set\n",
                    bad[0] ? bad : "(none)");
            g_nets[s].next_refresh = now + 10;
            continue;
        }
        egress_apply(s, want, n);
        g_nets[s].next_refresh =
            now + (ttl > 0 && ttl < EG_TTL_CAP ? ttl : EG_TTL_CAP);
    }
}
static int   g_nat_on;
static int   g_fwd_save = -1;

static int sh(const char *fmt, ...)
{
    char cmd[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof cmd, fmt, ap);
    va_end(ap);
    return system(cmd);
}

static void nat_ensure(void)
{
    if (g_nat_on) return;
    FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "r");
    if (f) { if (fscanf(f, "%d", &g_fwd_save) != 1) g_fwd_save = -1; fclose(f); }
    f = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (f) { fputs("1\n", f); fclose(f); }
    sh("iptables -t nat -C POSTROUTING -s 10.200.0.0/16 -j MASQUERADE 2>/dev/null"
       " || iptables -t nat -A POSTROUTING -s 10.200.0.0/16 -j MASQUERADE");
    sh("iptables -C FORWARD -s 10.200.0.0/16 -j ACCEPT 2>/dev/null"
       " || iptables -I FORWARD -s 10.200.0.0/16 -j ACCEPT");
    sh("iptables -C FORWARD -d 10.200.0.0/16 -j ACCEPT 2>/dev/null"
       " || iptables -I FORWARD -d 10.200.0.0/16 -j ACCEPT");
    sh("iptables -C FORWARD -s 10.200.0.0/16 -d 169.254.0.0/16 -j DROP 2>/dev/null"
       " || iptables -I FORWARD -s 10.200.0.0/16 -d 169.254.0.0/16 -j DROP");
    g_nat_on = 1;
}

static void nat_teardown(void)
{
    if (!g_nat_on) return;
    g_nat_on = 0;
    sh("iptables -t nat -D POSTROUTING -s 10.200.0.0/16 -j MASQUERADE 2>/dev/null");
    sh("iptables -D FORWARD -s 10.200.0.0/16 -j ACCEPT 2>/dev/null");
    sh("iptables -D FORWARD -d 10.200.0.0/16 -j ACCEPT 2>/dev/null");
    sh("iptables -D FORWARD -s 10.200.0.0/16 -d 169.254.0.0/16 -j DROP 2>/dev/null");
    if (g_fwd_save >= 0) {
        FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "w");
        if (f) { fprintf(f, "%d\n", g_fwd_save); fclose(f); }
    }
}

/* --egress allowlist on the FORWARD chain: DNS + the whitelisted
 * destinations pass, everything else from that veth is dropped.
 * Base rules sit above the global 10.200/16 ACCEPTs (inserted with
 * -I in reverse order); each resolved address gets one ACCEPT. */
static void egress_base(int idx, int add)
{
    const char *op = add ? "-I FORWARD 1" : "-D FORWARD";
    sh("iptables %s FORWARD -i vethh%d -j DROP 2>/dev/null", op, idx);
    sh("iptables %s FORWARD -i vethh%d -m conntrack "
       "--ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null", op, idx);
    sh("iptables %s FORWARD -i vethh%d -p udp --dport 53 "
       "-j ACCEPT 2>/dev/null", op, idx);
}

/* Returns 0 only when the rule is in the kernel; callers must not
 * account a rule that failed to install. */
static int egress_accept(int idx, const char *ip, const char *port, int add)
{
    const char *op = add ? "-I FORWARD 1" : "-D FORWARD";
    return sh("iptables %s FORWARD -i vethh%d -p tcp -d %s --dport %s "
              "-j ACCEPT 2>/dev/null", op, idx, ip, port);
}

/* A previous daemon run may have died without cleanup, leaving vethh*
 * links and their iptables rules behind.  The fresh daemon starts with an
 * empty netmap, so nothing found here belongs to a live cell of ours: the
 * orphaned cells already lost their policy owner.  Remove the pairs and
 * every rule that mentions them, or idx reuse grafts a dead cell's
 * allowlist onto a new one. */
static void net_recover_startup(void)
{
    sh("ip -o link show 2>/dev/null"
       " | sed -n 's/^[0-9]*: \\(vethh[0-9]*\\)@.*/\\1/p'"
       " | while read -r v; do"
       "   ip link del \"$v\" 2>/dev/null"
       "   && echo \"agentlsm: removed stale $v from a previous run\""
       " done >&2");
    sh("iptables-save 2>/dev/null | grep -E -- '-[io] vethh[0-9]+( |$)'"
       " | sed 's/^-A/-D/'"
       " | while read -r r; do iptables $r 2>/dev/null; done");
    /* and any global NAT rules a dead run left behind */
    sh("iptables -t nat -D POSTROUTING -s 10.200.0.0/16 -j MASQUERADE 2>/dev/null");
    sh("iptables -D FORWARD -s 10.200.0.0/16 -j ACCEPT 2>/dev/null");
    sh("iptables -D FORWARD -d 10.200.0.0/16 -j ACCEPT 2>/dev/null");
    sh("iptables -D FORWARD -s 10.200.0.0/16 -d 169.254.0.0/16 -j DROP 2>/dev/null");
}

static int net_up(pid_t pid, char *rep, size_t repn,
                  char hosts[][128], char ports[][8], int n_eg,
                  char nss[][64], int n_ns)
{
    int slot = -1;
    for (int i = 0; i < 64; i++)
        if (!g_nets[i].pid) { slot = i; break; }
    if (slot < 0) return -1;

    int idx = -1;
    for (int i = 0; i < 16384; i++)
        if (!(g_netmap[i >> 6] & (1ULL << (i & 63)))) {
            g_netmap[i >> 6] |= 1ULL << (i & 63);
            idx = i;
            break;
        }
    if (idx < 0) return -1;

    /* b = idx*4: 10.200.<b+1>/30 host end, 10.200.<b+2> cell end */
    unsigned b = idx * 4;
    if (sh("ip link add vethh%d type veth peer name vethc%d 2>/dev/null",
           idx, idx)) {
        /* stale from a crash: the link outlived the daemon, and so did its
         * iptables rules -- including the previous cell's per-IP ACCEPTs.
         * Scrub everything that mentions this veth, or the new cell would
         * silently inherit the old cell's allowlist. */
        fprintf(stderr, "agentlsm: veth%d: stale link from a previous run\n",
                idx);
        sh("ip link del vethh%d 2>/dev/null", idx);
        sh("iptables-save 2>/dev/null | grep -E -- '-[io] vethh%d( |$)'"
           " | sed 's/^-A/-D/'"
           " | while read -r r; do iptables $r 2>/dev/null; done", idx);
        if (sh("ip link add vethh%d type veth peer name vethc%d", idx, idx))
            goto fail;
    }
    if (sh("ip link set vethc%d netns %d", idx, (int)pid)) goto fail;
    if (sh("ip addr add 10.200.%u.%u/30 dev vethh%d",
           (b + 1) >> 8, (b + 1) & 255, idx)) goto fail;
    if (sh("ip link set vethh%d up", idx)) goto fail;

    nat_ensure();
    g_nets[slot].pid = pid;
    g_nets[slot].idx = idx;
    g_nets[slot].n_eg = 0;
    g_nets[slot].n_hosts = 0;
    g_nets[slot].n_ns = 0;
    g_nets[slot].next_refresh = 0;
    for (int h = 0; h < n_eg && h < MAX_EGRESS; h++) {
        snprintf(g_nets[slot].hosts[h].host,
                 sizeof g_nets[slot].hosts[h].host, "%s", hosts[h]);
        snprintf(g_nets[slot].hosts[h].port,
                 sizeof g_nets[slot].hosts[h].port, "%s", ports[h]);
    }
    g_nets[slot].n_hosts = n_eg > MAX_EGRESS ? MAX_EGRESS : n_eg;
    for (int k = 0; k < n_ns && k < MAX_NS; k++)
        snprintf(g_nets[slot].ns[k], sizeof g_nets[slot].ns[k], "%s", nss[k]);
    g_nets[slot].n_ns = n_ns > MAX_NS ? MAX_NS : n_ns;

    if (n_eg > 0) {
        egress_base(idx, 1);
        struct egpair want[MAX_EG_IPS];
        int n = 0, ttl = 0;
        char bad[128] = "";
        int r = egress_want(slot, want, &n, &ttl, bad, sizeof bad);
        if (r == -2) {
            snprintf(rep, repn, "ERR egress_too_many_ips\n");
            goto fail;
        }
        if (r < 0 || n == 0) {
            snprintf(rep, repn, "ERR egress_unresolved %s\n", bad);
            goto fail;
        }
        egress_apply(slot, want, n);
        g_nets[slot].next_refresh =
            time(NULL) + (ttl > 0 && ttl < EG_TTL_CAP ? ttl : EG_TTL_CAP);
    } else {
        /* No allowlist was requested, so the cell falls through to the
         * global `FORWARD -s 10.200.0.0/16 -j ACCEPT` installed by
         * nat_ensure() and can reach anything it can route.  That is what
         * plain `--net veth` means (real networking with NAT), but it is
         * also what an integrator gets by passing veth and forgetting
         * --egress, so say it in the journal instead of leaving the only
         * evidence in the reader's head. */
        fprintf(stderr, "agentlsm: WARNING: veth%d (pid %ld) has no egress "
                        "allowlist — unrestricted NAT\n",
                idx, (long)pid);
    }
    snprintf(rep, repn, "OK vethc%d 10.200.%u.%u 10.200.%u.%u %d %d\n",
             idx, (b + 2) >> 8, (b + 2) & 255,
             (b + 1) >> 8, (b + 1) & 255,
             g_nets[slot].n_hosts, g_nets[slot].n_eg);
    return 0;
fail:
    egress_base(idx, 0);
    sh("ip link del vethh%d 2>/dev/null", idx);
    g_netmap[idx >> 6] &= ~(1ULL << (idx & 63));
    g_nets[slot].pid = 0;
    g_nets[slot].n_eg = 0;
    g_nets[slot].n_hosts = 0;
    g_nets[slot].n_ns = 0;
    g_nets[slot].next_refresh = 0;
    return -1;
}

static void net_down(pid_t pid)
{
    for (int i = 0; i < 64; i++) {
        if (g_nets[i].pid != pid) continue;
        for (int j = 0; j < g_nets[i].n_eg; j++)
            egress_accept(g_nets[i].idx, g_nets[i].eg[j].ip,
                          g_nets[i].eg[j].port, 0);
        if (g_nets[i].n_eg) egress_base(g_nets[i].idx, 0);
        sh("ip link del vethh%d 2>/dev/null", g_nets[i].idx);
        g_netmap[g_nets[i].idx >> 6] &= ~(1ULL << (g_nets[i].idx & 63));
        g_nets[i].pid = 0;
        g_nets[i].n_eg = 0;
        g_nets[i].n_hosts = 0;
        g_nets[i].n_ns = 0;
        g_nets[i].next_refresh = 0;
    }
}

static void net_cleanup_all(void)
{
    for (int i = 0; i < 64; i++)
        if (g_nets[i].pid) {
            for (int j = 0; j < g_nets[i].n_eg; j++)
                egress_accept(g_nets[i].idx, g_nets[i].eg[j].ip,
                              g_nets[i].eg[j].port, 0);
            if (g_nets[i].n_eg) egress_base(g_nets[i].idx, 0);
            sh("ip link del vethh%d 2>/dev/null", g_nets[i].idx);
            g_netmap[g_nets[i].idx >> 6] &= ~(1ULL << (g_nets[i].idx & 63));
            g_nets[i].pid = 0;
            g_nets[i].n_eg = 0;
            g_nets[i].n_hosts = 0;
            g_nets[i].n_ns = 0;
        }
    nat_teardown();
}

static int cell_add(__u64 cgid, const char *prefix)
{
    struct { __u64 cgid; char prefix[PLEN]; } k = {0};
    k.cgid = cgid;
    snprintf(k.prefix, PLEN, "%s", prefix);
    __u32 act = ACT_DENY;
    if (bpf_map_update_elem(g_fd_cellpol, &k, &act, BPF_ANY)) return -1;
    __u32 one = 1;
    if (bpf_map_update_elem(g_fd_cells, &cgid, &one, BPF_ANY)) return -1;
    return 0;
}

static int cell_del(__u64 cgid, const char *prefix)
{
    struct { __u64 cgid; char prefix[PLEN]; } k = {0};
    k.cgid = cgid;
    snprintf(k.prefix, PLEN, "%s", prefix);
    return bpf_map_delete_elem(g_fd_cellpol, &k);
}

/* drop every rule of a cell: walk cellpol with get_next_key */
static int cell_clr(__u64 cgid)
{
    struct { __u64 cgid; char prefix[PLEN]; } cur = {0}, nxt;
    for (;;) {
        if (bpf_map_get_next_key(g_fd_cellpol, &cur, &nxt)) break;
        if (nxt.cgid == cgid)
            bpf_map_delete_elem(g_fd_cellpol, &nxt);
        cur = nxt;
    }
    return bpf_map_delete_elem(g_fd_cells, &cgid);
}

/* handle one full request line; reply written to fd */
static void serve_line(int ci, char *line)
{
    char rep[128];
    while (*line == ' ') line++;

    if (!strncmp(line, "ADD ", 4)) {
        unsigned long long cgid;
        char prefix[PLEN];
        if (sscanf(line + 4, "%llu %63s", &cgid, prefix) == 2 &&
            !cell_add(cgid, prefix))
            snprintf(rep, sizeof rep, "OK\n");
        else
            snprintf(rep, sizeof rep, "ERR add\n");
    } else if (!strncmp(line, "DEL ", 4)) {
        unsigned long long cgid;
        char prefix[PLEN];
        if (sscanf(line + 4, "%llu %63s", &cgid, prefix) == 2 &&
            !cell_del(cgid, prefix))
            snprintf(rep, sizeof rep, "OK\n");
        else
            snprintf(rep, sizeof rep, "ERR del\n");
    } else if (!strncmp(line, "CLR ", 4)) {
        unsigned long long cgid;
        if (sscanf(line + 4, "%llu", &cgid) == 1 && !cell_clr(cgid))
            snprintf(rep, sizeof rep, "OK\n");
        else
            snprintf(rep, sizeof rep, "ERR clr\n");
    } else if (!strcmp(line, "LIST")) {
        struct { __u64 cgid; char prefix[PLEN]; } cur = {0}, nxt;
        for (;;) {
            if (bpf_map_get_next_key(g_fd_cellpol, &cur, &nxt)) break;
            char l[PLEN + 32];
            snprintf(l, sizeof l, "%llu %s\n",
                     (unsigned long long)nxt.cgid, nxt.prefix);
            if (write(g_conn[ci].fd, l, strlen(l)) < 0) { conn_drop(ci); return; }
            cur = nxt;
        }
        snprintf(rep, sizeof rep, "END\n");
    } else if (!strncmp(line, "WATCH", 5)) {
        /* WATCH [deny,exec,open,net,trip] — bare WATCH = all classes */
        __u32 mask = 0;
        char *p = line + 5;
        while (*p == ' ') p++;
        for (char *tok = strtok(p, ","); tok; tok = strtok(NULL, ",")) {
            if (!strcmp(tok, "deny"))  mask |= 1 << EV_DENY;
            if (!strcmp(tok, "exec"))  mask |= 1 << EV_EXEC;
            if (!strcmp(tok, "open"))  mask |= 1 << EV_OPEN;
            if (!strcmp(tok, "net") || !strcmp(tok, "connect"))
                mask |= 1 << EV_CONNECT;
            if (!strcmp(tok, "trip"))  mask |= 1 << EV_TRIP;
        }
        g_conn[ci].watcher = 1;
        g_conn[ci].mask = mask ? mask : ~0u;
        snprintf(rep, sizeof rep, "OK\n");
    } else if (!strncmp(line, "NETUP ", 6)) {
        char *p = line + 6, *end;
        long pid = strtol(p, &end, 10);
        char hosts[MAX_EGRESS][128], ports[MAX_EGRESS][8];
        char nss[MAX_NS][64];
        int n_eg = 0, n_ns = 0, ok = (end != p), too_many = 0;
        p = end;
        for (;;) {
            while (*p == ' ') p++;
            if (!*p) break;
            if (!strncmp(p, "EGRESS", 6) && (p[6] == ' ' || !p[6])) {
                p += 6;
                while (*p == ' ') p++;
                if (!*p) break;
                if (n_eg >= MAX_EGRESS) { too_many = 1; break; }
                char *tok = p;
                while (*p && *p != ' ') p++;
                char save = *p; *p = 0;
                snprintf(hosts[n_eg], sizeof hosts[n_eg], "%s", tok);
                *p = save;
                while (*p == ' ') p++;
                if (!*p) break;
                tok = p;
                while (*p && *p != ' ') p++;
                save = *p; *p = 0;
                snprintf(ports[n_eg], sizeof ports[n_eg], "%s", tok);
                *p = save;
                n_eg++;
            } else if (!strncmp(p, "RESOLV", 6) && (p[6] == ' ' || !p[6])) {
                p += 6;
                while (*p == ' ') p++;
                if (!*p) break;
                char *tok = p;
                while (*p && *p != ' ') p++;
                char save = *p; *p = 0;
                if (n_ns < MAX_NS)
                    snprintf(nss[n_ns++], sizeof nss[0], "%s", tok);
                *p = save;
            } else {
                break;                        /* unknown token */
            }
        }
        int rc = 0;
        rep[0] = 0;
        if (ok && !too_many)
            rc = net_up((pid_t)pid, rep, sizeof rep, hosts, ports,
                        n_eg, nss, n_ns);
        /* keep net_up()'s specific ERR egress_* reply; only an unnamed
         * failure becomes the generic one (see netup_reply.h) */
        netup_reply(ok, too_many, rc, rep, sizeof rep);
    } else if (!strncmp(line, "NETDOWN ", 8)) {
        long pid;
        if (sscanf(line + 8, "%ld", &pid) == 1)
            net_down((pid_t)pid);
        snprintf(rep, sizeof rep, "OK\n");
    } else if (!strcmp(line, "QUIT") || !strcmp(line, "BYE")) {
        conn_drop(ci);
        return;
    } else {
        snprintf(rep, sizeof rep, "ERR unknown\n");
    }
    if (write(g_conn[ci].fd, rep, strlen(rep)) < 0)
        conn_drop(ci);
}

static int serve_mode(void)
{
    if (geteuid() != 0) {
        fprintf(stderr, "agentlsm: serve must run as root\n");
        return 1;
    }
    if (bpf_load_attach(0, 1, 0, 0, 0 /* MODE_SERVE */)) return 1;

    net_recover_startup();

    mkdir("/run/agentcell", 0755);
    unlink(LSM_SOCK);

    int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    snprintf(a.sun_path, sizeof a.sun_path, "%s", LSM_SOCK);
    socklen_t alen = offsetof(struct sockaddr_un, sun_path) +
                     strlen(a.sun_path) + 1;
    if (bind(lfd, (struct sockaddr *)&a, alen) < 0 || listen(lfd, 16) < 0) {
        perror("agentlsm: bind " LSM_SOCK); return 1;
    }
    chmod(LSM_SOCK, 0666);

    struct ring_buffer *rb =
        ring_buffer__new(g_fd_events, on_evt, NULL, NULL);
    if (!rb) { fprintf(stderr, "agentlsm: ringbuf failed\n"); return 1; }

    for (int i = 0; i < MAX_WATCH; i++) g_conn[i].fd = -1;

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    signal(SIGPIPE, SIG_IGN);   /* clients may vanish mid-write */
    printf("agentlsm: serving %s  (Ctrl-C to detach and stop)\n", LSM_SOCK);
    fflush(stdout);

    while (!g_stop) {
        /* 1) drain BPF events -> watchers */
        ring_buffer__poll(rb, 100);

        /* 1b) re-resolve egress hosts whose TTL is due */
        egress_refresh();

        /* 2) accept new control clients */
        struct pollfd pfd = { .fd = lfd, .events = POLLIN };
        poll(&pfd, 1, 0);
        if (pfd.revents & POLLIN) {
            int c = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
            if (c >= 0) {
                int slot = -1;
                for (int i = 0; i < MAX_WATCH; i++)
                    if (g_conn[i].fd < 0) { slot = i; break; }
                if (slot < 0) close(c);
                else {
                    g_conn[slot].fd = c;
                    g_conn[slot].watcher = 0;
                    g_conn[slot].mask = 0;
                    g_conn[slot].len = 0;
                }
            }
        }

        /* 3) read request lines from clients */
        for (int i = 0; i < MAX_WATCH; i++) {
            if (g_conn[i].fd < 0) continue;
            struct pollfd p = { .fd = g_conn[i].fd, .events = POLLIN };
            poll(&p, 1, 0);
            if (!(p.revents & POLLIN)) {
                if (p.revents & (POLLHUP | POLLERR)) conn_drop(i);
                continue;
            }
            char *b = g_conn[i].buf + g_conn[i].len;
            ssize_t r = read(g_conn[i].fd, b,
                             sizeof g_conn[i].buf - 1 - g_conn[i].len);
            if (r <= 0) { conn_drop(i); continue; }

            if (g_conn[i].drain) {
                /* an over-long line is in flight: swallow bytes up to and
                 * including its newline so the tail is never parsed as new
                 * commands, then resume normal parsing */
                ssize_t keep = drain_resume(g_conn[i].buf, (size_t)r);
                if (keep < 0) continue;
                g_conn[i].drain = 0;
                memmove(g_conn[i].buf,
                        g_conn[i].buf + ((size_t)r - (size_t)keep),
                        (size_t)keep);
                g_conn[i].len = (size_t)keep;
                g_conn[i].buf[g_conn[i].len] = 0;
            } else {
                g_conn[i].len += r;
                g_conn[i].buf[g_conn[i].len] = 0;

                /* process complete lines */
                char *nl;
                while ((nl = strchr(g_conn[i].buf, '\n'))) {
                    *nl = 0;
                    serve_line(i, g_conn[i].buf);
                    if (g_conn[i].fd < 0) break;         /* QUIT */
                    size_t rest = strlen(nl + 1);
                    memmove(g_conn[i].buf, nl + 1, rest);
                    g_conn[i].len = rest;
                    g_conn[i].buf[g_conn[i].len] = 0;
                }
            }
            if (g_conn[i].fd >= 0 &&
                g_conn[i].len >= sizeof g_conn[i].buf - 1) {
                static const char err[] = "ERR line_too_long\n";
                if (write(g_conn[i].fd, err, sizeof err - 1) < 0)
                    conn_drop(i);
                g_conn[i].len = 0;                    /* drop the partial line */
                g_conn[i].drain = 1;  /* and the rest of it, wherever it is */
            }
        }
    }

    ring_buffer__free(rb);
    net_cleanup_all();
    for (int i = 0; i < MAX_WATCH; i++)
        if (g_conn[i].fd >= 0) conn_drop(i);
    close(lfd);
    unlink(LSM_SOCK);
    bpf_detach();
    printf("agentlsm: detached\n");
    return 0;
}

/* ---- one-shot modes --------------------------------------------------- */

static int on_evt_oneshot(void *ctx, void *data, size_t size)
{
    (void)ctx; (void)size;
    printf("DENY (audit) %llu %s\n",
           (unsigned long long)((struct evt *)data)->cgid,
           (const char *)((struct evt *)data)->path);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "serve"))
        return serve_mode();

    const char *cgroup = NULL;
    const char *deny[64];
    int n_deny = 0, audit = 0, anycg = 0;
    double block_all = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--cgroup") && i + 1 < argc) cgroup = argv[++i];
        else if (!strcmp(argv[i], "--deny") && i + 1 < argc) deny[n_deny++] = argv[++i];
        else if (!strcmp(argv[i], "--audit")) audit = 1;
        else if (!strcmp(argv[i], "--any-cgroup")) anycg = 1;
        else if (!strcmp(argv[i], "--block-all") && i + 1 < argc)
            block_all = strtod(argv[++i], NULL);
        else {
            fprintf(stderr, "usage: %s serve\n"
                            "       %s --cgroup PATH [--deny PREFIX]... "
                            "[--audit] [--any-cgroup]\n"
                            "       %s --block-all SECONDS [--cgroup PATH]\n",
                    argv[0], argv[0], argv[0]);
            return 2;
        }
    }
    if (!block_all && !cgroup && !anycg) {
        fprintf(stderr, "agentlsm: --cgroup, --any-cgroup or --block-all "
                        "required (or 'serve')\n");
        return 2;
    }
    if (block_all && (block_all < 0.1 || block_all > 10.0)) {
        fprintf(stderr, "agentlsm: --block-all must be 0.1..10 seconds\n");
        return 2;
    }

    struct stat st = {0};
    if (cgroup && stat(cgroup, &st) < 0) { perror(cgroup); return 1; }

    if (geteuid() != 0) {
        fprintf(stderr, "agentlsm: must run as root (CAP_BPF + CAP_SYS_ADMIN "
                        "for LSM attach)\n");
        return 1;
    }

    if (block_all) {
        /* time-bounded deny-everything window, kernel-side deadline.
         * Scoped to --cgroup when given — the system-wide variant
         * EPERMs EVERY process on the machine, including the shell,
         * desktop or agent harness that launched it. */
        __u64 bcgid = (cgroup && !anycg) ? (__u64)st.st_ino : 0;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        __u64 until = (__u64)now.tv_sec * 1000000000ULL + now.tv_nsec
                    + (__u64)(block_all * 1e9) + 500000000ULL;
        if (bpf_load_attach(0, 0, until, bcgid, 0)) return 1;

        if (!bcgid)
            fprintf(stderr, "agentlsm: WARNING: no --cgroup — EVERY open "
                            "system-wide will fail for %.1fs\n", block_all);
        printf("agentlsm: BLOCK-ALL armed%s: opens DENIED for %.1fs "
               "(0.5s grace), kernel-side deadline, then auto-detach\n",
               bcgid ? " (cgroup-scoped)" : "", block_all);
        fflush(stdout);
        double total = 0.5 + block_all;
        while (total > 0 && !g_stop) {
            double step = total > 0.25 ? 0.25 : total;
            struct timespec ts = { (time_t)step,
                (long)((step - (time_t)step) * 1e9) };
            nanosleep(&ts, NULL);
            total -= step;
        }
        bpf_detach();
        printf("agentlsm: window over, detached\n");
        return 0;
    }

    if (bpf_load_attach((cgroup && !anycg) ? (__u64)st.st_ino : 0,
                        !audit, 0, 0, 1 /* MODE_FLAT */))
        return 1;

    if (n_deny == 0) {
        deny[n_deny++] = "/etc/shadow";
        deny[n_deny++] = "/etc/gshadow";
    }
    for (int i = 0; i < n_deny; i++) {
        char key[PLEN] = {0};
        snprintf(key, sizeof key, "%s", deny[i]);
        __u32 act = ACT_DENY;
        if (bpf_map_update_elem(g_fd_policy, key, &act, BPF_ANY)) {
            fprintf(stderr, "agentlsm: policy update failed: %s\n",
                    strerror(errno));
            return 1;
        }
    }

    printf("agentlsm: enforcing=%d cgid=%llu deny-list:\n", !audit,
           (unsigned long long)((cgroup && !anycg) ? st.st_ino : 0));
    for (int i = 0; i < n_deny; i++) printf("  - %s\n", deny[i]);
    printf("Ctrl-C to detach\n");

    struct ring_buffer *rb = NULL;
    if (audit) {
        rb = ring_buffer__new(g_fd_events, on_evt_oneshot, NULL, NULL);
        if (!rb) fprintf(stderr, "agentlsm: ringbuf setup failed\n");
    }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    while (!g_stop) {
        if (audit && rb) {
            if (ring_buffer__poll(rb, 1000) == -EINTR)
                break;
        } else {
            struct timespec ts = { 0, 100 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
    }

    if (rb) ring_buffer__free(rb);
    bpf_detach();
    printf("agentlsm: detached\n");
    return 0;
}
