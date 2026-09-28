/*
 * tests/stub-agentlsm.c — fake agentlsm control socket for protocol tests.
 *
 * `sand` talks to the root daemon over a unix socket (NETUP / NETDOWN / CLR /
 * QUIT ...).  A real daemon always answers one way, so the interesting cases
 * for `sand` — an older daemon, or a daemon that could not install the rules
 * it was asked for — cannot be produced on demand.  This stub answers just
 * enough of the protocol to drive those branches with no root and no daemon.
 *
 * Modes (argv[2]):
 *   v021     agentlsm >= 0.2.1 reply: "OK <if> <cell> <gw> <hosts> <ips>",
 *            counts derived from the request (hosts = EGRESS tokens, ips =
 *            hosts), i.e. everything the caller asked for was installed
 *   v020     pre-0.2.1 reply: three fields, no counts
 *   short    counts present but one host short of the request
 *   zeroips  every host reported, but zero addresses resolved
 *
 * Usage: stub-agentlsm <socket-path> <mode>
 *
 * Runs until SIGTERM/SIGINT, or until a client sends QUIT.  Exits nonzero on
 * a bad invocation so a typo in a test cannot silently pass as `v021`.
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop;

static void on_sig(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* How many hosts the client asked for: one "EGRESS <host> <port>" per host. */
static int count_hosts(const char *line)
{
    int n = 0;
    for (const char *p = line; (p = strstr(p, "EGRESS ")) != NULL; p += 7) {
        /* only count at a token boundary */
        if (p == line || p[-1] == ' ') n++;
    }
    return n;
}

static void reply_for(const char *mode, const char *req, char *rep, size_t repn)
{
    static const char *const okfmt = "OK vethc0 10.200.0.2 10.200.0.1 %d %d\n";
    int hosts = count_hosts(req);

    if (!strcmp(mode, "v020")) {
        snprintf(rep, repn, "OK vethc0 10.200.0.2 10.200.0.1\n");
    } else if (!strcmp(mode, "short")) {
        snprintf(rep, repn, okfmt, hosts > 0 ? hosts - 1 : 0, hosts);
    } else if (!strcmp(mode, "zeroips")) {
        snprintf(rep, repn, okfmt, hosts, 0);
    } else {                                  /* v021 */
        snprintf(rep, repn, okfmt, hosts, hosts);
    }
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <socket-path> <v021|v020|short|zeroips>\n",
                argv[0]);
        return 2;
    }
    const char *path = argv[1], *mode = argv[2];
    if (strcmp(mode, "v021") && strcmp(mode, "v020") &&
        strcmp(mode, "short") && strcmp(mode, "zeroips")) {
        fprintf(stderr, "stub-agentlsm: unknown mode '%s'\n", mode);
        return 2;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, on_sig);
    signal(SIGINT, on_sig);

    int lfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (lfd < 0) { perror("stub-agentlsm: socket"); return 1; }

    struct sockaddr_un a = { .sun_family = AF_UNIX };
    snprintf(a.sun_path, sizeof a.sun_path, "%s", path);
    socklen_t alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                 strlen(a.sun_path) + 1);
    unlink(path);
    if (bind(lfd, (struct sockaddr *)&a, alen) < 0 || listen(lfd, 8) < 0) {
        perror("stub-agentlsm: bind");
        return 1;
    }

    int quit = 0;
    while (!g_stop && !quit) {
        /* poll with a deadline: signal() installs handlers with SA_RESTART,
         * so a blocking accept() would never notice SIGTERM and the stub
         * would outlive the test that started it. */
        struct pollfd pfd = { .fd = lfd, .events = POLLIN };
        int pr = poll(&pfd, 1, 200);
        if (pr <= 0) continue;
        int c = accept(lfd, NULL, NULL);
        if (c < 0) continue;

        char buf[8192], rep[256];
        ssize_t r = read(c, buf, sizeof buf - 1);
        if (r > 0) {
            buf[r] = 0;
            char *nl = strchr(buf, '\n');
            if (nl) *nl = 0;
            if (!strcmp(buf, "QUIT")) {
                quit = 1;
            } else if (!strncmp(buf, "NETUP", 5)) {
                reply_for(mode, buf, rep, sizeof rep);
                ssize_t w = write(c, rep, strlen(rep));
                (void)w;
            } else {
                ssize_t w = write(c, "OK\n", 3);
                (void)w;
            }
        }
        close(c);
    }

    close(lfd);
    unlink(path);
    return 0;
}
