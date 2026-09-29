/*
 * netup_reply.h — control-protocol reply policy and over-long-line drain
 * math, isolated from BPF/root/iptables so tests/contract_test.c can drive
 * them directly.
 *
 * Both were silent regressions in the veth/NETUP path: the daemon used to
 * overwrite net_up()'s specific `ERR egress_*` with a generic `ERR netup`,
 * and an over-long line left its tail to be parsed as new commands.
 */
#ifndef AGENTCELL_NETUP_REPLY_H
#define AGENTCELL_NETUP_REPLY_H

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

/*
 * Decide the reply for a NETUP request.  `rep` already holds whatever
 * net_up() wrote (possibly empty):
 *   parsed == 0                 -> unparseable request
 *   parsed == 1, too_many       -> more EGRESS entries than MAX_EGRESS
 *   parsed == 1, !too_many      -> net_up() ran; rc != 0 means it failed
 *
 * A specific daemon error ("ERR egress_unresolved <host>", …) is kept; only
 * a failed net_up() that named no reason becomes the generic reply.
 */
static inline void netup_reply(int parsed, int too_many, int rc,
                               char *rep, size_t repn)
{
    if (!parsed) {
        snprintf(rep, repn, "ERR netup\n");
        return;
    }
    if (too_many) {
        snprintf(rep, repn, "ERR egress_too_many_hosts\n");
        return;
    }
    if (rc != 0 && rep[0] == '\0')
        snprintf(rep, repn, "ERR netup\n");
    /* else: keep net_up()'s "OK …" or specific "ERR egress_*" */
}

/*
 * A cell that asked for egress but sent no nameservers cannot be resolved
 * the way the cell resolves.  Falling back to getaddrinfo() on the host
 * stub re-creates the resolver skew this path exists to avoid, so net_up()
 * refuses such a request with "ERR egress_no_resolv".
 */
static inline int egress_no_resolv(int n_eg, int n_ns)
{
    return n_eg > 0 && n_ns == 0;
}

/*
 * After an over-long line was rejected, how many bytes after its first
 * newline must be kept (parsing resumes there)?  Returns -1 while no
 * newline has arrived yet.  `data` is the freshly read chunk.
 */
static inline ssize_t drain_resume(const char *data, size_t n)
{
    const char *nl = memchr(data, '\n', n);
    if (!nl) return -1;
    return (ssize_t)(n - (size_t)(nl - data) - 1);
}

#endif /* AGENTCELL_NETUP_REPLY_H */
