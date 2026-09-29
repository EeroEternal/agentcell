/*
 * contract_test.c — unit tests for the agentlsm control-protocol decisions
 * that regressed silently and had no automated coverage: the NETUP reply
 * policy (netup_reply) and the over-long-line drain math (drain_resume).
 *
 * Build with: make tests/contract_test   (or `make check`)
 * Runs unprivileged: no BPF, no root, no daemon, no iptables.
 */
#include <stdio.h>
#include <string.h>

#include "../src/netup_reply.h"

static int failures;

static void expect_reply(int parsed, int too_many, int rc,
                         const char *initial, const char *want,
                         const char *what)
{
    char rep[128];
    snprintf(rep, sizeof rep, "%s", initial);
    netup_reply(parsed, too_many, rc, rep, sizeof rep);
    if (strcmp(rep, want)) {
        fprintf(stderr, "FAIL %s: got %s want %s\n", what, rep, want);
        failures++;
    }
}

static void expect_drain(const char *data, ssize_t want, const char *what)
{
    ssize_t got = drain_resume(data, strlen(data));
    if (got != want) {
        fprintf(stderr, "FAIL %s: got %zd want %zd\n", what, got, want);
        failures++;
    }
}

int main(void)
{
    /* unparseable NETUP -> generic */
    expect_reply(0, 0, 0, "", "ERR netup\n", "unparsed");
    /* too many hosts -> specific, regardless of net_up */
    expect_reply(1, 1, 0, "", "ERR egress_too_many_hosts\n", "too many hosts");
    /* success: the OK reply is preserved */
    expect_reply(1, 0, 0, "OK vethc0 10.200.0.2 10.200.0.1 1 2\n",
                 "OK vethc0 10.200.0.2 10.200.0.1 1 2\n", "success preserved");
    /* daemon-named failure preserved -- the dead-code regression */
    expect_reply(1, 0, -1, "ERR egress_unresolved static.crates.io\n",
                 "ERR egress_unresolved static.crates.io\n",
                 "specific error preserved");
    expect_reply(1, 0, -1, "ERR egress_too_many_ips\n",
                 "ERR egress_too_many_ips\n", "too-many-ips preserved");
    /* net_up failed without naming a reason -> generic */
    expect_reply(1, 0, -1, "", "ERR netup\n", "unnamed failure");

    /* drain math: bytes to keep after the first newline */
    expect_drain("partial", -1, "drain: no newline");
    expect_drain("garbage\n", 0, "drain: newline at end");
    expect_drain("garbage\nNETDOWN 5\n", 10, "drain: keeps the tail");
    expect_drain("\nrest", 4, "drain: leading newline");

    if (failures) {
        fprintf(stderr, "contract_test: %d failure(s)\n", failures);
        return 1;
    }
    printf("contract_test: ok\n");
    return 0;
}
