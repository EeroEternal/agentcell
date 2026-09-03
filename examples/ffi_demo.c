/* ffi_demo.c — embed AgentCell from C (RFC 0001, Gap 5).
 *
 *   make ffi-demo && ./ffi-demo
 *
 * Spawns `sh -c 'echo ...; exit 7'` in a jail with pipes for stdio,
 * reads the complete output, checks the exact exit code — the Keel
 * integration shape (Rust links the same ABI, see RFC 0001).
 */
#include "../src/agentcell.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    int in_pipe[2], out_pipe[2];
    if (pipe(in_pipe) || pipe(out_pipe)) { perror("pipe"); return 1; }

    struct agentcell_config cfg = {0};
    cfg.mem_bytes = 512UL << 20;
    cfg.cpu_cores = 1.0;
    cfg.pids      = 32;

    const char *argv[] = { "sh", "-c", "echo hi-from-ffi; id -u; exit 7", NULL };
    /* HOME/PATH are ours to choose when envp is given */
    const char *envp[] = { "HOME=/home/agent", "PATH=/usr/bin:/bin", NULL };

    pid_t pid;
    int rc = agentcell_spawn(&cfg, argv, envp,
                             in_pipe[0], out_pipe[1], out_pipe[1], &pid);
    if (rc < 0) {
        fprintf(stderr, "spawn failed: %s\n", strerror(-rc));
        return 1;
    }
    close(in_pipe[0]);
    close(in_pipe[1]);         /* stdin EOF immediately */
    close(out_pipe[1]);

    printf("jailed pid %d; output:\n", pid);
    char buf[4096];
    ssize_t n;
    while ((n = read(out_pipe[0], buf, sizeof buf)) > 0)
        fwrite(buf, 1, n, stdout);
    close(out_pipe[0]);

    int st = 0;
    waitpid(pid, &st, 0);
    agentcell_release(pid);
    printf("exit code: %d (want 7)\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    return WIFEXITED(st) && WEXITSTATUS(st) == 7 ? 0 : 1;
}
