#!/usr/bin/env bash
# AgentCell regression suite — `make check`
#
# Unprivileged tests always run. Privileged tests (agentmon probes,
# agentlsm enforcement) run when `sudo -n` works and are skipped with
# a note otherwise. Every test cleans up after itself; the suite never
# leaves a cell, daemon, or BPF program behind.
set -u
cd "$(dirname "$0")/.."

# isolate cell sockets/infos from the real session
RT=$(mktemp -d /tmp/agentcell-check.XXXXXX)
export XDG_RUNTIME_DIR="$RT"
LOG="$RT/suite.log"
: > "$LOG"

# ---- tiny framework ----------------------------------------------------
C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_B=$'\033[1m'; C_0=$'\033[0m'
n_pass=0; n_fail=0; n_skip=0
pass(){ n_pass=$((n_pass+1)); printf '  %sok%s   %s\n' "$C_G" "$C_0" "$1"; }
fail(){ n_fail=$((n_fail+1)); printf '  %sFAIL%s %s   (log: %s)\n' "$C_R" "$C_0" "$1" "$LOG"; }
skip(){ n_skip=$((n_skip+1)); printf '  %sskip%s %s (%s)\n' "$C_Y" "$C_0" "$1" "${2:-}"; }
section(){ printf '\n%s== %s ==%s\n' "$C_B" "$1" "$C_0"; }

# t_ok NAME cmd...        — expect exit 0
t_ok(){ local n=$1; shift
        if "$@" >>"$LOG" 2>&1; then pass "$n"; else fail "$n"; fi; }
# t_no NAME cmd...        — expect nonzero exit
t_no(){ local n=$1; shift
        if "$@" >>"$LOG" 2>&1; then fail "$n"; else pass "$n"; fi; }
# t_out NAME PATTERN cmd... — expect PATTERN in stdout
t_out(){ local n=$1 p=$2; shift 2
         if "$@" >>"$LOG" 2>&1 && grep -q -- "$p" "$LOG"; then pass "$n"
         else fail "$n"; fi
         : > "$LOG"; }
# t_rc NAME WANT cmd...   — expect exact exit code
t_rc(){ local n=$1 want=$2; shift 2
         "$@" >>"$LOG" 2>&1; [ $? = "$want" ] && pass "$n" || fail "$n"; }

wait_sock(){ # PATH — up to 5s for the serve socket to appear
    for _ in $(seq 50); do [ -S "$1" ] && return 0; sleep 0.1; done; return 1; }
wait_gone(){ # PATH
    for _ in $(seq 50); do [ ! -e "$1" ] && return 0; sleep 0.1; done; return 1; }

SUDO=sudo
[ "$(id -u)" = 0 ] && SUDO=""
sudook(){
    if [ -z "$SUDO" ]; then return 0; fi          # already root
    $SUDO -n true 2>/dev/null && return 0         # CI / cached
    $SUDO -v 2>/dev/null && return 0              # interactive: ask once
    return 1
}
lsmok(){ sudook && $SUDO cat /sys/kernel/security/lsm 2>/dev/null \
                  | tr ',' '\n' | grep -qx bpf; }

DAEMON_PID=""; CELL_PID=""
cleanup(){
    trap - EXIT
    [ -n "$CELL_PID" ] && kill "$CELL_PID" 2>/dev/null
    if [ -n "$DAEMON_PID" ]; then
        $SUDO pkill -TERM -x agentlsm 2>/dev/null
        for _ in $(seq 30); do $SUDO kill -0 "$DAEMON_PID" 2>/dev/null || break
                                 sleep 0.1; done
    fi
    rm -rf "$RT"
}
trap cleanup EXIT

# ---- 1. unprivileged: launcher basics ----------------------------------
section "build + cli"
for b in sand agentmon agentlsm; do
    [ -x "./$b" ] && pass "binary $b" || fail "binary $b"
done
t_out "sand --help mentions serve"   "serve"   ./sand --help
t_out "sand --help mentions lsm"     "lsm"     ./sand --help

section "one-shot sandbox"
t_out "run echo"          "hi"      ./sand -- /bin/echo hi
t_out "pid namespace"     "^1$"     ./sand -- /bin/sh -c 'echo $$'
t_ok  "tmpfs writable"     ./sand -- touch /tmp/agentcell-t
t_no  "seccomp: mount"    ./sand -- mount -t tmpfs none /tmp
t_no  "seccomp: unshare"  ./sand -- unshare -p true
t_no  "landlock+ro: /etc" ./sand -- touch /etc/agentcell-test
if ./sand --timeout 2 -- sleep 30 >>"$LOG" 2>&1; then
    fail "timeout kills payload"
else
    pass "timeout kills payload"
fi

section "serve mode + exec protocol"
./sand serve --timeout 60 >"$RT/serve.out" 2>&1 &
CELL_PID=$!
# the "serving <sock>" line lands after clone+mounts; poll for it
for _ in $(seq 50); do
    SOCK=$(grep -o "$RT/[^ ]*\.sock" "$RT/serve.out" | head -1)
    [ -n "$SOCK" ] && [ -S "$SOCK" ] && break
    sleep 0.1
done
if [ -n "${SOCK:-}" ] && [ -S "$SOCK" ]; then pass "serve socket"
else fail "serve socket"; fi
t_out "cells lists the cell" "agentcell-" ./sand cells
t_out "exec echo"      "hello"   ./sand exec "$SOCK" -- /bin/echo hello
t_out "exec stdin"     "piped"   sh -c "printf piped | ./sand exec $SOCK -- cat"
t_rc  "exec rc 0 propagates"  0 ./sand exec "$SOCK" -- /bin/true
t_rc  "exec rc 7 propagates"  7 ./sand exec "$SOCK" -- sh -c 'exit 7'
kill "$CELL_PID" 2>/dev/null; wait "$CELL_PID" 2>/dev/null
wait_gone "$SOCK" && pass "socket cleaned on stop" || fail "socket cleaned on stop"
CELL_PID=""

section "sand lsm without daemon"
if ./sand lsm >>"$LOG" 2>&1; then fail "lsm errors without daemon"
else pass "lsm errors without daemon"; fi

# ---- 2. privileged: agentmon probes -------------------------------------
if sudook; then
    section "agentmon (root)"
    $SUDO ./agentmon --cgid 0 >"$RT/mon.log" 2>&1 &
    MON=$!
    sleep 2
    if $SUDO kill -0 "$MON" 2>/dev/null; then pass "agentmon starts (--cgid 0)"
    else fail "agentmon starts (--cgid 0)"; fi
    /bin/cat /etc/hostname >/dev/null 2>&1     # generate an OPEN
    sleep 1
    grep -q "OPEN" "$RT/mon.log" && pass "agentmon sees OPEN" \
                                  || fail "agentmon sees OPEN"
    $SUDO kill -TERM "$MON" 2>/dev/null; wait "$MON" 2>/dev/null
else
    section "agentmon (root)"
    skip "agentmon probes" "no passwordless sudo"
fi

# ---- 3. privileged: agentlsm daemon + enforcement -----------------------
if lsmok; then
    section "agentlsm daemon (root, bpf LSM present)"

    $SUDO ./agentlsm serve >"$RT/lsm.log" 2>&1 &
    DAEMON_PID=$!
    if wait_sock /run/agentcell/lsm.sock; then pass "daemon socket"
    else fail "daemon socket"; fi

    # a plain, unsecured cell — hot policy is applied to it later
    ./sand serve --timeout 90 >"$RT/cell.out" 2>&1 &
    CELL_PID=$!
    for _ in $(seq 50); do
        SOCK=$(grep -o "$RT/[^ ]*\.sock" "$RT/cell.out" | head -1)
        [ -n "$SOCK" ] && [ -S "$SOCK" ] && break
        sleep 0.1
    done
    if [ -n "${SOCK:-}" ] && [ -S "$SOCK" ]; then pass "cell socket"
    else fail "cell socket"; fi
    NAME=$(basename "$SOCK")

    t_out "baseline: hostname readable" "$(cat /etc/hostname)" \
          ./sand exec "$SOCK" -- cat /etc/hostname

    # hot deny -> EPERM inside, host unaffected, event with cell name
    ./sand lsm -f >"$RT/follow.log" 2>&1 &
    WATCH=$!
    sleep 0.5
    t_ok  "hot deny rule"           ./sand lsm deny "$NAME" /etc/hostname
    if ./sand exec "$SOCK" -- cat /etc/hostname >>"$LOG" 2>&1; then
        fail "deny enforced in-cell"
    else
        grep -q "Operation not permitted" "$LOG" \
            && pass "deny enforced in-cell" || fail "deny enforced in-cell"
    fi
    : > "$LOG"
    t_out "host unaffected"   "$(cat /etc/hostname)"  cat /etc/hostname
    sleep 0.5
    grep -q "DENY /etc/hostname" "$RT/follow.log" \
        && pass "event streamed with cell name" || fail "event streamed"
    kill "$WATCH" 2>/dev/null

    # hot allow -> readable again
    t_ok "hot allow rule" ./sand lsm allow "$NAME" /etc/hostname
    t_out "allow effective" "$(cat /etc/hostname)" \
          ./sand exec "$SOCK" -- cat /etc/hostname

    # reset + --secure cell registering its defaults while alive
    t_ok "reset rules" ./sand lsm reset "$NAME"
    ./sand --secure --timeout 10 -- sleep 8 >"$RT/sec.out" 2>&1 &
    SEC_CELL=$!
    sleep 1
    grep -q "LSM armed" "$RT/sec.out" && pass "--secure arms via daemon" \
                                        || fail "--secure arms via daemon"
    ./sand lsm | grep -q "/etc/shadow" \
        && pass "--secure default rules visible" \
        || fail "--secure default rules visible"
    wait "$SEC_CELL" 2>/dev/null

    # cell exit unregisters
    kill "$CELL_PID" 2>/dev/null; wait "$CELL_PID" 2>/dev/null; CELL_PID=""
    sleep 0.5
    if ./sand lsm | grep -q "$NAME"; then fail "auto-CLR on cell exit"
    else pass "auto-CLR on cell exit"; fi

    # block-all, scoped to a throwaway cell: kernel-side time-bounded
    # deny-everything window.  The SYSTEM-WIDE variant is intentionally
    # not run here — it EPERMs every open on the machine, including the
    # shell/agent harness running this suite (it once killed the AI
    # agent mid-run with "Error: EPERM: operation not permitted, open").
    ./sand serve --timeout 30 >"$RT/cell2.out" 2>&1 &
    CELL_PID=$!
    SOCK=""
    for _ in $(seq 50); do
        SOCK=$(grep -o "$RT/[^ ]*\.sock" "$RT/cell2.out" | head -1)
        [ -n "$SOCK" ] && [ -S "$SOCK" ] && break
        sleep 0.1
    done
    CG=""; [ -n "$SOCK" ] && CG=$(sed -n 's/^cg=//p' "$SOCK.info")
    if [ -z "$SOCK" ] || [ ! -S "$SOCK" ] || [ -z "$CG" ] || [ "$CG" = - ]; then
        fail "block-all: cell with cgroup"
    else
        $SUDO ./agentlsm --block-all 1 --cgroup "$CG" >"$RT/blk.log" 2>&1 &
        BLK=$!
        sleep 0.8        # 0.5s grace over; now inside the deny window
        if ./sand exec "$SOCK" -- cat /etc/hostname >>"$LOG" 2>&1; then
            fail "scoped block-all denies in-cell"
        else
            pass "scoped block-all denies in-cell"
        fi
        : > "$LOG"
        t_out "scoped block-all: host unaffected" "$(cat /etc/hostname)" \
              cat /etc/hostname
        wait "$BLK" 2>/dev/null
        t_out "block-all window self-expires" "$(cat /etc/hostname)" \
              ./sand exec "$SOCK" -- cat /etc/hostname
    fi
    kill "$CELL_PID" 2>/dev/null; wait "$CELL_PID" 2>/dev/null; CELL_PID=""

    # manual debug hammer, opt-in only: denies EVERY open system-wide
    if [ "${AGENTCELL_TEST_BLOCK_ALL_GLOBAL:-}" = 1 ]; then
        $SUDO ./agentlsm --block-all 0.5 >"$RT/blk.log" 2>&1 &
        BLK=$!
        sleep 0.6
        denied=0
        for _ in $(seq 10); do
            cat /etc/hostname >/dev/null 2>&1 || denied=1
            sleep 0.1
        done
        wait "$BLK" 2>/dev/null
        if [ "$denied" = 1 ]; then pass "block-all denies in window"
        else fail "block-all denies in window"; fi
        cat /etc/hostname >/dev/null 2>&1 && pass "block-all self-expires" \
                                            || fail "block-all self-expires"
    else
        skip "system-wide block-all" \
             "AGENTCELL_TEST_BLOCK_ALL_GLOBAL=1 to opt in (EPERMs the whole machine)"
    fi

    $SUDO pkill -TERM -x agentlsm 2>/dev/null
    wait_gone /run/agentcell/lsm.sock && pass "daemon cleans socket" \
                                        || fail "daemon cleans socket"
    DAEMON_PID=""
elif sudook; then
    section "agentlsm daemon (root)"
    skip "agentlsm enforcement" "bpf not in /sys/kernel/security/lsm"
fi

# ---- summary ------------------------------------------------------------
printf '\n%s%d passed, %d failed, %d skipped%s\n' \
    "$C_B" "$n_pass" "$n_fail" "$n_skip" "$C_0"
[ "$n_fail" = 0 ]
