/* arch selector for AgentCell syscall abstraction (RFC 0001, Gap 1).
 * Works for native builds (__x86_64__/__aarch64__) AND clang BPF
 * builds (-D__TARGET_ARCH_x86 / -D__TARGET_ARCH_arm64). */
#ifndef AGENTCELL_SYSCALLS_H
#define AGENTCELL_SYSCALLS_H

#if defined(__x86_64__) || defined(__TARGET_ARCH_x86)
#include "x86_64.h"
#elif defined(__aarch64__) || defined(__TARGET_ARCH_arm64)
#include "aarch64.h"
#else
#error "AgentCell: unsupported architecture (x86_64 and aarch64 only)"
#endif

#endif
