# AgentCell — low-level AI-agent sandbox (Arch/Omarchy, kernel 6.x/7.x)
#
#   sand       : the sandbox launcher      (unprivileged)
#   agentmon   : eBPF audit monitor        (run as root)
#   agentmon.bpf.o : eBPF probes (compiled by clang -target bpf)

CLANG ?= clang
CC    ?= cc
BPFOBJ = src/agentmon.bpf.o
BPFHDR = src/agentmon.bpf.h

CFLAGS  = -O2 -g -Wall -Wextra -Wno-format-truncation
BPFFLAGS = -target bpf -D__TARGET_ARCH_x86 -O2 -g

all: sand agentmon

sand: src/sand.c
	$(CC) $(CFLAGS) -o $@ $<

$(BPFOBJ): src/agentmon.bpf.c
	$(CLANG) $(BPFFLAGS) -c $< -o $@

# embed the BPF ELF as a C array so the loader needs no external .o
$(BPFHDR): $(BPFOBJ)
	xxd -i $< > $@
	sed -i 's/src_agentmon_bpf_o/bpf_elf/g' $@

agentmon: src/agentmon.c $(BPFHDR)
	$(CC) $(CFLAGS) -include $(BPFHDR) -o $@ src/agentmon.c -lbpf -lelf -lz

clean:
	rm -f sand agentmon $(BPFOBJ) $(BPFHDR)

.PHONY: all clean
