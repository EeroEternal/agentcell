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
BPFFLAGS = -target bpf -D__TARGET_ARCH_x86 -O2 -g -idirafter /usr/include/$(shell $(CC) -dumpmachine)
# -idirafter: clang -target bpf doesn't search gcc's multiarch include dir
# (asm/types.h lives there on Debian/Ubuntu; harmless if absent, e.g. Arch)

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

# BPF LSM enforcement (needs root at runtime, bpftool only at build)
LSMOBJ = src/agentlsm.bpf.o
LSMHDR = src/agentlsm.bpf.h

agentlsm: src/agentlsm.c $(LSMHDR)
	$(CC) $(CFLAGS) -include $(LSMHDR) -o $@ src/agentlsm.c -lbpf -lelf -lz

$(LSMOBJ): src/agentlsm.bpf.c src/vmlinux.h
	$(CLANG) $(BPFFLAGS) -Isrc -c $< -o $@

$(LSMHDR): $(LSMOBJ)
	xxd -i $< > $@
	sed -i 's/src_agentlsm_bpf_o/bpf_elf/g' $@

src/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/vmlinux.h

check: all
	tests/run.sh

# C ABI library (RFC 0001, Gap 5) — same isolation code as the CLI
libagentcell.a: src/libagentcell.c src/sand.c src/agentcell.h
	$(CC) $(CFLAGS) -c src/libagentcell.c -o libagentcell.o
	ar rcs $@ libagentcell.o

ffi-demo: libagentcell.a examples/ffi_demo.c
	$(CC) $(CFLAGS) -o ffi-demo examples/ffi_demo.c -L. -lagentcell

# Fast path on Arch: packed rootfs + pre-warmed cells (no clone per command)
ROOTFS ?= os/out/cell-root
SIZE   ?= 4

rootfs:
	os/cell-root/build.sh --minimal $(ROOTFS)

rootfs-host:
	os/cell-root/build.sh --from-host $(ROOTFS)

pool: sand
	@[ -d $(ROOTFS)/usr ] || $(MAKE) rootfs
	python3 os/agentcelld/pool.py --size $(SIZE) -- --rootfs $(abspath $(ROOTFS))

pool-exec: sand
	python3 os/agentcelld/pool.py exec -- $(CMD)

fast: sand rootfs
	os/fast.sh

all: sand agentmon agentlsm

.PHONY: all clean check lib ffi-demo rootfs rootfs-host pool pool-exec fast
