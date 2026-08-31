# AgentCell OS — phase 1 (tree in-repo)

A full bootable distro is **not** in this directory. That is months of
kernel + init + image work. What *is* here is the first cut of the
[design](../docs/agentcell-os.md), runnable on the host you already have.

| Piece | Status | What it is |
|---|---|---|
| `kernel/agentcell.config` | fragment | merge into a custom kernel; not a built `vmlinux` |
| `kernel/cmdline` | ready | `lsm=` line for the dedicated host |
| `cell-root/build.sh` | script | pack a read-only cell root (squashfs or erofs) |
| `agentcelld/pool.py` | **works today** | pre-warm `sand serve` cells; exec without cloning each time |
| ISO / mkosi image | not started | next phase |

```bash
# from the repo root
python3 os/agentcelld/pool.py --size 4          # pre-warm 4 cells
# another terminal:
python3 os/agentcelld/pool.py exec -- echo hi   # ~serve-mode latency, no new clone
```

Pack a directory tree and boot the jail from it (no live `/usr` bind):

```bash
os/cell-root/build.sh --minimal /tmp/cell-root
./sand --rootfs /tmp/cell-root -- echo hi
# .img / .squashfs: needs mkfs.erofs or mksquashfs; then mount and pass the mountpoint
```

## What “creating the OS” still needs

1. Kernel built with `kernel/agentcell.config` merged, boot with `kernel/cmdline`.
2. mkosi/archiso image: that kernel + `agentcelld` + `sand` + erofs cell-root.
3. `sand --rootfs` so the jail mounts one image instead of bind `/usr`.
4. Pooled veth pairs inside `agentcelld` (today `--net veth` still calls `ip link add`).

Until (3), `pool.py` already delivers the **biggest speed win** in the design:
do not `clone` six namespaces per agent command.
