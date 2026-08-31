#!/usr/bin/env bash
# Fast path on Arch: packed --rootfs + pre-warmed cell pool.
# Isolation is paid once; each command is sand exec into an idle cell.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
SIZE=${SIZE:-4}

make -s sand
if [ ! -x os/out/cell-root/usr/bin/echo ] && [ ! -x os/out/cell-root/bin/echo ]; then
    echo "fast: packing os/out/cell-root (minimal toolchain)" >&2
    os/cell-root/build.sh --minimal "$ROOT/os/out/cell-root"
fi

echo "fast: pool size=$SIZE rootfs=$ROOT/os/out/cell-root" >&2
echo "fast: in another terminal:  make pool-exec CMD='echo hi'" >&2
exec python3 os/agentcelld/pool.py --size "$SIZE" -- --rootfs "$ROOT/os/out/cell-root"
