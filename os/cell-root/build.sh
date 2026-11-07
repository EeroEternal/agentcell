#!/usr/bin/env bash
# Pack a read-only cell root (squashfs or erofs).
# Usage:
#   os/cell-root/build.sh --minimal OUT.img
#   os/cell-root/build.sh --from-host OUT.img   # copy host /usr /etc /bin … (large)
set -euo pipefail
MODE=minimal
OUT=""
while [ $# -gt 0 ]; do
    case $1 in
        --minimal) MODE=minimal; shift ;;
        --from-host) MODE=host; shift ;;
        -*) echo "unknown flag $1" >&2; exit 2 ;;
        *) OUT=$1; shift ;;
    esac
done
[ -n "$OUT" ] || { echo "usage: $0 [--minimal|--from-host] OUTDIR|OUT.img" >&2; exit 2; }

ST=$(mktemp -d /tmp/cell-root.XXXXXX)
chmod 0755 "$ST"
trap 'rm -rf "$ST"' EXIT

copy_bin() {
    local b=$1 dest=$ST/usr/bin
    mkdir -p "$dest"
    local p
    p=$(type -P "$b" 2>/dev/null) || p="/usr/bin/$b"
    [ -f "$p" ] || return 0
    cp -aL "$p" "$dest/"
    # copy .so deps (best-effort).  ldd prints the ELF interpreter as
    # "  /lib64/ld-linux... (0x...)" on Ubuntu (leading blanks, no "=>")
    # but as "/lib64/... => /lib64/..." on Arch — match both shapes
    ldd "$p" 2>/dev/null | awk '/=>/ {print $3} /^[[:space:]]*\// {print $1}' | while read -r so; do
        [ -f "$so" ] || continue
        mkdir -p "$ST$(dirname "$so")"
        # -L: dereference.  Ubuntu's ld-linux is itself a symlink
        # (../lib/x86_64-linux-gnu/...) — cp -a would copy a DANGLING
        # link and every payload would die with execvp ENOENT
        cp -anL "$so" "$ST$so" 2>/dev/null || true
    done
}

copy_so() {
    local name=$1 p
    p=$(ldconfig -p | awk -v name="$name" '$1 == name {path = $NF} END {print path}')
    [ -f "$p" ] || return 0
    mkdir -p "$ST$(dirname "$p")"
    cp -anL "$p" "$ST$p" 2>/dev/null || true
}

if [ "$MODE" = host ]; then
    echo "copying host /usr /etc (this is large)..." >&2
    mkdir -p "$ST"
    cp -a /usr "$ST/usr"
    cp -a /etc "$ST/etc"
    mkdir -p "$ST/bin" "$ST/lib" "$ST/lib64"
    # recreate usrmerge-style links if present
    [ -L /bin ] && cp -P /bin "$ST/bin" || true
    [ -L /lib ] && cp -P /lib "$ST/lib" || true
    [ -L /lib64 ] && cp -P /lib64 "$ST/lib64" || true
else
    mkdir -p "$ST/usr/bin" "$ST/etc" "$ST/tmp" "$ST/proc" "$ST/dev" "$ST/opt" "$ST/home/agent"
    echo "cell-root" > "$ST/etc/hostname"
    printf 'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n' > "$ST/etc/passwd"
    for b in bash sh cat echo ls true false pwd uname python3 \
             grep sed awk find xargs head tail wc sort uniq id env sleep \
             touch mkdir rm cp mv; do
        copy_bin "$b"
    done
    if command -v python3 >/dev/null 2>&1; then
        stdlib=$(python3 -c 'import sysconfig; print(sysconfig.get_paths()["stdlib"])')
        mkdir -p "$ST$(dirname "$stdlib")"
        cp -a "$stdlib" "$ST$(dirname "$stdlib")/"
        copy_so libffi.so.8
    fi
    ln -sfn usr/bin "$ST/bin"
    mkdir -p "$ST/usr/lib"
    # Ubuntu ldd copies land in real lib/ and lib64/ dirs — keep those
    # (they already satisfy the interpreter path); symlink only if empty
    [ -e "$ST/lib" ]   || ln -sfn usr/lib "$ST/lib"
    [ -e "$ST/lib64" ] || ln -sfn usr/lib "$ST/lib64"
fi

case $OUT in
    *.img|*.erofs|*.squashfs)
        if command -v mkfs.erofs >/dev/null; then
            mkfs.erofs -zlz4 "$OUT" "$ST"
            echo "wrote erofs $OUT" >&2
        elif command -v mksquashfs >/dev/null; then
            mksquashfs "$ST" "$OUT" -noappend -comp zstd
            echo "wrote squashfs $OUT" >&2
        else
            echo "install erofs-utils or squashfs-tools to pack images" >&2
            mkdir -p "$OUT.dir"
            cp -a "$ST"/. "$OUT.dir"/
            echo "wrote tree $OUT.dir instead" >&2
        fi
        ;;
    *)
        mkdir -p "$OUT"
        cp -a "$ST"/. "$OUT"/
        echo "wrote tree $OUT  (use: ./sand --rootfs $OUT -- CMD)" >&2
        ;;
esac
