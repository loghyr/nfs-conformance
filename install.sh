#!/bin/sh
# SPDX-FileCopyrightText: 2026 Tom Haynes <loghyr@gmail.com>
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0-only
#
# install.sh -- copy (or symlink) cthon26 xfstests wrappers into an
# existing xfstests checkout.
#
# Usage:
#   install.sh /path/to/xfstests           # copy
#   install.sh --symlink /path/to/xfstests # symlink (dev mode)
#   install.sh --dry-run /path/to/xfstests # show what would happen
#
# The destination must be an xfstests checkout with tests/nfs/ and
# common/ directories.  Existing files with the same names are
# overwritten; use --backup to keep timestamped copies.

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
MODE=copy
DRY=0
BACKUP=0
DEST=""

usage() {
    sed -n '4,18p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --symlink) MODE=symlink; shift;;
        --dry-run) DRY=1; shift;;
        --backup)  BACKUP=1; shift;;
        -h|--help) usage; exit 0;;
        -*) echo "install.sh: unknown option $1" >&2; exit 2;;
        *)  DEST="$1"; shift;;
    esac
done

if [ -z "$DEST" ]; then
    echo "install.sh: missing xfstests destination directory" >&2
    usage
    exit 2
fi

if [ ! -d "$DEST/tests/nfs" ] || [ ! -d "$DEST/common" ]; then
    echo "install.sh: $DEST does not look like an xfstests checkout" >&2
    echo "  (expected tests/nfs/ and common/ subdirectories)" >&2
    exit 2
fi

install_one() {
    src=$1
    dst=$2
    if [ $DRY -eq 1 ]; then
        echo "would $MODE: $src -> $dst"
        return
    fi
    if [ $BACKUP -eq 1 ] && [ -e "$dst" ]; then
        cp -p "$dst" "$dst.bak.$(date +%s)"
    fi
    case "$MODE" in
        copy)
            cp -p "$src" "$dst"
            ;;
        symlink)
            rm -f "$dst"
            ln -s "$src" "$dst"
            ;;
    esac
}

# Shared helper.
install_one "$SCRIPT_DIR/common/cthon26" "$DEST/common/cthon26"

# Test wrappers and their golden-output files.
for f in "$SCRIPT_DIR"/tests/nfs/*; do
    name=$(basename "$f")
    install_one "$f" "$DEST/tests/nfs/$name"
    # Test wrappers need to be executable.
    case "$name" in
        *.out) ;;
        *)     chmod +x "$DEST/tests/nfs/$name" 2>/dev/null || true;;
    esac
done

if [ $DRY -eq 0 ]; then
    n=$(ls "$SCRIPT_DIR/tests/nfs/" | grep -cEv '\.out$' || true)
    echo "Installed common/cthon26 + $n test wrappers into $DEST"
    echo ""
    echo "Next steps:"
    echo "  export CTHON26_BIN=/path/to/cthon26/nfsv42-tests"
    echo "  cd $DEST"
    echo "  ./check -nfs -g nfs"
fi
