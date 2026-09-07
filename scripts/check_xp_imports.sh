#!/usr/bin/env bash
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
#
# Refuse a 32-bit Windows image that names an entry point Windows XP
# does not export.
#
# XP loadability is a question about symbols, not about DLLs: the
# version boundary runs through KERNEL32 and WS2_32 rather than between
# them, and the loader resolves imports eagerly, so a single Vista-only
# name fails the whole image. An import table listing only XP-era DLLs
# is consistent with that and says nothing about it.
#
# This is a denylist and therefore incomplete by construction. It names
# the entry points that have actually been reached for here -- a
# condition variable, a 64-bit tick count, a one-time initialiser, a
# presentation-form converter -- so that reintroducing one is reported
# rather than discovered on the target. A name not on this list is not
# thereby XP-safe.
#
# Usage: check_xp_imports.sh <objdump> <image>...

set -e

OBJDUMP=${1:?usage: check_xp_imports.sh <objdump> <image>...}
shift

# Vista or later, all of them exported from a DLL that exists on XP.
DENY='GetTickCount64
InitOnceExecuteOnce
InitOnceBeginInitialize
InitOnceComplete
InitializeConditionVariable
SleepConditionVariableCS
SleepConditionVariableSRW
WakeConditionVariable
WakeAllConditionVariable
InitializeSRWLock
AcquireSRWLockExclusive
AcquireSRWLockShared
ReleaseSRWLockExclusive
ReleaseSRWLockShared
InitializeCriticalSectionEx
CreateEventExA
CreateEventExW
CreateThreadpoolWork
SubmitThreadpoolWork
CloseThreadpoolWork
GetLogicalProcessorInformationEx
inet_ntop
inet_pton
InetNtopW
InetPtonW'

status=0

for image in "$@"; do
    [ -e "$image" ] || continue

    imports=$("$OBJDUMP" -p "$image" |
              awk '/DLL Name:/{dll=$3} /^\t[0-9a-f]+\t/{print $3}')

    # Positive control first: an empty read would make every absence
    # assertion below pass against nothing at all.
    if ! printf '%s\n' "$imports" | grep -qx "GetLastError"; then
        echo "check_xp_imports: FATAL — no import table read from $image" >&2
        exit 1
    fi

    # An `if` and not `! grep -q`: under `set -e` a command preceded by
    # `!` is exempt from errexit, so the negated form would find a
    # forbidden symbol and let the script continue green.
    while IFS= read -r sym; do
        [ -n "$sym" ] || continue
        if printf '%s\n' "$imports" | grep -qx "$sym"; then
            echo "check_xp_imports: FATAL — $(basename "$image")" \
                 "imports $sym, which XP does not export" >&2
            status=1
        fi
    done <<EOF
$DENY
EOF
done

exit $status
