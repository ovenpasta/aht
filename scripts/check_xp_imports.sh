#!/usr/bin/env bash
#  Copyright (C) 2026 Aldo Nicolas Bruno
#  SPDX-License-Identifier: Apache-2.0
#
# Refuse a 32-bit Windows image that imports an entry point Windows
# XP does not export. The loader resolves imports eagerly, so one
# Vista-only name in KERNEL32 or WS2_32 fails the whole image; an
# import table listing only XP-era DLLs says nothing about it.
#
# Usage: check_xp_imports.sh <objdump> <image>...
# Exit 0 when no image imports a denied name, 1 otherwise or when an
# import table cannot be read.
#
# A denylist, so incomplete: it names the entry points this code base
# has reached for (condition variables, a 64-bit tick count, one-time
# initialisers, inet_pton). A name not on it is not thereby XP-safe.

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
        echo "check_xp_imports: FATAL - no import table read from $image" >&2
        exit 1
    fi

    # An `if`, not `! grep -q`: under `set -e` a `!` command is exempt
    # from errexit, so a hit would let the script continue green.
    while IFS= read -r sym; do
        [ -n "$sym" ] || continue
        if printf '%s\n' "$imports" | grep -qx "$sym"; then
            echo "check_xp_imports: FATAL - $(basename "$image")" \
                 "imports $sym, which XP does not export" >&2
            status=1
        fi
    done <<EOF
$DENY
EOF
done

exit $status
