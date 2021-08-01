#!/bin/bash

mnt="$1"
regfile="$2"

extract_prefix() {
    local regfile="$1"
    local prefix="$2"
    local prefix_esc="$(echo "$prefix" | sed -re 's#\\#\\\\#g')"
    cat "$regfile" \
        | dos2unix \
        | grep -E '^[^;]' \
        | awk '/^Windows Re/ { print;  want=1;   next;} /^\[-?'"$prefix_esc"'/ { want=1; print ""; print; next;} /^\[/ { want=0; } (want) { print;}' \
        | sed -re 's/CurrentControlSet/ControlSet001/g'
}

import_hive() {
    local regfile="$1"
    local prefix="$2"
    local hive="$3"
    if grep -qF "[$prefix" "$regfile"; then
        echo "Importing $prefix -> $hive"
        extract_prefix "$regfile" "$prefix" | hivexregedit --merge --prefix "$prefix" "$hive"
    fi
}

import_hive "$regfile" 'HKEY_LOCAL_MACHINE\SYSTEM'   "$mnt/Windows/System32/config/SYSTEM"
import_hive "$regfile" 'HKEY_LOCAL_MACHINE\SOFTWARE' "$mnt/Windows/System32/config/SOFTWARE"

import_hive "$regfile" 'HKEY_CURRENT_USER'      "$mnt/Users/Default/NTUSER.DAT"
