#!/bin/bash

mnt="$(readlink -f "$1")"

my_dir="$(dirname "$0")"
cd "$my_dir"

if [[ ! -e OpenSSH-Win64 ]]; then
    # adapted from https://github.com/PowerShell/Win32-OpenSSH/wiki/How-to-retrieve-links-to-latest-packages
    url="$(curl -v https://github.com/PowerShell/Win32-OpenSSH/releases/latest/ 2>&1 |grep -i '< location:'  | awk '{print $3}' |tr -d '\r\n'|sed -re 's/tag/download/')/OpenSSH-Win64.zip"
    curl "$url" -Lfo OpenSSH-Win64.zip
    unzip OpenSSH-Win64
fi
cp -rT OpenSSH-Win64 "$mnt/Program Files/OpenSSH"

hivexregedit --merge --prefix 'HKEY_LOCAL_MACHINE\SYSTEM' "$mnt"/Windows/System32/config/SYSTEM "$my_dir/sshd_service.reg"
hivexregedit --merge --prefix 'HKEY_LOCAL_MACHINE\SYSTEM' "$mnt"/Windows/System32/config/SYSTEM "$my_dir/sshd_firewall.reg"
"$my_dir/openssh_acl.py" "$mnt"

