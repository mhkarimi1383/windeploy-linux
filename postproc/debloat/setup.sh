#!/bin/bash

mnt="$(readlink -f "$1")"
cd "$(dirname "$0")"
../../reg_import.sh "$mnt" "$PWD/debloat.reg"

provisioned_apps="$(hivexregedit --export "$mnt/Windows/System32/config/SOFTWARE" 'Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications' --max-depth=2 --prefix="HKEY_LOCAL_MACHINE\SOFTWARE" |grep '^\[' | tail -n +2 | cut -d'\' -f9 | tr -d ']')"

{
    echo "Windows Registry Editor Version 5.00"
    echo
    echo '[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned]'
    echo

    for pkg in $provisioned_apps; do
        echo '[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\'"$pkg"']'
        echo
        echo '[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Staged\'"$pkg"']'
        echo
        echo '[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Config\'"$pkg"']'
        echo
        # Adding to 'Deprovisioned' should prevent re-installing app upon windows upgrade
        echo '[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\'"$pkg"']'
        echo
        rm -rf "$mnt/Program\ Files/WindowsApps/$pkg"
    done
} > /tmp/deprovision.reg
../../reg_import.sh "$mnt" "/tmp/deprovision.reg"
