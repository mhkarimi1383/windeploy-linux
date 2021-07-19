#!/bin/bash

mnt="$(readlink -f "$1")"
cd "$(dirname "$0")"
../../reg_import.sh "$mnt" "$PWD/debloat.reg"
