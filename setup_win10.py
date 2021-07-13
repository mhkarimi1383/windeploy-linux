#!/usr/bin/python3

import sys,os,shutil
import time
import string
import clize
from clize import ArgumentError, Parameter
import argparse
from contextlib import *
from pathlib import Path
import subprocess
import tempfile
import parted

def is_part(pth):
    pth = Path(pth)
    if not pth.is_block_device(): raise RuntimeError("Not a block device, cannot determine partition-ness")
    sys_path = Path("/sys/class/block") / pth.name
    if not sys_path.exists(): raise RuntimeError("{sys_path} does not exist (for {pth})")
    return (sys_path / 'partition').exists()



@contextmanager
def with_device(pth):
    pth = Path(pth)
    if pth.is_file():
        r = subprocess.run(['losetup', '--show', '-f', '-P', pth], check=True, capture_output=True)
        dev = Path(r.stdout.decode('ascii').strip())
        if not dev.is_block_device():
            raise RuntimeError(f"Cannot find loop device {dev}")
        try:
            yield dev
        finally:
            subprocess.run(['losetup', '-d', dev])
    elif pth.is_block_device():
        pass

def ci_lookup(base, *comps, creating=False, parents=False):
    """Lookup path components case-insensitively"""
    cur = Path(base)
    for idx, comp in enumerate(comps):
        cands = [ item for item in cur.iterdir() if  item.name.lower() == comp.lower() ]
        if not cands:
            if creating and idx == len(comps) - 1:
                cur = cur / comp
                break
            elif parents and idx < len(comps) - 1:
                cur = cur / comp
                cur.mkdir()
                continue
            else:
                raise FileNotFoundError(f"'{comp}' not found case-insensitively in '{cur}'")
        elif len(cands) > 1:
            raise RuntimeError(f"Multiple case-insensitive candidates for '{comp}' in '{cur}': {cands}")
        else:
            cur = cands[0]
    return cur


@contextmanager
def with_iso(iso):
    with ExitStack() as es:
        dir = Path(tempfile.mkdtemp(prefix="win10_iso_"))
        es.callback(lambda: dir.rmdir())
        subprocess.run(['mount', '-o', 'loop,ro', '-t', 'udf', str(iso), str(dir)], check=True)
        es.callback(lambda: subprocess.run(['umount', dir]))
        wim = ci_lookup(dir, 'sources', 'install.wim')
        yield wim

@contextmanager
def with_mounted(part):
    part = Path(part)
    with ExitStack() as es:
        dir = Path(tempfile.mkdtemp(prefix=f"ntfs_{part.name}_"))
        es.callback(lambda: dir.rmdir())
        subprocess.run(['ntfs-3g', str(part), dir], check=True)
        es.callback(lambda: subprocess.run(['umount', dir]))
        yield dir


def create_partitions(dev):
    with open(dev, 'r+b') as fh:
        fh.write(bytearray(4096)) # clear MBR and other metadata

    device = parted.Device(str(dev))
    disk = parted.freshDisk(device, 'msdos')
    geometry = parted.Geometry(device=device, start=2048,
                               length=device.getLength() - 2048)
    filesystem = parted.FileSystem(type='ntfs', geometry=geometry)
    partition = parted.Partition(disk=disk, type=parted.PARTITION_NORMAL,
                                 fs=filesystem, geometry=geometry)
    disk.addPartition(partition=partition,
                      constraint=device.optimalAlignedConstraint)
    partition.setFlag(parted.PARTITION_BOOT)
    disk.commit()


def part_path(dev, partno):
    dev = Path(dev)
    return dev.parent / f"{dev.name}{'p' if dev.name[-1] in string.digits else ''}{partno}"


def format_part(part):
    cmd = ['mkntfs', '-vv', '-f', '-S', '63', '-H', '255', '--partition-start', '2048', str(part)]
    subprocess.run(cmd, check=True)


def apply_wim(part, wim, image_name):
    subprocess.run(['wimapply', str(wim), str(image_name), str(part)], check=True)

def setup_vbr(part):
    subprocess.run(['ms-sys', '-f', '--ntfs', str(part)], check=True)

def setup_mbr(disk):
    subprocess.run(['ms-sys', '-f', '--mbr7', str(disk)], check=True)

def copy_boot_files(dir):
    shutil.copy(ci_lookup(dir, 'Windows', 'Boot', 'PCAT', 'bootmgr'), ci_lookup(dir, 'bootmgr', creating=True))
    boot_dir = ci_lookup(dir, 'Boot', creating=True)
    boot_dir.mkdir(exist_ok=True)
    shutil.copy(Path(__file__).parent / 'BCD', ci_lookup(boot_dir, 'BCD', creating=True))


def setup_part(part, wim, image_name, *, unattend=None, postproc=None):
    format_part(part)
    setup_vbr(part)
    apply_wim(part, wim, image_name)
    with with_mounted(part) as dir:
        copy_boot_files(dir)
        if unattend:
            trg = ci_lookup(dir, 'Windows', 'Panther', 'unattend.xml', creating=True, parents=True)
            print(f"Copying unattend file: {unattend} -> {trg}")
            shutil.copy(unattend, trg)
        if postproc:
            if '/' not in postproc: postproc = f"./{postproc}"
            subprocess.run([str(postproc), dir])


def exactly_one(*a):
    return sum( bool(x) for x in a ) == 1

def main(*, disk=None, part=None, wim=None, iso=None, image_name=None, unattend=None, postproc=None):
    if not exactly_one(disk, part):
        raise ArgumentError("You must specify exactly one of 'disk', 'part'")
    if not exactly_one(wim, iso):
        raise ArgumentError("You must specify exactly one of 'wim', 'iso'")
    with ExitStack() as es:
        if iso:
            wim = es.enter_context(with_iso(iso))
        if disk:
            create_partitions(disk)
            with with_device(disk) as dev:
                create_partitions(dev)
                setup_mbr(dev)
                part = part_path(dev, 1)
                setup_part(part, wim, image_name, unattend=unattend, postproc=postproc)
        else:
            setup_part(part, unattend=unattend, postproc=postproc)

if __name__ == '__main__':
    clize.run(main)



