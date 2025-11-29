#!/usr/bin/env python3

import sys
import shutil
import time
import string
from contextlib import ExitStack, contextmanager
from pathlib import Path
import subprocess
import tempfile
import parted
from ntfs_acl import *
import typer
from typing import Final

app = typer.Typer(
    name="windeploy-linux",
    help="Deploy Windows from Linux",
)

my_dir: Final[Path] = Path(__file__).parent
# allow postprocess scripts to import our python modules, especially ntfs_acl
os.environ["PYTHONPATH"] = f"{my_dir}:{os.environ.get('PYTHONPATH', '')}"  # type: ignore

ESP_SIZE: Final[int] = 300  # MiB

def is_part(pth):
    pth = Path(pth)
    if not pth.is_block_device():
        raise RuntimeError("Not a block device, cannot determine partition-ness")
    sys_path = Path("/sys/class/block") / pth.name
    if not sys_path.exists():
        raise RuntimeError("{sys_path} does not exist (for {pth})")
    return (sys_path / "partition").exists()


@contextmanager
def with_device(pth):
    pth = Path(pth)
    if pth.is_file():
        r = subprocess.run(
            ["losetup", "--show", "-f", "-P", pth], check=True, capture_output=True
        )
        dev = Path(r.stdout.decode("ascii").strip())
        if not dev.is_block_device():
            raise RuntimeError(f"Cannot find loop device {dev}")
        try:
            yield dev
        finally:
            subprocess.run(["losetup", "-d", dev])
    elif pth.is_block_device():
        time.sleep(1)
        subprocess.run(["partprobe", pth])
        time.sleep(1)
        yield pth
    else:
        raise Exception(f"'{pth}' is neither a file nor a block device")


def ci_lookup(base, *comps, creating=False, parents=False, mkdir=False):
    """Lookup path components case-insensitively"""
    cur = Path(base)
    for idx, comp in enumerate(comps):
        cands = [item for item in cur.iterdir() if item.name.lower() == comp.lower()]
        if not cands:
            if (creating or mkdir) and idx == len(comps) - 1:
                cur = cur / comp
                if mkdir:
                    cur.mkdir(exist_ok=True)
                break
            elif parents and idx < len(comps) - 1:
                cur = cur / comp
                cur.mkdir()
                continue
            else:
                raise FileNotFoundError(
                    f"'{comp}' not found case-insensitively in '{cur}'"
                )
        elif len(cands) > 1:
            raise RuntimeError(
                f"Multiple case-insensitive candidates for '{comp}' in '{cur}': {cands}"
            )
        else:
            cur = cands[0]
    return cur


@contextmanager
def with_iso(iso):
    with ExitStack() as es:
        dir = Path(tempfile.mkdtemp(prefix="win10_iso_"))
        es.callback(lambda: dir.rmdir())
        subprocess.run(
            ["mount", "-o", "loop,ro", "-t", "udf", str(iso), str(dir)], check=True
        )
        es.callback(lambda: subprocess.run(["umount", dir]))
        wim = str(ci_lookup(dir, "sources", "install.wim"))
        yield wim


@contextmanager
def with_mounted(part, *, fs="ntfs"):
    part = Path(part)
    with ExitStack() as es:
        dir = Path(tempfile.mkdtemp(prefix=f"win10_mnt_{part.name}_"))
        es.callback(lambda: dir.rmdir())
        cmd = ["mount", str(part), dir]
        if fs == "ntfs":
            cmd = ["ntfs-3g", "-o", "remove_hiberfile", str(part), dir]
        elif fs == "fat":
            cmd = ["mount", "-t", "vfat", str(part), dir]
        subprocess.run(cmd, check=True)
        es.callback(lambda: subprocess.run(["umount", dir]))
        yield dir

def create_partitions(dev, *, efi=False):
    with open(dev, "r+b") as fh:
        fh.write(bytearray(1024 * 1024))  # clear MBR and other metadata

    device = parted.Device(str(dev))
    esp_sec = None
    end_pad = None
    if efi:
        ptype = "gpt"
        esp_sec = parted.sizeToSectors(ESP_SIZE, "MiB", device.sectorSize)
        end_pad = parted.sizeToSectors(
            1, "MiB", device.sectorSize
        )  # leave space for secondary part table at the end
        extra_space = esp_sec + end_pad
    else:
        ptype = "msdos"
        extra_space = 0

    disk = parted.freshDisk(device, ptype)
    start = parted.sizeToSectors(1, "MiB", device.sectorSize)
    geometry = parted.Geometry(
        device=device, start=start, length=device.getLength() - start - extra_space
    )
    filesystem = parted.FileSystem(type="ntfs", geometry=geometry)
    partition = parted.Partition(
        disk=disk, type=parted.PARTITION_NORMAL, fs=filesystem, geometry=geometry
    )
    disk.addPartition(partition=partition, constraint=device.optimalAlignedConstraint)


    if efi:  # create ESP
        geometry = parted.Geometry(
            device=device, start=device.getLength() - esp_sec - end_pad, length=esp_sec
        )
        filesystem = parted.FileSystem(type="fat32", geometry=geometry)
        partition = parted.Partition(
            disk=disk, type=parted.PARTITION_NORMAL, fs=filesystem, geometry=geometry
        )
        disk.addPartition(
            partition=partition, constraint=device.optimalAlignedConstraint
        )

    partition.setFlag(parted.PARTITION_BOOT)

    disk.commit()


def part_path(dev, partno):
    dev = Path(dev)
    return (
        dev.parent / f"{dev.name}{'p' if dev.name[-1] in string.digits else ''}{partno}"
    )


def format_part(part):
    cmd = [
        "mkntfs",
        "-vv",
        "-f",
        "-S",
        "63",
        "-H",
        "255",
        "--partition-start",
        "2048",
        str(part),
    ]
    subprocess.run(cmd, check=True)


def apply_wim(part, wim, image_name):
    subprocess.run(["wimapply", str(wim), str(image_name), str(part)], check=True)


def setup_vbr(part):
    subprocess.run(["ms-sys", "-f", "--ntfs", str(part)], check=True)


def setup_mbr(disk):
    subprocess.run(["ms-sys", "-f", "--mbr7", str(disk)], check=True)


def copy_boot_files(dir):
    shutil.copy(
        ci_lookup(dir, "Windows", "Boot", "PCAT", "bootmgr"),
        ci_lookup(dir, "bootmgr", creating=True),
    )
    boot_dir = ci_lookup(dir, "Boot", creating=True)
    boot_dir.mkdir(exist_ok=True)
    shutil.copy(
        Path(__file__).parent / "BCD", ci_lookup(boot_dir, "BCD", creating=True)
    )


def copy_efi_files(win_mnt, esp_mnt):
    efi_boot = ci_lookup(esp_mnt, "EFI", "Boot", mkdir=True, parents=True)
    efi_ms = ci_lookup(esp_mnt, "EFI", "Microsoft", mkdir=True, parents=True)
    efi_ms_boot = ci_lookup(efi_ms, "Boot", mkdir=True)
    efi_ms_boot_res = ci_lookup(efi_ms_boot, "Resources", mkdir=True)
    efi_ms_boot_fonts = ci_lookup(efi_ms_boot, "Fonts", mkdir=True)
    efi_ms_recovery = ci_lookup(efi_ms, "Recovery", mkdir=True)
    win_boot = ci_lookup(win_mnt, "Windows", "Boot")
    win_boot_efi = ci_lookup(win_boot, "EFI")
    win_boot_res = ci_lookup(win_boot, "Resources")
    win_boot_fonts = ci_lookup(win_boot, "Fonts")
    bootmgfw = ci_lookup(win_boot_efi, "bootmgfw.efi")
    bootx64 = ci_lookup(efi_boot, "bootx64.efi", creating=True)
    shutil.copy(bootmgfw, bootx64)
    shutil.copytree(win_boot_efi, efi_ms_boot, dirs_exist_ok=True)
    shutil.copytree(win_boot_res, efi_ms_boot_res, dirs_exist_ok=True)
    shutil.copytree(win_boot_fonts, efi_ms_boot_fonts, dirs_exist_ok=True)
    shutil.copy(
        Path(__file__).parent / "BCD-efi", ci_lookup(efi_ms_boot, "BCD", creating=True)
    )


def setup_part(
    part, wim, image_name, *, unattend=None, postproc=None, postproc_only=False
):
    if not postproc_only:
        format_part(part)
        apply_wim(part, wim, image_name)
    setup_vbr(part)
    with with_mounted(part) as dir:
        copy_boot_files(dir)
        if unattend:
            trg = ci_lookup(
                dir, "Windows", "Panther", "unattend.xml", creating=True, parents=True
            )
            print(f"Copying unattend file: {unattend} -> {trg}")
            shutil.copy(unattend, trg)

            # Unattend.xml may contain sensitive information, including administrator's
            # password. We must protect it with correct ACLs.
            write_sd(
                trg,
                SecurityDescriptor(
                    dacl=[
                        ACE(ACE.ALLOW, MASK_FULL_CONTROL, SID_SYSTEM),
                        ACE(ACE.ALLOW, MASK_FULL_CONTROL, SID_ADMINISTRATORS),
                    ],
                    dacl_inherit=False,
                ),
            )
        for script in (postproc or []):
            script = str(script)
            if "/" not in script:
                script = f"./{script}"
            print("Running script", script, file=sys.stderr)
            subprocess.run([str(script), dir], check=True)


def exactly_one(*a):
    return sum(bool(x) for x in a) == 1

@app.command()
def main(
    *,
    disk: str | None = typer.Option(None, help="Disk device"),
    part: str | None = typer.Option(None, help="Partition device"),
    wim: str | None = typer.Option(None, help="WIM file"),
    iso: str | None = typer.Option(None, help="ISO file"),
    image_name: str | None = typer.Option(None, help="Image name"),
    unattend: str | None = typer.Option(None, help="Unattend file"),
    openssh_server: bool = typer.Option(False, help="Setup OpenSSH server"),
    debloat: bool = typer.Option(False, help="Debloat Windows"),
    postproc_only: bool = typer.Option(False, help="Only run postprocess scripts"),
    efi: bool = typer.Option(False, help="Use EFI"),
):
    postproc = []
    if not exactly_one(disk, part):
        raise typer.BadParameter("You must specify exactly one of 'disk', 'part'")
    if not (exactly_one(wim, iso) or postproc_only):
        raise typer.BadParameter("You must specify exactly one of 'wim', 'iso'")
    if openssh_server:
        postproc.append(my_dir / "postproc/openssh-server/setup.sh")
    if debloat:
        postproc.append(my_dir / "postproc/debloat/setup.sh")

    if disk and not Path(disk).is_block_device():
        raise typer.BadParameter(f"Not a block device: {disk}")
    if part and not Path(part).is_block_device():
        raise typer.BadParameter(f"Not a block device: {part}")
    if wim and not Path(wim).is_file():
        raise typer.BadParameter(f"Not a file: {wim}")
    if iso and not Path(iso).is_file():
        raise typer.BadParameter(f"Not a file: {iso}")

    with ExitStack() as es:
        if iso:
            wim = es.enter_context(with_iso(iso))
        if disk:
            if not postproc_only:
                create_partitions(disk, efi=efi)
            with with_device(disk) as dev:
                if not postproc_only and not efi:
                    setup_mbr(dev)
                part = part_path(dev, 1)
                esp = None
                if efi:
                    esp = part_path(dev, 2)
                if efi and not postproc_only:  # format ESP
                    subprocess.run(
                        ["mkfs.fat", "-F32", "-n", "ESP", str(esp)], check=True
                    )
                setup_part(
                    part,
                    wim,
                    image_name,
                    unattend=unattend,
                    postproc=postproc,
                    postproc_only=postproc_only,
                )
                if esp:  # copy EFI boot files
                    with (
                        with_mounted(part) as win_mnt,
                        with_mounted(esp, fs="fat") as esp_mnt,
                    ):
                        copy_efi_files(win_mnt, esp_mnt)
        else:
            setup_part(
                part, unattend=unattend, postproc=postproc, postproc_only=postproc_only
            )


if __name__ == "__main__":
    app()
