# Deploy Windows from Linux

This is a simple Python-Based Tool for deploying Windows from Linux.
Linux system (i.e., without booting from Windows installation ISO and without using Windows PE).

Supported Windows versions:

* Windows 10
* Windows 11
  * seems to bypass UEFI & TPM Requirements

(Others should work too, but are not tested.)

## Installation

We are working on a NixOS module and standalone setups/binaries.
But for now, you need to install it manually:

For that you need

* python3.13
* uv
* wimlib
* git
* parted
* ntfs-3g

```bash
git clone https://github.com/mhkarimi1383/windeploy-linux
cd windeploy-linux
uv sync
```

## Usage

```console
$ python3 ./main.py --help
                                                                                                                                                                       
 Usage: main.py [OPTIONS]                                                                                                                                              
                                                                                                                                                                       
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│    --disk                                         TEXT  Disk device                                                                                                 │
│    --part                                         TEXT  Partition device                                                                                            │
│    --wim                                          TEXT  WIM file                                                                                                    │
│    --iso                                          TEXT  ISO file                                                                                                    │
│ *  --image-name                                   TEXT  Image name [required]                                                                                       │
│    --unattend                                     TEXT  Unattend file                                                                                               │
│    --openssh-server        --no-openssh-server          Setup OpenSSH server [default: no-openssh-server]                                                           │
│    --debloat               --no-debloat                 Debloat Windows [default: no-debloat]                                                                       │
│    --postproc-only         --no-postproc-only           Only run postprocess scripts [default: no-postproc-only]                                                    │
│    --efi                   --no-efi                     Use EFI [default: no-efi]                                                                                   │
│    --install-completion                                 Install completion for the current shell.                                                                   │
│    --show-completion                                    Show completion for the current shell, to copy it or customize the installation.                            │
│    --help                                               Show this message and exit.                                                                                 │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

> Note: Use `wiminfo` to check the WIM file. and get the image name (if you don't know it).

## Use cases

* Mass-install Windows workstations from a Linux environment (e.g. PXE boot).
    (Here it may be useful to convert install.wim to a pipable WIM file
    and then you can stream it e.g. using HTTP from a server).
* Provision VMs with Windows with a single command, without any
    intermediate steps with mounting ISOs, changing boot order and the like.
* Deploy Windows from a Linux LiveCD.
* Making a Windows Pre-Installed Drive (e.g. Bootable Windows External Drive [Which is not allowed by Windows installer itself])

## Limitations

* Only limited partitioning options -- it can just erase whole disk and create a single partition.

## Additional resources

* [Create a windows system from scratch using Linux][from-scratch] -- forum thread at reboot.pro
    that discusses attempts to achieve exactly this
* [NTDEV YouTube channel][NTDEV] -- videos from crazy Windows experiments and hacks

### Windows boot process

* [Windows Vista-10 Startup Process][nt6start] summarized on Wikipedia
* [Windows 7-10 Master Boot Record][MBR] -- disassembly and analysis
* [Windows 8-10 NTFS Volume Boot Record][VBR] -- disassembly and analysis

#### BCD database

* [libbcd0][] -- Python library for reading/writing BCD databases
* [BCD notes, observations, experiments][bcdnotes]
* [BCD elements][bcdelem]
* [toolsnt][] -- A Rust library and CLI tool for manipulating BCD from Linux

### Windows installation process

* [Configuration passes in unattend.xml][passes]

[MBR]: https://thestarman.pcministry.com/asm/mbr/W7MBR.htm
[VBR]: https://thestarman.pcministry.com/asm/mbr/W8VBR.htm|
[from-scratch]: http://reboot.pro/topic/20468-create-a-windows-system-from-scratch-using-linux/
[passes]: https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/how-configuration-passes-work
[NTDEV]: https://www.youtube.com/c/NTDEV/videos
[libbcd0]: https://github.com/wodny/libbcd0/
[bcdnotes]: https://thestarman.pcministry.com/asm/mbr/BCD.htm
[nt6start]: https://en.wikipedia.org/wiki/Windows_NT_6_startup_process
[bcdelem]: https://www.geoffchappell.com/notes/windows/boot/bcd/elements.htm
[toolsnt]: https://codeberg.org/erin/toolsnt
