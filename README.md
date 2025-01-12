# Deploy Windows 10 from Linux

This is a simple Python script that installs Windows 10 to a target disk from a running
Linux system (i.e., without booting from Windows installation ISO and without using Windows PE).

**Update 2025-01-12: Also works with Windows 11.** (And currently, it seems to bypass
TMP requirements by default. Can be even installed on non-EFI BIOS.)

## Use cases

  * Mass-install Windows workstations from a PXE-booted Linux environment.
    (Here it may be useful to convert install.wim to a pipable WIM file
    and then you can stream it e.g. using HTTP from a server).
  * Provision VMs with Windows 10 with a single command, without any
    intermediate steps with mounting ISOs, changing boot order and the like.

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
