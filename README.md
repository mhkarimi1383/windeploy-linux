# Deploy Windows 10 from Linux

This is a simple Python script that installs Windows 10 to a target disk from a running
Linux system (i.e., without booting from Windows installation ISO and without using Windows PE).

## Use cases

  * Mass-install Windows workstations from a PXE-booted Linux environment.
    (Here it may be useful to convert install.wim to a pipable WIM file
    and then you can stream it e.g. using HTTP from a server).
  * Provision VMs with Windows 10 with a single command, without any
    intermediate steps with mounting ISOs, changing boot order and the like.

## Limitations

  * Currently supports only BIOS boot, not UEFI. But this should be easy
    to implement.

