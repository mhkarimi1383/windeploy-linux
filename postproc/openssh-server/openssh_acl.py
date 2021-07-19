#!/usr/bin/python3

import sys,os
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent.parent))
print(sys.path)

from ntfs_acl import *


mnt = Path(sys.argv[1])
openssh_dir = mnt / "Program Files/OpenSSH"


# Make sure only Administrators and SYSTEM can write to OpenSSH install dir
apply_sd_recursively(
        openssh_dir,
        SecurityDescriptor(dacl=[
            ACE(ACE.ALLOW, MASK_FULL_CONTROL, SID_SYSTEM),
            ACE(ACE.ALLOW, MASK_FULL_CONTROL, SID_ADMINISTRATORS) ,
            ACE(ACE.ALLOW, MASK_READ_EXECUTE, SID_EVERYONE)
        ], dacl_inherit=False),
        set_owner=True,
        set_group=True,
)
