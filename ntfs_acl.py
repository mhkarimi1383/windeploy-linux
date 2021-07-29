
import sys, os
from io import BytesIO
from construct import *
from pathlib import Path # overrides same name from construct
import ctypes
from textwrap import dedent

def dump_sd(path):
    return getxattr(path, "system.ntfs_acl")

def write_sd(path, sd):
    if isinstance(sd, SecurityDescriptor): sd = sd.build()
    elif isinstance(sd, Container): sd = SecurityDescriptorStruct.build(sd)
    os.setxattr(path, "system.ntfs_acl", sd)

_cdll = ctypes.CDLL(None)

#_cdll.libcnotify_verbose_set(1)

def getxattr(path, name):
    # We have to use ctypes instead of os.getxattr, because os.getxattr uses a 128B buffer,
    # which is too small (ironically, it retries with larger buffer if it gets ERANGE, but
    # ntfs-3g returns EIO instead of ERANGE when buffer is too small). It cannot be forced
    # to use larger buffer by default.
    if isinstance(name, str):
        name = name.encode('ascii')
    if isinstance(path, os.PathLike):
        path = str(path)
    if isinstance(path, str):
        path = path.encode(sys.getfilesystemencoding())
    global _cdll
    size = _cdll.getxattr(path, name, None, 0)
    buf = ctypes.create_string_buffer(b'', size)
    _cdll.getxattr(path, name, buf, size)
    return buf.raw


#class ClassAdapter(Adapter):
#    def __init__(self, cls, *a, **kw):
#        self.adapt_cls = cls
#        super().__init__(*a, **kw)
#
#    def _decode(self, obj, context, path):
#        return self.adapt_cls.from_construct(obj)
#
#    def _encode(self, obj, context, path):
#        if not isinstance(obj, self.adapt_cls): raise TypeError
#        return obj.to_construct()
#
#class ACLAdapter(Adapter):
#    def _decode(self, obj, context, path):
#        assert len(obj.items) == obj.cnt
#        return obj.items
#
#    def _encode(self, obj, context, path):
#        return dict(revision=2, cnt=len(obj), items=obj)


def _getpath(obj, path):
    if isinstance(path, str): path = path.split('.')
    for c in path:
        obj = obj[c]
    return obj

def _setpath(obj, path, val):
    if isinstance(path, str): path = path.split('.')
    for c in path[:-1]:
        obj = obj[c]
    obj[path[-1]] = val

class WithSize(Subconstruct):
    def __init__(self, size_path, subcon, pattern=b"\x00"):
        if not isinstance(pattern, bytes) or len(pattern) != 1:
            raise PaddingError("pattern expected to be bytes of length 1")
        super().__init__(subcon)
        self.size_path = size_path
        self.pattern = pattern

    def _parse(self, stream, context, path):
        position1 = stream.tell()
        obj = self.subcon._parsereport(stream, context, path)
        #print("obj:", obj)
        position2 = stream.tell()

        actual_length = (position2 - position1)
        formal_length = _getpath(obj, self.size_path)
        if formal_length < 0:
            raise PaddingError("length cannot be negative", path=path)
        pad = formal_length - actual_length
        #print("Path:", path)
        #print("Subcon:", self.subcon, self is ACEStruct, self is ACLStruct)
        #print("Formal length:", formal_length)
        #print("Actual length:", actual_length, position1, "..", position2)
        if pad < 0:
            raise PaddingError("subcon parsed %d bytes but was allowed only %d" % (actual_length, formal_length), path=path)
        stream_read(stream, pad, path)
        return obj

    def _build(self, obj, stream, context, path):
        tmpstream = BytesIO()
        self.subcon._build(obj, tmpstream, context, path)
        size = len(tmpstream.getvalue())
        _setpath(obj, self.size_path, size)
        #print(size, obj)
        return self.subcon._build(obj, stream, context, path)

    def _sizeof(self, context, path):
        return self.subcon._sizeof(context, path)


# https://github.com/tuxera/ntfs-3g/blob/a4a837025b6ac2b0c44c93e34e22535fe9e95b27/ntfsprogs/ntfssecaudit.c#L1229
SDHeaderStruct = Struct(
    "revision" / Const(1, Byte),
    Padding(1),
    "flags" / FlagsEnum(Int16ul,
        # https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-control
        SE_OWNER_DEFAULTED        =  0x0001,
        SE_GROUP_DEFAULTED        =  0x0002,
        SE_DACL_PRESENT           =  0x0004,
        SE_DACL_DEFAULTED         =  0x0008,
        SE_SACL_DEFAULTED         =  0x0008,
        SE_SACL_PRESENT           =  0x0010,
        SE_DACL_AUTO_INHERIT_REQ  =  0x0100,
        SE_SACL_AUTO_INHERIT_REQ  =  0x0200,
        SE_DACL_AUTO_INHERITED    =  0x0400,
        SE_SACL_AUTO_INHERITED    =  0x0800,
        SE_DACL_PROTECTED         =  0x1000,
        SE_SACL_PROTECTED         =  0x2000,
        SE_RM_CONTROL_VALID       =  0x4000,
        SE_SELF_RELATIVE          =  0x8000,
    ),
    "owner_sid_offset" / Int32ul,
    "group_sid_offset" / Int32ul,
    "sacl_offset" / Int32ul,
    "dacl_offset" / Int32ul,
)

# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid
# https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-components
# https://github.com/tuxera/ntfs-3g/blob/a4a837025b6ac2b0c44c93e34e22535fe9e95b27/ntfsprogs/ntfssecaudit.c#L957
SIDStruct = Struct(
    "revision" / Const(1, Byte),
    "cnt" / Byte,
    "auth" / BytesInteger(6), # strangely, this is big endian, unlike other fields
    "subauth" / Int32ul[this.cnt],
)

# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl
# https://github.com/tuxera/ntfs-3g/blob/a4a837025b6ac2b0c44c93e34e22535fe9e95b27/ntfsprogs/ntfssecaudit.c#L1420
ACLHeaderStruct = Struct(
    "revision" / Byte, # Const(2, Byte),
    Padding(1),
    "size" / Int16ul,
    "cnt" / Int16ul,
    Padding(2),
    
)

# https://docs.microsoft.com/en-us/windows/win32/secauthz/ace
# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header
ACCESS_MAX_MS_V2_ACE_TYPE = 0x3
ACCESS_MAX_MS_V3_ACE_TYPE = 0x4
ACCESS_MAX_MS_V4_ACE_TYPE = 0x8
ACCESS_MAX_MS_V5_ACE_TYPE = 0x14
ACEHeaderStruct = Struct(
    "type" / Enum(Byte,
        # from wine's winnt.h
        ACCESS_ALLOWED_ACE_TYPE   = 0x0,
        ACCESS_DENIED_ACE_TYPE    = 0x1,
        SYSTEM_AUDIT_ACE_TYPE     = 0x2,
        SYSTEM_ALARM_ACE_TYPE     = 0x3,
        ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x4,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE   = 0x5,
        ACCESS_DENIED_OBJECT_ACE_TYPE    = 0x6,
        ACCESS_AUDIT_OBJECT_ACE_TYPE     = 0x7,
        ACCESS_ALARM_OBJECT_ACE_TYPE     = 0x8,
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x9,
        ACCESS_DENIED_CALLBACK_ACE_TYPE  = 0xa,
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0xb,
        ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  = 0xc,
        SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0xd,
        SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0xe,
        SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0xf,
        SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10,
        SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11,
        SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE  = 0x12,
        SYSTEM_SCOPED_POLICY_ID_ACE_TYPE    = 0x13,
        SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE = 0x14,
    ),
    "flags" / FlagsEnum(Byte,
        # from wine's winnt.h
        # inheritance AceFlags
        OBJECT_INHERIT_ACE       = 0x01,
        CONTAINER_INHERIT_ACE    = 0x02,
        NO_PROPAGATE_INHERIT_ACE = 0x04,
        INHERIT_ONLY_ACE         = 0x08,
        INHERITED_ACE            = 0x10,

        # AceFlags mask for what events we (should) audit
        SUCCESSFUL_ACCESS_ACE_FLAG = 0x40,
        FAILED_ACCESS_ACE_FLAG     = 0x80,
    ),
    "size" / Int16ul,
)


# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_ace
AllowDenyBodyStruct = Struct(
    # https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask
    "access_mask" / Int32ul,
    "sid" / SIDStruct,
)

ACE_BODY_STRUCTS = {
            'ACCESS_ALLOWED_ACE_TYPE': AllowDenyBodyStruct,
            'ACCESS_DENIED_ACE_TYPE': AllowDenyBodyStruct,
            # ...
        }
ACEStruct = WithSize('header.size', Struct(
    "header" / ACEHeaderStruct,
    "body" / Switch(
        this.header.type,
        ACE_BODY_STRUCTS,
    ),
    #Padding(lambda this: this.header.size - this._subcons.header.sizeof() - this._subcons.body.sizeof()),
))

ACLStruct = WithSize('header.size', Struct(
    "header" / ACLHeaderStruct,
    "items" / ACEStruct[this.header.cnt],
    #Padding(lambda this: this.header.size - this._subcons.header.sizeof() - this._subcons.items.sizeof()),
))

SecurityDescriptorStruct = Struct(
    "header" / SDHeaderStruct,
    "owner_sid" / Pointer(this.header.owner_sid_offset, SIDStruct),
    "group_sid" / Pointer(this.header.group_sid_offset, SIDStruct),
    "sacl" / If(lambda this: this.header.flags.get('SE_SACL_PRESENT') and this.header.sacl_offset >= this._subcons.header.sizeof(), Pointer(this.header.sacl_offset, ACLStruct)),
    "dacl" / If(lambda this: this.header.flags.get('SE_DACL_PRESENT') and this.header.dacl_offset >= this._subcons.header.sizeof(), Pointer(this.header.dacl_offset, ACLStruct)),
)

class Constructable:
    @classmethod
    def parse(cls, s):
        return cls.from_construct(cls.STRUCT.parse(s))

    def build(self):
        return self.STRUCT.build(self.to_construct())



class SID(Constructable):
    STRUCT = SIDStruct
    def __init__(self, revision, auth=None, *subauth):
        if isinstance(revision, str):
            if not revision.startswith('S-'): raise ValueError
            revision, auth, *subauth = [ int(x) for x in revision[2:].split('-') ]
        elif isinstance(revision, SID):
            sid = revision
            revision = sid.revision
            auth = sid.auth
            subauth = sid.subauth
        if auth is None: raise ValueError
        self.revision = revision
        self.auth = auth
        self.subauth = tuple(subauth)

    def __eq__(self, other):
        if isinstance(other, SID):
            return self.revision == other.revision and self.auth == other.auth and self.subauth == other.subauth
        elif isinstance(other, str):
            return self == SID(other)
        else: return NotImplemented

    __req__ = __eq__

    def __hash__(self):
        return hash((self.revision, self.auth, self.subauth))

    def __str__(self):
        return 'S-' + '-'.join( str(a) for a in (self.revision, self.auth)+self.subauth )

    def __repr__(self):
        return f'SID({str(self)!r})'

    @classmethod
    def from_construct(cls, cont):
        return cls(cont.revision, cont.auth, *cont.subauth)

    def to_construct(self):
        return dict(revision=self.revision, cnt=len(self.subauth), auth=self.auth, subauth=self.subauth)

SID_ADMINISTRATORS = SID('S-1-5-32-544') # the built-in Administrators group
SID_SYSTEM = SID('S-1-5-18') # the Local System (NT AUTHORITY\SYSTEM) account
SID_USERS = SID('S-1-5-32-545')
SID_AUTH_USERS = SID('S-1-5-11') # Authenticated Users
SID_EVERYONE = SID('S-1-1-0')

# as empiricaly set by Windows 10
MASK_FULL_CONTROL = 0x1f01ff
MASK_READ_EXECUTE = 0x1200a9

def flags2set(flags):
    return frozenset( str(k) for k,v in flags.items() if v if k != '_flagsenum' )

def set2flags(s):
    return Container({ f: True for f in set(s) })

class ACE(Constructable):
    STRUCT = ACEStruct
    ALLOW = 'ACCESS_ALLOWED_ACE_TYPE'
    DENY = 'ACCESS_DENIED_ACE_TYPE'
    def __init__(self, type, access_mask, sid, flags=None, inheritance=None):
        self.type = type
        self.access_mask = access_mask
        self.sid = sid
        if flags is None and inheritance is None:
            inheritance = 'all'
        flags = set(flags or [])
        if inheritance in ('object', 'file', 'all'):
            flags |= {'OBJECT_INHERIT_ACE'}
        if inheritance in ('container', 'dir', 'all'):
            flags |= {'CONTAINER_INHERIT_ACE'}
        self.flags = frozenset(flags)

    def __repr__(self):
        return f'ACE({self.type!r}, {self.access_mask!r}, {self.sid!r}, flags={set(self.flags)!r})'
        
    @classmethod
    def from_construct(cls, cont):
        if cont.header.type not in (cls.ALLOW, cls.DENY):
            raise NotImplementedError
        return ACE(str(cont.header.type), cont.body.access_mask, SID.from_construct(cont.body.sid), flags=flags2set(cont.header.flags))

    def to_construct(self):
        r = Container()
        r.header = Container(type=self.type, size=0, flags=set2flags(self.flags))
        r.body = Container(access_mask=self.access_mask, sid=self.sid.to_construct(), flags={ f: True for f in self.flags })
        return r

    def make_inherited(self):
        return ACE(self.type, self.access_mask, self.sid, self.flags | {"INHERITED_ACE"} - {"INHERIT_ONLY_ACE"})


class SecurityDescriptor(Constructable):
    STRUCT = SecurityDescriptorStruct

    def __init__(self, *, owner_sid=SID_ADMINISTRATORS, group_sid=SID_ADMINISTRATORS, dacl=[], sacl=None, sacl_inherit=True, dacl_inherit=True):
        self.owner_sid = SID(owner_sid)
        self.group_sid = SID(group_sid)
        self.sacl = sacl
        self.dacl = dacl
        self.sacl_inherit = sacl_inherit
        self.dacl_inherit = dacl_inherit

    def __repr__(self):
        r = ['SecurityDescriptor(']
        r.append(f'    owner_sid={self.owner_sid!r},')
        r.append(f'    group_sid={self.group_sid!r},')
        for name in ('sacl', 'dacl'):
            acl = getattr(self, name)
            if not acl: continue
            r.append(f'    {name}=[')
            for ace in acl:
                r.append(' '*8 + repr(ace))
            r.append('    ],')
        if not self.sacl_inherit: r.append('    sacl_inherit=False,')
        if not self.dacl_inherit: r.append('    dacl_inherit=False,')
        r.append(')')
        return '\n'.join(r)

    @classmethod
    def acl_from_construct(cls, cont):
        if cont: return [ ACE.from_construct(itm) for itm in cont['items'] ]
        else: return None

    @classmethod
    def acl_to_construct(cls, acl):
        # Empty ACL is not the same as no ACL.
        # https://docs.microsoft.com/en-us/windows/win32/secauthz/null-dacls-and-empty-dacls
        if acl is None:
            return None
        else:
            r = Container()
            r.header = Container(revision=2,  cnt=len(acl), size=0)
            r.items = [ itm.to_construct() for itm in acl ]
            return r


    @classmethod
    def from_construct(cls, cont):
        owner_sid = SID.from_construct(cont.owner_sid)
        group_sid = SID.from_construct(cont.group_sid)
        sacl = cls.acl_from_construct(cont.sacl)
        dacl = cls.acl_from_construct(cont.dacl)
        flags = flags2set(cont.header.flags)
        return SecurityDescriptor(owner_sid=owner_sid, group_sid=group_sid, sacl=sacl, dacl=dacl,
                                    sacl_inherit="SE_SACL_PROTECTED" not in flags,
                                    dacl_inherit="SE_DACL_PROTECTED" not in flags,
                                    )


    def to_construct(self):
        hdr = Container()
        r = Container()
        r.header = hdr
        r.owner_sid = self.owner_sid.to_construct()
        r.group_sid = self.group_sid.to_construct()
        r.dacl = self.acl_to_construct(self.dacl)
        r.sacl = self.acl_to_construct(self.sacl)

        # SE_SELF_RELATIVE specifies that offsets in header are relative to start of SD.
        # This should be always set in on-disk SDs.
        # https://docs.microsoft.com/en-us/windows/win32/secauthz/absolute-and-self-relative-security-descriptors
        flags = {"SE_SELF_RELATIVE"}
        # Windows seems to always set SE_DACL_AUTO_INHERITED but not SE_DACL_AUTO_INHERIT_REQ. We mirror that.
        if self.sacl is not None: flags |= {"SE_SACL_PRESENT", "SE_SACL_AUTO_INHERITED"}
        if self.dacl is not None: flags |= {"SE_DACL_PRESENT", "SE_DACL_AUTO_INHERITED"}
        if not self.sacl_inherit:
            flags |= {"SE_SACL_PROTECTED"}
        if not self.dacl_inherit:
            flags |= {"SE_DACL_PROTECTED"}

        hdr.flags = set2flags(flags)

        sacl_size = len(ACLStruct.build(r.sacl)) if r.sacl else 0
        dacl_size = len(ACLStruct.build(r.dacl)) if r.dacl else 0
        pos = SDHeaderStruct.sizeof()
        def add_element(struct, cont):
            nonlocal pos
            off = pos
            pos += len(struct.build(cont))
            return off
        hdr.owner_sid_offset = add_element(SIDStruct, r.owner_sid)
        hdr.group_sid_offset = add_element(SIDStruct, r.group_sid)
        if r.sacl: hdr.sacl_offset = add_element(ACLStruct, r.sacl)
        else: hdr.sacl_offset = 0
        if r.dacl: hdr.dacl_offset = add_element(ACLStruct, r.dacl)
        else: hdr.dacl_offset = 0
        return r


def apply_sd_recursively(path, sd=None, *, dacl=None, skip_protected=True, set_owner=False, set_group=False):
    path = Path(path)
    if sd is None:
        sd = SecurityDescriptor.parse(dump_sd(path))
    else:
        write_sd(path, sd)

    def visit(p):
        is_dir = p.is_dir()
        kind = 'CONTAINER' if is_dir else 'OBJECT'
        acl = [ ace.make_inherited() for ace in sd.dacl if f'{kind}_INHERIT_ACE' in ace.flags ]
        child_sd = SecurityDescriptor.parse(dump_sd(p))
        if (not child_sd.dacl_inherit) and skip_protected: return # do not modify ACL and do not recurse
        child_sd.dacl = acl
        if set_owner: child_sd.owner_sid = sd.owner_sid
        if set_group: child_sd.group_sid = sd.group_sid
        print(p, child_sd)
        write_sd(p, child_sd)
        if is_dir:
            for child in p.iterdir(): visit(child)

    for p in path.iterdir(): visit(p)



