"""Windows private host pins. Imported inertly; never called by offline tests."""
import ctypes as c
from ctypes import wintypes as w
import ntpath
import os
import pathlib
import re

from admin_recovery import require, Hold, Pending, sha, digest

SYSTEM = 'S-1-5-18'
ADMIN = 'S-1-5-32-544'
TI = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
# True ancestor directories: adding a new entry (FILE_ADD_FILE 0x2,
# FILE_ADD_SUBDIRECTORY 0x4) cannot rename, delete or replace the component.
ANCESTOR_MUTATION = 0x500d0150
# The pinned object itself and every directory holding harness code
# (interpreter, driver, host, system executable): adding entries is mutation too.
MUTATION = ANCESTOR_MUTATION | 0x6
SYSTEM_OWNERS = {TI, SYSTEM, ADMIN}


def validate_links(links, owner, system_executable=False):
    """Pure hardlink decision. Only a system-owned executable may have extra names.

    Extra links are tolerated solely for pin_system_executable leaves (for
    example OpenSSH's WinSxS link or Git's cmd shim), whose owner must be
    TrustedInstaller, SYSTEM or BUILTIN Administrators. The caller still holds the
    leaf with share=READ and checks the bound hash through that handle.
    """
    if links != 1:
        require(system_executable and owner in SYSTEM_OWNERS, 'Source hardlink refused')


def validate_acl(owner, protected, aces, sid, private, tolerant=False, ancestor=False):
    """Pure decision used by the native descriptor reader and offline tests.

    Returns the untrusted Allow ACEs with mutation bits. They are only possible
    in tolerant (read-only source) mode; strict and private modes refuse them.
    ancestor=True (a true ancestor directory, not a code directory) uses the
    relaxed mask without 0x2/0x4; every other object uses the full mask.
    """
    require(not (private and tolerant), 'Private pins are never tolerant')
    limit = ANCESTOR_MUTATION if ancestor else MUTATION
    require(owner in ({sid} if private else {sid, SYSTEM, ADMIN, TI}), 'Untrusted owner')
    writers = []
    if private:
        require(protected and len(aces) == 3 and
                set(a[3] for a in aces) == {sid, SYSTEM, ADMIN}, 'Private DACL principals')
        require(all(a[:3] == (0, 3, 0x1f01ff) for a in aces), 'Private ACE mask/inheritance')
    else:
        # ACE: type, flags, mask, SID. Unknown object/callback ACEs refuse.
        for kind, flags, mask, principal in aces:
            require(kind in (0, 1), 'Unsupported ancestor ACE')
            # INHERIT_ONLY ACEs do not apply to this object.
            if kind == 0 and not flags & 0x08 and principal not in {sid, SYSTEM, ADMIN, TI} \
                    and mask & limit:
                require(tolerant, 'Untrusted mutation')
                writers.append(dict(sid=principal, mask='0x%08x' % mask, flags='0x%02x' % flags))
    return writers


class SECURITY_ATTRIBUTES(c.Structure):
    _fields_ = [('length', w.DWORD), ('descriptor', c.c_void_p), ('inherit', w.BOOL)]


class FILE_INFO(c.Structure):
    _fields_ = [('attributes', w.DWORD), ('creation', w.FILETIME), ('access', w.FILETIME),
                ('write', w.FILETIME), ('volume', w.DWORD), ('sizeHigh', w.DWORD),
                ('sizeLow', w.DWORD), ('links', w.DWORD), ('indexHigh', w.DWORD),
                ('indexLow', w.DWORD)]


class ACL_SIZE(c.Structure):
    _fields_ = [('count', w.DWORD), ('used', w.DWORD), ('free', w.DWORD)]


class WindowsAdmission:
    def __init__(self, sid):
        require(os.name == 'nt' and re.fullmatch(r'S-1-5-21-(?:\d+-){3}\d+', sid),
                'Original Windows user SID required')
        self.sid = sid
        self.pins = []
        self.closed = False
        self.code_dirs = frozenset()
        self.k = c.WinDLL('kernel32', use_last_error=True)
        self.a = c.WinDLL('advapi32', use_last_error=True)
        self.k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p,
                                      w.DWORD, w.DWORD, c.c_void_p]
        self.k.CreateFileW.restype = c.c_void_p
        self.k.CreateDirectoryW.argtypes = [w.LPCWSTR, c.POINTER(SECURITY_ATTRIBUTES)]
        self.k.CreateDirectoryW.restype = w.BOOL
        self.k.GetFileInformationByHandle.argtypes = [c.c_void_p, c.POINTER(FILE_INFO)]
        self.k.GetFileInformationByHandle.restype = w.BOOL
        self.k.GetFileInformationByHandleEx.argtypes = [c.c_void_p, c.c_int, c.c_void_p, w.DWORD]
        self.k.GetFileInformationByHandleEx.restype = w.BOOL
        self.k.ReadFile.argtypes = [c.c_void_p, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]
        self.k.ReadFile.restype = w.BOOL
        self.k.CloseHandle.argtypes = [c.c_void_p]
        self.k.CloseHandle.restype = w.BOOL
        self.k.LocalFree.argtypes = [c.c_void_p]
        self.k.LocalFree.restype = c.c_void_p
        self.a.GetSecurityInfo.argtypes = [c.c_void_p, c.c_int, w.DWORD,
                                          *([c.POINTER(c.c_void_p)] * 5)]
        self.a.GetSecurityInfo.restype = w.DWORD
        self.a.GetSecurityDescriptorLength.argtypes = [c.c_void_p]
        self.a.GetSecurityDescriptorLength.restype = w.DWORD
        self.a.GetSecurityDescriptorControl.argtypes = [c.c_void_p, c.POINTER(w.WORD), c.POINTER(w.DWORD)]
        self.a.GetSecurityDescriptorControl.restype = w.BOOL
        self.a.GetAclInformation.argtypes = [c.c_void_p, c.c_void_p, w.DWORD, c.c_int]
        self.a.GetAclInformation.restype = w.BOOL
        self.a.GetAce.argtypes = [c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)]
        self.a.GetAce.restype = w.BOOL
        self.a.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(c.c_void_p)]
        self.a.ConvertSidToStringSidW.restype = w.BOOL
        self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.POINTER(w.DWORD)]
        self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
        self.k.GetCurrentProcess.argtypes = []
        self.k.GetCurrentProcess.restype = c.c_void_p
        self.a.OpenProcessToken.argtypes = [c.c_void_p,w.DWORD,c.POINTER(c.c_void_p)]
        self.a.OpenProcessToken.restype = w.BOOL
        self.a.GetTokenInformation.argtypes = [c.c_void_p,c.c_int,c.c_void_p,w.DWORD,c.POINTER(w.DWORD)]
        self.a.GetTokenInformation.restype = w.BOOL
        require(self._current_sid() == sid, 'Admission SID differs from original process token')

    def _current_sid(self):
        # Same TokenUser contract as the reviewed launcher, bounded allocation.
        token=c.c_void_p()
        self._ok(self.a.OpenProcessToken(self.k.GetCurrentProcess(),8,c.byref(token)))
        try:
            size=w.DWORD()
            self.a.GetTokenInformation(token,1,None,0,c.byref(size))
            require(c.sizeof(c.c_void_p)+4 <= size.value <= 4096,'TokenUser bound')
            data=c.create_string_buffer(size.value);actual=w.DWORD()
            self._ok(self.a.GetTokenInformation(token,1,data,size.value,c.byref(actual)))
            require(c.sizeof(c.c_void_p)+4 <= actual.value <= size.value,'TokenUser length')
            return self._sid(c.cast(data,c.POINTER(c.c_void_p))[0])
        finally:
            self._ok(self.k.CloseHandle(token))

    def _ok(self, value):
        if not value:
            raise c.WinError(c.get_last_error())

    def _sid(self, address):
        text = c.c_void_p()
        self._ok(self.a.ConvertSidToStringSidW(address, c.byref(text)))
        try:
            return c.wstring_at(text)
        finally:
            self.k.LocalFree(text)

    def _descriptor(self, handle, private, tolerant=False, ancestor=False):
        """Returns (raw descriptor, untrusted writers) after the ACL decision."""
        owner, protected, aces, raw = self._acl(handle)
        return raw, validate_acl(owner, protected, aces, self.sid, private, tolerant, ancestor)

    def declare_code_directories(self, paths):
        """Directories whose files the harness loads or executes.

        Must be declared before the first pin. Such a directory never gets the
        relaxed ancestor mask, even when pinned as an ancestor of another path.
        """
        require(not self.pins and not self.code_dirs, 'Code directories declared after pinning')
        self.code_dirs = frozenset(ntpath.normcase(self.canonical(path)) for path in paths)

    def _ancestor(self, path):
        return ntpath.normcase(str(path)) not in self.code_dirs

    def _acl(self, handle):
        """Native read only: (owner SID, protected, ACEs, raw descriptor)."""
        owner, group, acl, sacl, sd = [c.c_void_p() for _ in range(5)]
        error = self.a.GetSecurityInfo(handle, 1, 7, *map(c.byref, (owner, group, acl, sacl, sd)))
        if error:
            raise c.WinError(error)
        try:
            require(acl.value is not None, 'Null DACL')
            control, revision = w.WORD(), w.DWORD()
            self._ok(self.a.GetSecurityDescriptorControl(sd, c.byref(control), c.byref(revision)))
            info = ACL_SIZE()
            self._ok(self.a.GetAclInformation(acl, c.byref(info), c.sizeof(info), 2))
            require(info.count <= 128, 'ACL bounds')
            aces = []
            for index in range(info.count):
                ace = c.c_void_p()
                self._ok(self.a.GetAce(acl, index, c.byref(ace)))
                header = c.string_at(ace, 8)
                kind, flags = header[0], header[1]
                require(kind in (0, 1) and int.from_bytes(header[2:4], 'little') >= 12,
                        'Unsupported ACE')
                aces.append((kind, flags, int.from_bytes(header[4:8], 'little'), self._sid(ace.value+8)))
            length = self.a.GetSecurityDescriptorLength(sd)
            require(0 < length <= 65536, 'Descriptor bounds')
            return self._sid(owner), bool(control.value & 0x1000), aces, c.string_at(sd, length)
        finally:
            self.k.LocalFree(sd)

    @staticmethod
    def canonical(path):
        value = str(path)
        require(re.match(r'^[A-Za-z]:\\', value) and '/' not in value and ':' not in value[2:],
                'Absolute DOS path only')
        require(str(pathlib.Path(value).absolute()) == value, 'Canonical path')
        for part in pathlib.Path(value).parts[1:]:
            require(part not in ('.', '..') and not part.endswith(('.', ' ')), 'Path alias')
        return value

    def _pin(self, path, directory, private=False, tolerant=False, system_executable=False,
             ancestor=False):
        # Only a true ancestor directory (not a declared code directory) is relaxed.
        ancestor = bool(ancestor and directory and not private and self._ancestor(path))
        handle = self.k.CreateFileW(str(path), 0x20080 | (0 if directory else 0x80000000),
                                    1, None, 3, 0x02200000, None)
        require(handle not in (None, c.c_void_p(-1).value), 'Cannot pin path')
        # Retain immediately; failed validation never pretends no pin was acquired.
        pin = dict(handle=handle, descriptor=None, path=str(path), private=private, tolerant=tolerant,
                   ancestor=ancestor)
        self.pins.append(pin)
        info = FILE_INFO()
        self._ok(self.k.GetFileInformationByHandle(handle, c.byref(info)))
        require(not info.attributes & 0x400 and bool(info.attributes & 0x10) == directory,
                'Reparse/type mismatch')
        if directory:
            case = w.DWORD()
            self._ok(self.k.GetFileInformationByHandleEx(handle, 23, c.byref(case), c.sizeof(case)))
            require(case.value == 0, 'Case-sensitive directory refused')
        owner, protected, aces, raw = self._acl(handle)
        if not directory:
            validate_links(info.links, owner, system_executable)
        pin['writers'] = validate_acl(owner, protected, aces, self.sid, private, tolerant, ancestor)
        pin['owner'] = owner
        pin['links'] = info.links
        pin['descriptor'] = raw
        pin['identity'] = (info.volume, info.indexHigh, info.indexLow)
        pin['size'] = (info.sizeHigh << 32) | info.sizeLow
        return pin

    def pin_source(self, path):
        path = pathlib.Path(self.canonical(path))
        for part in reversed(path.parents):
            self._pin(part, True, ancestor=True)
        return self._pin(path, path.is_dir())

    @staticmethod
    def _component(pin):
        return dict(path=pin['path'], fileId='%08x:%08x%08x' % pin['identity'],
                    untrustedWriters=pin['writers'])

    def _readonly(self, path, limit):
        path = pathlib.Path(self.canonical(path))
        components = [self._pin(part, True, tolerant=True, ancestor=True) for part in reversed(path.parents)]
        leaf = self._pin(path, False, tolerant=True)
        components.append(leaf)
        require(leaf['size'] <= limit, 'Read-only source bound')
        return path, self._read_held(leaf['handle'], leaf['size']), components

    def pin_readonly_source(self, path, expected_sha256, limit):
        """Pin an external read-only input whose ancestors may have third-party writers.

        Owner, ACE type, reparse, hardlink and case checks stay; untrusted Allow
        ACEs with mutation bits are tolerated and returned as evidence. The leaf
        is a file held with share=READ; its bytes are read through that held
        handle and must match the caller-bound hash before they are returned.
        """
        digest(expected_sha256)
        path, raw, components = self._readonly(path, limit)
        require(sha(raw) == expected_sha256, 'Read-only source content hash')
        # Re-open every component by name and compare file ID/descriptor.
        self.revalidate()
        return raw, dict(path=str(path), sha256=expected_sha256,
                         components=[self._component(pin) for pin in components])

    def pin_readonly_content(self, path, limit, check):
        """Read-only pin whose bytes are validated by content, not by a bound hash.

        Used only for checkout metadata (.git pointer, HEAD, ref, packed-refs)
        whose exact expected content the caller derives from the baseline and
        configuration. check(raw) must raise on any deviation; evidence keeps the hash.
        """
        require(callable(check), 'Content check required')
        path, raw, components = self._readonly(path, limit)
        check(raw)
        self.revalidate()
        return raw, dict(path=str(path), sha256=sha(raw),
                         components=[self._component(pin) for pin in components])

    def pin_system_executable(self, path, expected_sha256, limit):
        """Pin a system executable that may legitimately have extra hard links.

        Ancestors and leaf use the strict ACL decision. The leaf may have links > 1
        only when owned by TrustedInstaller, SYSTEM or BUILTIN Administrators. It
        is held with share=READ, which applies to the file object, so writes via
        any other name are refused while pinned. The bytes are read through that
        held handle and must match the configuration-bound hash.
        """
        digest(expected_sha256)
        path = pathlib.Path(self.canonical(path))
        # The directory holding the executable is a code directory (full mask).
        components = [self._pin(part, True, ancestor=part != path.parent)
                      for part in reversed(path.parents)]
        leaf = self._pin(path, False, system_executable=True)
        components.append(leaf)
        require(leaf['size'] <= limit, 'System executable bound')
        raw = self._read_held(leaf['handle'], leaf['size'])
        require(sha(raw) == expected_sha256, 'System executable content hash')
        self.revalidate()
        return raw, dict(path=str(path), sha256=expected_sha256, links=leaf['links'],
                         owner=leaf['owner'], fileId='%08x:%08x%08x' % leaf['identity'],
                         components=[self._component(pin) for pin in components])

    def _read_held(self, handle, size):
        # Freshly opened synchronous handle: the file pointer is at offset zero.
        buffer = c.create_string_buffer(size + 1)
        count = w.DWORD()
        self._ok(self.k.ReadFile(handle, buffer, size + 1, c.byref(count), None))
        require(count.value == size, 'Read-only source changed during read')
        return buffer.raw[:size]

    def read_once(self, path, limit):
        """Validate, read and close one private-root file; no retained pin."""
        path = pathlib.Path(self.canonical(path))
        require(not self.closed and any(pin['path'] == str(path.parent) for pin in self.pins),
                'Unpinned parent')
        handle = self.k.CreateFileW(str(path), 0x80020080, 1, None, 3, 0x02200000, None)
        if handle in (None, c.c_void_p(-1).value):
            # Typically a writer still holds the file without delete/read sharing.
            raise Pending('Cannot open file')
        try:
            info = FILE_INFO()
            self._ok(self.k.GetFileInformationByHandle(handle, c.byref(info)))
            require(not info.attributes & 0x410 and info.links == 1, 'Reparse/type/hardlink mismatch')
            self._descriptor(handle, False)  # strict; raises on untrusted writers
            size = (info.sizeHigh << 32) | info.sizeLow
            require(size <= limit, 'File bound')
            buffer = c.create_string_buffer(size + 1)
            count = w.DWORD()
            self._ok(self.k.ReadFile(handle, buffer, size + 1, c.byref(count), None))
            if count.value != size:
                raise Pending('File changed during read')
            return buffer.raw[:size]
        finally:
            self._ok(self.k.CloseHandle(handle))

    def create_root(self, path):
        path = pathlib.Path(self.canonical(path))
        self.pin_source(path.parent)
        sd = c.c_void_p()
        sddl = 'O:'+self.sid+'G:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;'+self.sid+')'
        self._ok(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, c.byref(sd), None))
        try:
            attrs = SECURITY_ATTRIBUTES(c.sizeof(SECURITY_ATTRIBUTES), sd, False)
            self._ok(self.k.CreateDirectoryW(str(path), c.byref(attrs)))
        finally:
            self.k.LocalFree(sd)
        self._pin(path, True, True)
        return path

    def revalidate(self):
        require(not self.closed and bool(self.pins), 'Admission unavailable')
        for pin in self.pins:
            info = FILE_INFO()
            self._ok(self.k.GetFileInformationByHandle(pin['handle'], c.byref(info)))
            require(not info.attributes & 0x400 and
                    (info.volume, info.indexHigh, info.indexLow) == pin['identity'] and
                    self._descriptor(pin['handle'], pin['private'], pin['tolerant'],
                                     pin.get('ancestor', False))[0] == pin['descriptor'],
                    'Pinned path/descriptor changed')
            # Attribute-only directory pins impose no sharing, so a directory can
            # be renamed and its name rebound. Re-open by name and compare the ID.
            probe = self.k.CreateFileW(pin['path'], 0x80, 7, None, 3, 0x02200000, None)
            require(probe not in (None, c.c_void_p(-1).value), 'Pinned path unavailable')
            try:
                current = FILE_INFO()
                self._ok(self.k.GetFileInformationByHandle(probe, c.byref(current)))
                require((current.volume, current.indexHigh, current.indexLow) == pin['identity'],
                        'Pinned path rebound')
            finally:
                self._ok(self.k.CloseHandle(probe))

    def close_after_settlement(self, owner):
        require(owner.state == 'SETTLED' and owner.settlement is not None, 'No administrative settlement')
        self.revalidate()
        for pin in self.pins:
            self._ok(self.k.CloseHandle(pin['handle']))
        self.closed = True
