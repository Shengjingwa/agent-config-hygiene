from __future__ import annotations

import getpass
import os
import stat
import unicodedata
from pathlib import Path


def safe_display_text(value: str) -> str:
    """Escape terminal control and format characters in display-only text."""
    pieces: list[str] = []
    for character in value:
        if character == "\\":
            pieces.append("\\\\")
        elif unicodedata.category(character).startswith("C"):
            pieces.append(f"\\u{{{ord(character):x}}}")
        else:
            pieces.append(character)
    return "".join(pieces)


def current_principal_identifiers() -> set[str]:
    """Return case-folded names and SID for the current Windows user."""
    if os.name != "nt":
        return {getpass.getuser().casefold()}
    identifiers: set[str] = set()

    import ctypes
    from ctypes import wintypes

    token_query = 0x0008
    token_user = 1
    error_insufficient_buffer = 122
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            token_query,
            ctypes.byref(token),
        ):
            return identifiers
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            token_user,
            None,
            0,
            ctypes.byref(needed),
        )
        if ctypes.get_last_error() != error_insufficient_buffer or needed.value == 0:
            return identifiers
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token,
            token_user,
            buffer,
            needed,
            ctypes.byref(needed),
        ):
            return identifiers
        sid = ctypes.cast(
            buffer,
            ctypes.POINTER(ctypes.c_void_p),
        ).contents.value
        sid_text = wintypes.LPWSTR()
        if sid and advapi32.ConvertSidToStringSidW(
            sid,
            ctypes.byref(sid_text),
        ):
            try:
                identifiers.add(sid_text.value.casefold())
            finally:
                kernel32.LocalFree(ctypes.cast(sid_text, ctypes.c_void_p))
        try:
            identifiers.add(current_account_name().casefold())
        except RuntimeError:
            pass
        return identifiers
    finally:
        if token:
            kernel32.CloseHandle(token)


def current_account_name() -> str:
    """Return the current account name for a user-scoped scheduler."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        name_sam_compatible = 2
        secur32 = ctypes.WinDLL("secur32", use_last_error=True)
        secur32.GetUserNameExW.argtypes = [
            ctypes.c_int,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.ULONG),
        ]
        secur32.GetUserNameExW.restype = wintypes.BOOL
        size = wintypes.ULONG()
        secur32.GetUserNameExW(
            name_sam_compatible,
            None,
            ctypes.byref(size),
        )
        if size.value:
            buffer = ctypes.create_unicode_buffer(size.value)
            if secur32.GetUserNameExW(
                name_sam_compatible,
                buffer,
                ctypes.byref(size),
            ):
                return buffer.value
        raise RuntimeError("Unable to resolve the current Windows account")
    return getpass.getuser()


def is_linklike(path: Path) -> bool:
    """Return whether a path is a symlink or Windows directory junction."""
    if path.is_symlink():
        return True
    is_junction = getattr(os.path, "isjunction", None)
    if is_junction and is_junction(path):
        return True
    if os.name == "nt":
        try:
            attributes = path.lstat().st_file_attributes
        except (AttributeError, OSError):
            return False
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return False


def first_linklike_component(path: Path, boundary: Path) -> Path | None:
    """Find a link-like existing component from boundary through path."""
    lexical_path = Path(os.path.abspath(path))
    lexical_boundary = Path(os.path.abspath(boundary))
    try:
        relative = lexical_path.relative_to(lexical_boundary)
    except ValueError:
        return lexical_path if is_linklike(lexical_path) else None
    current = lexical_boundary
    if os.path.lexists(current) and is_linklike(current):
        return current
    for part in relative.parts:
        current = current / part
        if os.path.lexists(current) and is_linklike(current):
            return current
    return None


def owned_by_current_principal(path: Path) -> bool:
    """Return whether the path owner belongs to the current security context."""
    if os.name != "nt":
        try:
            return path.lstat().st_uid == os.getuid()
        except OSError:
            return False

    import ctypes
    from ctypes import wintypes

    token_query = 0x0008
    token_user = 1
    token_owner = 4
    owner_security_information = 0x00000001
    se_file_object = 1
    error_insufficient_buffer = 122

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi32.EqualSid.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    owner_sid = ctypes.c_void_p()
    security_descriptor = ctypes.c_void_p()
    result = advapi32.GetNamedSecurityInfoW(
        str(path),
        se_file_object,
        owner_security_information,
        ctypes.byref(owner_sid),
        None,
        None,
        None,
        ctypes.byref(security_descriptor),
    )
    if result != 0 or not owner_sid:
        if security_descriptor:
            kernel32.LocalFree(security_descriptor)
        return False

    token = wintypes.HANDLE()
    try:
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            token_query,
            ctypes.byref(token),
        ):
            return False
        for information_class in (token_user, token_owner):
            needed = wintypes.DWORD()
            advapi32.GetTokenInformation(
                token,
                information_class,
                None,
                0,
                ctypes.byref(needed),
            )
            if ctypes.get_last_error() != error_insufficient_buffer or needed.value == 0:
                continue
            buffer = ctypes.create_string_buffer(needed.value)
            if not advapi32.GetTokenInformation(
                token,
                information_class,
                buffer,
                needed,
                ctypes.byref(needed),
            ):
                continue
            candidate_sid = ctypes.cast(
                buffer,
                ctypes.POINTER(ctypes.c_void_p),
            ).contents.value
            if candidate_sid and advapi32.EqualSid(owner_sid, candidate_sid):
                return True
        return False
    finally:
        if token:
            kernel32.CloseHandle(token)
        if security_descriptor:
            kernel32.LocalFree(security_descriptor)
