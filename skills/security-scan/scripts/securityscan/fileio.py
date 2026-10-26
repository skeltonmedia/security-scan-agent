"""Open selected files without following a raced symlink outside project scope."""
import os
import stat
from pathlib import Path


def _windows_final_path(fd):
    import ctypes
    import msvcrt
    from ctypes import wintypes
    function = ctypes.WinDLL("kernel32", use_last_error=True).GetFinalPathNameByHandleW
    function.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    function.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    count = function(msvcrt.get_osfhandle(fd), buffer, len(buffer), 0)
    if not count or count >= len(buffer):
        raise OSError("could not establish final file scope")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value)


def _open_scoped(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("file path escaped selected scope")
    if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"):
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in relative.parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = child
            return os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        finally:
            os.close(directory)
    if os.name == "nt":
        fd = os.open(root / relative, os.O_RDONLY | os.O_BINARY)
        try:
            final = _windows_final_path(fd)
            # Check the already-open handle's target before reading bytes.
            if os.path.commonpath([os.path.normcase(str(root)), os.path.normcase(str(final))]) != os.path.normcase(str(root)):
                raise OSError("opened file target escaped selected scope")
            return fd
        except BaseException:
            os.close(fd)
            raise
    raise OSError("race-resistant file scope checks are unsupported on this platform")


def bounded_read(root, relative, max_bytes):
    fd = _open_scoped(root, relative)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            return None, "special"
        if info.st_size > max_bytes:
            return None, "large"
        raw = handle.read(max_bytes + 1)
        if len(raw) > max_bytes:
            return None, "growing"
        return raw, "read"
