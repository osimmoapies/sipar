"""One wording for a file that cannot be read (round 7): `cannot read X: permission denied`.

Python's own text repeats the path and shows internals (`[Errno 13] Permission denied: 'x.sipar'`,
`'utf-8' codec can't decode byte 0xff in position 19`); every reader of a source file, journal, memory store,
mock script or pin file says why in the same short words instead."""
from __future__ import annotations


def why_unreadable(e: BaseException) -> str:
    """The reason in a few lowercase words, without the path (the caller names the file once)."""
    if isinstance(e, UnicodeDecodeError):
        return "not UTF-8 text"
    if isinstance(e, FileNotFoundError):
        return "no such file"
    if isinstance(e, IsADirectoryError):
        return "is a directory"
    if isinstance(e, PermissionError):
        return "permission denied"
    text = (e.strerror if isinstance(e, OSError) else None) or str(e) or type(e).__name__
    return text[:1].lower() + text[1:]


# ------------------------------------------------------------------ the safe reader (round 8, M3 / L1)
# open() of a FIFO blocks until a writer comes (a hang), and read() of /dev/zero or a huge file never ends
# (or eats all memory). Every file Sipar reads from its own folders (memory store, log and lock, MCP pin file,
# mock script, journal) goes through open_regular: opened without blocking, then it must be a regular file,
# and at most `limit` bytes. Program sources may also be a pipe (`sipar check <(gen.sh)`), read up to the limit.

import errno as _errno
import os as _os
import stat as _stat

MAX_FILE_BYTES = 256 * 1024 * 1024      # memory store / log, mock script, journal, program source


SYMLINK = "not a regular file (a symbolic link)"


class FileRefused(OSError):
    """A file Sipar does not read: not a regular file, or too large. `strerror` holds the reason in the
    words of why_unreadable ("not a regular file", "too large (... bytes; the limit is ...)")."""


def _mb(n: int) -> str:
    return f"{n // (1024 * 1024)} MB" if n >= 1024 * 1024 else f"{n:,} bytes"


def open_regular(path: str, limit: int | None, *, write: bool = False, allow_pipe: bool = False,
                 nofollow: bool = False) -> int:
    """An fd of `path` (read-only; write=True: write-only, append, created 0o666 when missing) that is a
    regular file of at most `limit` bytes (None: any size) — or a pipe when allow_pipe, put back in blocking
    mode. Never blocks on a FIFO. nofollow=True: a symbolic link as the last part of `path` is FileRefused
    "not a regular file (a symbolic link)" and never followed, so nothing is created or written where it points
    (round 9, F5: the memory store's own files). Raises OSError: the usual ones, IsADirectoryError, or FileRefused."""
    nb = getattr(_os, "O_NONBLOCK", 0)
    flags = nb | getattr(_os, "O_NOCTTY", 0) | getattr(_os, "O_CLOEXEC", 0)
    flags |= (_os.O_WRONLY | _os.O_APPEND | _os.O_CREAT) if write else _os.O_RDONLY
    if nofollow:
        flags |= getattr(_os, "O_NOFOLLOW", 0)
    try:
        fd = _os.open(path, flags, 0o666)
    except OSError as e:
        if e.errno == _errno.ENXIO:         # a FIFO opened for writing with no reader
            raise FileRefused(_errno.ENXIO, "not a regular file") from None
        if nofollow and e.errno == _errno.ELOOP and _os.path.islink(path):    # O_NOFOLLOW met a link
            raise FileRefused(_errno.ELOOP, SYMLINK) from None
        raise
    try:
        st = _os.fstat(fd)
        if _stat.S_ISDIR(st.st_mode):
            raise IsADirectoryError(_errno.EISDIR, "is a directory")
        if allow_pipe and not write and _stat.S_ISFIFO(st.st_mode):
            if nb:
                _os.set_blocking(fd, True)      # a pipe with a writer is read to its end
            return fd
        if not _stat.S_ISREG(st.st_mode):
            raise FileRefused(_errno.EINVAL, "not a regular file")
        if limit is not None and st.st_size > limit:
            raise FileRefused(_errno.EFBIG, f"too large ({st.st_size:,} bytes; the limit is {_mb(limit)})")
        return fd
    except BaseException:
        _os.close(fd)
        raise


def read_bytes(path: str, limit: int = MAX_FILE_BYTES, *, allow_pipe: bool = False) -> bytes:
    """The whole file through open_regular, never more than `limit` bytes (a file that grows past it, or a
    longer pipe, is FileRefused "too large")."""
    fd = open_regular(path, limit, allow_pipe=allow_pipe)
    try:
        parts, n = [], 0
        while True:
            chunk = _os.read(fd, min(1 << 20, limit + 1 - n))
            if not chunk:
                break
            parts.append(chunk)
            n += len(chunk)
            if n > limit:
                raise FileRefused(_errno.EFBIG, f"too large (more than {_mb(limit)})")
        return b"".join(parts)
    finally:
        _os.close(fd)


def read_text(path: str, limit: int = MAX_FILE_BYTES, *, encoding: str = "utf-8", allow_pipe: bool = False) -> str:
    """read_bytes decoded like open(path, encoding=...).read(): "\\r\\n" and "\\r" become "\\n".
    Not UTF-8 raises UnicodeDecodeError."""
    text = read_bytes(path, limit, allow_pipe=allow_pipe).decode(encoding)
    if "\r" in text:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text


def program_dir(program_file) -> str:
    """The folder that holds `.sipar/` (runs, memory, fixtures, MCP pins) and that relative `allow fs` paths
    start from: the program's own folder — or the current folder when the program is not a regular file, such
    as a pipe (`sipar run <(gen.sh)`, `cat x.sipar | sipar run /dev/stdin`), whose "folder" (/dev/fd) cannot
    hold files (round 9, M4). A path that cannot be looked up keeps its own folder."""
    path = _os.path.abspath(program_file)
    try:
        regular = _stat.S_ISREG(_os.stat(path).st_mode)
    except (OSError, ValueError):
        regular = True
    return _os.path.dirname(path) if regular else _os.getcwd()
