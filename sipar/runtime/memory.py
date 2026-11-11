"""`memory` module: labelled persistent key/value memory (SPEC.md §5, §6).

Values are stored as JSON in `<program dir>/.sipar/memory/<program stem>.json`:

    {"version": 1,
     "entries": {"<key>": {"value": <json>, "labels": [[<path>, ["untrusted:...", ...]], ...], "enc": 2}}}

Enums with payload are stored as {"variant": {fields}} ("enc": 2). Entries without "enc" were written in the
older tagged form {"tag": "variant", ...fields}; they still load unless the enum has a field named `tag`
(then the old form is ambiguous and loading is an `io` error).

A path is a list of steps from the stored value to a labelled leaf: an int (list index) or a str (map key,
record field, enum payload field); a final {"key": k} step means "the map key k itself". Labels are kept per
leaf, so a value saved while untrusted loads back untrusted, exactly where it was untrusted.
Secrets are never stored (error kind `taint`). Writes take an exclusive flock on `<store>.lock` (reads a shared
one). A store file up to SMALL_STORE bytes is rewritten whole (temp file + os.replace()), so a crash leaves
the old file and concurrent writers do not lose each other's keys; a bigger one takes later writes in the
append-only log `<store>.log`, folded in when it outgrows the store file. The store file carries a random
"gen" and the log a header line with it, so a log is only ever applied to its own store file (see FileStore).
In `sipar test` the store is in memory and fresh for every test.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from typing import Any

from ..errors import SiparRuntimeError
from ..errors import clip
from ..fileread import SYMLINK, FileRefused, open_regular, program_dir, read_text, why_unreadable
from . import jsondeep
from .decode import MAX_VALUE_DEPTH, TOO_DEEP, from_json, too_deep, type_str
from .effects import check_sinks
from .values import (EMPTY, EnumVal, LDict, LFloat, LInt, LList, LRecord, LStr, RangeVal, Record, deep_label,
                     holds_lone_surrogate, labels_of, mark_secrets, mutated, own_labels, set_labels)

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None

VERSION = 1
ENC = 2          # entry encoding: enums with payload as {"variant": {fields}} (entries without "enc" are 1)
MAX_KEY = 256
MAX_FILE = 1024 * 1024 * 1024   # store file and log: a bigger one is never read, and no write makes one (round 8)


# ------------------------------------------------------------------ value <-> (json, label paths)

def encode(v: Any) -> tuple[Any, list]:
    """Sipar value -> (plain JSON, [[path, sorted labels], ...]). Raises `value` on cycles and functions."""
    paths: list = []
    stack: set[int] = set()

    path: list = []         # one shared trail (copied only for a labelled leaf): linear for deep values

    def leaf(x: Any, path: list) -> None:
        if isinstance(x, (LStr, LInt, LFloat)) and x.labels:
            paths.append([list(path), sorted(x.labels)])

    def sub(y: Any, seg: Any) -> Any:
        if len(path) >= MAX_VALUE_DEPTH:
            raise SiparRuntimeError("value", f"memory.save: value {TOO_DEEP}")
        path.append(seg)
        try:
            return walk(y)
        finally:
            path.pop()

    def walk(x: Any) -> Any:
        if x is None or x is True or x is False:
            return x
        if isinstance(x, str):
            leaf(x, path)
            return str.__str__(x)
        if isinstance(x, int):
            leaf(x, path)
            return int(x)
        if isinstance(x, float):
            if x != x or x in (float("inf"), float("-inf")):
                raise SiparRuntimeError("value", "memory.save: NaN and infinity cannot be stored")
            leaf(x, path)
            return float(x)
        if isinstance(x, RangeVal):
            if x.labels:
                for i in range(x.end - x.start):
                    paths.append([path + [i], sorted(x.labels)])
            return list(range(x.start, x.end))
        if isinstance(x, (list, dict, Record, EnumVal)):
            if id(x) in stack:
                raise SiparRuntimeError("value", "memory.save: the value contains itself (a cycle); it cannot be "
                                                 "stored as JSON")
            stack.add(id(x))
            if own_labels(x):       # a container picked with a labelled index/key (SPEC §6): keep its labels
                paths.append([path + [{"own": True}], sorted(own_labels(x))])
            try:
                if isinstance(x, list):
                    return [sub(y, i) for i, y in enumerate(x)]
                if isinstance(x, dict):
                    out = {}
                    for k, y in x.items():
                        ks = str.__str__(k) if isinstance(k, str) else str(k)
                        if isinstance(k, LStr) and k.labels:
                            paths.append([path + [{"key": ks}], sorted(k.labels)])
                        out[ks] = sub(y, ks)
                    return out
                if isinstance(x, Record):
                    return {f: sub(y, f) for f, y in x.fields.items()}
                if not x.fields:
                    return x.variant
                return {x.variant: {f: sub(y, f) for f, y in x.fields.items()}}
            finally:
                stack.discard(id(x))
        raise SiparRuntimeError("value", "memory.save: functions cannot be stored")

    try:
        data = walk(v)
    except RecursionError:
        raise SiparRuntimeError("value", "memory.save: value too deeply nested")
    return data, paths


# a label path has one step per level of the value (at most MAX_VALUE_DEPTH) plus a last {"own": true} / {"key": k};
# a longer one is malformed (round 9, F2: 2,000,000 steps made a 6 MB error line and a 12 MB journal)
MAX_LABEL_PATH = MAX_VALUE_DEPTH + 1


def _valid_paths(paths: Any) -> bool:
    if not isinstance(paths, list):
        return False
    for p in paths:
        if not (isinstance(p, list) and len(p) == 2 and isinstance(p[0], list) and isinstance(p[1], list)
                and len(p[0]) <= MAX_LABEL_PATH and all(isinstance(l, str) for l in p[1])):
            return False
        for s in p[0]:
            if not (isinstance(s, str) or (isinstance(s, int) and not isinstance(s, bool))
                    or (isinstance(s, dict) and set(s) == {"key"} and isinstance(s["key"], str))
                    or s == {"own": True}):
                return False
    return True


def decode(entry: Any, t, tenv, key: str) -> Any:
    """Stored entry -> Sipar value of type t with the stored labels re-attached leaf by leaf.
    A label that cannot be put back (the type changed so that the leaf is now a Bool, none or enum) is an
    error kind `decode`: memory never silently drops a label."""
    if not isinstance(entry, dict) or "value" not in entry or not _valid_paths(entry.get("labels", [])):
        raise SiparRuntimeError("io", f"memory entry {key!r} is malformed")
    enc = entry.get("enc", 1)
    if type(enc) is not int or enc not in (1, ENC):        # round 9, F6: not 2.0, 1.0 or true
        raise SiparRuntimeError("io", f"memory entry {key!r} has an unknown encoding")
    if too_deep(entry["value"]):
        raise SiparRuntimeError("io", f"memory.load({key!r}): the stored value is nested too deeply")
    try:
        v = from_json(entry["value"], t, tenv, EMPTY, "$", "any" if enc == ENC else "legacy")
    except SiparRuntimeError as e:
        if e.kind == "io":
            raise SiparRuntimeError("io", f"memory.load({key!r}): {e.message}")
        raise SiparRuntimeError("decode", f"memory.load({key!r}): the stored value does not match {type_str(t)}: "
                                          f"{e.message}")
    except RecursionError:
        raise SiparRuntimeError("io", f"memory.load({key!r}): the stored value is nested too deeply")
    for path, labels in entry.get("labels", []):
        v = _relabel(v, path, frozenset(labels), key, t)
        mutated()                       # _relabel changes v in place (L, round 6)
    return v


def _short(x: Any, n: int = 120) -> str:
    """Stored data in an error message, cut to about n characters (round 9, F2: it was echoed whole)."""
    text = str(x)
    return text if len(text) <= n else f"{clip(text, n)}... ({len(text):,} characters)"


def _relabel(v: Any, path: list, labels: frozenset, key: str, t, whole: list | None = None) -> Any:
    """`whole`: the stored path that `path` is the rest of (the error names it, not the rest; round 9)."""
    whole = path if whole is None else whole

    def bad() -> SiparRuntimeError:
        return SiparRuntimeError("decode", f"memory.load({key!r}): stored labels {_short(sorted(labels))} do not "
                                           f"fit {type_str(t)} at {_short(whole)}")

    if not path:
        if isinstance(v, (str, int, float)) and not isinstance(v, bool):
            return set_labels(v, labels_of(v) | labels)
        raise bad()
    step, rest = path[0], path[1:]
    if step == {"own": True}:           # the container's own labels (SPEC §6 selection)
        if rest:
            raise bad()
        if isinstance(v, list):
            return LList(v, own_labels(v) | labels)
        if isinstance(v, dict):
            return LDict(v, own_labels(v) | labels)
        if isinstance(v, Record):
            return LRecord(v.type_name, v.fields, own_labels(v) | labels)
        raise bad()
    if isinstance(step, dict):
        if rest or not isinstance(v, dict) or step["key"] not in v:
            raise bad()
        items = list(v.items())
        v.clear()
        for k, y in items:
            if k == step["key"]:
                k = set_labels(k, labels_of(k) | labels)
            v[k] = y
        return v
    if isinstance(step, int) and isinstance(v, list) and 0 <= step < len(v):
        v[step] = _relabel(v[step], rest, labels, key, t, whole)
        return v
    if isinstance(step, str):
        if isinstance(v, dict) and step in v:
            v[step] = _relabel(v[step], rest, labels, key, t, whole)
            return v
        if isinstance(v, (Record, EnumVal)) and step in v.fields:
            v.fields[step] = _relabel(v.fields[step], rest, labels, key, t, whole)
            return v
    raise bad()


# ------------------------------------------------------------------ stores

def dump_store(entries: dict, gen: str | None = None, merged: str | None = None) -> str:
    """The store file text: one entry per line. Each entry goes through the C JSON encoder (json.dump with
    `indent` is the pure-Python one, whose nested generators cost depth² for a deep value — round 5).
    `gen` is the store's generation stamp (FileStore); None writes the store without one (as before round 7).
    `merged` is the SHA-256 of a header-less log folded into this store (FileStore, round 8)."""
    lines = [f" {jsondeep.dumps(k, ensure_ascii=False)}: {jsondeep.dumps(v, ensure_ascii=False)}"
             for k, v in entries.items()]
    body = "{\n" + ",\n".join(lines) + "\n }" if lines else "{}"
    stamp = f', "gen": {jsondeep.dumps(gen)}' if gen is not None else ""
    if merged is not None:
        stamp += f', "merged": {jsondeep.dumps(merged)}'
    return '{"version": ' + str(VERSION) + stamp + ', "entries": ' + body + "}\n"


class MemStore:
    """In-memory store (used by `sipar test`)."""

    def __init__(self):
        self.entries: dict[str, dict] = {}

    def get(self, key: str) -> dict | None:
        if key not in self.entries:
            return None
        return _checked_entry(key, jsondeep.loads(jsondeep.dumps(self.entries[key])))

    def keys(self) -> list[str]:
        return sorted(self.entries)

    def put(self, key: str, entry: dict) -> None:
        self.entries[key] = jsondeep.loads(jsondeep.dumps(entry))

    def delete(self, key: str) -> bool:
        return self.entries.pop(key, None) is not None


def _checked_entry(key: str, e: Any) -> dict:
    """L4 (round 8): a stored entry that is not {"value": ..., "labels": [...]} (also null) is error kind `io`
    inside the memory.load effect, so the error is journaled and replays the same; keys() lists such a key
    and memory.delete removes it (returns true), as for every other malformed entry."""
    if not isinstance(e, dict) or "value" not in e or not _valid_paths(e.get("labels", [])):
        raise SiparRuntimeError("io", f"memory entry {key!r} is malformed")
    e.setdefault("labels", [])
    return e


def _too_big(what: str, path: str) -> SiparRuntimeError:
    return SiparRuntimeError("io", f"cannot write memory store {path}: the {what} would be larger than "
                                   f"{MAX_FILE // (1024 * 1024)} MB; delete keys you no longer need")


SMALL_STORE = 8 * 1024      # a store file up to this size is rewritten whole on every write (as before round 6)


class FileStore:
    """The store file `<stem>.json` plus, once it is over SMALL_STORE bytes, an append-only log
    `<stem>.json.log` of later writes (F6, round 6: rewriting the whole file on every save was quadratic).

    A log line is {"k": key, "e": entry} (a save) or {"k": key, "d": 1} (a delete), written with
    jsondeep.dumps_line; exactly these shapes, anything else is an `io` error. Blank lines are skipped.

    Generations (round 7): every rewrite of the store file stamps it with a new random "gen", and a log
    starts with the header line {"g": gen} of the store it belongs to. A log is applied only on top of the
    store file with that gen; a log with another gen, or any log when there is no store file (it was deleted,
    or a crash came between "replace the store file" and "remove the log", so the log is already folded
    in), is ignored, and the next write removes it. A store without "gen" and a log without a header
    (written before round 7) still go together; the first write after that stamps the store (a full
    rewrite). A log without a header next to a stamped store is an `io` error (never silently dropped),
    unless it is the one that rewrite folded in: the store's "merged" is its SHA-256 (M2, round 8).
    Store, log and lock must be regular files, store and log at most MAX_FILE bytes (M3, round 8). Writes never
    follow a symlink: a lock or log that is one, or a store file that is one, is an `io` error (F5, round 9).

    When the log grows past the store file it is folded in (compaction): each byte is rewritten a bounded number of times, so N saves cost O(N)
    amortized. A last log line without a newline is a write that a crash cut short: it is ignored, and the
    next writer cuts it off. Writes hold an exclusive flock on `<stem>.json.lock`, reads a shared one.
    The parsed store is kept between calls and only re-read when a file changed (only new log lines when
    just the log grew), so memory.load in a loop is linear too."""

    def __init__(self, path: str):
        self.path = path
        self.log = path + ".log"
        self._entries: dict | None = None
        self._base_id: tuple | None = None      # (inode, size, mtime_ns, ctime_ns) of the store file read
        self._log_ino: int | None = None
        self._log_off = 0                       # bytes of the log already applied
        self._base_size = 0
        self._gen: str | None = None            # the "gen" of the store file read (None: none, or no file)
        self._merged: str | None = None         # its "merged": SHA-256 of a header-less log already folded in
        self._merged_id: tuple | None = None    # (inode, size, mtime_ns) of the log last seen to match it

    # ---------------------------------------------------------- reading
    def _read_base(self) -> tuple[dict, str | None, str | None]:
        """(entries, gen, merged) of the store file; ({}, None, None) when there is none."""
        try:        # round 8: a FIFO, a device (a symlink to /dev/zero) or a file over MAX_FILE is not read
            text = read_text(self.path, MAX_FILE)
        except FileNotFoundError:
            return {}, None, None
        except (OSError, UnicodeDecodeError) as e:     # round 7: not UTF-8 was a raw Python error
            fix = "; fix or delete it (it was not changed)" if isinstance(e, (UnicodeDecodeError, FileRefused)) else ""
            raise SiparRuntimeError("io", f"cannot read memory store {self.path}: {why_unreadable(e)}{fix}")
        try:
            data = jsondeep.loads(text)
        except RecursionError:
            raise SiparRuntimeError("io", f"memory store {self.path} is nested too deeply to read; fix or delete "
                                          "it (it was not changed)")
        except jsondeep.NumberTooLarge as e:
            raise SiparRuntimeError("io", f"memory store {self.path} holds {e}; fix or delete it (it was not changed)")
        except ValueError:
            raise SiparRuntimeError("io", f"memory store {self.path} is not valid JSON; fix or delete it "
                                          "(it was not changed)")
        if "\\u" in text and holds_lone_surrogate(data):          # round 5, C2: never a Sipar Str
            raise SiparRuntimeError("io", f"memory store {self.path} holds text that is not valid Unicode (a lone "
                                          "surrogate); fix or delete it (it was not changed)")
        if (not isinstance(data, dict) or data.get("version") != VERSION or not isinstance(data.get("entries"), dict)
                or not isinstance(data.get("gen", ""), str) or not isinstance(data.get("merged", ""), str)):
            raise SiparRuntimeError("io", f"memory store {self.path} has an unknown format (expected "
                                          f"\"version\": {VERSION}); it was not changed")
        return data["entries"], data.get("gen"), data.get("merged")

    def _parse_line(self, raw: bytes) -> Any:
        try:
            text = raw.decode("utf-8")
            rec = jsondeep.loads(text)
        except RecursionError:
            raise SiparRuntimeError("io", f"memory store log {self.log} is nested too deeply to read; fix or "
                                          "delete it (it was not changed)")
        except jsondeep.NumberTooLarge as e:
            raise SiparRuntimeError("io", f"memory store log {self.log} holds {e}; fix or delete it (it was not "
                                          "changed)")
        except ValueError:                  # UnicodeDecodeError is a ValueError
            raise SiparRuntimeError("io", f"memory store log {self.log} is not valid JSON; fix or delete it "
                                          "(it was not changed)")
        if "\\u" in text and holds_lone_surrogate(rec):
            raise SiparRuntimeError("io", f"memory store log {self.log} holds text that is not valid Unicode "
                                          "(a lone surrogate); fix or delete it (it was not changed)")
        return rec

    def _bad_format(self) -> SiparRuntimeError:
        return SiparRuntimeError("io", f"memory store log {self.log} has an unknown format; fix or delete it "
                                       "(it was not changed)")

    def _apply_log(self, entries: dict, fh, off: int) -> int:
        """Apply the complete log lines from byte `off` on; returns the bytes of the log now applied.
        From byte 0 the log must first show that it belongs to the store file read (see the class doc);
        a log that does not is skipped whole and 0 is returned, so it is checked again on the next read."""
        fh.seek(off)
        if off == 0:
            if self._base_id is None:
                return 0                        # no store file: a log left next to nothing is never applied
            while True:                         # the first non-blank line
                raw = fh.readline()
                if not raw.endswith(b"\n"):
                    return 0                    # none yet (or one a crash cut short)
                if raw.strip():
                    break
                off += len(raw)
            rec = self._parse_line(raw)
            if isinstance(rec, dict) and "g" in rec:
                if set(rec) != {"g"} or not isinstance(rec["g"], str):
                    raise self._bad_format()
                if rec["g"] != self._gen:
                    return 0                    # the log of another store file
                off += len(raw)
            elif self._gen is not None:
                if self._merged is not None and self._is_merged(fh):
                    return 0                    # M2 (round 8): the round-6 log this store already holds
                raise self._bad_format()        # a stamped store's log always starts with its header
            else:
                fh.seek(off)                    # both from before round 7: the first line is a record
        data = fh.read()
        end = data.rfind(b"\n") + 1
        for raw in data[:end].split(b"\n")[:-1]:
            if not raw.strip():
                continue                        # a blank (or "\r") line
            rec = self._parse_line(raw)
            if not isinstance(rec, dict) or not isinstance(rec.get("k"), str):
                raise self._bad_format()
            if set(rec) == {"k", "e"} and isinstance(rec["e"], dict):
                entries[rec["k"]] = rec["e"]
            elif set(rec) == {"k", "d"} and type(rec["d"]) is int and rec["d"] == 1:
                entries.pop(rec["k"], None)
            else:
                raise self._bad_format()
        return off + end

    @staticmethod
    def _log_hash(fh) -> str:
        fh.seek(0)
        h = hashlib.sha256()
        while chunk := fh.read(1 << 20):
            h.update(chunk)
        return h.hexdigest()

    def _is_merged(self, fh) -> bool:
        """The log is the header-less (round-6) log whose SHA-256 the store records as folded in: a crash came
        between "replace the store file" and "remove the log" in the upgrade (M2, round 8)."""
        st = os.fstat(fh.fileno())
        lid = (st.st_ino, st.st_size, st.st_mtime_ns)
        if lid != self._merged_id:
            if self._log_hash(fh) != self._merged:
                return False
            self._merged_id = lid
        return True

    def _sync(self) -> dict:
        """The current entries (the caller holds the lock)."""
        try:
            st = os.stat(self.path)
            base_id: tuple | None = (st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        except FileNotFoundError:
            base_id = None
        except OSError as e:
            raise SiparRuntimeError("io", f"cannot read memory store {self.path}: {why_unreadable(e)}")
        try:
            lfh = os.fdopen(open_regular(self.log, MAX_FILE), "rb")
        except FileNotFoundError:
            lfh = None
        except OSError as e:
            raise SiparRuntimeError("io", f"cannot read memory store log {self.log}: {why_unreadable(e)}")
        try:
            ino = os.fstat(lfh.fileno()).st_ino if lfh is not None else None
            fresh = (self._entries is None or base_id != self._base_id or ino != self._log_ino
                     or (lfh is not None and os.fstat(lfh.fileno()).st_size < self._log_off))
            if fresh:
                self._entries = None
                entries, self._gen, self._merged = self._read_base()
                self._merged_id = None
                self._base_id = base_id
                off = 0
            else:
                entries, off = self._entries, self._log_off
            if lfh is not None:
                off = self._apply_log(entries, lfh, off)
            self._entries, self._base_id, self._log_ino, self._log_off = entries, base_id, ino, off
            self._base_size = base_id[1] if base_id is not None else 0
            return entries
        except BaseException:
            self._entries = None
            raise
        finally:
            if lfh is not None:
                lfh.close()

    def _locked(self, mode: int, make: bool):
        """The open lock file, locked. For a read (make False) None when the store folder does not exist or
        the lock file cannot be opened (a read-only folder): the read then goes on unlocked, as before."""
        d = os.path.dirname(self.path)
        if not make:
            try:
                lock = self._open_lock() if os.path.isdir(d) else None
            except FileRefused as e:
                raise SiparRuntimeError("io", f"cannot open memory store lock {self.path}.lock: {e.strerror}; "
                                              "delete it")
            except OSError:
                lock = None
            if lock is not None and fcntl is not None:
                try:
                    fcntl.flock(lock.fileno(), mode)
                except BaseException:
                    lock.close()
                    raise
            return lock
        try:
            os.makedirs(d, exist_ok=True)
            lock = self._open_lock()
        except FileRefused as e:
            raise SiparRuntimeError("io", f"cannot open memory store lock {self.path}.lock: {e.strerror}; delete it")
        except FileExistsError:             # round 5, M: the folder is a file ("File exists" misled)
            raise SiparRuntimeError("io", f"cannot open memory store {self.path}: {d} is not a directory")
        except OSError as e:
            raise SiparRuntimeError("io", f"cannot open memory store {self.path}: {why_unreadable(e)}")
        if fcntl is not None:
            try:
                fcntl.flock(lock.fileno(), mode)
            except BaseException:
                lock.close()
                raise
        return lock

    def _open_lock(self):
        """The lock file, opened without blocking (round 8: a FIFO there hung the run); a regular file only."""
        return os.fdopen(open_regular(self.path + ".lock", None, write=True, nofollow=True), "ab")

    @staticmethod
    def _unlock(lock) -> None:
        if fcntl is not None:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        lock.close()

    def _read(self) -> dict:
        lock = self._locked(fcntl.LOCK_SH if fcntl is not None else 0, False)
        if lock is None:
            return self._sync()
        try:
            return self._sync()
        finally:
            self._unlock(lock)

    def get(self, key: str) -> dict | None:
        entries = self._read()
        if key not in entries:
            return None
        return _checked_entry(key, jsondeep.loads(jsondeep.dumps(entries[key])))    # the caller gets its own copy

    def keys(self) -> list[str]:
        return sorted(self._read())

    # ---------------------------------------------------------- writing
    def _rewrite(self, entries: dict) -> None:
        """Write the whole store file (temp file + fsync + rename), then drop the log it now contains."""
        d = os.path.dirname(self.path)
        gen = os.urandom(8).hex()           # a new generation: a log left behind no longer applies
        merged = None
        if self._gen is None:               # upgrading a round-6 store: record which header-less log it folds in,
            try:                            # so a crash before the unlink below leaves a log that is skipped (M2)
                with os.fdopen(open_regular(self.log, MAX_FILE), "rb") as lfh:
                    merged = self._log_hash(lfh)
            except FileNotFoundError:
                pass
        data = dump_store(entries, gen, merged).encode("utf-8")
        if len(data) > MAX_FILE:
            raise _too_big("store file", self.path)
        fd, tmp = tempfile.mkstemp(prefix=".mem-", suffix=".tmp", dir=d)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        try:
            os.unlink(self.log)
        except FileNotFoundError:
            pass
        st = os.stat(self.path)             # the cache now matches the files (we hold the lock)
        self._entries, self._log_ino, self._log_off, self._gen, self._merged = entries, None, 0, gen, merged
        self._base_id = (st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        self._base_size = st.st_size

    def _append(self, line: str) -> None:
        if self._log_off == 0:              # a new log, or one that is empty, cut short or not this store's
            line = jsondeep.dumps_line({"g": self._gen}) + "\n" + line
        if self._log_off + len(line.encode("utf-8")) > MAX_FILE:
            raise _too_big("log", self.log)
        try:                                # round 9, F5/F5b: never through a symlink, never a FIFO
            fd = open_regular(self.log, None, write=True, nofollow=True)
        except OSError as e:
            fix = "; delete it" if isinstance(e, FileRefused) else ""
            raise SiparRuntimeError("io", f"cannot write memory store log {self.log}: {why_unreadable(e)}{fix}")
        with os.fdopen(fd, "ab") as fh:
            if fh.tell() > self._log_off:   # a line a crashed writer cut short (or a stale log): cut it off
                fh.truncate(self._log_off)
            try:
                fh.write(line.encode("utf-8"))
                fh.flush()
                os.fsync(fh.fileno())
            except BaseException:
                try:                        # a failed save must not show up later
                    fh.truncate(self._log_off)
                except OSError:
                    pass
                raise
            self._log_off = fh.tell()
            self._log_ino = os.fstat(fh.fileno()).st_ino

    def _update(self, key: str, entry: dict | None) -> bool:
        lock = self._locked(fcntl.LOCK_EX if fcntl is not None else 0, True)
        try:
            if os.path.islink(self.path):   # round 9, F5: a rewrite would silently replace the link
                raise SiparRuntimeError("io", f"cannot write memory store {self.path}: {SYMLINK}; put the store "
                                              "file itself there")
            entries = self._sync()
            had = key in entries
            if entry is None and not had:
                return False                    # nothing to write
            if entry is None:
                entries.pop(key, None)
            else:
                entries[key] = entry
            if self._base_size <= SMALL_STORE or self._gen is None:   # no gen: stamp the store (round 7)
                self._rewrite(entries)
            else:
                rec = {"k": key, "e": entry} if entry is not None else {"k": key, "d": 1}
                self._append(jsondeep.dumps_line(rec) + "\n")
                if self._log_off > self._base_size:
                    try:
                        self._rewrite(entries)  # compaction
                    except (OSError, SiparRuntimeError):
                        pass                    # the save is safe in the log; the next write tries again
            return had
        except OSError as e:
            self._entries = None
            raise SiparRuntimeError("io", f"cannot write memory store {self.path}: {why_unreadable(e)}")
        except BaseException:
            self._entries = None
            raise
        finally:
            self._unlock(lock)

    def put(self, key: str, entry: dict) -> None:
        self._update(key, entry)

    def delete(self, key: str) -> bool:
        return self._update(key, None)


def store_path(program_file: str) -> str:
    base = program_dir(program_file)      # a pipe program: the current folder (round 9, M4)
    stem = os.path.splitext(os.path.basename(program_file))[0] or "program"
    return os.path.join(base, ".sipar", "memory", stem + ".json")


def store_for(rt) -> Any:
    if getattr(rt, "_memory_store", None) is None:
        rt._memory_store = MemStore() if rt.test_mode else FileStore(store_path(rt.file))
    return rt._memory_store


# ------------------------------------------------------------------ the four functions

def _key(fname: str, key: Any) -> str:
    if not isinstance(key, str):
        raise SiparRuntimeError("type", f"{fname}: key must be Str")
    k = str.__str__(key)
    if not k:
        raise SiparRuntimeError("value", f"{fname}: key must not be empty")
    if len(k) > MAX_KEY:
        raise SiparRuntimeError("value", f"{fname}: key is {len(k)} characters; the limit is {MAX_KEY}")
    return k


def save(rt, key: Any, value: Any) -> None:
    check_sinks("memory.save", {"key": key, "value": value})
    k = _key("memory.save", key)
    data, paths = encode(value)
    entry = {"value": data, "labels": paths, "enc": ENC}
    rt.journal.effect("memory.save", {"key": k, "value": data, "labels": paths, "enc": ENC},
                      lambda: store_for(rt).put(k, entry))
    return None


def load(rt, key: Any, t) -> Any:
    check_sinks("memory.load", {"key": key})
    if t is None:
        raise SiparRuntimeError("type", "memory.load: the type of the stored value is unknown here; run "
                                        "`sipar check` (write e.g. let x: List[Str]? = memory.load(\"k\"))")
    k = _key("memory.load", key)
    try:
        entry = rt.journal.effect("memory.load", {"key": k, "type": type_str(t)}, lambda: store_for(rt).get(k))
        if entry is None:
            return None
        v = mark_secrets(decode(entry, t, rt.tenv, k))      # text stored before the secret was known (SPEC §6)
    except RecursionError:      # journal scrub / labelling of a stored value Python cannot walk (SPEC §5)
        raise SiparRuntimeError("io", f"memory.load({k!r}): the stored value is nested too deeply") from None
    kl = labels_of(key)
    return deep_label(v, kl) if kl else v


def delete(rt, key: Any) -> bool:
    check_sinks("memory.delete", {"key": key})
    k = _key("memory.delete", key)
    return bool(rt.journal.effect("memory.delete", {"key": k}, lambda: store_for(rt).delete(k)))


def keys(rt) -> list:
    ks = rt.journal.effect("memory.keys", {}, lambda: store_for(rt).keys())
    if not isinstance(ks, list) or not all(isinstance(k, str) for k in ks):
        raise SiparRuntimeError("replay", "memory.keys: journal entry is not a list of strings")
    return mark_secrets(list(ks))
