from __future__ import annotations

import logging
from datetime import datetime, timezone
from errno import ENOTEMPTY
from io import BytesIO
from pathlib import PurePath, PureWindowsPath
from typing import Any, ClassVar
import os
import hashlib

from fsspec import AbstractFileSystem
from fsspec.implementations.local import LocalFileSystem
from fsspec.utils import stringify_path

import ixpy

logger = logging.getLogger(__name__)


class IxpMemoryFileSystem(AbstractFileSystem):
    """A filesystem based on a dict of BytesIO objects

    This is a global filesystem so instances of this class all point to the same
    in memory filesystem.
    """

    protocol = "ixpmemory"
    root_marker = "/"

    def __init__(self, *args, **kwargs):
        self.store = IxpMemoryFile(path="/")
        self.store.qid._type.directory = True
        self.store.qid._path = 0
        super().__init__(*args, **kwargs)

    @classmethod
    def _strip_protocol(cls, path):
        if isinstance(path, PurePath):
            if isinstance(path, PureWindowsPath):
                return LocalFileSystem._strip_protocol(path)
            else:
                path = stringify_path(path)

        protocol = "ixpmemory"
        if path.startswith(f"{protocol}://"):
            path = path[len(f"{protocol}://") :]
        if "::" in path or "://" in path:
            return path.rstrip("/")
        path = path.lstrip("/").rstrip("/")
        return "/" + path if path else ""

    def ls(self, path, detail=True, **kwargs):
        path = self._strip_protocol(path)
        try:
            items = self.store.get_by_path(path)._children
        except Exception as e:
            raise FileNotFoundError(f"{path} - {str(e)}")
        out = []
        as_9p = kwargs.get("as_9p", False)
        for item in items:
            stat = item.fs_stat()
            if as_9p:
                stat = item.as_9p()
            out.append(stat)
        if detail:
            return out
        return sorted([f["name"] for f in out])

    def mkfunc(self, path, obj):
        path = self._strip_protocol(path)
        if not self.isdir(path):
            raise NotADirectoryError(f"mkfunc path={path} MUST be a directory")
        directory = self.store.get_by_path(path)
        directory.add_child(obj)

    def mkdir(self, path, create_parents=True, **kwargs):
        path = self._strip_protocol(path)
        item = self.store.get_by_path(path)

        if item and self.isfile(path):
            raise FileExistsError(path)
        if self._parent(path).strip("/") and self.isfile(self._parent(path)):
            raise NotADirectoryError(self._parent(path))
        if create_parents and self._parent(path).strip("/"):
            try:
                self.mkdir(self._parent(path), create_parents, **kwargs)
            except FileExistsError:
                pass

        parent = self.store.get_by_path(self._parent(path))
        if parent and not item:
            child = IxpMemoryFile(path=path)
            child.qid._type.directory = True
            parent.add_child(child)

    def makedirs(self, path, exist_ok=False):
        try:
            self.mkdir(path, create_parents=True)
        except FileExistsError:
            if not exist_ok:
                raise

    def pipe_file(self, path, value, **kwargs):
        """Set the bytes of given file

        Avoids copies of the data if possible
        """
        self.open(path, "wb", data=value)

    def rmdir(self, path):
        path = self._strip_protocol(path)
        parent_path = self._parent(path)
        child_name = os.path.basename(path)
        # print(f"rmdir(path={path}) parent={parent_path} child={child_name}")

        child = self.store.get_by_path(path)
        parent = self.store.get_by_path(parent_path)
        if path == "":
            # silently avoid deleting FS root
            return
        if child:
            if not self.ls(path):
                parent.remove_child_by_name(child_name)
            else:
                raise OSError(ENOTEMPTY, "Directory not empty", path)
        else:
            raise FileNotFoundError(path)

    def info(self, path, **kwargs):
        logger.debug(f"path={path}")
        path = self._strip_protocol(path)
        item = self.store.get_by_path(path)
        if not item:
            raise FileNotFoundError(path)
        elif kwargs.get("as_9p", False):
            return item.as_9p()
        else:
            return item.fs_stat()

    def chmod(self, path, mode):
        logger.debug(f"path={path}")
        path = self._strip_protocol(path)
        item = self.store.get_by_path(path)
        if not item:
            raise FileNotFoundError(path)
        item.mode = mode
        return True

    def chown(self, path, user_id, group_id):
        logger.debug(f"path={path}")
        path = self._strip_protocol(path)
        item = self.store.get_by_path(path)
        if not item:
            raise FileNotFoundError(path)
        if user_id:
            item.uid = user_id
        if group_id:
            item.gid = group_id
        return True

    def utime(self, path, times=None):
        logger.debug(f"path={path} times={times}")
        path = self._strip_protocol(path)
        item = self.store.get_by_path(path)
        if not item:
            raise FileNotFoundError(path)
        atime = times[0]
        mtime = times[1]
        logger.debug(f"atime={atime} mtime={mtime})")
        if atime:
            item.atime = atime
        if mtime:
            item.mtime = mtime
        return True

    def _raw(self, path, **kwargs):
        return self.info(path, as_9p=True, **kwargs)

    def _open(
        self,
        path,
        mode="rb",
        block_size=None,
        autocommit=True,
        cache_options=None,
        **kwargs,
    ):
        path = self._strip_protocol(path)
        item = self.store.get_by_path(path)
        logger.debug(f"item is {type(item)}")

        if item and item.qid._type.directory:
            raise IsADirectoryError(path)
        parent = path
        # This checks to see if any part of the path is a file
        while len(parent) > 1:
            parent = self._parent(parent)
            if self.isfile(parent):
                raise FileExistsError(parent)
        if mode in ["rb", "ab", "r+b"]:
            if item:
                f = item
                if mode == "ab":
                    # position at the end of file
                    f.seek(0, 2)
                else:
                    # position at the beginning of file
                    f.seek(0)
                return f
            else:
                raise FileNotFoundError(path)
        elif mode == "wb":
            m = IxpMemoryFile(fs=self, path=path, data=kwargs.get("data"))
            if not self._intrans:
                m.commit()
            parent_dir = self.store.get_by_path(self._parent(path))
            parent_dir.add_child(m)
            return m
        else:
            name = self.__class__.__name__
            raise ValueError(f"unsupported file mode for {name}: {mode!r}")

    def cp_file(self, path1, path2, **kwargs):
        path1 = self._strip_protocol(path1)
        path2 = self._strip_protocol(path2)
        path2_name = os.path.basename(path2)
        if self.isfile(path1):
            path1_file = self.store.get_by_path(path1)
            path2_parent = self.store.get_by_path(self._parent(path2))
            path2_file = self.store[path2] = IxpMemoryFile(
                fs=self, path=path2, data=path1_file.getvalue()
            )  # implicit copy
            path2_parent.add_child(path2_file)
        elif self.isdir(path1):
            # FIXME: Is this even what I want?
            if not path2_parent.contains_child(path2_name):
                path1_file = self.store.get_by_path(path1)
                path1_copy = copy.deepcopy(path1_file)
                path2_parent.add_child(path1_copy)
        else:
            raise FileNotFoundError(path1)

    def cat_file(self, path, start=None, end=None, **kwargs):
        logger.debug(f"path={path}")
        path = self._strip_protocol(path)
        f = self.store.get_by_path(path)
        logger.debug(f"f is {type(f)}")
        try:
            return bytes(f.getbuffer()[start:end])
        except KeyError:
            raise FileNotFoundError(path)

    def _rm(self, path):
        path = self._strip_protocol(path)
        name = os.path.basename(path)
        parent = self.store.get_by_path(self._parent(path))

        if parent.contains_child(name):
            parent.remove_child_by_name(name)
        else:
            raise FileNotFoundError(path)

    def modified(self, path):
        info = self.info(path)
        return info["mtime"]

    def created(self, path):
        info = self.info(path)
        return info["mtime"]

    def rm(self, path, recursive=False, maxdepth=None):
        if isinstance(path, str):
            path = self._strip_protocol(path)
        else:
            path = [self._strip_protocol(p) for p in path]
        # FIXME: This doesn't work
        paths = self.expand_path(path, recursive=recursive, maxdepth=maxdepth)
        print(f"rm paths {paths}")
        for p in reversed(paths):
            # If the expanded path doesn't exist, it is only because the expanded
            # path was a directory that does not exist in self.pseudo_dirs. This
            # is possible if you directly create files without making the
            # directories first.
            if not self.exists(p):
                continue
            if self.isfile(p):
                self.rm_file(p)
            else:
                self.rmdir(p)


class QIDType:
    def __init__(self):
        self.directory = False
        self.append = False
        self.exclusive = False
        self.mount = False
        self.auth_file = False
        self.temp_file = False


class QID:
    def __init__(self, path):
        self._type = QIDType()
        self._version = 1
        self._path = self._to_path_number(path)

    def _to_path_number(self, path):
        # Create SHA-1 hash of the string
        sha1_hash = hashlib.sha1(path.encode()).digest()

        # Take the first N bytes (8 bits per byte) of the hash
        first_n_bytes = sha1_hash[:8]
        result = int.from_bytes(first_n_bytes, byteorder="big", signed=False)
        return result


class IxpMemoryFile(BytesIO):
    """A BytesIO which can't close and works as a context manager

    Can initialise with data. Each path should only be active once at any moment.

    No need to provide fs, path if auto-committing (default)
    """

    def __init__(
        self, fs=None, path=None, data=None, mode=0o755, uid="glenda", gid="glenda"
    ):
        logger.debug(f"path={path}")
        self.fs = fs
        name = os.path.basename(path)

        self.qid = QID(path=path)
        self._mode = mode
        self.atime = datetime.now(tz=timezone.utc)
        self.mtime = datetime.now(tz=timezone.utc)
        self.name = name
        self.uid = uid
        self.gid = gid
        self.muid = uid
        self._path = path
        self._children = []
        if data:
            super().__init__(data)
            self.seek(0)

    @property
    def length(self):
        """The length of the buffer, or 0 if it's a dynamic file

        A file is considered to be dynamic if qid.version is 0
        """
        if self.qid._version > 0:
            return self.getbuffer().nbytes
        else:
            return 0

    @property
    def mode(self):
        mode = self._mode
        if self.qid._type.directory:
            mode = mode | ixpy.DMDIR
        return mode

    @mode.setter
    def mode(self, value):
        self._mode = value

    def __enter__(self):
        return self

    def close(self):
        pass

    def discard(self):
        pass

    def commit(self):
        # self.fs.store[self.path] = self
        self.modified = datetime.now(tz=timezone.utc)

    def as_9p(self):
        return {
            "qid": {
                "type": {
                    "dir": self.qid._type.directory,
                    "append": self.qid._type.append,
                    "exclusive": self.qid._type.exclusive,
                    "mount": self.qid._type.mount,
                    "auth_file": self.qid._type.auth_file,
                    "temp_file": self.qid._type.temp_file,
                },
                "version": self.qid._version,
                "path": self.qid._path,
            },
            "mode": self.mode,
            "atime": self.atime.isoformat().replace("+00:00", "Z"),
            "mtime": self.mtime.isoformat().replace("+00:00", "Z"),
            "length": self.length,
            "name": self.name,
            "uid": self.uid,
            "gid": self.gid,
            "muid": self.muid,
        }

    def fs_stat(self):
        return {
            "name": self.name,
            "type": "directory" if self.qid._type.directory else "file",
            "size": self.length,
            "qid": self.qid,
            "mode": self.mode,
            "accessed": self.atime.timestamp(),
            "modified": self.mtime.timestamp(),
            "uid": self.uid,
            "gid": self.gid,
            "muid": self.muid,
        }

    def add_child(self, child):
        self._children.append(child)

    def contains_child(self, name):
        for child in self._children:
            if child.name == name:
                return True
        return False

    def remove_child_by_name(self, name):
        for i, child in enumerate(self._children):
            if child.name == name:
                del self._children[i]
                return True  # Return True if the child was found and removed
        return False  # Return False if no child with the specified name was found

    def get_by_path(self, path):
        # If the path is "/", return the current object (assuming it's the root)
        if path == "/" or path == "":
            return self

        # Split the path into parts
        parts = path.strip("/").split("/")

        # Start with the current object
        current = self

        for part in parts:
            # Search among the children for the matching name
            found = None
            for child in current._children:
                if child.name == part:
                    found = child
                    break

            if found is None:
                # If no child with the specified name is found, return None or raise an error
                return None

            # Move to the found child
            current = found

        return current
