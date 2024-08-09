"""9P implementation of fsspec."""

from __future__ import annotations

import io
import os
import pathlib
from typing import Optional
from datetime import datetime, timezone

import fsspec.spec
import logging

import ixpy

logging.basicConfig(level=logging.WARNING)


class P9Error(Exception):
    """Base class for P9FileSystem errors."""


class P9FileNotFound(P9Error):
    """File not found error."""


class P9FileSystem(fsspec.AbstractFileSystem):
    """9P implementation of fsspec."""

    protocol = "ixp"

    def __init__(
        self,
        host: str,
        port: int,
        verbose: bool = False,
        username: str = "glenda",
        aname: str = "",
        **kwargs,
    ):
        """9P2000 implementation of fsspec.

        Args:
            host: 9P2000 server host
            port: 9P2000 server port
        """
        super().__init__(**kwargs)
        self.host = host
        self.port = port
        self.verbose = verbose
        self.aname = aname

        self.log = logging.getLogger(self.__class__.__name__)

        self.ixp = ixpy.Client(host=host, port=port, fid_pool=ixpy.HashFidPool())
        self.ixp._open_socket()

        self.ixp.Tversion(tag=65535, version="9P2000")
        self.ixp.Tattach(fid=0, uname=username, aname=aname)

    @classmethod
    def _strip_protocol(cls, path):
        # print(f"_strip_protocol: {path}")
        return path

    def _mkdir(self, path, mode: int = 0o755):
        self.log.info(f"_mkdir({path}, {mode})")
        mode = mode | ixpy.DMDIR

        return self._mknod(path, mode)

    def mkdir(
        self, path, create_parents=True, exist_ok=False, mode: int = 0o755, **kwargs
    ):
        if create_parents:
            self.makedirs(path, exist_ok=True)
            return
        self._mkdir(path=path, mode=mode)

    def makedirs(self, path, exist_ok=False):
        self.log.info(f"makedirs({path}, exist_ok={exist_ok})")
        parents = pathlib.Path(path).parents
        # skip '.' item returned by 'parents'
        items = [str(parent) for parent in reversed(parents) if str(parent) != "."]
        items.append(path)
        for item in items:
            if exist_ok and self.exists(item):
                if not self.isdir(item):
                    raise P9Error(f"{item} exists and not a directory")
                continue
            self.mkdir(item, create_parents=False)

    def info(self, path, **kwargs):
        self.log.info(f"info({path})")

        if not self.exists(path):
            raise P9FileNotFound(f"{path} does not exist")

        fid = self.ixp.fid_pool[path]
        rv = self.ixp.Twalk(fid=0, newfid=fid, wnames=path)
        item = self.ixp.Tstat(fid=fid).payload
        self.log.debug(f"Tstat result: {item}")
        item_type = "directory" if item.qid["type"]["dir"] else "file"
        if item_type == "directory" and not path.endswith("/"):
            path = f"{path}/"
        rv = {
            "name": path,
            "type": item_type,
            "mode": item.mode,
            "size": item.length,
            "atime": item.atime,
            "mtime": item.mtime,
            "uid": item.uid,
            "gid": item.gid,
        }
        return rv

    def exists(self, path, **kwargs) -> bool:
        """Is there a file at the given path"""
        rv = self.ixp.Twalk(fid=0, newfid=100, wnames=path)
        nwqid = rv.payload.nwqid
        parts = path.split("/")[1:]
        return nwqid == len(parts)

    def isdir(self, path) -> bool:
        """Is this entry directory-like?"""
        # FIXME: Cache stuff! check if path was in cache
        wnames = path
        # print(f"exists: walking {wnames}")
        rv = self.ixp.Twalk(fid=0, newfid=100, wnames=wnames)
        nwqid = rv.payload.nwqid
        parts = wnames.split("/")[1:]
        if nwqid != len(parts):
            return False
        return rv.payload.wqids[-1]["type"]["dir"]

    def isfile(self, path):
        """Is this entry file-like?"""
        raise NotImplementedError

    def rmdir(self, path):
        raise NotImplementedError

    def _listdir(self, path: str):
        self.log.info(f"_listdir: {path}")
        out = b""
        with ixpy.IXPReader(self.ixp, path) as reader:
            for chunk in reader.read():
                out += chunk
        entries = []
        for f in ixpy.StatPayloads.parse(out):
            entries.append(
                {
                    "name": f"{path}/{f.name}",
                    "size": f.length,
                    "type": "directory" if f.qid.type.dir else "file",
                    "mode": f.mode,
                    "mtime": f.mtime,
                    "atime": f.atime,
                    "ctime": f.mtime,
                    # FIXME: Figure something out here
                    "uid": 0,
                    "gid": 0,
                    # "ino": stat_info.st_ino,
                    # "islink": os.path.islink(entry_path),
                    # "nlink": stat_info.st_nlink,
                }
            )
        return entries

    def ls(self, path, detail=True, **kwargs):
        entries = self._listdir(path)
        if detail is True:
            entries
        else:
            rv = [entry["name"] for entry in entries]
            entries = rv
        return entries

    def rm_file(self, path):
        fid = self.ixp.fid_pool[path]
        self.ixp.Twalk(fid=0, newfid=fid, wnames=path)
        self.ixp.Tremove(fid=fid)
        self.ixp.fid_pool.close(fid)

    def rm(self, path, recursive=False, maxdepth=None):
        """Delete files.

        Parameters
        ----------
        path: str or list of str
            File(s) to delete.
        recursive: bool
            If file(s) are directories, recursively delete contents and then
            also remove the directory
        maxdepth: int or None
            Depth to pass to walk for finding files to delete, if recursive.
            If None, there will be no limit and infinite recursion may be
            possible.
        """
        path = self.expand_path(path, recursive=recursive, maxdepth=maxdepth)
        self.log.info(f"rm({path}, recursive={recursive}, maxdepth={maxdepth})")
        for p in reversed(path):
            self.rm_file(p)

    def _mknod(self, path, mode):
        perm = mode
        parts = path.split("/")[1:]
        name = parts.pop()

        fid = self.ixp.fid_pool[f"mknod:{path}"]
        self.log.info(f"_mknod: Twalk(fid=0, newfid={fid}, wnames={parts})")
        self.ixp.Twalk(fid=0, newfid=fid, wnames=parts)
        self.log.info(f"_mknod: Tcreate(fid={fid}, name={name}, perm={perm}, mode=0)")
        self.ixp.Tcreate(fid=fid, name=name, perm=perm, mode=0)
        # FIXME: Refactor to leave this unclunked, or do reference counting
        #        so that we don't need to walk it again, if it's open
        self.log.info(f"_mknod: Tclunk(fid={fid})")
        self.ixp.Tclunk(fid=fid)
        self.ixp.fid_pool.close(fid)
        return True

    def cp_file(self, path1, path2, **kwargs):
        """Copy within two locations in the same filesystem."""
        self.log.info(f"cp_file({path1}, {path2})")
        src_info = self.info(path1)
        dst_info = None
        try:
            dst_info = self.info(path2)
        except P9FileNotFound:
            self._mknod(path2, src_info["mode"])
            dst_info = self.info(path2)

        if dst_info["type"] == "directory":
            path2 = str(pathlib.Path(path2) / pathlib.Path(path1).name)
            self._mknod(path2, src_info["mode"])

        sf = self._open(path1, "rb")
        df = self._open(path2, "wb")
        try:
            df.write(sf.read())
            # for i in range((src_info['size'] + self.client.msize - 1) // self.client.msize):
            #     block = self._read(self.client.msize, i * self.client.msize, sf)
            #     self._write(block, i * self.client.msize, df)
        finally:
            pass
            # self._release_fid(sf)
            # self._release_fid(df)

    def mv(self, path1, path2, recursive=None, maxdepth=None, **kwargs):
        # TODO: reuse the same code from p8fs-init
        #       BUT add a check for the Twstat trick
        if path1 == path2:
            return
        self.copy(path1, path2, recursive=recursive, maxdepth=maxdepth)
        self.rm(path1, recursive=recursive)

    def accessed(self, path):
        rv = self.info(path)
        return rv["atime"]

    def modified(self, path):
        self.log.info(f"modified({path})")
        rv = self.info(path)
        return rv["mtime"]

    def created(self, path):
        raise NotImplementedError

    def _empty_stat(self):
        return {
            # FIXME: Give this a default value
            "mode": 438,
            # FIXME: Give this a default value
            "atime": "1969-12-31T23:59:59.000000000Z",
            # FIXME: Give this a default value
            "mtime": "1969-12-31T23:59:59.000000000Z",
            "name": "",
            "uid": "",
            "gid": "",
            "muid": "",
        }

    def chmod(self, path, mode):
        # FIXME: I probably want to replace all of this with .exists()
        fid = self.ixp.fid_pool[path]
        self.ixp.Twalk(fid=0, newfid=fid, wnames=path)
        item = self.ixp.Tstat(fid=fid).payload
        stat = self._empty_stat()
        # FIXME: Give this a default value
        stat["qid"] = item.qid
        stat["mode"] = 0o666
        rv = self.ixp.Twstat(fid=fid, stat=stat)
        self.log.debug(f"chmod result: {rv}")

    def chown(self, path, user_name, group_name):
        # FIXME: I probably want to replace all of this with .exists()
        fid = self.ixp.fid_pool[path]
        self.ixp.Twalk(fid=0, newfid=fid, wnames=path)
        item = self.ixp.Tstat(fid=fid).payload
        stat = self._empty_stat()
        stat["qid"] = item.qid
        stat["uid"] = user_name
        stat["gid"] = group_name
        self.log.debug(f"chown: stat={stat}")
        rv = self.ixp.Twstat(fid=fid, stat=stat)
        self.log.debug(f"chown result: {rv}")

    def utime(self, path, times=None):
        # FIXME: I probably want to replace all of this with .exists()
        fid = self.ixp.fid_pool[path]
        self.ixp.Twalk(fid=0, newfid=fid, wnames=path)
        item = self.ixp.Tstat(fid=fid).payload

        if times is None:
            now_utc = datetime.now(timezone.utc)

            # Format the time as ISO 8601 timestamp
            current_time = now_utc.isoformat()
            times = (current_time, current_time)

        stat = self._empty_stat()
        stat["qid"] = item.qid
        stat["atime"] = str(times[0])
        stat["mtime"] = str(times[1])
        self.log.info(f"Twstat(fid={fid}, stat={stat})")
        rv = self.ixp.Twstat(fid=fid, stat=stat)
        self.log.debug(f"Twstat returned: {rv}")

    def _open(
        self,
        path,
        mode="rb",
        block_size=None,
        autocommit=True,
        cache_options=None,
        **kwargs,
    ):
        return P9BufferedFile(
            self,
            path,
            mode,
            block_size,
            autocommit,
            cache_options=cache_options,
            **kwargs,
        )


class P9BufferedFile(fsspec.spec.AbstractBufferedFile):
    _fid: Optional[int] = None

    def __init__(self, *args, **kwargs):
        # Call the __init__ method of the superclass
        super().__init__(*args, **kwargs)
        self.log = logging.getLogger(self.__class__.__name__)

    def _upload_chunk(self, final=False):
        """Write one part of a multi-block file upload

        Parameters
        ==========
        final: bool
            This is the last block, so should complete file, if
            self.autocommit is True.
        """
        self.log.debug("_upload_chunk")
        if self.offset is None or self._fid is None:
            try:
                self._initiate_upload()
            except:  # noqa: E722
                self.closed = True
                raise

        data = self.buffer.getvalue()
        size = len(data)
        offset = 0
        msize = self.fs.ixp.msize - ixpy.IO_HEADER_SIZE
        self.log.debug(f"_upload_chunk msize={msize}")
        while offset < size - 1:
            asize = min(msize, size - offset)
            # print(f"** _upload_chunk asize={asize}")
            # self.fs._write(data[offset:offset + asize], self.offset + offset, self._f)
            off = self.offset + offset
            payload = data[offset : offset + asize]
            # print(f"Twrite(fid={self._fid} offset={off} size={size} data=payload)")
            self.fs.ixp.Twrite(
                fid=self._fid,
                offset=off,
                size=size,
                data=payload,
            )
            offset += asize
        self.log.debug("_upload_chunk DONE")
        return True

    def _initiate_upload(self):
        """Create remote file/upload"""
        self.offset = 0

        parts = list(pathlib.Path(self.path).parts)
        name = parts.pop()
        # FIXME: these should be dynamic, right?
        perm = 0o755
        # mode = os.O_WRONLY | os.O_TRUNC
        mode = 1

        # info = self.fs.info(self.path)
        # print(f"_initiate_upload info: {info}")

        if not self.fs.exists(self.path):
            fid = self.fs.ixp.fid_pool[f"create:{self.path}"]
            self.log.info(f"Twalk(fid=0, newfid={fid}, wnames={parts})")
            self.fs.ixp.Twalk(fid=0, newfid=fid, wnames=parts)
            self.log.info(f"Tcreate(fid={fid}, name={name}, perm={perm}, mode=0)")
            self.fs.ixp.Tcreate(fid=fid, name=name, perm=perm, mode=0)

        info = self.fs.info(self.path)
        if "a" in self.mode:
            self.offset = info["size"]

        fid = self.fs.ixp.fid_pool[f"opened:{self.path}"]
        self.log.info(f"Twalk(fid=0, newfid={fid}, wnames={self.path})")
        self.fs.ixp.Twalk(fid=0, newfid=fid, wnames=self.path)
        self.log.info(f"Topen(fid={fid}, mode=rwx: {mode})")
        self.fs.ixp.Topen(fid=fid, mode={"rwx": mode})
        self._fid = fid

    def _fetch_range(self, start: int, end: int) -> bytes:
        """Get the specified set of bytes from remote"""
        self.log.info(f"_fetch_range({start}, {end})")
        if self._fid is None:
            self.log.info(f"_fetch_range: creating fid for {self.path}")
            fid = self.fs.ixp.fid_pool[self.path]
            self.fs.ixp.Twalk(fid=0, newfid=fid, wnames=self.path)
            self.fs.ixp.Topen(fid=fid, mode={"rwx": os.O_RDONLY})
            self.log.info(f"_fetch_range: created fid {fid}")
            self._fid = fid
        data = io.BytesIO()
        offset = start
        msize = self.fs.ixp.msize - ixpy.IO_HEADER_SIZE
        msize = int(msize / 2)
        msize = 1024
        self.log.debug(f"_fetch_range msize={msize} offset={offset} < end={end}")
        while offset < end:
            count = min(msize, end - offset + 1)
            self.fs.ixp.Tread(fid=self._fid, offset=offset, count=count)
            offset += data.write(self.fs.ixp.last_reply.payload.data)
        return data.getvalue()

    def close(self):
        """Close file"""
        super().close()
        if self._fid is not None:
            self.log.info(f"Closing FID: {self._fid}")
            self.fs.ixp.Tclunk(fid=self._fid)
            self.fs.ixp.fid_pool.close(self._fid)
            self._fid = None
