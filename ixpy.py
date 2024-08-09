#!/usr/bin/env python3

from typing import Optional
from typing import Union
import base64
import datetime
import errno
import json
import locale
import logging
import random
import socket

from construct import (  # type: ignore
    Adapter,
    Array,
    BitStruct,
    BitsInteger,
    Bytes,
    Computed,
    Default,
    Enum,
    Flag,
    GreedyBytes,
    GreedyRange,
    Int16ul,
    Int32sl,
    Int32ub,
    Int32ul,
    Int64ul,
    Int8ul,
    Padding,
    PascalString,
    Prefixed,
    Struct,
    Switch,
    len_,
    this,
)
import construct

logging.basicConfig(level=logging.WARNING)

# See also:
# https://github.com/plan9foundation/plan9/blob/9db62717612a49f78a83b26ff5a176971c6cdd18/sys/include/libc.h#L545-L552

OREAD = OPEN_FOR_READ = 0
OWRITE = OPEN_FOR_WRITE = 1
ORDWR = OPEN_FOR_READ_AND_WRITE = 2
OEXEC = OPEN_FOR_READ_CHECK_EXECUTE = 3  # execute, == read but check execute permission
OTRUNC = WITH_TRUNCATE = 16  # or'ed in (except for exec), truncate file first
OCEXEC = WITH_CLOSE_ON_EXEC = 32  # or'ed in, close on exec
ORCLOSE = WITH_REMOVE_ON_CLOSE = 64  # or'ed in, remove on close
OEXCL = WITH_EXCLUSIVE_USE = 0x1000  # or'ed in, exclusive use (create only)

# via: https://github.com/pbchekin/p9fs-py/blob/8fe727bde1f1fecf94869da4432ba0555aa53502/src/py9p/py9p.py#L190C1-L207C51
# Dir.mode
DMDIR = 0x80000000  # mode bit for directories
DMAPPEND = 0x40000000  # mode bit for append only files
DMEXCL = 0x20000000  # mode bit for exclusive use files
DMMOUNT = 0x10000000  # mode bit for mounted channel
DMAUTH = 0x08000000  # mode bit for authentication file
DMTMP = 0x04000000  # mode bit for non-backed-up file
DMSYMLINK = 0x02000000  # mode bit for symbolic link (Unix, 9P2000.u)
DMDEVICE = 0x00800000  # mode bit for device file (Unix, 9P2000.u)
DMNAMEDPIPE = 0x00200000  # mode bit for named pipe (Unix, 9P2000.u)
DMSOCKET = 0x00100000  # mode bit for socket (Unix, 9P2000.u)
DMSETUID = 0x00080000  # mode bit for setuid (Unix, 9P2000.u)
DMSETGID = 0x00040000  # mode bit for setgid (Unix, 9P2000.u)
DMSTICKY = 0x00010000  # mode bit for sticky bit (Unix, 9P2000.u)

DMREAD = 0x4  # mode bit for read permission
DMWRITE = 0x2  # mode bit for write permission
DMEXEC = 0x1  # mode bit for execute permission

# When reading data using a Rread message, the maximum amount of data that
# we can read is the msize which is negotiated with the server minus
# this value below, which is the total size of the Tread headers that
# aren't part of the data payload
IO_HEADER_SIZE = 24
IOHDRSZ = 24

# e.g.: {'E2BIG': 7, 'EACCES': 13}
errno_dict = {
    name: getattr(errno, name)
    for name in dir(errno)
    if isinstance(getattr(errno, name), int)
}
Errno = Enum(Int32ul, **errno_dict)  # In 9P, at least


PrefixedString = PascalString(Int16ul, "utf8")
Bytes1 = Int8ul
Bytes2 = Int16ul
Bytes4 = Int32ul
Bytes8 = Int64ul

StatMode = Int32ub

DEFAULT_M_SIZE = 8192

# "If the client does not wish to authenticate the connection, or knows that
# authentication is not required, the afid field in the attach message should be
# set to NOFID, defined as (u32int)~0 in <fcall.h>. If the client does wish to
# authenticate, it must acquire and validate an afid using an auth message
# before doing the attach."
# via: http://9p.io/magic/man2html/5/attach
NOFID = 0xFFFFFFFF


def file_mode_to_9p_mode(file_mode):
    result = {
        "mode": OPEN_FOR_READ,
        "truncate": False,
        "append": False,
        "io_type": "text",
    }
    if "b" in file_mode:
        result["io_type"] = "binary"
    if "w" in file_mode:
        result["mode"] = OPEN_FOR_WRITE
        result["truncate"] = True
    if "x" in file_mode:
        result["mode"] = OPEN_FOR_WRITE | WITH_EXCLUSIVE_USE
    if "a" in file_mode:
        result["mode"] = OPEN_FOR_WRITE
        result["append"] = True
    if "+" in file_mode:
        result["mode"] = OPEN_FOR_READ_AND_WRITE

    return result


class Message:
    def __init__(self):
        self.message = IxpMessage

    def _message_build(self, name, tag, payload):
        return self.message.build({"type": name, "tag": tag, "payload": payload})

    def deserialize(self, data):
        return self.message.parse(data)

    def __getattr__(self, name):
        def method(*args, **kwargs):
            if "tag" not in kwargs:
                kwargs["tag"] = 1
            tag = kwargs["tag"]
            del kwargs["tag"]
            data = self._message_build(name, tag, kwargs)
            return data

        return method


class Rerror(Exception):
    def __init__(self, message):
        super().__init__(message)


def receive_all(sock, length):
    log = logging.getLogger("receieve_all")
    data = b""
    while len(data) < length:
        want = length - len(data)
        log.debug(f"Want: {want}")
        more = sock.recv(want)
        if not more:
            raise EOFError(
                f"Was expecting {length} bytes but got {len(data)} bytes before the socket closed"
            )
        data += more
        got = len(more)
        log.debug(f"receive_all got: {got}")
    return data


class Client:
    def __init__(self, host=None, port=None, fid_pool=None, start_at_tag=1):
        self.host = host
        self.port = port
        self.fid_pool = fid_pool
        self.msize = DEFAULT_M_SIZE
        self.message = IxpMessage
        self.tag = start_at_tag
        self.last_reply = None
        self.socket = None
        self.log = logging.getLogger(self.__class__.__name__)

    def _open_socket(self):
        if self.socket:
            self._close_socket()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.settimeout(5)  # Set a timeout of 10 seconds
        self.socket.connect((self.host, self.port))
        self.log.info("Socket connected")

    def _close_socket(self):
        try:
            if self.socket:
                self.socket.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            self.log.warn(f"Error shutting down socket: {e}")
        finally:
            if self.socket:
                self.socket.close()
                self.socket = None
                self.log.info("Socket closed")

    def _reset_socket(self):
        self.log.debug("Resetting socket...")
        self._close_socket()
        self._open_socket()

    def __enter__(self):
        # self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.socket.connect((self.host, self.port))
        self._open_socket()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
        # FIXME: Why is this commented out??!?!
        # for fid in self.fid_pool.open_fids:
        #     print(f"Client self.Tclunk(fid={fid})")
        #     self.Tclunk(fid=fid)
        #     self.fid_pool.close(fid)

        # self._close_socket()
        # try:
        #     self.socket.shutdown(socket.SHUT_RDWR)
        # except OSError as e:
        #     print(f"Error shutting down socket: {e}")
        # finally:
        #     self.socket.close()
        #     print("Socket closed")

    # FIXME: Get this working with server too
    def __getattr__(self, name):
        def method(*args, **kwargs):
            # Use the internal tag counter if no tag is set
            if "tag" not in kwargs:
                kwargs["tag"] = self.tag
                self.tag += 1
            # Remove tag from kwargs as it is set seperately
            tag = kwargs["tag"]
            del kwargs["tag"]
            # Allow a string to be passed to wnames
            if "wnames" in kwargs and isinstance(kwargs["wnames"], str):
                if not kwargs["wnames"].startswith("/"):
                    raise ValueError(
                        "If a string is passed to wnames, it MUST start with '/'"
                    )
                kwargs["wnames"] = kwargs["wnames"].split("/")[1:]
            # FIXME: Consider renaming "payload" to something like "__embedded"
            obj = {"type": name, "tag": tag, "payload": kwargs}
            # print(f"Sent: {obj}")
            data = self.message.build(obj)
            self.socket.sendall(data)
            received = self.socket.recv(self.msize)

            reply = self.message.parse(received)
            if reply.type == "Rerror":
                raise Rerror(f"9P2000 Error for {name}({tag}): {reply.payload.ename}")
            elif name == "Tversion" and reply.type == "Rversion":
                self.log.info(f"Setting msize to: {reply.payload.msize}")
                self.msize = reply.payload.msize
            self.last_reply = reply
            return reply

        return method


class HashFidPool:
    # FIXME: create a MAX_VALUE define elsewhere
    def __init__(self, max_value=2**31 - 1):
        self.max_value = max_value
        self._by_name = dict()
        self._by_fid = dict()
        self.log = logging.getLogger(self.__class__.__name__)

    def __getitem__(self, key):
        if key in self._by_name:
            return self._by_name[key]
        else:
            return self.new(key)

    def new(self, name=None):
        """Generates a random fid and adds it to the set of open fids."""
        while True:
            # Generate a random number between 1 and max_value
            fid = random.randint(1, self.max_value)
            # Check if the fid is already in use
            if fid not in self._by_fid:
                if not name:
                    name = fid
                self._by_fid[fid] = name
                self._by_name[name] = fid
                return fid

    # FIXME: Use reference counting
    def close(self, item):
        if item in self._by_fid:
            fid = item
            name = self._by_fid[fid]
            del self._by_fid[fid]
            del self._by_name[name]
            self.log.info(f"closed name '{name}' using fid {fid} from FidPool")
        if item in self._by_name:
            name = item
            fid = self._by_name[name]
            del self._by_fid[fid]
            del self._by_name[name]
            self.log.info(f"closed fid {fid} using name '{name}' from FidPool")

    # FIXME: Find a way to remove this method
    @property
    def open_fids(self):
        """Returns a list of all open fids."""
        return list(self._by_fid.keys())


class IXPOpener:
    def __init__(
        self,
        ixp: Client,
        file: str,
        mode: str = "r",
        buffering: int = -1,
        encoding=None,
        errors=None,
        newline=None,
        closefd: bool = True,
        opener=None,
    ) -> None:
        self.ixp = ixp
        self.file = file
        self.option = file_mode_to_9p_mode(mode)
        self.buffering = buffering
        self.errors = errors
        self.closefd = closefd
        self.opener = opener
        self.log = logging.getLogger(self.__class__.__name__)

        self.log.info(
            f"__init__(file={file} mode={mode} buffering={buffering}"
            f" errors={errors} closefd={closefd} opener={opener})"
        )

        if not encoding:
            self.encoding = locale.getencoding()
        else:
            self.encoding = encoding

        self.offset = 0
        self.fid = ixp.fid_pool[file]
        self.ixp.Twalk(fid=0, newfid=self.fid, wnames=self.file)
        stat = self.ixp.Tstat(fid=self.fid).payload
        ixp_mode = self.option["mode"]
        if self.option["append"]:
            self.offset = stat.length
            self.log.info(f"__init__: appending after offset {self.offset}")
        self.ixp.Topen(fid=self.fid, mode={"rwx": ixp_mode})
        self.log.info(f"__init__: {self.file} as fid {self.fid} with mode {ixp_mode}")

    def write(self, payload: Union[str, bytes]) -> int:
        if isinstance(payload, str) and self.option["io_type"] == "text":
            payload = payload.encode(self.encoding)
        else:
            raise TypeError("Writing a string when file is not opened for text")
        size = len(payload)
        self.log.debug(f"write(fid={self.fid} offset={self.offset} size={size} ...)")
        self.ixp.Twrite(fid=self.fid, offset=self.offset, size=size, data=payload)
        self.offset += size
        return size

    def seek(self, position: int):
        self.offset = position

    def read(self, count: Optional[int] = None) -> Union[str, bytes]:
        max_size = self.ixp.msize - IO_HEADER_SIZE

        if count is None or count > max_size:
            count = max_size
        self.log.debug(f"read(count={count})")
        if not self.fid:
            raise ValueError(f"fid for {self.file} is not set")
        output = b""
        while True:
            self.log.debug(
                f"Tread(tag={self.ixp.tag}, fid={self.fid}, "
                f"offset={self.offset}, count={count})"
            )
            self.ixp.Tread(fid=self.fid, offset=self.offset, count=count)
            data = self.ixp.last_reply.payload.data
            reply_count = self.ixp.last_reply.payload.count
            if not data:
                break
            output += data
            # print(f"if {reply_count} <= {count}:")
            if reply_count < count:
                self.log.debug("That's all, folks!")
                break
            else:
                self.offset += count
        return output

    def __iter__(self):
        return self

    def __next__(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.log.debug(f"__exit__: Tclunk(fid={self.fid})")
        self.ixp.Tclunk(fid=self.fid)
        self.ixp.fid_pool.close(self.fid)


# FIXME: Modify to open in append mode if we're appending
# FIXME: Refactor this into an Open class with read, write, append
class IXPWriter:
    def __init__(self, ixp, fid):
        self.offset = 0
        self.fid = fid
        self.ixp = ixp
        self.log = logging.getLogger(self.__class__.__name__)
        self.log.debug(f"__init__({self.fid})")

    def append(self, data):
        if not self.fid:
            raise ValueError("fid is not set")
        size = len(data)
        # print(
        #     f"ixp.Twrite(tag={self.ixp.tag}, fid={self.fid}, "
        #     f"offset={self.offset}, size={size}, data=data)"
        # )
        self.ixp.Twrite(fid=self.fid, offset=self.offset, size=size, data=data)
        self.offset += size

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.ixp.Tclunk(fid=self.fid)
        self.ixp.fid_pool.close(self.fid)


class IXPReader:
    def __init__(self, ixp, path):
        self.offset = 0
        self.path = path
        self.fid_path = f"IXPReader:{path}"
        self.ixp = ixp
        self.fid = ixp.fid_pool
        myfid = self.fid[self.fid_path]
        self.log = logging.getLogger(self.__class__.__name__)
        # print(f"Twalk(fid=0, newfid={myfid}, wnames={self.path}")
        self.ixp.Twalk(fid=0, newfid=myfid, wnames=self.path)
        # print(rv)
        # print(f"Topen(fid={myfid}, mode=rwx: 0)")
        self.ixp.Topen(fid=myfid, mode={"rwx": 0})
        # print(f"IXPReader {self.path} : {self.fid[self.fid_path]}")

    def read(self):
        count = self.ixp.msize - IO_HEADER_SIZE
        # count = 900
        if not self.fid[self.fid_path]:
            raise ValueError(f"fid for {self.fid_path} is not set")
        while True:
            # print(
            #     f"ixp.Tread(tag={self.ixp.tag}, fid={self.fid[self.path]}, "
            #     f"offset={self.offset}, count={count})"
            # )
            self.ixp.Tread(fid=self.fid[self.fid_path], offset=self.offset, count=count)
            data = self.ixp.last_reply.payload.data
            reply_count = self.ixp.last_reply.payload.count
            if not data:
                break
            yield data
            # print(f"if {reply_count} <= {count}:")
            if reply_count < count:
                self.log.debug("read: That's all, folks!")
                break
            else:
                self.offset += count

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.ixp.Tclunk(fid=self.fid[self.fid_path])
        self.ixp.fid_pool.close(self.fid[self.fid_path])


class HexAdapter(Adapter):
    def _decode(self, obj, context, path):
        # Convert the integer to a hex string prefixed with '0x'
        return f"0x{obj:02x}"

    def _encode(self, obj, context, path):
        # Convert the hex string back to an integer
        return int(obj, 16)


# Adapter to convert parsed data to ISO 8601 format
# FIXME: Update this to handle nanoseconds
class Plan9TimestampAdapter(Adapter):
    def _decode(self, obj, context, path):
        # obj is the container with seconds and nanoseconds
        # dt = datetime.datetime.fromtimestamp(obj.seconds, datetime.UTC)
        dt = datetime.datetime.utcfromtimestamp(obj.seconds)
        date_str = dt.strftime("%Y-%m-%dT%H:%M:%S")
        # 09d ensures nanoseconds are zero-padded to 9 digits
        if not obj.nanoseconds:
            obj.nanoseconds = 0
        rv = f"{date_str}.{obj.nanoseconds:09d}Z"
        return str(rv)

    def _encode(self, obj, context, path):
        """Split the ISO timestamp to get date-time and nanoseconds"""
        # FIXME: Clean this up
        if "Z" in obj:
            obj = obj.replace("Z", "")
        if "." in obj:
            datetime_part, ns_part = obj.split(".")
        else:
            datetime_part = str(obj)
            ns_part = 0
        datetime_part += "Z"
        dt = datetime.datetime.fromisoformat(datetime_part)
        total_seconds = int(dt.timestamp())
        nanoseconds = int(ns_part)
        rv = {"seconds": total_seconds, "nanoseconds": nanoseconds}
        return rv


class Base64Adapter(Adapter):
    def _decode(self, obj, context, path):
        return base64.b64encode(obj).decode("utf-8")

    def _encode(self, obj, context, path):
        return base64.b64decode(obj)


QID = Struct(
    "type"
    / BitStruct(
        "dir" / Default(Flag, False),
        "append" / Default(Flag, False),
        "exclusive" / Default(Flag, False),
        "mount" / Default(Flag, False),
        "auth_file" / Default(Flag, False),
        "temp_file" / Default(Flag, False),
        # These are named so that we can set them to "True"
        # in the edge case where we are setting all bits
        # in the QID to "True" during a Twstat operation
        "__unused_1" / Default(Flag, False),
        "__unused_2" / Default(Flag, False),
    ),
    "version" / Int32ul,
    "path" / Int64ul,
)

POSIXRequestMaskFlags = BitStruct(
    # --
    # define P9_GETATTR_CTIME        0x00000080ULL
    "ctime" / Default(Flag, False),
    # define P9_GETATTR_MTIME        0x00000040ULL
    "mtime" / Default(Flag, False),
    # define P9_GETATTR_ATIME        0x00000020ULL
    "atime" / Default(Flag, False),
    # define P9_GETATTR_RDEV         0x00000010ULL
    "rdev" / Default(Flag, False),
    # define P9_GETATTR_GID          0x00000008ULL
    "gid" / Default(Flag, False),
    # define P9_GETATTR_UID          0x00000004ULL
    "uid" / Default(Flag, False),
    # define P9_GETATTR_NLINK        0x00000002ULL
    "nlink" / Default(Flag, False),
    # define P9_GETATTR_MODE         0x00000001ULL
    "mode" / Default(Flag, False),
    # ---
    Padding(2),
    # define P9_GETATTR_DATA_VERSION 0x00002000ULL
    "data_version" / Default(Flag, False),
    # define P9_GETATTR_GEN          0x00001000ULL
    "gen" / Default(Flag, False),
    # define P9_GETATTR_BTIME        0x00000800ULL
    "btime" / Default(Flag, False),
    # define P9_GETATTR_BLOCKS       0x00000400ULL
    "blocks" / Default(Flag, False),
    # define P9_GETATTR_SIZE         0x00000200ULL
    "size" / Default(Flag, False),
    # define P9_GETATTR_INO          0x00000100ULL
    "ino" / Default(Flag, False),
    # ---
    # TODO: Figure out how to model these ... eventually
    # define P9_GETATTR_BASIC        0x000007ffULL /* Mask for fields up to BLOCKS */
    # define P9_GETATTR_ALL          0x00003fffULL /* Mask for All fields above */
    Padding(48),
)


# From Wireshark:
#
# .0.. .... = Remove on close: Not set
# ...0 .... = Trunc: Not set
# .... ..00 = Open/Create Mode: Read Access (0)
#
# From ChatGPT:
# OREAD    (0): Open for reading
# OWRITE   (1): Open for writing
# ORDWR    (2): Open for reading and writing
# OEXEC    (3): Open for executing
#
# OTRUNC  (16): Truncate file when opened. Set file length to 0 if it exists
# ORCLOSE (64): Remove file when it is closed. Useful for temporary files
# See also: https://github.com/pbchekin/p9fs-py/blob/main/src/py9p/py9p.py#L161
Mode = BitStruct(
    Padding(1),
    "orclose" / Default(Flag, False),
    Padding(1),
    "trunc" / Default(Flag, False),
    Padding(2),
    "rwx" / Default(BitsInteger(2), 0),
)

POSIXMode = BitStruct(
    Padding(1),
    "read_group" / Default(Flag, False),
    "write_group" / Default(Flag, False),
    "exec_group" / Default(Flag, False),
    Padding(1),
    "read_others" / Default(Flag, False),
    "write_others" / Default(Flag, False),
    "exec_others" / Default(Flag, False),
    # -----
    Padding(5),
    "read_owner" / Default(Flag, False),
    "write_owner" / Default(Flag, False),
    "exec_owner" / Default(Flag, False),
    # ----
    Padding(8),
    # ----
    "dir" / Default(Flag, False),
    "append" / Default(Flag, False),
    "exclusive" / Default(Flag, False),
    "mount" / Default(Flag, False),
    "auth_file" / Default(Flag, False),
    "temp_file" / Default(Flag, False),
    Padding(2),
)

# Directory entries are represented as variable-length records:
#     qid[13] offset[8] type[1] name[s]
ReaddirEntry = Struct(
    "qid" / QID,
    "offset" / Bytes8,
    "count" / Bytes1,
    "name" / PrefixedString,
)
ReaddirEntries = GreedyRange(ReaddirEntry)

# Bytes4
# FIXME: THIS IS WRONG!!!
TlopenFlags = BitStruct(
    # ----
    "excl" / Default(Flag, False),
    "create" / Default(Flag, False),
    Padding(2),
    Padding(2),
    "rdwr" / Default(Flag, False),
    "wronly" / Default(Flag, False),
    "rdonly" / Computed(lambda this: this.wronly and this.rdwr),
    # ----
    "largefile" / Default(Flag, False),
    "direct" / Default(Flag, False),
    "fasync" / Default(Flag, False),
    "dsync" / Default(Flag, False),
    "nonblock" / Default(Flag, False),
    "append" / Default(Flag, False),
    "trunc" / Default(Flag, False),
    "noctty" / Default(Flag, False),
    # ----
    Padding(3),
    "sync" / Default(Flag, False),
    "cloexec" / Default(Flag, False),
    "noatime" / Default(Flag, False),
    "nofollow" / Default(Flag, False),
    "directory" / Default(Flag, False),
    # ----
    Padding(8),
)

# https://github.com/plan9foundation/plan9/blob/9db62717612a49f78a83b26ff5a176971c6cdd18/sys/src/cmd/cwfs/9p1.h#L60-L105
#
# https://github.com/plan9foundation/plan9/blob/9db62717612a49f78a83b26ff5a176971c6cdd18/sys/include/fcall.h#L90-L121

MessageTypes = Enum(
    Int8ul,
    # 9P2000.L message types.
    # As found in diod/libnpfs/9p.h: https://github.com/chaos/diod/blob/b4b5e8e00ed11b21d7fcf05a080dc054a8eac2d6/libnpfs/9p.h#L82-L122
    #  and p9fs-py/src/py9p/py9p.py: https://github.com/pbchekin/p9fs-py/blob/main/src/py9p/py9p.py#L48
    Tlerror=6,  # illegal, presumably
    Rlerror=7,
    Tstatfs=8,
    Rstatfs=9,
    Tlopen=12,
    Rlopen=13,
    Tlcreate=14,
    Rlcreate=15,
    Tsymlink=16,
    Rsymlink=17,
    Tmknod=18,
    Rmknod=19,
    Trename=20,
    Rrename=21,
    Treadlink=22,
    Rreadlink=23,
    Tgetattr=24,
    Rgetattr=25,
    Tsetattr=26,
    Rsetattr=27,
    Txattrwalk=30,
    Rxattrwalk=31,
    Txattrcreate=32,
    Rxattrcreate=33,
    Treaddir=40,
    Rreaddir=41,
    Tfsync=50,
    Rfsync=51,
    Tlock=52,
    Rlock=53,
    Tgetlock=54,
    Rgetlock=55,
    Tlink=70,
    Rlink=71,
    Tmkdir=72,
    Rmkdir=73,
    Trenameat=74,
    Rrenameat=75,
    Tunlinkat=76,
    Runlinkat=77,
    # 9p2000 / 9P2000.u message types.
    # As found in: plan9/sys/include/fcall.h: https://github.com/plan9foundation/plan9/blob/9db62717612a49f78a83b26ff5a176971c6cdd18/sys/include/fcall.h#L90-L121
    #         and: p9fs-py/src/py9p/py9p.py: https://github.com/pbchekin/p9fs-py/blob/main/src/py9p/py9p.py#L48
    Tversion=100,
    Rversion=101,
    Tauth=102,
    Rauth=103,
    Tattach=104,
    Rattach=105,
    Terror=106,  # illegal
    Rerror=107,
    Tflush=108,
    Rflush=109,
    Twalk=110,
    Rwalk=111,
    Topen=112,
    Ropen=113,
    Tcreate=114,
    Rcreate=115,
    Tread=116,
    Rread=117,
    Twrite=118,
    Rwrite=119,
    Tclunk=120,
    Rclunk=121,
    Tremove=122,
    Rremove=123,
    Tstat=124,
    Rstat=125,
    Twstat=126,
    Rwstat=127,
    Tmax=128,
)

StatPayload = """
The stat transaction inquires about the file identified by fid.
The reply will contain a machine–independent directory entry, stat,
laid out as follows:
    size[2]      total byte count of the following data
    type[2]      for kernel use
    dev[4]       for kernel use
    qid.type[1]  the type of the file (directory, etc.),
                 represented as a bit vector corresponding to the high 8 bits
                 of the file's mode word.
    qid.vers[4]  version number for given path
    qid.path[8]  the file server's unique identification for the file
    mode[4]      permissions and flags
    atime[4]     last access time
    mtime[4]     last modification time
    length[8]    length of file in bytes
    name[s]      file name;
                 must be / if the file is the root directory of the server
    uid[s]       owner name
    gid[s]       group name
    muid[s]      name of the user who last modified the file

via: http://9p.io/magic/man2html/5/stat
""" * Prefixed(
    Bytes2,
    Struct(
        "_type" / Default(Bytes2, 65535) * "for kernel use",
        "_dev" / Default(Bytes4, 4294967295) * "for kernel use",
        "qid" / QID,
        "mode" / Default(Bytes4, 438) * "permissions and flags",
        "atime"
        / Plan9TimestampAdapter(
            Struct(
                "seconds" / Int32sl,
                "nanoseconds" / Computed(0),
            )
        )
        * "last access time",
        "mtime"
        / Plan9TimestampAdapter(
            Struct(
                "seconds" / Int32sl,
                "nanoseconds" / Computed(0),
            )
        )
        * "last modification time",
        "length" / Default(Bytes8, 18446744073709551615) * "length of file in bytes",
        "name"
        / PrefixedString
        * "file name; must be / if the file is the root directory of the server",
        "uid" / PrefixedString * "owner name",
        "gid" / PrefixedString * "group name",
        "muid" / PrefixedString * "name of the user who last modified the file",
    ),
)
StatPayloads = GreedyRange(StatPayload)

PrefixedStatPayload = Prefixed(Bytes2, StatPayload)

IxpMessage = Prefixed(
    Int32ul,  # It doesn't look like I can access this data
    Struct(
        "type" / MessageTypes,
        "tag" / Default(Bytes2, 0),
        "payload"
        / Switch(
            this.type,
            {
                # --------------------
                # 9P2000.L
                # --------------------
                # Message Type: 7
                # size[4] Rlerror tag[2] ecode[4]
                "Rlerror": Struct(
                    "ecode" / Errno,
                ),
                # Message Type: 12
                # size[4] Tlopen tag[2] fid[4] flags[4]
                "Tlopen": Struct(
                    "fid" / Bytes4,
                    "flags" / Bytes4,  # TlopenFlags,
                ),
                # Message Type: 13
                # size[4] Rlopen tag[2] qid[13] iounit[4]
                "Rlopen": Struct(
                    "qid" / QID,
                    "iounit" / Bytes4,
                ),
                # Message Type: 14
                # size[4] Tlcreate tag[2] fid[4] name[s] flags[4] mode[4] gid[4]
                "Tlcreate": Struct(
                    "fid" / Bytes4,
                    "name" / PrefixedString,
                    "flags" / Bytes4,  # TlopenFlags,
                    "mode" / Bytes4,  # POSIXMode,
                    "gid" / Bytes4,
                ),
                # Message Type: 15
                # size[4] Rlcreate tag[2] qid[13] iounit[4]
                "Rlcreate": Struct("qid" / QID, "iounit" / Bytes4),
                # Message Type: 24
                # size[4] Tgetattr tag[2] fid[4] request_mask[8]
                "Tgetattr": Struct(
                    "fid" / Bytes4,
                    "request_mask" / Bytes8,  # POSIXRequestMask,
                ),
                # Message Type: 25
                # size[4] Rgetattr tag[2] valid[8] qid[13] mode[4] uid[4] gid[4] nlink[8]
                #                  rdev[8] size[8] blksize[8] blocks[8]
                #                  atime_sec[8] atime_nsec[8] mtime_sec[8] mtime_nsec[8]
                #                  ctime_sec[8] ctime_nsec[8] btime_sec[8] btime_nsec[8]
                #                  gen[8] data_version[8]
                "Rgetattr": Struct(
                    "valid" / Bytes8,  # POSIXRequestMask,
                    "qid" / QID,
                    "mode" / Bytes4,  # POSIXMode,
                    "uid" / Bytes4,
                    "gid" / Bytes4,
                    "nlink" / Bytes8,
                    "rdev" / Bytes8,
                    "size" / Bytes8,
                    "blksize" / Bytes8,
                    "blocks" / Bytes8,
                    # FIXME: see below
                    "atime"
                    / Plan9TimestampAdapter(
                        Struct(
                            "seconds" / Bytes8,
                            "nanoseconds" / Bytes8,
                        )
                    ),
                    # FIXME: name better: "mtime" / Plan9Timestamp
                    "mtime"
                    / Plan9TimestampAdapter(
                        Struct(
                            "seconds" / Bytes8,
                            "nanoseconds" / Bytes8,
                        )
                    ),
                    "ctime"
                    / Plan9TimestampAdapter(
                        Struct(
                            "seconds" / Bytes8,
                            "nanoseconds" / Bytes8,
                        )
                    ),
                    "btime"
                    / Plan9TimestampAdapter(
                        Struct(
                            "seconds" / Bytes8,
                            "nanoseconds" / Bytes8,
                        )
                    ),
                    "gen" / Bytes8,
                    "data_version" / Bytes8,
                ),
                # Message Type: 40
                # size[4] Treaddir tag[2] fid[4] offset[8] count[4]
                "Treaddir": Struct(
                    "fid" / Bytes4,
                    "offset" / Bytes8,
                    "count" / Bytes4,
                ),
                # Message Type: 41
                # size[4] Rreaddir tag[2] count[4] data[count]
                "Rreaddir": Struct(
                    "count" / Bytes4,
                    "entries" / GreedyRange(ReaddirEntry),
                ),
                # Message Type: 72
                # size[4] Tmkdir tag[2] dfid[4] name[s] mode[4] gid[4]
                "Tmkdir": Struct(
                    "dfid" / Bytes4,
                    "name" / PrefixedString,
                    "mode" / Bytes4,  # POSIXMode,
                    "gid" / Bytes4,
                ),
                # Message Type: 73
                # size[4] Rmkdir tag[2] qid[13]
                "Rmkdir": Struct(
                    "qid" / QID,
                ),
                # -----------------------------------------------------------------
                # 9P2000 Messages
                # -----------------------------------------------------------------
                # Message Type: 100
                # size[4] Tversion tag[2] msize[4] version[s]
                "Tversion": Struct(
                    "msize" / Default(Bytes4, DEFAULT_M_SIZE),
                    "version" / PrefixedString,
                ),
                # Message Type: 101
                # size[4] Rversion tag[2] msize[4] version[s]
                "Rversion": Struct(
                    "msize" / Bytes4,
                    "version" / PrefixedString,
                ),
                # Message Type: 102
                # size[4] Tauth tag[2] afid[4] uname[s] aname[s]
                "Tauth": Struct(
                    "afid" / Bytes4,
                    "uname" / PrefixedString,
                    "aname" / PrefixedString,
                ),
                # Message Type: 103
                # size[4] Rauth tag[2] aqid[13]
                "Rauth": Struct(
                    "aqid" / QID,
                ),
                # Message Type: 104
                # 9P2000
                # size[4] Tattach tag[2] fid[4] afid[4] uname[s] aname[s]
                # 9P2000.u (.L subset)
                # size[4] Tattach tag[2] fid[4] afid[4] uname[s] aname[s] n_uname[4]
                "Tattach": Struct(
                    "fid" / Bytes4,
                    "afid" / Default(Bytes4, NOFID),
                    "uname" / PrefixedString,
                    "aname" / PrefixedString,
                    # "n_uname" / Optional(Bytes4),
                ),
                # Message Type: 105
                # size[4] Rattach tag[2] qid[13]
                "Rattach": Struct(
                    "qid" / QID,
                ),
                # Message Type: 107
                # size[4] Rerror tag[2] ename[s]
                "Rerror": Struct(
                    "ename" / PrefixedString,
                ),
                # Message Type: 108
                # size[4] Tflush tag[2] oldtag[2]
                "Tflush": Struct(
                    "oldtag" / Bytes2,
                ),
                # Message Type: 109
                # size[4] Rflush tag[2]
                "Rflush": Struct(),
                # Message Type: 110
                # size[4] Twalk tag[2] fid[4] newfid[4] nwname[2] nwname*(wname[s])
                "Twalk": Struct(
                    "fid" / Bytes4,
                    "newfid" / Bytes4,
                    # number of walks
                    "nwname" / Default(Bytes2, lambda this: len(this.wnames)),
                    "wnames"
                    / Array(
                        this.nwname,
                        PrefixedString,
                    ),
                ),
                # Message Type: 111
                # size[4] Rwalk tag[2] nwqid[2] nwqid*(wqid[13])
                "Rwalk": Struct(
                    # number of qids
                    "nwqid" / Default(Bytes2, lambda this: len(this.wqids)),
                    "wqids"
                    / Array(
                        this.nwqid,
                        QID,
                    ),
                ),
                # Message Type: 112
                # size[4] Topen tag[2] fid[4] mode[1]
                "Topen": Struct(
                    "fid" / Bytes4,
                    "mode" / Mode,
                ),
                # Message Type: 113
                # size[4] Ropen tag[2] qid[13] iounit[4]
                "Ropen": Struct(
                    "qid" / QID,
                    "iounit" / Bytes4,
                ),
                # Message Type: 114
                # size[4] Tcreate tag[2] fid[4] name[s] perm[4] mode[1]
                "Tcreate": Struct(
                    "fid" / Bytes4,
                    "name" / PrefixedString,
                    "perm" / Bytes4,
                    "mode" / Bytes1,
                ),
                # Message Type: 115
                # size[4] Rcreate tag[2] qid[13] iounit[4]
                "Rcreate": Struct(
                    "qid" / QID,
                    "iounit" / Bytes4,
                ),
                # Message Type: 116
                # size[4] Tread tag[2] fid[4] offset[8] count[4]
                "Tread": Struct(
                    "fid" / Bytes4,
                    "offset" / Bytes8,
                    "count" / Bytes4,
                ),
                # Message Type: 117
                # size[4] Rread tag[2] count[4] data[count]
                "Rread": Struct(
                    "count" / Bytes4,
                    "data" / Bytes(this.count),
                ),
                # Message Type: 118
                # size[4] Twrite tag[2] fid[4] offset[8] count[4] data[count]
                "Twrite": Struct(
                    "fid" / Bytes4,
                    "offset" / Default(Bytes8, 0),
                    # "count" / Bytes4,
                    "count" / Default(Bytes4, lambda this: len(this.data)),
                    "data"
                    / Bytes(lambda this: this.count if this.count else len_(this.data)),
                ),
                # Message Type: 119
                # size[4] Rwrite tag[2] count[4]
                "Rwrite": Struct(
                    "count" / Bytes4,
                ),
                # Message Type: 120
                # size[4] Tclunk tag[2] fid[4]
                "Tclunk": Struct(
                    "fid" / Bytes4,
                ),
                # Message Type: 121
                # size[4] Rclunk tag[2]
                "Rclunk": Struct(),
                # Message Type: 122
                # size[4] Tremove tag[2] fid[4]
                "Tremove": Struct(
                    "fid" / Bytes4,
                ),
                # Message Type: 123
                # size[4] Rremove tag[2]
                "Rremove": Struct(),
                # Message Type: 124
                # size[4] Tstat tag[2] fid[4]
                "Tstat": Struct(
                    "fid" / Bytes4,
                ),
                # Message Type: 125
                # size[4] Rstat tag[2] stat[n]
                "Rstat": PrefixedStatPayload,
                # Message Type: 126
                # size[4] Twstat tag[2] fid[4] stat[n]
                "Twstat": Struct("fid" / Bytes4, "stat" / PrefixedStatPayload),
                # Message Type: 127
                # size[4] Rwstat tag[2]
                "Rwstat": Struct(),
            },
            Struct("Undefined" / GreedyBytes),
        ),
    ),
    True,  # Include the size of the prefix in the total count
)


def container_to_dict(container):
    # print(f"[container_to_dict] Got: {container}")
    if isinstance(container, (str, int, float, bool, list, tuple)):
        return container
    rv = dict(container)
    # Discard the "_io" key if it exists, as it messes up json.dumps()
    to_remove = [key for key in rv.keys() if key.startswith("_io")]
    for key in to_remove:
        del rv[key]
    for key, value in rv.items():
        # ListContainers are a special case
        if isinstance(value, (construct.ListContainer)):
            rv[key] = [container_to_dict(item) for item in rv[key]]
        elif isinstance(value, bytes):
            rv[key] = base64.b64encode(value).decode("utf-8")
        elif not isinstance(value, (str, int, float, bool, list, tuple)):
            rv[key] = container_to_dict(value)
    return rv


def container_to_json(container):
    """
    Container to JSON
    """
    rv = container_to_dict(container)
    if "payload" in rv:
        rv.update(dict(rv["payload"]))
        del rv["payload"]
    rv["_size"] = len(IxpMessage.build(container))
    as_json = json.dumps(rv)
    # print(f"[container_to_json] {as_json}")
    return as_json


def to_container_object(obj):
    container_json = {"payload": {}}
    for key, value in obj.items():
        if key == "data":
            value = base64.b64decode(value)
        if key in ("type", "tag"):
            container_json[key] = value
        elif key == "_size":
            pass
        else:
            container_json["payload"][key] = value
    return container_json
