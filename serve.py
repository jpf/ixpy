from datetime import datetime
import hashlib
import os
import socket
import sys
import threading
import time
import traceback
import io

import fsspec

import ixpy
from ixpy import IxpMessage, container_to_json, Builder
from ixpmemoryfs import IxpMemoryFileSystem, IxpMemoryFile

import logging


def setup_custom_logger():
    # formatter = logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(module)s [%(name)s:%(lineno)s]  %(message)s')
    formatter = logging.Formatter(
        fmt="[%(levelname)s]\t%(filename)s:%(lineno)s (%(funcName)s)\t%(message)s"
    )

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    logger.handlers.clear()
    logger.addHandler(handler)
    return logger


logger = setup_custom_logger()

# TODO:
# - Get subdirectories working
# - Get ixpmemoryfs working as an fsspec module, so I can do fsspec.setup() - or whatever


class DynamicObj(IxpMemoryFile):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.qid._version = 0
        self.value = 0

    def getbuffer(self):
        msg = f"The running total is: {self.value}\n"
        rv = io.BytesIO(msg.encode("utf-8"))
        return rv.getbuffer()

    def write(self, value):
        logger.debug(f"value={value}")
        num = value.strip()
        if num == b"":
            self.value = 0
        else:
            self.value += int(num)
        return len(value)

    def seek(self, offset, whence=0):
        logger.debug(f"offset={offset} whence={whence}")
        pass


class Server:
    def __init__(self, host="localhost", port=8888):
        self.host = host
        self.port = port
        self.socket = None
        self.ixp = Builder()
        self.message = IxpMessage
        self.log = logger

        self.fs = IxpMemoryFileSystem()

        self.fid = {0: "/"}

    def start(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        self.log.info(f"Server started on {self.host}:{self.port}")

        while True:
            client_socket, addr = self.socket.accept()
            self.log.info(f"Connection from {addr}")
            try:
                self.handle_client(client_socket)
            except Exception as e:
                self.log.error(f"Error handling client: {str(e)}")
                traceback.print_exception(type(e), e, e.__traceback__)
            finally:
                client_socket.close()

    def stop(self):
        pass

    def handle_client(self, client_socket):
        while True:
            message = client_socket.recv(self.ixp.msize)
            if len(message) < 4:
                self.log.info("No more data, shutting down")
                self.log.info(f"Unclunked fids: {self.fid}")
                return False
            request = self.message.parse(message)
            try:
                response = self.handle_message(request)
            except Exception as e:
                response = self.ixp.Terror(fid=request.fid, ename=f"General error: {e}")
            client_socket.sendall(self.message.build(response))

    def paths_from_wnames(self, wnames):
        paths = []
        for i in range(1, len(wnames) + 1):
            path = "/" + "/".join(wnames[:i])
            paths.append(path)
        return paths

    def paths_from_path(self, path: str):
        paths = []
        wnames = path.strip("/").split("/")
        for i in range(1, len(wnames) + 1):
            path = "/" + "/".join(wnames[:i])
            paths.append(path)
        return paths

    def _path_to_qid(self, path):
        self.log.debug(f"path={path}")
        try:
            info = self.fs.info(path, as_9p=True)
        except FileNotFoundError:
            self.log.debug(f"path not found {path}")
            return None
        except Exception as e:
            self.log.debug(
                f"path={path} got unhandled exception: {type(e).__name__}: {e}"
            )
            return None
        self.log.debug(f"got info: {info}")
        return info["qid"]

    def _handle_walk(self, request):
        wnames = request.payload.wnames
        for wname in wnames:
            if "/" in wname:
                return self.ixp.Rerror(
                    tag=request.tag, ename=f"wname '{wname}' must not contain '/'"
                )

        current_path = self.fid.get(request.payload.fid, "/")
        self.log.debug(f"current_path={current_path} wnames={wnames}")
        full_path = os.path.join(current_path, *wnames)
        self.log.debug(f"full_path={full_path}")

        # paths = self.paths_from_path(full_path)
        paths = self.paths_from_wnames(wnames)
        self.log.debug(f"paths={paths}")
        wqids = []
        for path in paths:
            try:
                qid = self._path_to_qid(path)
            except Exception as e:
                return self.ixp.Rerror(tag=request.tag, ename=f"{e}")
            if qid:
                wqids.append(qid)
        self.log.debug(
            f"SET FID {request.payload.newfid} = {full_path} which is from {wnames}"
        )
        self.fid[request.payload.newfid] = full_path
        return self.ixp.Rwalk(tag=request.tag, wqids=wqids)

    def _listdir(self, path):
        self.log.debug(f"path={path}")
        results = self.fs.ls(path, detail=True, as_9p=True)
        self.log.debug(f"results='{results}'")
        data = ixpy.StatPayloads.build(results)
        return data

    def handle_message(self, request):
        if request.type == "Tversion":
            rv = self.ixp.Rversion(
                tag=request.tag, msize=request.payload.msize, version="9P2000"
            )
            return rv
        elif request.type == "Tattach":
            return self.ixp.Rattach(
                tag=request.tag,
                qid={
                    "type": {
                        "dir": True,
                        "append": False,
                        "exclusive": False,
                        "mount": False,
                        "auth_file": False,
                        "temp_file": False,
                    },
                    "version": 0,
                    "path": 0,
                },
            )
        elif request.type == "Twalk":
            return self._handle_walk(request)
        elif request.type == "Tcreate":
            fid = request.payload.fid
            perm = request.payload.perm
            is_dir = (perm & ixpy.DMDIR) != 0
            base = self.fid[fid]
            path = os.path.join(base, request.payload.name)
            self.log.debug(f"Tcreate on {fid} which is {base} = {path}")
            if is_dir:
                self.fs.mkdir(path)
            else:
                self.fs.touch(path)
            qid = self.fs.info(path, as_9p=True)["qid"]
            return self.ixp.Rcreate(tag=request.tag, qid=qid, iounit=self.ixp.msize)
        elif request.type == "Tstat":
            fid = request.payload.fid
            path = self.fid[fid]
            try:
                stat_payload = self.fs.info(path, as_9p=True)
            except Exception as e:
                return self.ixp.Rerror(tag=request.tag, ename=f"Tstat error: {e}")
            return self.ixp.Rstat(tag=request.tag, **stat_payload)
        elif request.type == "Topen":
            fid = request.payload.fid
            path = self.fid[fid]
            qid = self.fs.info(path, as_9p=True)["qid"]
            if not qid:
                return self.ixp.Rerror(
                    tag=request.tag, ename=f"Error getting QID for FID={fid}"
                )
            iounit = self.ixp.msize
            if path == "/":
                iounit = 0
            return self.ixp.Ropen(tag=request.tag, qid=qid, iounit=iounit)
        elif request.type == "Twrite":
            fid = request.payload.fid
            offset = request.payload.offset
            count = request.payload.count
            data = request.payload.data
            path = self.fid[fid]
            written = 0
            # self.log.debug(f"Twrite path={path} offset={offset} count={count} data={data}")
            # FIXME: "r+b" should be dynamic!!!!
            with self.fs.open(path, "r+b") as f:
                f.seek(offset)
                written += f.write(data[:count])
            return self.ixp.Rwrite(tag=request.tag, count=written)
        elif request.type == "Tread":
            fid = request.payload.fid
            path = self.fid[fid]
            self.log.debug(f"Tread fid={fid} path={path} open fids: {self.fid}")
            if self.fs.isdir(path):
                self.log.debug("Tread is dir")
                data = self._listdir(path)
                self.log.debug(f"Tread len(data)={len(data)}")
                if request.payload.offset >= len(data):
                    data = b""
            else:
                self.log.debug("Tread NOT dir")
                offset = request.payload.offset
                count = request.payload.count
                start = offset
                end = start + count
                data = self.fs.cat_file(path, start=start, end=end)
            return self.ixp.Rread(tag=request.tag, data=data, count=len(data))
        elif request.type == "Tremove":
            fid = request.payload.fid
            path = self.fid[fid]
            self.fs.rm(path)
            return self.ixp.Rremove(tag=request.tag)
        elif request.type == "Twstat":
            fid = request.payload.fid
            path = self.fid[fid]

            mode = request.payload.stat.mode
            if mode != ixpy.MODE_MAX:
                self.log.debug(f"Twstat chmod({path}, {mode})")
                self.fs.chmod(path, mode)

            user_id = None
            if request.payload.stat.uid:
                user_id = request.payload.stat.uid
            group_id = None
            if request.payload.stat.gid:
                group_id = request.payload.stat.gid

            if user_id or group_id:
                self.log.debug(f"Twstat chown({path}, {user_id}, {group_id})")
                self.fs.chown(path, user_id, group_id)

            TIME_MAX = "1969-12-31T23:59:59.000000000Z"

            atime = None
            if request.payload.stat.atime != TIME_MAX:
                atime = datetime.fromisoformat(request.payload.stat.atime)
            mtime = None
            if request.payload.stat.mtime != TIME_MAX:
                mtime = datetime.fromisoformat(request.payload.stat.mtime)
            if atime or mtime:
                self.fs.utime(path, (atime, mtime))

            return self.ixp.Rwstat(tag=request.tag)
        elif request.type == "Tclunk":
            del self.fid[request.payload.fid]
            return self.ixp.Rclunk(tag=request.tag)
        else:
            return self.ixp.Rerror(
                tag=request.tag, ename=f"Unknown request type: {request.type}"
            )


def start_server():
    try:
        server = Server()
        server.fs.mkdir("/usr/glenda/test/", parents=True)
        # FIXME: directories aren't working yet ... why?
        server.fs.mkfunc("/", DynamicObj(path="/hello"))
        server.start()
    except KeyboardInterrupt:
        logger.info("Server shutting down")
    finally:
        server.stop()


def monitor_file_changes(server_thread, file_path):
    last_mtime = os.path.getmtime(file_path)

    while server_thread.is_alive():
        current_mtime = os.path.getmtime(file_path)
        if current_mtime != last_mtime:
            logger.info("File changed, restarting server...")
            os.execv(sys.executable, ["python"] + sys.argv)
        time.sleep(1)


if __name__ == "__main__":
    server_thread = threading.Thread(target=start_server)
    server_thread.start()

    # Monitor changes to the source file
    monitor_file_changes(server_thread, __file__)
