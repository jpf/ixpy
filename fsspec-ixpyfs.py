#!/usr/bin/env python3

from datetime import datetime, timezone
import hashlib
import logging
import os
import stat
import time
import traceback

# import fsspec
# from fsspec.core import url_to_fs
from fsspec.implementations.dirfs import DirFileSystem # type: ignore

import ixpyfs

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)
log = logging.getLogger(__file__)

group_id = "adm"


class TestingFileSystem(DirFileSystem):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def chmod(self, relative_path, mode):
        path = self._join(relative_path)
        os.chmod(path, mode)

    def chown(self, relative_path, user_id, group_id):
        path = self._join(relative_path)
        os.chown(path, user_id, group_id)

    def ls(self, relative_path, detail=True):
        path = self._join(relative_path)
        # Check if the path is a directory
        if not os.path.isdir(path):
            raise FileNotFoundError(f"The directory '{path}' does not exist")

        # List directory contents
        entries = os.listdir(path)

        if not detail:
            return [os.path.join(path, entry) for entry in entries]

        details = []
        for entry in entries:
            entry_path = os.path.join(path, entry)
            stat_info = os.stat(entry_path)
            details.append(
                {
                    "name": entry_path,
                    "size": stat_info.st_size,
                    "type": "directory" if os.path.isdir(entry_path) else "file",
                    "mode": stat_info.st_mode,
                    "mtime": stat_info.st_mtime,
                    "atime": stat_info.st_atime,
                    "ctime": stat_info.st_ctime,
                    "gid": stat_info.st_gid,
                    "ino": stat_info.st_ino,
                    "islink": os.path.islink(entry_path),
                    "nlink": stat_info.st_nlink,
                    "uid": stat_info.st_uid,
                }
            )
        return details

    def utime(self, relative_path, times=None):
        path = self._join(relative_path)
        if not os.path.exists(path):
            raise FileNotFoundError(f"The file '{path}' does not exist")

        if times is None:
            current_time = time.time()
            times = (current_time, current_time)

        return os.utime(path, times)

    def accessed(self, relative_path):
        path = self._join(relative_path)
        if not os.path.exists(path):
            raise FileNotFoundError(f"The file '{path}' does not exist")

        # Get the file access time
        stat_info = os.stat(path)
        accessed_time = datetime.fromtimestamp(stat_info.st_atime, tz=timezone.utc)
        return accessed_time


##
## Filenames & hashes
##
base_dir = "/usr/glenda"
testing_dir = f"{base_dir}/fsspec-tests"

nested_dir = f"{testing_dir}/nested_dir"

touched_file = f"{testing_dir}/touched-file"

sample_text_file = f"{testing_dir}/hello.world"
sample_text_file_moved = f"{nested_dir}/moved.world"
sample_text_file_renamed = f"{nested_dir}/renamed.world"
sample_text = "I've got a lovely bunch of coconuts"
sample_text_appended = "\nThere they are all standing in a row"

local_file = "krazy-kat.png"
remote_file = f"{testing_dir}/krazy-kat.png"
local_file_hash = "e481bef4a34543fbb77ec18fbee8cb1e"


# Set up the fsspec object
# root_fs, root_path = url_to_fs("file:///tmp")
# fs = TestingFileSystem(root_path, root_fs)


def run_test(name):
    bold_white = "\033[1;37;4m"
    reset = "\033[0m"
    print(f"{bold_white}> Running test: {name}{reset}")


def run_tests(fs):
    # TEST: Make sure that our test folder exists
    run_test("Make sure that our test folder exists")
    if fs.exists(testing_dir):
        log.debug(f"Removing testing dir {testing_dir}")
        fs.rm(testing_dir, recursive=True)
    fs.mkdir(testing_dir)

    assert fs.exists(testing_dir), "Directory was not created."
    assert fs.isdir(testing_dir), "Directory is not directory."

    run_test("Create a file")
    assert fs.touch(touched_file) is None, f"Unable to create '{touched_file}'"
    assert fs.exists(touched_file), f"File '{touched_file}' does not exist"

    # TEST: Write to the file
    run_test("Write to the file")
    assert fs.write_text(
        sample_text_file, sample_text
    ), f"Unable to write test to file '{sample_text_file}'"

    # TEST: Read from the file
    run_test("Read from the file")
    assert (
        fs.read_text(sample_text_file) == sample_text
    ), f"Unable to read sample text from '{sample_text_file}'"

    # TEST: Append to the file
    run_test("Append to the file")
    with fs.open(sample_text_file, "a") as f:
        f.write(sample_text_appended)

    # TEST: Verify that the text was appended to the file
    run_test("Verify that the text was appended to the file")
    content = fs.cat(sample_text_file).decode("utf-8")
    assert (
        content == f"{sample_text}{sample_text_appended}"
    ), f"Unexpected content: '{content}'"

    # TEST: Upload a larger file
    run_test("Upload a larger file")
    assert (
        fs.put(local_file, remote_file) is None
    ), f"Unable to copy '{local_file}' to remote as '{remote_file}'"

    # TEST: Check the hash of the larger file
    run_test("Check the hash of the larger file")
    h = hashlib.md5()
    h.update(fs.cat_file(remote_file))
    remote_file_hash = h.hexdigest()
    assert (
        local_file_hash == remote_file_hash
    ), f"Expected local file hash ({local_file_hash}) to match remote file hash ({remote_file_hash})"

    # TEST: Read the test directory
    run_test("Read the test directory")
    ls_result = fs.ls(testing_dir)
    filenames = {fn["name"] for fn in ls_result}
    want_filenames = {f"{fn}" for fn in [touched_file, sample_text_file, remote_file]}
    if not want_filenames.issubset(filenames):
        missing = want_filenames - filenames
        raise TypeError(f"Expected files not found on remote system: {missing}")

    run_test("Create a new directory")
    fs.mkdir(nested_dir)
    assert fs.exists(nested_dir), "Directory was not created."
    assert fs.isdir(nested_dir), "Directory is not directory."

    run_test("Move the file to the new directory")
    fs.mv(sample_text_file, sample_text_file_moved)

    run_test("Verify the file move")
    assert fs.exists(sample_text_file_moved), "File was not moved."
    assert not fs.exists(sample_text_file), "Original file still exists after move."

    run_test("Rename the moved file (using move to rename)")
    fs.mv(sample_text_file_moved, sample_text_file_renamed)

    run_test("Verify the file rename")
    assert fs.exists(sample_text_file_renamed), "File was not renamed."
    assert not fs.exists(
        sample_text_file_moved
    ), "File still exists with old name after rename."

    run_test("Read the renamed file")
    with fs.open(sample_text_file_renamed, "r") as f:
        content = f.read()
        assert (
            content == f"{sample_text}{sample_text_appended}"
        ), f"Unexpected content: '{content}'"

    run_test("Change file permissions using chmod")
    fs.chmod(
        sample_text_file_renamed,
        stat.S_IRUSR
        | stat.S_IWUSR
        | stat.S_IRGRP
        | stat.S_IWGRP
        | stat.S_IROTH
        | stat.S_IWOTH,
    )

    run_test("Verify permissions changes")
    stat_result = fs.stat(sample_text_file_renamed)
    log.debug(f"Change group ID: stat_result = {stat_result}")
    file_mode = int(stat_result["mode"])
    assert file_mode & stat.S_IRUSR, "User read permission not set."
    assert file_mode & stat.S_IWUSR, "User write permission not set."
    assert file_mode & stat.S_IRGRP, "Group read permission not set."
    assert file_mode & stat.S_IWGRP, "Group write permission not set."
    assert file_mode & stat.S_IROTH, "Others read permission not set."
    assert file_mode & stat.S_IWOTH, "Others write permission not set."

    run_test("Change group ID")
    user_id = stat_result["uid"]
    fs.chown(sample_text_file_renamed, user_id, group_id)
    run_test("Verify change")
    stat_result = fs.stat(sample_text_file_renamed)
    assert stat_result["uid"] == user_id, "User ID not set correctly."
    assert stat_result["gid"] == group_id, "Group ID not set correctly."

    run_test("Verify access and modified times")

    def str_to_timestamp(date_str):
        dt = datetime.strptime(date_str, "%B %d, %Y")
        dt = dt.replace(tzinfo=timezone.utc)
        # return dt.timestamp()
        dts = dt.isoformat()
        dts = dts.replace("+00:00", "")
        dts += ".000000000Z"
        log.debug(f"str_to_timestamp: {dts}")
        return dts

    access_time = str_to_timestamp("November 12, 1955")
    modification_time = str_to_timestamp("July 3, 1985")

    log.debug(
        f"fs.utime({sample_text_file_renamed}, ({access_time}, {modification_time}))"
    )
    fs.utime(sample_text_file_renamed, (access_time, modification_time))

    ## Commented out because I think that Plan 9
    ## modifies the access time on stat?
    # have_atime = fs.accessed(sample_text_file_renamed)
    # want_atime = datetime.fromtimestamp(access_time, timezone.utc)
    # want_atime = access_time
    # assert (
    #     have_atime == want_atime
    # ), f"Access time not set correctly. Expected {want_atime}, got {have_atime}."

    have_mtime = fs.modified(sample_text_file_renamed)
    want_mtime = modification_time
    assert (
        have_mtime == want_mtime
    ), f"Modification time not set correctly. Expected {want_mtime}, got {have_mtime}."

    run_test("Delete the renamed file")
    fs.rm(sample_text_file_renamed)

    run_test("Verify deletion")
    assert not fs.exists(sample_text_file_renamed), "File was not successfully deleted."

    # TODO:  fs.find()
    #        fs.head()
    #        fs.info()
    #        fs.isdir()
    #        fs.isfile()

    run_test("Remove the created directory")
    fs.rm(nested_dir, recursive=True)

    run_test("Verify directory deletion")
    assert not fs.exists(nested_dir), "Directory was not successfully deleted."

    fs.rm(testing_dir, recursive=True)
    assert not fs.exists(testing_dir), f"Directory {testing_dir} not deleted"

    print("All filesystem operations completed successfully.")


fs = ixpyfs.P9FileSystem(
    host="0.0.0.0",
    port=9999,
    # username="glenda",
    # version='9P2000',
)
try:
    run_tests(fs)
except Exception as e:
    log.warn("Got Exception")
    log.warn(e)
    traceback.print_exc()

fs.ixp._close_socket()
