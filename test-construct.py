#!/usr/bin/env python3

import base64
import binascii
import json

from deepdiff import DeepDiff # type: ignore
import construct # type: ignore

from ixpy import IxpMessage, container_to_json, to_container_object

tests = []
with open("./9P2000-tests.json", "r") as file:
    tests = json.load(file)

def base64_to_hexdump(base64_string):
    """Convert a base64 encoded string to a hexdump string."""
    try:
        binary_data = base64.b64decode(base64_string)
        hex_data = binascii.hexlify(binary_data)
        # Format the hex string for readability
        # This will format it as pairs of hex digits (bytes) separated by spaces
        hexdump = ' '.join(hex_data[i:i+2].decode() for i in range(0, len(hex_data), 2))

        return hexdump
    except Exception as e:
        print("An error occurred:", e)
        return None

def json_to_base64():
    for test in tests:
        want = test["base64"]
        if "json" not in test:
            continue
        obj = test["json"]

        what = obj["type"]
        if "repr" in test:
            what = test["repr"]
        print(f"[json-to-base64] {what}: ", end="")
        container_json = to_container_object(obj)
        enc = IxpMessage.build(container_json)
        have = base64.b64encode(enc).decode("utf-8")
        if want == have:
            print("OK ")
        else:
            print(f"NOT:\n\t {want}\n\t !=\n\t {have}")
            w = json.loads(container_to_json(IxpMessage.parse(base64.b64decode(want))))
            h = json.loads(container_to_json(IxpMessage.parse(base64.b64decode(have))))
            print(base64_to_hexdump(want))
            print(base64_to_hexdump(have))
            differences = DeepDiff(w, h, ignore_order=True)
            print(differences)
            diff_serializable = json.loads(json.dumps(differences, default=str))
            print(json.dumps(diff_serializable, indent=4))

def make_repr(obj):
    ignore = ["data", "atime", "mtime"]
    args = [f"tag={obj.tag}"]
    for key, value in obj.payload.items():
        if key.startswith("_"):
            continue
        elif key in ignore:
            continue
        if isinstance(value, (construct.Container, construct.ListContainer)):
            value="..."
        args.append(f"{key}={value}")
    args_str = " ".join(args)
    print(f"{obj.type}({args_str})")

def base64_to_json():
    for test in tests:
        payload = base64.b64decode(test["base64"])
        parsed = IxpMessage.parse(payload)
        if "repr" not in test or test["repr"] == "":
            make_repr(parsed)
        if "json" in test:
            what = test["json"]["type"]
            if "repr" in test:
                what = test["repr"]
            print(f"[base64-to-json] {what} ", end="")
            want = test["json"]
            for key in ["_flags", "_mode", "_valid", "_request_mask"]:
                if key in want:
                    del want[key]
            have = json.loads(container_to_json(parsed))
            differences = DeepDiff(want, have, ignore_order=True)
            if differences:
                print("DIFFERENCES")
                print(f"\tWant: {want}")
                print(f"\tHave: {have}")
                diff_serializable = json.loads(json.dumps(differences, default=str))
                print(json.dumps(diff_serializable, indent=4))
            else:
                print("OK")


base64_to_json()
json_to_base64()
