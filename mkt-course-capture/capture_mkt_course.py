#!/usr/bin/env python3
import hashlib
import os
from pathlib import Path
import sys
import time

import frida


HOST = "127.0.0.1:27042"
PROCESS_NAME = "Gadget"
HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "mkt-course-dump"
SIGNATURE_AGENT = HERE / "mkt-signature-spoof.js"
if not SIGNATURE_AGENT.is_file():
    SIGNATURE_AGENT = HERE.parent / "mkt-signature-spoof.js"
COURSE_AGENT = HERE / "mkt-course-capture.js"

open_files = {}


def safe_output_path(device_path: str) -> Path:
    pieces = [piece for piece in device_path.replace("\\", "/").split("/") if piece not in ("", ".", "..")]
    return OUTPUT.joinpath(*pieces)


def on_message(message, data):
    if message.get("type") == "error":
        print("[agent-error]", message.get("stack", message))
        return

    payload = message.get("payload", {})
    kind = payload.get("type")

    if kind == "path":
        print(f"[path:{payload.get('operation')}] {payload.get('path')}")
    elif kind == "status":
        print(f"[status] {payload.get('message')}")
    elif kind == "file-start":
        output_path = safe_output_path(payload["path"])
        output_path.parent.mkdir(parents=True, exist_ok=True)
        handle = output_path.open("wb")
        open_files[payload["id"]] = {
            "handle": handle,
            "path": output_path,
            "hash": hashlib.sha256(),
            "written": 0,
        }
        print(f"[dump:start] {payload['size']} bytes -> {output_path}")
    elif kind == "file-chunk":
        state = open_files.get(payload["id"])
        if state is not None and data is not None:
            state["handle"].write(data)
            state["hash"].update(data)
            state["written"] += len(data)
    elif kind == "file-end":
        state = open_files.pop(payload["id"], None)
        if state is not None:
            state["handle"].close()
            digest = state["hash"].hexdigest()
            print(f"[dump:done] {state['written']} bytes sha256={digest} {state['path']}")
    elif kind == "file-skip":
        print(f"[dump:skip] {payload.get('size')} bytes {payload.get('path')} ({payload.get('reason')})")
    elif kind == "file-error":
        print(f"[dump:error] {payload.get('path')}: {payload.get('error')}")
    else:
        print("[message]", payload)


def load_script(session, path: Path):
    source = path.read_text(encoding="utf-8")
    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    return script


def main():
    for required in (SIGNATURE_AGENT, COURSE_AGENT):
        if not required.is_file():
            raise SystemExit(f"Missing required file: {required}")

    OUTPUT.mkdir(parents=True, exist_ok=True)
    manager = frida.get_device_manager()
    device = manager.add_remote_device(HOST)
    processes = device.enumerate_processes()
    gadget = next((process for process in processes if process.name == PROCESS_NAME), None)
    if gadget is None:
        raise SystemExit("Gadget is not running. Launch the patched MKT build after adb port forwarding, then retry.")

    print(f"[connect] {gadget.name} pid={gadget.pid}")
    session = device.attach(gadget.pid)
    signature_script = load_script(session, SIGNATURE_AGENT)
    course_script = load_script(session, COURSE_AGENT)

    print("\nMKT is running with the signature spoof active.")
    print("Navigate to the downloaded course's Practice button.")
    input("Press Enter immediately BEFORE tapping Practice...")
    course_script.exports_sync.arm()
    print("\nCAPTURE ARMED — tap Practice now and enter the race.")
    print("Let the course finish loading, then return here and press Enter.\n")
    input()
    course_script.exports_sync.disarm()
    time.sleep(2)
    print(f"Capture stopped. Files are in: {OUTPUT}")
    print("Keep this window open a few seconds if a final dump is still completing.")
    time.sleep(5)

    session.detach()
    _ = signature_script


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
        for state in open_files.values():
            state["handle"].close()
        sys.exit(130)
