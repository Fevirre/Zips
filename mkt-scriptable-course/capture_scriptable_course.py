#!/usr/bin/env python3
import json
from pathlib import Path
import re
import sys
import time

import frida


HOST = "127.0.0.1:27042"
HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "ScriptableCourse-dump"


def find_agent(name):
    local = HERE / name
    if local.is_file():
        return local
    parent = HERE.parent / name
    if parent.is_file():
        return parent
    raise SystemExit(f"Missing required agent: {name}")


SIGNATURE_AGENT = find_agent("mkt-signature-spoof.js")
SCRIPTABLE_AGENT = find_agent("mkt-scriptable-course.js")
saved_count = 0
lap_snapshot_count = 0


def safe_name(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "ScriptableCourse"


def on_message(message, data):
    global saved_count, lap_snapshot_count
    if message.get("type") == "error":
        print("[agent-error]", message.get("stack", message))
        return

    payload = message.get("payload", {})
    kind = payload.get("type")
    if kind == "scriptable-status":
        print("[status]", payload.get("message"))
    elif kind == "scriptable-error":
        print("[error]", payload.get("className", ""), payload.get("error"))
    elif kind == "scriptable-course":
        saved_count += 1
        OUTPUT.mkdir(parents=True, exist_ok=True)
        class_name = safe_name(payload.get("className", "ScriptableCourse"))
        handle = safe_name(payload.get("handle", str(saved_count)))
        base = OUTPUT / f"{saved_count:03d}-{class_name}-{handle}"

        complete_path = base.with_suffix(".complete.json")
        complete_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

        unity_json = payload.get("unityJson")
        if unity_json:
            unity_path = base.with_suffix(".unity.json")
            try:
                parsed = json.loads(unity_json)
                unity_path.write_text(json.dumps(parsed, indent=2, ensure_ascii=False), encoding="utf-8")
            except json.JSONDecodeError:
                unity_path.write_text(unity_json, encoding="utf-8")

        reflected_path = base.with_suffix(".reflected.json")
        reflected_path.write_text(
            json.dumps(payload.get("reflected"), indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        print(f"[DUMPED] {payload.get('className')} -> {complete_path}")
    elif kind == "lap-class-catalog":
        OUTPUT.mkdir(parents=True, exist_ok=True)
        catalog_path = OUTPUT / "lap-class-catalog.json"
        catalog_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[LAP CATALOG] {len(payload.get('classes', []))} candidate classes -> {catalog_path}")
    elif kind == "lap-runtime":
        lap_snapshot_count += 1
        OUTPUT.mkdir(parents=True, exist_ok=True)
        class_name = safe_name(payload.get("className", "LapRuntime"))
        handle = safe_name(payload.get("handle", str(lap_snapshot_count)))
        path = OUTPUT / f"lap-{lap_snapshot_count:04d}-{class_name}-{handle}.json"
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[LAP SNAPSHOT] {payload.get('className')} -> {path}")
    else:
        print("[message]", payload)


def load_script(session, path):
    script = session.create_script(path.read_text(encoding="utf-8"))
    script.on("message", on_message)
    script.load()
    return script


def main():
    manager = frida.get_device_manager()
    device = manager.add_remote_device(HOST)
    gadget = next((p for p in device.enumerate_processes() if p.name == "Gadget"), None)
    if gadget is None:
        raise SystemExit("Gadget is not running. Forward port 27042 and launch patched MKT first.")

    print(f"[connect] Gadget pid={gadget.pid}")
    session = device.attach(gadget.pid)
    signature = load_script(session, SIGNATURE_AGENT)
    scriptable = load_script(session, SCRIPTABLE_AGENT)

    print("Signature spoof active. Navigate to the downloaded course's Practice button.")
    input("Press Enter immediately BEFORE tapping Practice...")
    scriptable.exports_sync.arm()
    print("CAPTURE ARMED — tap Practice and wait until the race is fully loaded.")
    input("Once loaded, press Enter to force a final scan...")
    scriptable.exports_sync.scan()
    time.sleep(3)
    scriptable.exports_sync.disarm()
    print(
        f"Finished: {saved_count} ScriptableCourse instance(s), "
        f"{lap_snapshot_count} lap/race snapshot(s) written to {OUTPUT}"
    )
    input("Press Enter to detach...")
    session.detach()
    _ = signature


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(130)
