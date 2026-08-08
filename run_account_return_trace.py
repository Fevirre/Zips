#!/usr/bin/env python3
import json
import pathlib

import frida


ROOT = pathlib.Path(__file__).resolve().parent
SIGNATURE_AGENT = ROOT / "mkt-signature-spoof.js"
RETURN_AGENT = ROOT / "mkt-account-return-tracer.js"


def on_message(message, data):
    if message.get("type") == "send":
        print(json.dumps(message.get("payload"), indent=2))
    else:
        print(json.dumps(message, indent=2))


def main():
    print("[RUNNER] account-return-v2-java")
    for path in (SIGNATURE_AGENT, RETURN_AGENT):
        if not path.is_file():
            raise SystemExit(f"Missing required agent beside runner: {path.name}")

    device = frida.get_usb_device(timeout=10)
    try:
        process = device.get_process("Gadget")
        session = device.attach(process.pid)
    except frida.ProcessNotFoundError:
        raise SystemExit("Gadget is not visible. Launch the rebuilt MKT first, then retry.")

    scripts = []
    for path in (SIGNATURE_AGENT, RETURN_AGENT):
        script = session.create_script(path.read_text(encoding="utf-8"))
        script.on("message", on_message)
        script.load()
        scripts.append(script)
        print(f"[LOADED] {path.name}")

    try:
        device.resume(process.pid)
        print("[RESUMED] MKT")
    except frida.InvalidOperationError:
        print("[STATUS] MKT was already running")

    print("Complete Nintendo linking in Chrome and return to MKT.")
    print("Wait for Link Complete, then press Enter here to stop and save the console output.")
    try:
        input()
    except KeyboardInterrupt:
        pass
    finally:
        for script in reversed(scripts):
            try:
                script.unload()
            except Exception:
                pass
        session.detach()


if __name__ == "__main__":
    main()
