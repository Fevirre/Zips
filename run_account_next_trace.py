#!/usr/bin/env python3
import json
import pathlib
import sys
import time

import frida


ROOT = pathlib.Path(__file__).resolve().parent
TRACE_AGENT = ROOT / "mkt-account-next-tracer.js"
RUNNER_VERSION = "two-stage-v5-dialog-action"


def find_signature_agent():
    candidates = (
        ROOT / "mkt-signature-spoof.js",
        ROOT / "runtime-redirect" / "mkt-signature-spoof.js",
        ROOT.parent / "mkt-signature-spoof.js",
        ROOT.parent / "runtime-redirect" / "mkt-signature-spoof.js",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    searched = "\n  ".join(str(path) for path in candidates)
    raise SystemExit(
        "Missing mkt-signature-spoof.js. Put it beside this runner.\n"
        f"Searched:\n  {searched}"
    )


def on_message(message, data):
    if message.get("type") == "send":
        payload = message.get("payload")
        if isinstance(payload, dict) and payload.get("type") == "account-next-click":
            print("\n[CAPTURED] Nintendo Account screen button")
            print(json.dumps(payload, indent=2))
            print("\nCapture recorded. The tracer will automatically re-arm for the next MKT button.")
        elif isinstance(payload, dict):
            print(f"[{payload.get('type', 'message')}] {payload.get('message', payload)}")
        else:
            print(payload)
    else:
        print(message)


def main():
    print(f"[RUNNER] {RUNNER_VERSION}")
    signature_agent = find_signature_agent()
    if not TRACE_AGENT.is_file():
        raise SystemExit(
            f"Missing required tracer: {TRACE_AGENT}\n"
            "Put mkt-account-next-tracer.js beside this runner."
        )

    device = frida.get_usb_device(timeout=10)
    try:
        gadget_process = device.get_process("Gadget")
        session = device.attach(gadget_process.pid)
    except frida.ProcessNotFoundError:
        raise SystemExit("Gadget is not visible. Launch the rebuilt MKT first, then retry.")

    scripts = []
    for path in (signature_agent, TRACE_AGENT):
        script = session.create_script(path.read_text(encoding="utf-8"))
        script.on("message", on_message)
        script.load()
        scripts.append(script)
        print(f"[LOADED] {path.name}")

    try:
        device.resume(gadget_process.pid)
        print("[RESUMED] MKT after both agents loaded")
    except frida.InvalidOperationError:
        # Harmless when Gadget was configured to resume automatically.
        print("[STATUS] MKT was already running")

    print("Signature spoofing and the multi-button account tracer are active.")
    print("Tap Nintendo Account > Next, complete linking in Chrome, then tap Link Complete > OK.")
    print("Press Enter only after both MKT buttons have been captured.")
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
