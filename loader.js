'use strict';

/*
 * loader.js
 * Permanent Frida Gadget entry script for the Android-only MKT project.
 *
 * Put THIS loader where Gadget's fixed APK config points.
 * Mutable workloads live outside the APK at:
 *
 *   /storage/emulated/0/Frida/Scripts/
 *
 * Current load order:
 *   1. Logger.js
 *   2. account_loader.js
 */

const LOADER_VERSION = "loader-v1";
const SCRIPT_DIR = "/storage/emulated/0/Frida/Scripts";

const WORKLOADS = [
  "Logger.js",
  "account_loader.js"
];

function report(message) {
  const text = "[LOADER] " + message;
  console.log(text);

  try {
    if (globalThis.MKTLogger) {
      globalThis.MKTLogger.log("LOADER", "STATUS", {
        version: LOADER_VERSION,
        message
      });
    }
  } catch (_) {}
}

function readScript(path) {
  const file = new File(path, "r");
  try {
    return file.readText();
  } finally {
    file.close();
  }
}

function loadScript(filename) {
  const path = SCRIPT_DIR + "/" + filename;

  report("loading " + path);

  try {
    const source = readScript(path);

    if (!source || source.length === 0) {
      throw new Error("script is empty");
    }

    // Evaluate in this Gadget script's global context so workloads can share
    // globals such as MKTLogger and Il2Cpp.
    (0, eval)(
      source +
      "\n//# sourceURL=" +
      path.replace(/\s/g, "%20")
    );

    report("loaded " + filename + " (" + source.length + " chars)");
    return true;
  } catch (error) {
    const detail =
      error && error.stack
        ? String(error.stack)
        : String(error);

    console.error("[LOADER] failed " + filename + ": " + detail);

    try {
      if (globalThis.MKTLogger) {
        globalThis.MKTLogger.error("SCRIPT-LOAD-FAILED", {
          filename,
          path,
          error: detail
        });
      }
    } catch (_) {}

    return false;
  }
}

report(
  LOADER_VERSION +
  " starting; external script directory=" +
  SCRIPT_DIR
);

for (const workload of WORKLOADS) {
  loadScript(workload);
}

report("startup complete");
