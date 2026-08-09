'use strict';

const VERSION = "loader-debug-v1";
const ROOT = "/storage/emulated/0/Android/data/com.nintendo.zaka/files/Frida";
const SCRIPT_DIR = ROOT + "/Scripts";
const LOG_DIR = ROOT + "/Logs";
const BOOT_LOG = LOG_DIR + "/loader_boot.log";

function cstr(s) {
  return Memory.allocUtf8String(s);
}

function getExport(name) {
  const p = Module.findGlobalExportByName(name);
  if (p === null) throw new Error("missing libc export: " + name);
  return p;
}

function mkdirp(path) {
  try {
    const system = new NativeFunction(getExport("system"), "int", ["pointer"]);
    const cmd = 'mkdir -p "' + path + '"';
    return system(cstr(cmd)) === 0;
  } catch (e) {
    console.error("[LOADER-DEBUG] mkdir failed: " + e);
    return false;
  }
}

function append(path, line) {
  try {
    const f = new File(path, "a");
    f.write(line + "\n");
    f.flush();
    f.close();
    return true;
  } catch (e) {
    console.error("[LOADER-DEBUG] write failed: " + e);
    return false;
  }
}

function stamp() {
  return new Date().toISOString();
}

mkdirp(LOG_DIR);

append(
  BOOT_LOG,
  stamp() + " [" + VERSION + "] START pid=" + Process.id +
  " arch=" + Process.arch
);

append(
  BOOT_LOG,
  stamp() + " scriptDir=" + SCRIPT_DIR
);

function loadOne(name) {
  const path = SCRIPT_DIR + "/" + name;

  append(BOOT_LOG, stamp() + " LOAD-BEGIN " + path);

  try {
    const f = new File(path, "r");
    let src = "";
    try {
      src = f.readText();
    } finally {
      f.close();
    }

    append(
      BOOT_LOG,
      stamp() + " READ-OK " + name + " bytes=" + src.length
    );

    (0, eval)(src + "\n//# sourceURL=" + path.replace(/\s/g, "%20"));

    append(BOOT_LOG, stamp() + " EVAL-OK " + name);
    return true;
  } catch (e) {
    const detail = e && e.stack ? String(e.stack) : String(e);
    append(
      BOOT_LOG,
      stamp() + " LOAD-ERROR " + name + " :: " +
      detail.replace(/\r?\n/g, " | ")
    );
    return false;
  }
}

loadOne("Logger.js");
loadOne("account_loader.js");

append(BOOT_LOG, stamp() + " STARTUP-COMPLETE");
