'use strict';

const ROOT = "/storage/emulated/0/Android/data/com.nintendo.zaka/files/Frida";
const SCRIPT_DIR = ROOT + "/Scripts";
const LOG_PATH = ROOT + "/Logs/loader_runtime.log";

function log(msg) {
  try {
    const f = new File(LOG_PATH, "a");
    f.write(new Date().toISOString() + " " + msg + "\n");
    f.flush();
    f.close();
  } catch (_) {}
}

function run(name) {
  const path = SCRIPT_DIR + "/" + name;
  log("LOAD-BEGIN " + name);
  try {
    const f = new File(path, "r");
    let src = "";
    try { src = f.readText(); } finally { f.close(); }
    log("READ-OK " + name + " bytes=" + src.length);
    (0, eval)(src + "\n//# sourceURL=" + path);
    log("EVAL-OK " + name);
  } catch (e) {
    log("LOAD-ERROR " + name + " " + String(e));
  }
}

log("START pid=" + Process.id + " arch=" + Process.arch);
run("spoofer.js");
run("time_probe.js");
log("DONE");
