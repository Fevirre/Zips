'use strict';

const VERSION = "loader-baseline-v1";
const ROOT = "/storage/emulated/0/Android/data/com.nintendo.zaka/files/Frida";
const LOG_DIR = ROOT + "/Logs";
const BOOT_LOG = LOG_DIR + "/loader_baseline.log";

function append(path, line) {
  try {
    const file = new File(path, "a");
    file.write(line + "\n");
    file.flush();
    file.close();
  } catch (_) {}
}

append(
  BOOT_LOG,
  new Date().toISOString() +
  " [" + VERSION + "] START pid=" + Process.id +
  " arch=" + Process.arch
);

// Baseline test intentionally loads NOTHING else.
// No Logger.js, no account_loader.js, no IL2CPP bridge, no hooks.
