'use strict';

/*
 * Logger.js
 * Standalone Android-side Frida Gadget logger for the MKT project.
 *
 * Output directory:
 *   /storage/emulated/0/Frida/Logs/
 *
 * This logger is intentionally passive:
 *   - no IL2CPP replacements
 *   - no game-method hooks
 *   - no account-state changes
 *
 * It records Gadget/runtime information plus messages forwarded to the
 * global MKTLogger API by other workloads such as account_loader.js.
 */

const LOGGER_VERSION = "Logger-v1";
const LOG_DIR = "/storage/emulated/0/Frida/Logs";
const MAX_LINE_LENGTH = 16384;

let logFile = null;
let logPath = null;
let initialized = false;

function pad2(value) {
  return String(value).padStart(2, "0");
}

function timestamp() {
  const d = new Date();
  return (
    d.getFullYear() + "-" +
    pad2(d.getMonth() + 1) + "-" +
    pad2(d.getDate()) + " " +
    pad2(d.getHours()) + ":" +
    pad2(d.getMinutes()) + ":" +
    pad2(d.getSeconds()) + "." +
    String(d.getMilliseconds()).padStart(3, "0")
  );
}

function fileTimestamp() {
  const d = new Date();
  return (
    d.getFullYear() +
    pad2(d.getMonth() + 1) +
    pad2(d.getDate()) + "-" +
    pad2(d.getHours()) +
    pad2(d.getMinutes()) +
    pad2(d.getSeconds())
  );
}

function safeString(value) {
  try {
    if (typeof value === "string") {
      return value;
    }
    return JSON.stringify(value);
  } catch (_) {
    try {
      return String(value);
    } catch (_) {
      return "<unprintable>";
    }
  }
}

function sanitizeLine(value) {
  let text = safeString(value);
  text = text.replace(/\r/g, "\\r").replace(/\n/g, "\\n");
  if (text.length > MAX_LINE_LENGTH) {
    text = text.slice(0, MAX_LINE_LENGTH) + "...<truncated>";
  }
  return text;
}

function ensureDirectory() {
  if (Java.available) {
    let ok = false;

    Java.perform(() => {
      const File = Java.use("java.io.File");
      const dir = File.$new(LOG_DIR);

      if (dir.exists()) {
        ok = dir.isDirectory();
      } else {
        ok = dir.mkdirs();
      }
    });

    return ok;
  }

  const system = new NativeFunction(
    Module.getExportByName(null, "system"),
    "int",
    ["pointer"]
  );
  const command = Memory.allocUtf8String('mkdir -p "' + LOG_DIR + '"');
  return system(command) === 0;
}

function openLog() {
  if (initialized) {
    return;
  }

  initialized = true;

  try {
    if (!ensureDirectory()) {
      throw new Error("could not create/access " + LOG_DIR);
    }

    logPath = LOG_DIR + "/MKT-" + fileTimestamp() + ".log";
    logFile = new File(logPath, "a");

    write("LOGGER", "START", {
      version: LOGGER_VERSION,
      pid: Process.id,
      architecture: Process.arch,
      platform: Process.platform,
      path: logPath
    });
  } catch (error) {
    initialized = false;
    console.error("[LOGGER] initialization failed: " + safeString(error));
  }
}

function write(source, event, details) {
  if (!initialized) {
    openLog();
  }

  if (logFile === null) {
    console.log(
      "[LOGGER-FALLBACK] " +
      timestamp() + " [" + source + "] " + event + " " + sanitizeLine(details)
    );
    return;
  }

  const detailText =
    details === undefined || details === null || details === ""
      ? ""
      : " " + sanitizeLine(details);

  const line =
    timestamp() +
    " [" + sanitizeLine(source) + "] " +
    sanitizeLine(event) +
    detailText +
    "\n";

  try {
    logFile.write(line);
    logFile.flush();
  } catch (error) {
    console.error("[LOGGER] write failed: " + safeString(error));
  }
}

globalThis.MKTLogger = {
  version: LOGGER_VERSION,
  directory: LOG_DIR,

  log(source, event, details) {
    write(source || "SCRIPT", event || "EVENT", details);
  },

  info(event, details) {
    write("INFO", event, details);
  },

  warn(event, details) {
    write("WARN", event, details);
  },

  error(event, details) {
    write("ERROR", event, details);
  },

  path() {
    return logPath;
  },

  flush() {
    try {
      if (logFile !== null) {
        logFile.flush();
      }
    } catch (_) {}
  }
};

openLog();

write("LOGGER", "READY", {
  directory: LOG_DIR,
  file: logPath
});

if (typeof Process.setExceptionHandler === "function") {
  Process.setExceptionHandler((details) => {
    write("NATIVE", "EXCEPTION", details);
    return false;
  });
}

setInterval(() => {
  write("LOGGER", "HEARTBEAT", {
    pid: Process.id,
    uptimeMs: Date.now()
  });
}, 30000);

rpc.exports = {
  status() {
    return {
      version: LOGGER_VERSION,
      directory: LOG_DIR,
      path: logPath,
      initialized: initialized
    };
  },

  mark(message) {
    write("MANUAL", "MARK", message);
    return true;
  },

  flush() {
    globalThis.MKTLogger.flush();
    return true;
  }
};
