'use strict';

/*
 * time_probe.js
 * Passive MKT time-check probe.
 *
 * Writes:
 * /storage/emulated/0/Android/data/com.nintendo.zaka/files/Frida/Logs/time_probe.log
 *
 * No return values are modified.
 */

const VERSION = "time-probe-v1";
const LOG_DIR = "/storage/emulated/0/Android/data/com.nintendo.zaka/files/Frida/Logs";
const LOG_PATH = LOG_DIR + "/time_probe.log";
const MAX_NATIVE_EVENTS = 120;
const MAX_JAVA_EVENTS = 80;

let nativeEvents = 0;
let javaEvents = 0;
let logFile = null;

function safe(v) {
  try { return String(v); } catch (_) { return "<unprintable>"; }
}

function mkdirp(path) {
  try {
    const systemPtr = Module.findGlobalExportByName("system");
    if (systemPtr === null) return false;
    const system = new NativeFunction(systemPtr, "int", ["pointer"]);
    return system(Memory.allocUtf8String('mkdir -p "' + path + '"')) === 0;
  } catch (_) {
    return false;
  }
}

function openLog() {
  if (logFile !== null) return;
  mkdirp(LOG_DIR);
  logFile = new File(LOG_PATH, "a");
}

function write(kind, details) {
  try {
    openLog();
    const line =
      new Date().toISOString() +
      " [" + VERSION + "] " +
      kind + " " +
      JSON.stringify(details || {}) +
      "\n";
    logFile.write(line);
    logFile.flush();
  } catch (e) {
    console.error("[TIME-PROBE] log failed: " + safe(e));
  }
}

function backtrace(context) {
  try {
    return Thread.backtrace(context, Backtracer.ACCURATE)
      .slice(0, 10)
      .map(DebugSymbol.fromAddress)
      .map(x => x.toString());
  } catch (_) {
    return [];
  }
}

write("START", {
  pid: Process.id,
  arch: Process.arch,
  platform: Process.platform
});

function attachClockGettime() {
  const p = Module.findGlobalExportByName("clock_gettime");
  if (p === null) {
    write("HOOK-MISSING", { name: "clock_gettime" });
    return;
  }

  Interceptor.attach(p, {
    onEnter(args) {
      if (nativeEvents >= MAX_NATIVE_EVENTS) return;
      this.capture = true;
      this.clockId = args[0].toInt32();
      this.ts = args[1];
      this.bt = backtrace(this.context);
    },
    onLeave(retval) {
      if (!this.capture) return;
      nativeEvents++;
      let sec = null;
      let nsec = null;
      try {
        sec = this.ts.readS64().toString();
        nsec = this.ts.add(Process.pointerSize).readS64().toString();
      } catch (_) {}

      write("clock_gettime", {
        event: nativeEvents,
        clockId: this.clockId,
        retval: retval.toInt32(),
        sec,
        nsec,
        backtrace: this.bt
      });
    }
  });

  write("HOOKED", { name: "clock_gettime", address: p.toString() });
}

function attachGettimeofday() {
  const p = Module.findGlobalExportByName("gettimeofday");
  if (p === null) {
    write("HOOK-MISSING", { name: "gettimeofday" });
    return;
  }

  Interceptor.attach(p, {
    onEnter(args) {
      if (nativeEvents >= MAX_NATIVE_EVENTS) return;
      this.capture = true;
      this.tv = args[0];
      this.bt = backtrace(this.context);
    },
    onLeave(retval) {
      if (!this.capture) return;
      nativeEvents++;
      let sec = null;
      let usec = null;
      try {
        sec = this.tv.readS64().toString();
        usec = this.tv.add(Process.pointerSize).readS64().toString();
      } catch (_) {}

      write("gettimeofday", {
        event: nativeEvents,
        retval: retval.toInt32(),
        sec,
        usec,
        backtrace: this.bt
      });
    }
  });

  write("HOOKED", { name: "gettimeofday", address: p.toString() });
}

attachClockGettime();
attachGettimeofday();

if (typeof Java !== "undefined" && Java.available) {
  Java.perform(() => {
    try {
      const System = Java.use("java.lang.System");
      const DateCls = Java.use("java.util.Date");
      const TimeZone = Java.use("java.util.TimeZone");

      const currentTimeMillis = System.currentTimeMillis.overload();
      currentTimeMillis.implementation = function () {
        const value = currentTimeMillis.call(this);
        if (javaEvents < MAX_JAVA_EVENTS) {
          javaEvents++;
          write("System.currentTimeMillis", {
            event: javaEvents,
            value: safe(value),
            timezone: safe(TimeZone.getDefault().getID())
          });
        }
        return value;
      };

      const dateCtor = DateCls.$init.overload();
      dateCtor.implementation = function () {
        const ret = dateCtor.call(this);
        if (javaEvents < MAX_JAVA_EVENTS) {
          javaEvents++;
          try {
            write("Date.<init>", {
              event: javaEvents,
              millis: safe(this.getTime()),
              text: safe(this.toString())
            });
          } catch (_) {}
        }
        return ret;
      };

      write("JAVA-HOOKS-READY", {
        timezone: safe(TimeZone.getDefault().getID())
      });
    } catch (e) {
      write("JAVA-HOOK-ERROR", {
        error: safe(e),
        stack: e && e.stack ? safe(e.stack) : null
      });
    }
  });
} else {
  write("JAVA-UNAVAILABLE", {});
}

setTimeout(() => {
  write("STATUS", {
    nativeEvents,
    javaEvents
  });
}, 15000);
