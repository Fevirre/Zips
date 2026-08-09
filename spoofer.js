'use strict';

/*
 * spoofer.js - native-only Android/QJS regional spoofer + runtime tracer v4
 * No Java bridge required.
 *
 * Goals:
 *   - set US/New York environment once
 *   - keep Android property spoof/probe
 *   - avoid hot-path getenv interception
 *   - log selected native runtime functions with caller module + offset
 *   - never modify clock/network/file return values
 */

const VERSION = 'spoofer-native-v4';
const ROOT = '/storage/emulated/0/Android/data/com.nintendo.zaka/files/Frida/Logs';
const LOG_PATH = ROOT + '/spoofer.log';
const RUNTIME_LOG = ROOT + '/runtime_functions.log';

const SPOOF_PROPERTIES = {
  'persist.sys.timezone': 'America/New_York',
  'persist.sys.locale': 'en-US',
  'ro.product.locale': 'en-US',
  'ro.product.locale.region': 'US',
  'ro.product.locale.language': 'en',
  'persist.sys.timezone.auto': '1',
  'persist.sys.time.auto': '1'
};

const SPOOF_ENV = {
  'TZ': 'America/New_York',
  'LANG': 'en_US.UTF-8',
  'LC_ALL': 'en_US.UTF-8',
  'LANGUAGE': 'en_US:en'
};

const runtimeCounts = new Map();
const propertyCounts = new Map();
const MAX_RUNTIME_LINES = 500;
let runtimeLines = 0;

function append(path, message) {
  try {
    const f = new File(path, 'a');
    f.write(new Date().toISOString() + ' [' + VERSION + '] ' + message + '\n');
    f.flush();
    f.close();
  } catch (_) {}
}

function log(message) {
  append(LOG_PATH, message);
  try { console.log('[mkt-spoofer] ' + message); } catch (_) {}
}

function runtimeLog(message) {
  if (runtimeLines >= MAX_RUNTIME_LINES) return;
  runtimeLines++;
  append(RUNTIME_LOG, message);
}

function globalExport(name) {
  try { return Module.findGlobalExportByName(name); } catch (_) { return null; }
}

function callerInfo(address) {
  try {
    const mod = Process.findModuleByAddress(address);
    if (mod !== null) {
      return mod.name + '+0x' + address.sub(mod.base).toString(16);
    }
  } catch (_) {}
  try { return DebugSymbol.fromAddress(address).toString(); } catch (_) {}
  return address ? address.toString() : '<unknown>';
}

function shouldEmitRuntime(name) {
  const n = (runtimeCounts.get(name) || 0) + 1;
  runtimeCounts.set(name, n);
  return n <= 3 || n === 10 || n === 50 || n === 100 || n === 500 || n === 1000;
}

function applyEnvironment() {
  const setenvPtr = globalExport('setenv');
  if (setenvPtr !== null) {
    const setenv = new NativeFunction(setenvPtr, 'int', ['pointer', 'pointer', 'int']);
    for (const key of Object.keys(SPOOF_ENV)) {
      const rc = setenv(
        Memory.allocUtf8String(key),
        Memory.allocUtf8String(SPOOF_ENV[key]),
        1
      );
      log('setenv ' + key + '=' + SPOOF_ENV[key] + ' rc=' + rc);
    }
  }

  const tzsetPtr = globalExport('tzset');
  if (tzsetPtr !== null) {
    try {
      new NativeFunction(tzsetPtr, 'void', [])();
      log('tzset applied');
    } catch (e) {
      log('tzset failed: ' + e);
    }
  }
}

function interestingProperty(key) {
  if (!key) return false;
  const k = key.toLowerCase();
  return k.includes('time') || k.includes('clock') || k.includes('date') ||
         k.includes('zone') || k.includes('locale') || k.includes('region') ||
         k.includes('country') || k.includes('language') || k.includes('ntp') ||
         k.includes('network');
}

function propertyLog(channel, key, value, spoofed) {
  const id = channel + ':' + key;
  const n = (propertyCounts.get(id) || 0) + 1;
  propertyCounts.set(id, n);
  if (n <= 3 || n === 10 || n === 50 || n === 100) {
    log('PROPERTY ' + channel + ' key=' + key + ' count=' + n +
        ' value=' + value + ' spoofed=' + (spoofed ? '1' : '0'));
  }
}

function hookPropertyApi(name) {
  const p = globalExport(name);
  if (p === null) {
    log(name + ' export not found');
    return;
  }

  Interceptor.attach(p, {
    onEnter(args) {
      this.key = null;
      this.out = args[1];
      try { this.key = args[0].readUtf8String(); } catch (_) {}
    },
    onLeave(retval) {
      if (!this.key) return;

      const replacement = SPOOF_PROPERTIES[this.key];
      if (replacement !== undefined) {
        try {
          this.out.writeUtf8String(replacement);
          retval.replace(replacement.length);
          propertyLog(name, this.key, replacement, true);
        } catch (e) {
          log('property write failed ' + name + ' key=' + this.key + ' error=' + e);
        }
        return;
      }

      if (interestingProperty(this.key)) {
        let value = '';
        try { value = this.out.readUtf8String(); } catch (_) {}
        propertyLog(name, this.key, value, false);
      }
    }
  });

  log('hooked ' + name + ' @ ' + p);
}

function safeReadUtf8(p) {
  try {
    if (p === null || p.isNull()) return '<null>';
    return p.readUtf8String();
  } catch (_) {
    return '<unreadable>';
  }
}

function traceFunction(name, formatter) {
  const p = globalExport(name);
  if (p === null) {
    runtimeLog('MISSING ' + name);
    return;
  }

  try {
    Interceptor.attach(p, {
      onEnter(args) {
        this.emit = shouldEmitRuntime(name);
        if (!this.emit) return;
        this.caller = callerInfo(this.returnAddress);
        this.detail = '';
        try {
          if (formatter) this.detail = formatter(args) || '';
        } catch (_) {}
      },
      onLeave(retval) {
        if (!this.emit) return;
        runtimeLog('CALL ' + name + ' caller=' + this.caller +
                   (this.detail ? ' ' + this.detail : '') +
                   ' ret=' + retval);
      }
    });
    runtimeLog('HOOKED ' + name + ' @ ' + p);
  } catch (e) {
    runtimeLog('HOOK-ERROR ' + name + ' ' + e);
  }
}

function installRuntimeTracing() {
  runtimeLog('START pid=' + Process.id + ' arch=' + Process.arch);

  // Time / clock reads.
  traceFunction('time');
  traceFunction('gettimeofday');
  traceFunction('clock_gettime', args => 'clockId=' + args[0].toInt32());
  traceFunction('clock_getres', args => 'clockId=' + args[0].toInt32());

  // DNS / network lifecycle.
  traceFunction('getaddrinfo', args => 'host=' + safeReadUtf8(args[0]));
  traceFunction('connect', args => 'fd=' + args[0].toInt32());
  traceFunction('send', args => 'fd=' + args[0].toInt32() + ' len=' + args[2].toInt32());
  traceFunction('recv', args => 'fd=' + args[0].toInt32() + ' len=' + args[2].toInt32());

  // File/runtime loading paths often used for integrity/config checks.
  traceFunction('open', args => 'path=' + safeReadUtf8(args[0]));
  traceFunction('openat', args => 'path=' + safeReadUtf8(args[1]));
  traceFunction('fopen', args => 'path=' + safeReadUtf8(args[0]));
  traceFunction('access', args => 'path=' + safeReadUtf8(args[0]));
  traceFunction('stat', args => 'path=' + safeReadUtf8(args[0]));
  traceFunction('dlopen', args => 'path=' + safeReadUtf8(args[0]));
  traceFunction('android_dlopen_ext', args => 'path=' + safeReadUtf8(args[0]));

  runtimeLog('READY');
}

function summary() {
  const runtime = [];
  for (const [name, count] of runtimeCounts.entries()) runtime.push(name + '=' + count);
  runtime.sort();
  log('RUNTIME-SUMMARY ' + runtime.join(', '));

  const props = [];
  for (const [name, count] of propertyCounts.entries()) props.push(name + '=' + count);
  props.sort();
  log('PROPERTY-SUMMARY ' + props.join(', '));
}

log('START pid=' + Process.id + ' arch=' + Process.arch);
log('mode=native-only region+runtime-trace; Java bridge not required');

try {
  applyEnvironment();
  hookPropertyApi('__system_property_get');
  hookPropertyApi('property_get');
  log('READY timezone=America/New_York locale=en-US country=US');

  // Delay runtime tracing so early Gadget/Unity startup remains light.
  setTimeout(function () {
    try {
      installRuntimeTracing();
    } catch (e) {
      runtimeLog('FATAL ' + (e && e.stack ? e.stack : e));
    }
  }, 2500);

  setTimeout(summary, 15000);
  setTimeout(summary, 30000);
} catch (e) {
  log('FATAL ' + (e && e.stack ? e.stack : e));
}
