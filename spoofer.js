'use strict';

/*
 * spoofer.js - native-only Android/QJS regional probe v3
 * No Java bridge required.
 *
 * Keeps the working America/New_York / en-US environment spoof while
 * rate-limiting duplicate reads and logging the time/locale-related
 * system-property keys MKT actually requests.
 */

const VERSION = 'spoofer-native-v3';
const LOG_PATH = '/storage/emulated/0/Android/data/com.nintendo.zaka/files/Frida/Logs/spoofer.log';

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

const pinnedStrings = {};
for (const key of Object.keys(SPOOF_ENV)) {
  pinnedStrings[key] = Memory.allocUtf8String(SPOOF_ENV[key]);
}

const hitCounts = new Map();
const firstSeen = new Set();
const MAX_UNIQUE_LOGS = 160;
const MAX_PER_KEY_VERBOSE = 3;
let uniqueLogs = 0;

function log(message) {
  try {
    const f = new File(LOG_PATH, 'a');
    f.write(new Date().toISOString() + ' [' + VERSION + '] ' + message + '\n');
    f.flush();
    f.close();
  } catch (_) {}
  try { console.log('[mkt-spoofer] ' + message); } catch (_) {}
}

function shouldLogKey(channel, key) {
  const id = channel + ':' + key;
  const count = (hitCounts.get(id) || 0) + 1;
  hitCounts.set(id, count);

  if (count <= MAX_PER_KEY_VERBOSE) return true;
  if (count === 10 || count === 50 || count === 100 || count === 500 || count === 1000) return true;
  return false;
}

function logKey(channel, key, value, spoofed) {
  const id = channel + ':' + key;
  if (!firstSeen.has(id)) {
    firstSeen.add(id);
    if (uniqueLogs < MAX_UNIQUE_LOGS) {
      uniqueLogs++;
      log('FIRST ' + channel + ' key=' + key + ' value=' + value + (spoofed ? ' spoofed=1' : ' spoofed=0'));
    }
    return;
  }

  if (shouldLogKey(channel, key)) {
    const count = hitCounts.get(id) || 0;
    log('HIT ' + channel + ' key=' + key + ' count=' + count + ' value=' + value + (spoofed ? ' spoofed=1' : ' spoofed=0'));
  }
}

function interestingKey(key) {
  if (!key) return false;
  const k = key.toLowerCase();
  return k.includes('time') ||
         k.includes('clock') ||
         k.includes('date') ||
         k.includes('zone') ||
         k.includes('locale') ||
         k.includes('region') ||
         k.includes('country') ||
         k.includes('language') ||
         k.includes('network') ||
         k.includes('ntp');
}

function globalExport(name) {
  try { return Module.findGlobalExportByName(name); } catch (_) { return null; }
}

function applyEnvironment() {
  const setenvPtr = globalExport('setenv');
  if (setenvPtr !== null) {
    try {
      const setenv = new NativeFunction(setenvPtr, 'int', ['pointer', 'pointer', 'int']);
      for (const key of Object.keys(SPOOF_ENV)) {
        const k = Memory.allocUtf8String(key);
        const v = Memory.allocUtf8String(SPOOF_ENV[key]);
        const rc = setenv(k, v, 1);
        log('setenv ' + key + '=' + SPOOF_ENV[key] + ' rc=' + rc);
      }
    } catch (e) {
      log('setenv setup failed: ' + e);
    }
  } else {
    log('setenv export not found');
  }

  const tzsetPtr = globalExport('tzset');
  if (tzsetPtr !== null) {
    try {
      const tzset = new NativeFunction(tzsetPtr, 'void', []);
      tzset();
      log('tzset applied');
    } catch (e) {
      log('tzset failed: ' + e);
    }
  }
}

function hookSystemPropertyGet() {
  const p = globalExport('__system_property_get');
  if (p === null) {
    log('__system_property_get export not found');
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
          logKey('__system_property_get', this.key, replacement, true);
        } catch (e) {
          log('property write failed key=' + this.key + ' error=' + e);
        }
        return;
      }

      if (interestingKey(this.key)) {
        let value = '';
        try { value = this.out.readUtf8String(); } catch (_) {}
        logKey('__system_property_get', this.key, value, false);
      }
    }
  });

  log('hooked __system_property_get @ ' + p);
}

function hookPropertyGet() {
  const p = globalExport('property_get');
  if (p === null) {
    log('property_get export not found');
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
          logKey('property_get', this.key, replacement, true);
        } catch (e) {
          log('property_get write failed key=' + this.key + ' error=' + e);
        }
        return;
      }

      if (interestingKey(this.key)) {
        let value = '';
        try { value = this.out.readUtf8String(); } catch (_) {}
        logKey('property_get', this.key, value, false);
      }
    }
  });

  log('hooked property_get @ ' + p);
}

function hookGetenv() {
  const p = globalExport('getenv');
  if (p === null) {
    log('getenv export not found');
    return;
  }

  Interceptor.attach(p, {
    onEnter(args) {
      this.key = null;
      try { this.key = args[0].readUtf8String(); } catch (_) {}
    },
    onLeave(retval) {
      if (!this.key) return;

      const replacement = SPOOF_ENV[this.key];
      if (replacement !== undefined) {
        retval.replace(pinnedStrings[this.key]);
        logKey('getenv', this.key, replacement, true);
        return;
      }

      if (interestingKey(this.key)) {
        let value = '<null>';
        try {
          if (!retval.isNull()) value = retval.readUtf8String();
        } catch (_) {}
        logKey('getenv', this.key, value, false);
      }
    }
  });

  log('hooked getenv @ ' + p);
}

function summary() {
  const entries = [];
  for (const [id, count] of hitCounts.entries()) {
    entries.push(id + '=' + count);
  }
  entries.sort();
  log('SUMMARY ' + entries.join(', '));
}

log('START pid=' + Process.id + ' arch=' + Process.arch);
log('mode=native-only targeted-probe; Java bridge not required');

try {
  applyEnvironment();
  hookSystemPropertyGet();
  hookPropertyGet();
  hookGetenv();
  log('READY timezone=America/New_York locale=en-US country=US');
  setTimeout(summary, 15000);
  setTimeout(summary, 30000);
} catch (e) {
  log('FATAL ' + (e && e.stack ? e.stack : e));
}
