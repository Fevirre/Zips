'use strict';

/*
 * spoofer.js - native-only Android/QJS regional spoofer
 * No Java bridge is required.
 *
 * Scope for this revision:
 *   - America/New_York timezone identity
 *   - en-US / US locale identity
 *   - Android system-property reads
 *   - libc environment reads
 *   - passive logging of the exact keys MKT requests
 *
 * Deliberately NOT hooking clock_gettime/gettimeofday yet, because the
 * earlier time probe showed that aggressive startup interception can stall MKT.
 */

const VERSION = 'spoofer-native-v2';
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

let eventCount = 0;
const MAX_LOG_EVENTS = 300;

function log(message) {
  try {
    const f = new File(LOG_PATH, 'a');
    f.write(new Date().toISOString() + ' [' + VERSION + '] ' + message + '\n');
    f.flush();
    f.close();
  } catch (_) {}

  try { console.log('[mkt-spoofer] ' + message); } catch (_) {}
}

function logEvent(message) {
  if (eventCount >= MAX_LOG_EVENTS) return;
  eventCount++;
  log(message);
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
          logEvent('__system_property_get ' + this.key + ' => ' + replacement);
        } catch (e) {
          logEvent('__system_property_get write failed ' + this.key + ': ' + e);
        }
        return;
      }

      if (this.key.indexOf('time') !== -1 ||
          this.key.indexOf('locale') !== -1 ||
          this.key.indexOf('region') !== -1 ||
          this.key.indexOf('country') !== -1) {
        let value = '';
        try { value = this.out.readUtf8String(); } catch (_) {}
        logEvent('__system_property_get observed ' + this.key + ' => ' + value);
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
      if (replacement === undefined) return;
      try {
        this.out.writeUtf8String(replacement);
        retval.replace(replacement.length);
        logEvent('property_get ' + this.key + ' => ' + replacement);
      } catch (e) {
        logEvent('property_get write failed ' + this.key + ': ' + e);
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
      if (replacement === undefined) return;
      retval.replace(pinnedStrings[this.key]);
      logEvent('getenv ' + this.key + ' => ' + replacement);
    }
  });

  log('hooked getenv @ ' + p);
}

log('START pid=' + Process.id + ' arch=' + Process.arch);
log('mode=native-only; Java bridge not required');

try {
  applyEnvironment();
  hookSystemPropertyGet();
  hookPropertyGet();
  hookGetenv();
  log('READY timezone=America/New_York locale=en-US country=US');
} catch (e) {
  log('FATAL ' + (e && e.stack ? e.stack : e));
}
