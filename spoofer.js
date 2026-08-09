'use strict';

/*
 * spoofer.js - native-only Android/QJS region + runtime + signature probe v5
 * No Java bridge required.
 *
 * This revision does NOT globally force crypto verification results.
 * It identifies MKT-specific certificate/hash callers first so TLS and
 * asset integrity are not accidentally broken.
 */

const VERSION = 'spoofer-native-v5';
const ROOT = '/storage/emulated/0/Android/data/com.nintendo.zaka/files/Frida/Logs';
const LOG_PATH = ROOT + '/spoofer.log';
const RUNTIME_LOG = ROOT + '/runtime_functions.log';
const SIGNATURE_LOG = ROOT + '/signature_functions.log';

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
const signatureCounts = new Map();
const propertyCounts = new Map();
let runtimeLines = 0;
let signatureLines = 0;
const MAX_RUNTIME_LINES = 350;
const MAX_SIGNATURE_LINES = 450;

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

function signatureLog(message) {
  if (signatureLines >= MAX_SIGNATURE_LINES) return;
  signatureLines++;
  append(SIGNATURE_LOG, message);
}

function globalExport(name) {
  try { return Module.findGlobalExportByName(name); } catch (_) { return null; }
}

function callerInfo(address) {
  try {
    const mod = Process.findModuleByAddress(address);
    if (mod !== null) return mod.name + '+0x' + address.sub(mod.base).toString(16);
  } catch (_) {}
  try { return DebugSymbol.fromAddress(address).toString(); } catch (_) {}
  return address ? address.toString() : '<unknown>';
}

function callerModule(address) {
  try {
    const mod = Process.findModuleByAddress(address);
    return mod ? mod.name : '<unknown>';
  } catch (_) { return '<unknown>'; }
}

function shouldEmit(map, name) {
  const n = (map.get(name) || 0) + 1;
  map.set(name, n);
  return n <= 5 || n === 10 || n === 25 || n === 50 || n === 100 || n === 250 || n === 500 || n === 1000;
}

function safeReadUtf8(p) {
  try {
    if (p === null || p.isNull()) return '<null>';
    return p.readUtf8String();
  } catch (_) { return '<unreadable>'; }
}

function applyEnvironment() {
  const setenvPtr = globalExport('setenv');
  if (setenvPtr !== null) {
    const setenv = new NativeFunction(setenvPtr, 'int', ['pointer', 'pointer', 'int']);
    for (const key of Object.keys(SPOOF_ENV)) {
      const rc = setenv(Memory.allocUtf8String(key), Memory.allocUtf8String(SPOOF_ENV[key]), 1);
      log('setenv ' + key + '=' + SPOOF_ENV[key] + ' rc=' + rc);
    }
  }
  const tzsetPtr = globalExport('tzset');
  if (tzsetPtr !== null) {
    try { new NativeFunction(tzsetPtr, 'void', [])(); log('tzset applied'); }
    catch (e) { log('tzset failed: ' + e); }
  }
}

function interestingProperty(key) {
  if (!key) return false;
  const k = key.toLowerCase();
  return k.includes('time') || k.includes('clock') || k.includes('date') ||
         k.includes('zone') || k.includes('locale') || k.includes('region') ||
         k.includes('country') || k.includes('language') || k.includes('ntp') ||
         k.includes('network') || k.includes('sign') || k.includes('cert');
}

function propertyLog(channel, key, value, spoofed) {
  const id = channel + ':' + key;
  const n = (propertyCounts.get(id) || 0) + 1;
  propertyCounts.set(id, n);
  if (n <= 3 || n === 10 || n === 50 || n === 100) {
    log('PROPERTY ' + channel + ' key=' + key + ' count=' + n + ' value=' + value + ' spoofed=' + (spoofed ? '1' : '0'));
  }
}

function hookPropertyApi(name) {
  const p = globalExport(name);
  if (p === null) { log(name + ' export not found'); return; }
  Interceptor.attach(p, {
    onEnter(args) {
      this.key = null; this.out = args[1];
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
        } catch (e) { log('property write failed ' + name + ' key=' + this.key + ' error=' + e); }
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

function traceRuntime(name, formatter) {
  const p = globalExport(name);
  if (p === null) { runtimeLog('MISSING ' + name); return; }
  try {
    Interceptor.attach(p, {
      onEnter(args) {
        this.emit = shouldEmit(runtimeCounts, name);
        if (!this.emit) return;
        this.caller = callerInfo(this.returnAddress);
        this.detail = '';
        try { if (formatter) this.detail = formatter(args) || ''; } catch (_) {}
      },
      onLeave(retval) {
        if (!this.emit) return;
        runtimeLog('CALL ' + name + ' caller=' + this.caller + (this.detail ? ' ' + this.detail : '') + ' ret=' + retval);
      }
    });
    runtimeLog('HOOKED ' + name + ' @ ' + p);
  } catch (e) { runtimeLog('HOOK-ERROR ' + name + ' ' + e); }
}

function traceSignature(name, formatter, includeResult) {
  const p = globalExport(name);
  if (p === null) { signatureLog('MISSING ' + name); return; }
  try {
    Interceptor.attach(p, {
      onEnter(args) {
        const caller = callerModule(this.returnAddress);
        // Crypto is very noisy during TLS. Preserve samples from all callers,
        // but favor application/Unity callers by giving them their own key.
        this.key = name + ':' + caller;
        this.emit = shouldEmit(signatureCounts, this.key);
        if (!this.emit) return;
        this.caller = callerInfo(this.returnAddress);
        this.detail = '';
        try { if (formatter) this.detail = formatter(args) || ''; } catch (_) {}
      },
      onLeave(retval) {
        if (!this.emit) return;
        signatureLog('CALL ' + name + ' caller=' + this.caller +
          (this.detail ? ' ' + this.detail : '') +
          (includeResult === false ? '' : ' ret=' + retval));
      }
    });
    signatureLog('HOOKED ' + name + ' @ ' + p);
  } catch (e) { signatureLog('HOOK-ERROR ' + name + ' ' + e); }
}

function installRuntimeTracing() {
  runtimeLog('START pid=' + Process.id + ' arch=' + Process.arch);
  traceRuntime('time');
  traceRuntime('gettimeofday');
  // Keep monotonic clock noise out of v5.
  traceRuntime('getaddrinfo', args => 'host=' + safeReadUtf8(args[0]));
  traceRuntime('connect', args => 'fd=' + args[0].toInt32());
  traceRuntime('dlopen', args => 'path=' + safeReadUtf8(args[0]));
  traceRuntime('android_dlopen_ext', args => 'path=' + safeReadUtf8(args[0]));
  runtimeLog('READY');
}

function installSignatureTracing() {
  signatureLog('START pid=' + Process.id + ' arch=' + Process.arch);

  // Direct one-shot digests.
  traceSignature('SHA1', args => 'data=' + args[0] + ' len=' + args[1].toString());
  traceSignature('SHA256', args => 'data=' + args[0] + ' len=' + args[1].toString());
  traceSignature('MD5', args => 'data=' + args[0] + ' len=' + args[1].toString());

  // EVP digest pipeline used by BoringSSL/OpenSSL and many signature checks.
  traceSignature('EVP_DigestInit_ex');
  traceSignature('EVP_DigestUpdate', args => 'len=' + args[2].toString());
  traceSignature('EVP_DigestFinal_ex');
  traceSignature('EVP_DigestVerifyInit');
  traceSignature('EVP_DigestVerifyUpdate', args => 'len=' + args[2].toString());
  traceSignature('EVP_DigestVerifyFinal');
  traceSignature('EVP_VerifyFinal');

  // X.509 / certificate parsing and verification.
  traceSignature('d2i_X509');
  traceSignature('X509_digest');
  traceSignature('X509_verify');
  traceSignature('X509_verify_cert');
  traceSignature('X509_check_host');

  // TLS verification signals. Observational only.
  traceSignature('SSL_get_verify_result');
  traceSignature('SSL_do_handshake');
  traceSignature('SSL_connect');
  traceSignature('SSL_CTX_set_verify', null, false);
  traceSignature('SSL_set_verify', null, false);

  // Common low-level signature primitives where exported.
  traceSignature('RSA_verify');
  traceSignature('ECDSA_verify');

  // Record crypto-related modules currently present.
  try {
    const mods = Process.enumerateModules();
    for (const m of mods) {
      const n = m.name.toLowerCase();
      if (n.includes('ssl') || n.includes('crypto') || n.includes('il2cpp') || n.includes('unity') || n === 'libms.so') {
        signatureLog('MODULE ' + m.name + ' base=' + m.base + ' size=' + m.size);
      }
    }
  } catch (_) {}

  signatureLog('READY');
}

function summary() {
  const r = [];
  for (const [name, count] of runtimeCounts.entries()) r.push(name + '=' + count);
  r.sort();
  log('RUNTIME-SUMMARY ' + r.join(', '));

  const s = [];
  for (const [name, count] of signatureCounts.entries()) s.push(name + '=' + count);
  s.sort();
  log('SIGNATURE-SUMMARY ' + s.join(', '));

  const p = [];
  for (const [name, count] of propertyCounts.entries()) p.push(name + '=' + count);
  p.sort();
  log('PROPERTY-SUMMARY ' + p.join(', '));
}

log('START pid=' + Process.id + ' arch=' + Process.arch);
log('mode=native-only region+runtime+signature-probe; Java bridge not required');

try {
  applyEnvironment();
  hookPropertyApi('__system_property_get');
  hookPropertyApi('property_get');
  log('READY timezone=America/New_York locale=en-US country=US');

  // Arm after early Gadget/Unity startup to avoid the earlier gray-screen issue.
  setTimeout(function () {
    try { installRuntimeTracing(); }
    catch (e) { runtimeLog('FATAL ' + (e && e.stack ? e.stack : e)); }
  }, 2500);

  setTimeout(function () {
    try { installSignatureTracing(); }
    catch (e) { signatureLog('FATAL ' + (e && e.stack ? e.stack : e)); }
  }, 3000);

  setTimeout(summary, 15000);
  setTimeout(summary, 30000);
} catch (e) {
  log('FATAL ' + (e && e.stack ? e.stack : e));
}
