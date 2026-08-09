'use strict';

/*
 * spoofer.js - native-only Android/QJS region + early per-module signature probe v6
 * No Java bridge required. Observational crypto hooks only; no digest/verify result is modified.
 */

const VERSION = 'spoofer-native-v6';
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

const CRYPTO_NAMES = new Set([
  'SHA1','SHA256','MD5',
  'EVP_DigestInit_ex','EVP_DigestUpdate','EVP_DigestFinal_ex',
  'EVP_DigestVerifyInit','EVP_DigestVerifyUpdate','EVP_DigestVerifyFinal','EVP_VerifyFinal',
  'd2i_X509','X509_digest','X509_verify','X509_verify_cert','X509_check_host',
  'SSL_get_verify_result','SSL_do_handshake','SSL_connect','SSL_CTX_set_verify','SSL_set_verify',
  'RSA_verify','ECDSA_verify'
]);

const hookedAddresses = new Set();
const signatureCounts = new Map();
const runtimeCounts = new Map();
const propertyCounts = new Map();
let signatureLines = 0;
let runtimeLines = 0;
const MAX_SIGNATURE_LINES = 800;
const MAX_RUNTIME_LINES = 250;

function append(path, message) {
  try {
    const f = new File(path, 'a');
    f.write(new Date().toISOString() + ' [' + VERSION + '] ' + message + '\n');
    f.flush();
    f.close();
  } catch (_) {}
}
function log(m) { append(LOG_PATH, m); try { console.log('[mkt-spoofer] ' + m); } catch (_) {} }
function siglog(m) { if (signatureLines++ < MAX_SIGNATURE_LINES) append(SIGNATURE_LOG, m); }
function rtlog(m) { if (runtimeLines++ < MAX_RUNTIME_LINES) append(RUNTIME_LOG, m); }
function gexp(n) { try { return Module.findGlobalExportByName(n); } catch (_) { return null; } }
function safeStr(p) { try { return (!p || p.isNull()) ? '<null>' : p.readUtf8String(); } catch (_) { return '<unreadable>'; } }
function callerInfo(a) {
  try { const m = Process.findModuleByAddress(a); if (m) return m.name + '+0x' + a.sub(m.base).toString(16); } catch (_) {}
  return a ? a.toString() : '<unknown>';
}
function bump(map, key) { const n = (map.get(key) || 0) + 1; map.set(key, n); return n; }
function sampled(n) { return n <= 8 || n === 10 || n === 25 || n === 50 || n === 100 || n === 250 || n === 500 || n === 1000; }

function applyEnvironment() {
  const p = gexp('setenv');
  if (p) {
    const setenv = new NativeFunction(p, 'int', ['pointer','pointer','int']);
    for (const k of Object.keys(SPOOF_ENV)) {
      const rc = setenv(Memory.allocUtf8String(k), Memory.allocUtf8String(SPOOF_ENV[k]), 1);
      log('setenv ' + k + '=' + SPOOF_ENV[k] + ' rc=' + rc);
    }
  }
  const tz = gexp('tzset');
  if (tz) { try { new NativeFunction(tz, 'void', [])(); log('tzset applied'); } catch (e) { log('tzset failed: ' + e); } }
}

function interestingProperty(k) {
  if (!k) return false;
  k = k.toLowerCase();
  return k.includes('time') || k.includes('zone') || k.includes('locale') || k.includes('region') ||
         k.includes('country') || k.includes('language') || k.includes('sign') || k.includes('cert');
}
function hookPropertyApi(name) {
  const p = gexp(name); if (!p) { log(name + ' export not found'); return; }
  Interceptor.attach(p, {
    onEnter(args) { this.k = null; this.out = args[1]; try { this.k = args[0].readUtf8String(); } catch (_) {} },
    onLeave(ret) {
      if (!this.k) return;
      const repl = SPOOF_PROPERTIES[this.k];
      if (repl !== undefined) {
        try { this.out.writeUtf8String(repl); ret.replace(repl.length); } catch (_) {}
        const n = bump(propertyCounts, name + ':' + this.k); if (sampled(n)) log('PROPERTY ' + name + ' key=' + this.k + ' count=' + n + ' value=' + repl + ' spoofed=1');
      } else if (interestingProperty(this.k)) {
        let v = ''; try { v = this.out.readUtf8String(); } catch (_) {}
        const n = bump(propertyCounts, name + ':' + this.k); if (sampled(n)) log('PROPERTY ' + name + ' key=' + this.k + ' count=' + n + ' value=' + v + ' spoofed=0');
      }
    }
  });
  log('hooked ' + name + ' @ ' + p);
}

function cryptoDetail(name, args) {
  try {
    if (name === 'SHA1' || name === 'SHA256' || name === 'MD5') return 'len=' + args[1].toString();
    if (name === 'EVP_DigestUpdate' || name === 'EVP_DigestVerifyUpdate') return 'len=' + args[2].toString();
  } catch (_) {}
  return '';
}

function hookCryptoAddress(moduleName, symbolName, address) {
  const id = address.toString();
  if (hookedAddresses.has(id)) return;
  hookedAddresses.add(id);
  try {
    Interceptor.attach(address, {
      onEnter(args) {
        this.caller = callerInfo(this.returnAddress);
        this.key = moduleName + '!' + symbolName + '<-' + this.caller.split('+')[0];
        this.n = bump(signatureCounts, this.key);
        this.emit = sampled(this.n);
        this.detail = this.emit ? cryptoDetail(symbolName, args) : '';
      },
      onLeave(ret) {
        if (!this.emit) return;
        siglog('CALL module=' + moduleName + ' symbol=' + symbolName + ' count=' + this.n +
               ' caller=' + this.caller + (this.detail ? ' ' + this.detail : '') + ' ret=' + ret);
      }
    });
    siglog('HOOKED module=' + moduleName + ' symbol=' + symbolName + ' @ ' + address);
  } catch (e) {
    siglog('HOOK-ERROR module=' + moduleName + ' symbol=' + symbolName + ' @ ' + address + ' error=' + e);
  }
}

function scanCryptoModules(reason) {
  siglog('SCAN reason=' + reason);
  let mods = [];
  try { mods = Process.enumerateModules(); } catch (e) { siglog('SCAN-ERROR ' + e); return; }
  for (const m of mods) {
    const low = m.name.toLowerCase();
    if (!(low.includes('crypto') || low.includes('ssl') || low.includes('il2cpp') || low.includes('unity') || m.name === 'libms.so')) continue;
    siglog('MODULE name=' + m.name + ' base=' + m.base + ' size=' + m.size);
    let exps = [];
    try { exps = m.enumerateExports(); } catch (e) { siglog('EXPORTS-ERROR module=' + m.name + ' ' + e); continue; }
    for (const e of exps) {
      if (e.type === 'function' && CRYPTO_NAMES.has(e.name)) hookCryptoAddress(m.name, e.name, e.address);
      if (m.name === 'libms.so' && e.type === 'function') {
        const n = e.name.toLowerCase();
        if (n.includes('sign') || n.includes('cert') || n.includes('hash') || n.includes('verify') || n.includes('digest'))
          siglog('LIBMS-EXPORT name=' + e.name + ' @ ' + e.address);
      }
    }
  }
}

function traceRuntime(name, formatter) {
  const p = gexp(name); if (!p) { rtlog('MISSING ' + name); return; }
  try {
    Interceptor.attach(p, {
      onEnter(args) {
        this.n = bump(runtimeCounts, name); this.emit = sampled(this.n);
        if (!this.emit) return;
        this.caller = callerInfo(this.returnAddress); this.detail = '';
        try { if (formatter) this.detail = formatter(args) || ''; } catch (_) {}
      },
      onLeave(ret) { if (this.emit) rtlog('CALL ' + name + ' count=' + this.n + ' caller=' + this.caller + (this.detail ? ' ' + this.detail : '') + ' ret=' + ret); }
    });
    rtlog('HOOKED ' + name + ' @ ' + p);
  } catch (e) { rtlog('HOOK-ERROR ' + name + ' ' + e); }
}

function hookLoaderForRescan() {
  for (const name of ['dlopen','android_dlopen_ext']) {
    const p = gexp(name); if (!p) continue;
    try {
      Interceptor.attach(p, {
        onEnter(args) { this.path = safeStr(args[0]); },
        onLeave(ret) {
          if (ret.isNull()) return;
          const path = this.path || '';
          if (/lib(ms|crypto|ssl|unity|il2cpp)/i.test(path)) {
            siglog('LOAD ' + name + ' path=' + path + ' ret=' + ret);
            setTimeout(function () { scanCryptoModules('after-load:' + path); }, 0);
          }
        }
      });
      siglog('LOADER-HOOKED ' + name + ' @ ' + p);
    } catch (e) { siglog('LOADER-HOOK-ERROR ' + name + ' ' + e); }
  }
}

function summary() {
  const s = []; for (const [k,v] of signatureCounts) s.push(k + '=' + v); s.sort();
  log('SIGNATURE-SUMMARY ' + s.join(', '));
  const r = []; for (const [k,v] of runtimeCounts) r.push(k + '=' + v); r.sort();
  log('RUNTIME-SUMMARY ' + r.join(', '));
  const p = []; for (const [k,v] of propertyCounts) p.push(k + '=' + v); p.sort();
  log('PROPERTY-SUMMARY ' + p.join(', '));
}

log('START pid=' + Process.id + ' arch=' + Process.arch);
log('mode=native-only v6 early-per-module-signature-probe');
try {
  applyEnvironment();
  hookPropertyApi('__system_property_get');
  hookPropertyApi('property_get');

  // Signature probe arms immediately, before MKT's first network/libms activity.
  siglog('START pid=' + Process.id + ' arch=' + Process.arch);
  scanCryptoModules('startup');
  hookLoaderForRescan();
  siglog('READY-EARLY');

  // Keep general runtime tracing delayed/light.
  setTimeout(function () {
    rtlog('START pid=' + Process.id + ' arch=' + Process.arch);
    traceRuntime('time');
    traceRuntime('gettimeofday');
    traceRuntime('getaddrinfo', a => 'host=' + safeStr(a[0]));
    traceRuntime('connect', a => 'fd=' + a[0].toInt32());
    rtlog('READY');
  }, 2500);

  log('READY timezone=America/New_York locale=en-US country=US signatureProbe=early');
  setTimeout(summary, 15000);
  setTimeout(summary, 30000);
} catch (e) {
  log('FATAL ' + (e && e.stack ? e.stack : e));
}
