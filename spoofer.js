'use strict';

/* spoofer.js - standalone MKT package/signature spoof workload */
const TARGET_PACKAGE = 'com.nintendo.zaka';
const ORIGINAL_CERT_DER_B64 = 'MIIFhzCCA2+gAwIBAgIVAIU1KXkmC2j3Ni+bG3ovYRY9jlrMMA0GCSqGSIb3DQEBCwUAMHQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRQwEgYDVQQKEwtHb29nbGUgSW5jLjEQMA4GA1UECxMHQW5kcm9pZDEQMA4GA1UEAxMHQW5kcm9pZDAeFw0xOTAyMjAyMzQzMzlaFw00OTAyMjAyMzQzMzlaMHQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRQwEgYDVQQKEwtHb29nbGUgSW5jLjEQMA4GA1UECxMHQW5kcm9pZDEQMA4GA1UEAxMHQW5kcm9pZDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALVSqmNxpS71nf0w/lkUGjJ5l1EaOt772+Z3jahLBhPjuwreXDb+9G2DEljWldKKRcG4X1qZaecGTq3OwsAWvajCv0Pac9ePPHe5ciMAeIZwRcgOirpeVBXPZPdNGlWIim6BJNwChSBLjvJNnPhRfkfg2JEjZoZTblPUWOQdlmJ3Z7q4prk7w1FK9ajwzYEn3qrYNYb3cCO/zWjcO5Dhl5fXmhjzhVPrDulM47dDMplEH+T3PSqgly7jhY3O9Gqcq9BRtgyQ/TUxh1R5F5yb3Ap1o0p9wxfAgan74rbeV33wGWTutKoq1KbP10UWmwAP1te2EVmSOVtoi+wj0mIY7hOMUALKae62U5H4+K+ero5+kXz8TLkGnZIgpPb14b86vAmT1V31lajqweRwORE5zASofrLKzP10TLS3ngsaDqhLnkdklDH4A3ONCywPfDf9qZGaSfE9kEPKp9CLLB7P5l87npJnMep23slpXbwULb+KWd76dIMWO7yX079xYY4CFz0a9Peu/ThTSwOwVxxT5ipHcQo6q9HEJIyfGGs1CX3Uwie0sTAnyAqQLADAI8dZUwHid2xoU3S6jgOAQN30y56WkkTHnm2VqmtMBdTW8Smt8BMrNuGP+y5EDkj/P4gA66eOD1qIGFPUKcsfsogSydQ01SIFr3p7+Uzo+OHftqCJAgMBAAGjEDAOMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBACkUuIMgbYZ8NHDXJJfZvObG3cnhmncVaI14WDer942Iqnyg8R3xBbm73hlECHUga2hDinr0QSOQ+59/+h8RVZedPPhITrv01KEhLL+a3NuVu/X7zGESbAGiH9C+4pr0p65pur+nte0QYl5THRQoCBIP4+144oAe+XruPK0MGd1oT8ON4r01l9g4a3I0FkGntvMMPmIOpHz1e6FIOaayFe34DG0QUhvv03vGb7UgpVq/SjET+niX1qh4wvuJvEE027yEJsH24NKi73rUZRbj0zeVqM8FTWBL4mWY3nMro9RpI5d17bAMOQsIKTc0vPzikoAUxr69tqRu1moJFMxRNHW3SHqIjWE5BDbYOW1bUelIZTQbH23HlU6ufE5FDCxjDU22zBnY2SgnZyIxBnbTTmrKT6FnaFZqDTNQUuXdOapnETbWS3oFS1KRNccV50E0PVVWUy8woH7FrUu4KKD9o3/pGLHSz5/rWjHDz/SMHU/uOc+mJfWRsuS7SSvFQG/b9ruF9gGeqZX9LlVf6aP+QSW/ksQ0uAfH+0Hpukbakwz/LZNlv2jHBRJrlHhoSynKJM57AlLfOFNyihf5fCTvOfNGTZ1jCdo10ACkQfbJMe49SP3B8HCH/cLCp6JZ/yhTbDRg1QNpnCaqPIEflJz8uotgtvA6/EA91zT90xSYpmEW';

function installHooks() {
  if (typeof Java === 'undefined' || !Java.available) {
    console.log('[mkt-sigspoof] Java unavailable; retrying');
    setTimeout(installHooks, 250);
    return;
  }
  Java.perform(function () {
    try {
      const Base64 = Java.use('android.util.Base64');
      const Signature = Java.use('android.content.pm.Signature');
      const APM = Java.use('android.app.ApplicationPackageManager');
      const SigningInfo = Java.use('android.content.pm.SigningInfo');
      const PackageManager = Java.use('android.content.pm.PackageManager');
      const certBytes = Base64.decode(ORIGINAL_CERT_DER_B64, 0);
      const originalSignature = Signature.$new(certBytes);
      const originalSignatures = Java.array('android.content.pm.Signature', [originalSignature]);
      const trackedSigningInfo = new Set();
      const isTarget = p => p !== null && p.toString() === TARGET_PACKAGE;
      function spoofPackageInfo(info) {
        if (info === null) return info;
        try { info.signatures.value = originalSignatures; } catch (_) {}
        try {
          const si = info.signingInfo.value;
          if (si !== null) trackedSigningInfo.add(si.hashCode().toString());
        } catch (_) {}
        return info;
      }
      const legacy = APM.getPackageInfo.overload('java.lang.String', 'int');
      legacy.implementation = function (packageName, flags) {
        const info = legacy.call(this, packageName, flags);
        if (isTarget(packageName)) {
          console.log('[mkt-sigspoof] getPackageInfo(int): ' + packageName);
          return spoofPackageInfo(info);
        }
        return info;
      };
      try {
        const modern = APM.getPackageInfo.overload('java.lang.String', 'android.content.pm.PackageManager$PackageInfoFlags');
        modern.implementation = function (packageName, flags) {
          const info = modern.call(this, packageName, flags);
          if (isTarget(packageName)) {
            console.log('[mkt-sigspoof] getPackageInfo(flags): ' + packageName);
            return spoofPackageInfo(info);
          }
          return info;
        };
      } catch (_) {}
      const signers = SigningInfo.getApkContentsSigners.overload();
      signers.implementation = function () {
        if (trackedSigningInfo.has(this.hashCode().toString())) return originalSignatures;
        return signers.call(this);
      };
      const history = SigningInfo.getSigningCertificateHistory.overload();
      history.implementation = function () {
        if (trackedSigningInfo.has(this.hashCode().toString())) return originalSignatures;
        return history.call(this);
      };
      for (const ov of APM.hasSigningCertificate.overloads) {
        ov.implementation = function (packageName, certificate, type) {
          if (isTarget(packageName)) return true;
          return ov.call(this, packageName, certificate, type);
        };
      }
      try {
        const check = APM.checkSignatures.overload('java.lang.String', 'java.lang.String');
        check.implementation = function (a, b) {
          if (isTarget(a) || isTarget(b)) return PackageManager.SIGNATURE_MATCH.value;
          return check.call(this, a, b);
        };
      } catch (_) {}
      console.log('[mkt-sigspoof] hooks installed');
    } catch (e) {
      console.log('[mkt-sigspoof] install error: ' + (e.stack || e));
    }
  });
}
setImmediate(installHooks);
