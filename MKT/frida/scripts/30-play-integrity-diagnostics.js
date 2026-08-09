/*
 * MKT 4.0.0 - Play Integrity / Play services diagnostics
 *
 * Intended location:
 *   /storage/emulated/0/Android/data/com.nintendo.zaka/files/frida/scripts/
 *
 * Logs:
 *   /storage/emulated/0/Android/data/com.nintendo.zaka/files/frida/logs/
 *
 * This script observes calls and results only. It does not spoof signatures,
 * alter Play Integrity verdicts, or change return values.
 */

'use strict';

const ROOT = "/storage/emulated/0/Android/data/com.nintendo.zaka/files/frida";
const LOG_DIR = ROOT + "/logs";
const MAIN_LOG = LOG_DIR + "/play-integrity.log";
const ERR_LOG = LOG_DIR + "/errors.log";

function isoNow() {
    return new Date().toISOString();
}

function append(path, msg) {
    try {
        const f = new File(path, "a");
        f.write("[" + isoNow() + "] " + msg + "\n");
        f.flush();
        f.close();
    } catch (e) {
        console.error("[MKT-DIAG][LOGGER] " + e);
    }
}

function log(msg) {
    console.log("[MKT-DIAG] " + msg);
    append(MAIN_LOG, msg);
}

function error(where, e) {
    const text = "[" + where + "] " + (e && (e.stack || e.message) ? (e.stack || e.message) : String(e));
    console.error("[MKT-DIAG] " + text);
    append(ERR_LOG, text);
}

function safeString(x) {
    try {
        if (x === null || x === undefined) return String(x);
        return String(x);
    } catch (_) {
        return "<unprintable>";
    }
}

function byteHex(bytes, maxLen) {
    try {
        const lim = Math.min(bytes.length, maxLen || bytes.length);
        let out = "";
        for (let i = 0; i < lim; i++) {
            let b = bytes[i];
            if (b < 0) b += 256;
            out += ("0" + b.toString(16)).slice(-2);
        }
        if (bytes.length > lim) out += "...";
        return out;
    } catch (e) {
        return "<hex-error:" + e + ">";
    }
}

function installJavaHooks() {
    Java.perform(function () {
        log("Java runtime ready; installing diagnostics hooks");

        let Log = null;
        let Exception = null;
        try {
            Log = Java.use("android.util.Log");
            Exception = Java.use("java.lang.Exception");
        } catch (e) {
            error("stack-init", e);
        }

        function stack() {
            try {
                return Log.getStackTraceString(Exception.$new());
            } catch (_) {
                return "<stack unavailable>";
            }
        }

        function hookAll(className, methodName, handlerFactory) {
            try {
                const C = Java.use(className);
                if (!C[methodName]) return false;

                C[methodName].overloads.forEach(function (ov) {
                    const original = ov;
                    ov.implementation = handlerFactory(C, original);
                });

                log("Hooked " + className + "." + methodName);
                return true;
            } catch (e) {
                log("Not available: " + className + "." + methodName + " (" + e + ")");
                return false;
            }
        }

        try {
            const PM = Java.use("android.app.ApplicationPackageManager");

            if (PM.getPackageInfo) {
                PM.getPackageInfo.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        const args = Array.prototype.slice.call(arguments);
                        let pkg = args.length > 0 ? safeString(args[0]) : "<unknown>";

                        let shouldLog = (pkg.indexOf("com.nintendo.zaka") !== -1);
                        if (shouldLog) {
                            log("PackageManager.getPackageInfo(" + args.map(safeString).join(", ") + ")\n" + stack());
                        }

                        const result = ov.apply(this, args);

                        if (shouldLog) {
                            try {
                                log("getPackageInfo result package=" + safeString(result.packageName));
                                try {
                                    const si = result.signingInfo;
                                    if (si) {
                                        const signers = si.getApkContentsSigners();
                                        log("SigningInfo.getApkContentsSigners count=" + signers.length);
                                        for (let i = 0; i < signers.length; i++) {
                                            const raw = signers[i].toByteArray();
                                            log(" signer[" + i + "] bytes=" + raw.length + " head=" + byteHex(raw, 32));
                                        }
                                    }
                                } catch (e) {
                                    error("getPackageInfo-signingInfo", e);
                                }

                                try {
                                    if (result.signatures) {
                                        log("legacy signatures count=" + result.signatures.length);
                                        for (let i = 0; i < result.signatures.length; i++) {
                                            const raw = result.signatures[i].toByteArray();
                                            log(" legacy signer[" + i + "] bytes=" + raw.length + " head=" + byteHex(raw, 32));
                                        }
                                    }
                                } catch (e) {
                                    error("getPackageInfo-signatures", e);
                                }
                            } catch (e) {
                                error("getPackageInfo-result", e);
                            }
                        }

                        return result;
                    };
                });
                log("Hooked ApplicationPackageManager.getPackageInfo");
            }
        } catch (e) {
            error("PackageManager hooks", e);
        }

        try {
            const Signature = Java.use("android.content.pm.Signature");
            Signature.toByteArray.implementation = function () {
                const out = this.toByteArray();
                try {
                    log("Signature.toByteArray len=" + out.length + " head=" + byteHex(out, 32) + "\n" + stack());
                } catch (e) {
                    error("Signature.toByteArray-log", e);
                }
                return out;
            };
            log("Hooked android.content.pm.Signature.toByteArray");
        } catch (e) {
            error("Signature hook", e);
        }

        try {
            const MD = Java.use("java.security.MessageDigest");

            MD.getInstance.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    const args = Array.prototype.slice.call(arguments);
                    const alg = args.length ? safeString(args[0]) : "?";
                    const out = ov.apply(this, args);

                    if (/sha|md5/i.test(alg)) {
                        log("MessageDigest.getInstance(" + alg + ")\n" + stack());
                    }
                    return out;
                };
            });

            MD.digest.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    const args = Array.prototype.slice.call(arguments);
                    const out = ov.apply(this, args);
                    try {
                        const alg = safeString(this.getAlgorithm());
                        if (/sha|md5/i.test(alg)) {
                            log("MessageDigest.digest alg=" + alg +
                                " argc=" + args.length +
                                " result=" + byteHex(out, 64));
                        }
                    } catch (e) {
                        error("MessageDigest.digest-log", e);
                    }
                    return out;
                };
            });

            log("Hooked java.security.MessageDigest");
        } catch (e) {
            error("MessageDigest hooks", e);
        }

        const integrityTargets = [
            ["com.google.android.play.core.integrity.IntegrityManagerFactory", "create"],
            ["com.google.android.play.core.integrity.IntegrityManager", "requestIntegrityToken"],
            ["com.google.android.play.core.integrity.StandardIntegrityManagerFactory", "create"],
            ["com.google.android.play.core.integrity.StandardIntegrityManager", "prepareIntegrityToken"],
            ["com.google.android.play.core.integrity.StandardIntegrityManager$StandardIntegrityTokenProvider", "request"]
        ];

        integrityTargets.forEach(function (item) {
            const cls = item[0];
            const method = item[1];

            hookAll(cls, method, function (_, ov) {
                return function () {
                    const args = Array.prototype.slice.call(arguments);
                    log(cls + "." + method + "(" + args.map(safeString).join(", ") + ")\n" + stack());

                    const ret = ov.apply(this, args);

                    try {
                        log(cls + "." + method + " returned " +
                            (ret ? safeString(ret.getClass ? ret.getClass().getName() : ret) : "null"));
                    } catch (_) {}

                    return ret;
                };
            });
        });

        const builderTargets = [
            ["com.google.android.play.core.integrity.IntegrityTokenRequest$Builder", "setNonce"],
            ["com.google.android.play.core.integrity.IntegrityTokenRequest$Builder", "setCloudProjectNumber"],
            ["com.google.android.play.core.integrity.StandardIntegrityManager$PrepareIntegrityTokenRequest$Builder", "setCloudProjectNumber"],
            ["com.google.android.play.core.integrity.StandardIntegrityManager$StandardIntegrityTokenRequest$Builder", "setRequestHash"]
        ];

        builderTargets.forEach(function (item) {
            hookAll(item[0], item[1], function (_, ov) {
                return function () {
                    const args = Array.prototype.slice.call(arguments);
                    log(item[0] + "." + item[1] + "(" + args.map(safeString).join(", ") + ")");
                    return ov.apply(this, args);
                };
            });
        });

        function attachTaskListeners(task, label) {
            if (!task) return task;

            try {
                const OnSuccessListener = Java.registerClass({
                    name: "com.mktprototype.frida.SuccessListener" + Math.floor(Math.random() * 100000000),
                    implements: [Java.use("com.google.android.gms.tasks.OnSuccessListener")],
                    methods: {
                        onSuccess: function (result) {
                            log(label + " SUCCESS result=" + safeString(result));
                            try {
                                if (result && result.token) {
                                    log(label + " token() available; token length=" + safeString(result.token()).length);
                                }
                            } catch (_) {}
                        }
                    }
                });

                const OnFailureListener = Java.registerClass({
                    name: "com.mktprototype.frida.FailureListener" + Math.floor(Math.random() * 100000000),
                    implements: [Java.use("com.google.android.gms.tasks.OnFailureListener")],
                    methods: {
                        onFailure: function (ex) {
                            let msg = label + " FAILURE " + safeString(ex);
                            try {
                                msg += "\nclass=" + safeString(ex.getClass().getName());
                            } catch (_) {}
                            try {
                                msg += "\nmessage=" + safeString(ex.getMessage());
                            } catch (_) {}
                            try {
                                msg += "\nstack=" + Log.getStackTraceString(ex);
                            } catch (_) {}
                            log(msg);
                        }
                    }
                });

                task.addOnSuccessListener(OnSuccessListener.$new());
                task.addOnFailureListener(OnFailureListener.$new());
                log("Attached Task listeners to " + label);
            } catch (e) {
                error("attachTaskListeners:" + label, e);
            }

            return task;
        }

        [
            ["com.google.android.play.core.integrity.IntegrityManager", "requestIntegrityToken"],
            ["com.google.android.play.core.integrity.StandardIntegrityManager", "prepareIntegrityToken"],
            ["com.google.android.play.core.integrity.StandardIntegrityManager$StandardIntegrityTokenProvider", "request"]
        ].forEach(function (item) {
            try {
                const C = Java.use(item[0]);
                if (!C[item[1]]) return;

                C[item[1]].overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        const args = Array.prototype.slice.call(arguments);
                        log("[TASK] " + item[0] + "." + item[1] +
                            "(" + args.map(safeString).join(", ") + ")\n" + stack());
                        const ret = ov.apply(this, args);
                        attachTaskListeners(ret, item[0] + "." + item[1]);
                        return ret;
                    };
                });
                log("Task listener hook installed for " + item[0] + "." + item[1]);
            } catch (e) {
                log("Task hook unavailable: " + item[0] + "." + item[1] + " (" + e + ")");
            }
        });

        try {
            const ApiException = Java.use("com.google.android.gms.common.api.ApiException");
            ApiException.getStatusCode.implementation = function () {
                const code = this.getStatusCode();
                try {
                    log("ApiException.getStatusCode => " + code +
                        ", message=" + safeString(this.getMessage()) +
                        "\n" + stack());
                } catch (_) {}
                return code;
            };
            log("Hooked ApiException.getStatusCode");
        } catch (e) {
            log("ApiException hook unavailable: " + e);
        }

        const firebaseTargets = [
            ["com.google.firebase.FirebaseApp", "initializeApp"],
            ["com.google.firebase.appcheck.FirebaseAppCheck", "getInstance"],
            ["com.google.firebase.appcheck.FirebaseAppCheck", "getAppCheckToken"],
            ["com.google.firebase.appcheck.playintegrity.PlayIntegrityAppCheckProviderFactory", "getInstance"]
        ];

        firebaseTargets.forEach(function (item) {
            hookAll(item[0], item[1], function (_, ov) {
                return function () {
                    const args = Array.prototype.slice.call(arguments);
                    log(item[0] + "." + item[1] +
                        "(" + args.map(safeString).join(", ") + ")\n" + stack());
                    const ret = ov.apply(this, args);
                    try {
                        if (ret && ret.addOnFailureListener) {
                            attachTaskListeners(ret, item[0] + "." + item[1]);
                        }
                    } catch (_) {}
                    return ret;
                };
            });
        });

        try {
            const interesting = [];
            Java.enumerateLoadedClasses({
                onMatch: function (name) {
                    const low = name.toLowerCase();
                    if (low.indexOf("integrity") !== -1 ||
                        low.indexOf("appcheck") !== -1 ||
                        low.indexOf("playcore") !== -1) {
                        interesting.push(name);
                    }
                },
                onComplete: function () {
                    log("Loaded integrity/AppCheck-related classes (" + interesting.length + "):\n  " +
                        interesting.sort().join("\n  "));
                }
            });
        } catch (e) {
            error("class-scan", e);
        }

        log("Diagnostics hooks installed");
    });
}

function waitForJava() {
    if (typeof Java === "undefined") {
        log("Java bridge is not present in this script runtime. " +
            "If using Frida 17+ autonomous Gadget scripts, bundle frida-java-bridge " +
            "with frida-compile before deploying this module.");
        return;
    }

    try {
        if (Java.available) {
            installJavaHooks();
        } else {
            log("Java.available=false; retrying");
            setTimeout(waitForJava, 250);
        }
    } catch (e) {
        error("waitForJava", e);
        setTimeout(waitForJava, 500);
    }
}

log("30-play-integrity-diagnostics.js loaded");
waitForJava();
