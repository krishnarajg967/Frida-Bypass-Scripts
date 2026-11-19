/*
 * Android Emulator Detection Bypass - Frida script
 * Usage:
 *   frida -U -l emulator-bypass.js -f <package_name>
 *   (or attach: frida -U -l emulator-bypass.js -n <package_name>)
 *
 * Spoofs the common signals apps use to decide they are running on an
 * emulator: Build.* fields, system properties, telephony defaults, and
 * the tell-tale QEMU/Genymotion files. Tune the spoofed values near the
 * top to match a real device if an app fingerprints a specific model.
 */

'use strict';

// ---- Values we pretend to be (a plausible real device) ----
var FAKE_BUILD = {
    FINGERPRINT: 'google/redfin/redfin:13/TQ3A.230805.001/10316531:user/release-keys',
    MODEL:        'Pixel 5',
    MANUFACTURER: 'Google',
    BRAND:        'google',
    DEVICE:       'redfin',
    PRODUCT:      'redfin',
    BOARD:        'redfin',
    HARDWARE:     'redfin',
    HOST:         'abfarm-release',
    BOOTLOADER:   'r3-0.4-8351081',
    TAGS:         'release-keys',
    TYPE:         'user',
    USER:         'android-build'
};

// System properties that scream "emulator" if present/wrong.
var FAKE_PROPS = {
    'ro.kernel.qemu':            '0',
    'ro.hardware':               'redfin',
    'ro.product.model':          'Pixel 5',
    'ro.product.manufacturer':   'Google',
    'ro.product.brand':          'google',
    'ro.product.device':         'redfin',
    'ro.product.name':           'redfin',
    'ro.build.fingerprint':      FAKE_BUILD.FINGERPRINT,
    'ro.bootmode':               'unknown',
    'ro.secure':                 '1',
    'init.svc.qemud':            null,     // null => pretend it does not exist
    'init.svc.qemu-props':       null,
    'qemu.hw.mainkeys':          null,
    'qemu.sf.fake_camera':       null,
    'ro.kernel.android.qemud':   null,
    'init.svc.adbd':             null,     // hide the adb daemon
    'sys.usb.state':             'mtp',    // not 'adb' / 'mtp,adb'
    'ro.debuggable':             '0'
};

// File paths that only exist on emulators. We'll report them as missing.
var EMULATOR_FILES = [
    '/dev/socket/qemud',
    '/dev/qemu_pipe',
    '/system/lib/libc_malloc_debug_qemu.so',
    '/sys/qemu_trace',
    '/system/bin/qemu-props',
    '/dev/socket/genyd',
    '/dev/socket/baseband_genyd',
    '/system/bin/microvirtd',
    '/system/lib/vboxguest.ko',
    '/system/lib/vboxsf.ko',
    '/system/bin/androVM-vbox-sf',
    '/system/bin/nox-prop',
    '/system/bin/ldinit',
    '/system/bin/ldmountsvc',
    '/system/lib/libdroid4x.so',
    '/fstab.ttVM_x86',
    '/fstab.vbox86',
    '/init.ttVM_x86.rc',
    '/init.vbox86.rc',
    '/init.nox.rc',
    '/ueventd.android_x86.rc',
    '/ueventd.ttVM_x86.rc',
    '/ueventd.vbox86.rc',
    '/ueventd.nox.rc'
];

function log(msg) { console.log('[emu-bypass] ' + msg); }

Java.perform(function () {

    // ---- 1. Build.* static fields ----
    try {
        var Build = Java.use('android.os.Build');
        Object.keys(FAKE_BUILD).forEach(function (field) {
            try { Build[field].value = FAKE_BUILD[field]; }
            catch (e) { /* field may not exist on this API level */ }
        });
        log('Build.* fields spoofed');
    } catch (e) { log('Build hook failed: ' + e); }

    // ---- 2. System property getters (Java layer) ----
    try {
        var SystemProperties = Java.use('android.os.SystemProperties');

        var getS = SystemProperties.get.overload('java.lang.String');
        getS.implementation = function (key) {
            if (key in FAKE_PROPS) {
                var v = FAKE_PROPS[key];
                return v === null ? '' : v;
            }
            return getS.call(this, key);
        };

        var getSD = SystemProperties.get.overload('java.lang.String', 'java.lang.String');
        getSD.implementation = function (key, def) {
            if (key in FAKE_PROPS) {
                var v = FAKE_PROPS[key];
                return v === null ? def : v;
            }
            return getSD.call(this, key, def);
        };
        log('SystemProperties.get spoofed');
    } catch (e) { log('SystemProperties hook failed: ' + e); }

    // ---- 3. TelephonyManager defaults (emulators return canned values) ----
    try {
        var TM = Java.use('android.telephony.TelephonyManager');

        try {
            TM.getNetworkOperatorName.implementation = function () {
                var r = this.getNetworkOperatorName();
                return (r === 'Android' || r === null || r === '') ? 'Airtel' : r;
            };
        } catch (e) {}

        try {
            TM.getSimOperatorName.implementation = function () {
                var r = this.getSimOperatorName();
                return (r === 'Android' || r === null || r === '') ? 'Airtel' : r;
            };
        } catch (e) {}

        // getDeviceId / getImei often return all-zeros on emulators.
        ['getDeviceId', 'getImei', 'getSubscriberId', 'getSimSerialNumber', 'getLine1Number']
        .forEach(function (name) {
            if (TM[name]) {
                try {
                    TM[name].overloads.forEach(function (ov) {
                        ov.implementation = function () {
                            var r = ov.apply(this, arguments);
                            if (r === null || /^0+$/.test(String(r))) {
                                return '356938035643809'.slice(0, String(r || '356938035643809').length) || '356938035643809';
                            }
                            return r;
                        };
                    });
                } catch (e) {}
            }
        });
        log('TelephonyManager defaults spoofed');
    } catch (e) { log('TelephonyManager hook failed: ' + e); }

    // ---- 4. Emulator file-existence checks (java.io.File) ----
    try {
        var File = Java.use('java.io.File');

        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (EMULATOR_FILES.indexOf(path) !== -1) {
                log('hid file: ' + path);
                return false;
            }
            return this.exists();
        };
        log('File.exists spoofed');
    } catch (e) { log('File.exists hook failed: ' + e); }

    // ---- 4b. ADB / developer-settings checks (Settings.Global & Settings.Secure) ----
    // Apps read these keys to detect "ADB enabled" and USB debugging.
    var ADB_KEYS = {
        'adb_enabled': 0,
        'development_settings_enabled': 0,
        'adb_wifi_enabled': 0
    };

    ['android.provider.Settings$Global', 'android.provider.Settings$Secure',
     'android.provider.Settings$System'].forEach(function (clsName) {
        try {
            var cls = Java.use(clsName);
            // getInt(resolver, name) and getInt(resolver, name, def)
            if (cls.getInt) {
                cls.getInt.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        var key = arguments[1];
                        if (key in ADB_KEYS) {
                            log('forced ' + key + '=0 (' + clsName + ')');
                            return ADB_KEYS[key];
                        }
                        return ov.apply(this, arguments);
                    };
                });
            }
            // getString(resolver, name) — some apps read it as a string
            if (cls.getString) {
                cls.getString.overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        var key = arguments[1];
                        if (key in ADB_KEYS) { return '0'; }
                        return ov.apply(this, arguments);
                    };
                });
            }
            log(clsName + ' ADB keys spoofed');
        } catch (e) { log(clsName + ' hook failed: ' + e); }
    });

    // ---- 5. Native getprop via libc (catches checks that bypass the Java layer) ----
    try {
        var sysProp = Module.findExportByName(null, '__system_property_get');
        if (sysProp) {
            Interceptor.attach(sysProp, {
                onEnter: function (args) {
                    this.key = args[0].readCString();
                    this.buf = args[1];
                },
                onLeave: function (retval) {
                    if (this.key in FAKE_PROPS) {
                        var v = FAKE_PROPS[this.key];
                        v = (v === null) ? '' : v;
                        this.buf.writeUtf8String(v);
                        retval.replace(v.length);
                    }
                }
            });
            log('native __system_property_get spoofed');
        }
    } catch (e) { log('native prop hook failed: ' + e); }

    log('all hooks installed');
});
