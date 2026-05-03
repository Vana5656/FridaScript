// ==================== DEX DUMP & FIX SCRIPT v5.2 ====================
// Focus: dump DEX from packed APKs (DexProtector / Licel etc.) when the
// runtime is killed on Frida detection.
//
// Changes vs v5.1:
//   + Frida anti-detection module installed synchronously at load:
//        - filters lines from /proc/self/maps, /proc/self/status,
//          /proc/self/task/<tid>/{maps,status} containing frida-agent,
//          gum-js-loop, gmain, gdbus, gum-rt, linjector, libfridagadget
//        - rewrites pthread_getname_np / prctl(PR_GET_NAME) outputs
//          for known Frida thread names
//        - hides files like /data/local/tmp/re.frida.server,
//          /data/local/tmp/frida-server (access/stat/lstat -> ENOENT)
//        - ptrace(PTRACE_TRACEME) always returns 0
//        - all hooks installed BEFORE setImmediate so DexProtector init
//          sees a clean view from the very first check
//   + No banner/log spew before evasion is in place (DexProtector also
//     scans console output buffers in some builds)
//
// Earlier (v5/5.1) features kept:
//   + ClassLinker::DefineClass + multi DexFile loaders + mmap +
//     mprotect(PROT_EXEC) + madvise(MADV_DONTNEED/FREE/REMOVE) + dlopen
//   + Real DEX repair: shifted-magic search, file_size, Adler-32
//     checksum, SHA-1 signature
//   + Region content watcher for lazy-decrypted methods
// ===================================================================

'use strict';

// ---------- COLOR LOG ----------
const Color = { RESET: "\x1b[39;49;00m" };
function _log(input, c) {
    if (typeof input === 'object') input = JSON.stringify(input);
    console.log("\x1b[3" + c + "m" + input + Color.RESET);
}
const Blue   = s => _log(s, "4;01");
const Cyan   = s => _log(s, "6;01");
const Green  = s => _log(s, "2;01");
const Purple = s => _log(s, "5;01");
const Red    = s => _log(s, "1;01");
const Yellow = s => _log(s, "3;01");

// ---------- CONFIG ----------
const CFG = {
    MIN_DEX_SIZE:        0x70,                  // sizeof(DexFile::Header)
    MAX_DEX_SIZE:        256 * 1024 * 1024,
    SCAN_INTERVAL_MS:    15000,
    INITIAL_SCAN_DELAY:  2000,
    MAX_HEADER_SEARCH:   0x100000,              // 1 MiB shifted-DEX search window
    REGION_WATCH_HEAD:   4096,                  // bytes hashed for change detection
    OUTPUT_DIR:          null,                  // resolved at startup
    EVADE:               true                   // install Frida anti-detection
};

// ====================================================================
// ANTI-DETECTION (Frida hide) — must run synchronously, ASAP
// ====================================================================
// Substrings that should not appear in /proc/self/maps and similar
const FRIDA_PATH_NEEDLES = [
    "frida-agent", "frida-gadget", "libfridagadget",
    "gum-js-loop", "gum-rt", "linjector",
    "frida-helper", "re.frida"
];
// Thread name needles (rewritten to a benign name)
const FRIDA_THREAD_NEEDLES = [
    "gum-js-loop", "gmain", "gdbus", "pool-frida",
    "frida-agent", "linjector", "gum-rt"
];
// File paths whose existence we deny
const FRIDA_FILE_PATHS = [
    "/data/local/tmp/re.frida.server",
    "/data/local/tmp/frida-server",
    "/data/local/tmp/frida-agent",
    "/data/local/tmp/frida-gadget",
    "/system/bin/frida-server",
    "/system/xbin/frida-server"
];
// FDs we know point at /proc/self/maps and similar (need read() filtering)
const procFdSet = new Set();

function strContainsAnyLower(s, list) {
    const lower = s.toLowerCase();
    for (let i = 0; i < list.length; i++) {
        if (lower.indexOf(list[i]) !== -1) return true;
    }
    return false;
}

// Filter the buffer that was just filled by read(fd, buf, n).
// Replaces bytes inside lines containing FRIDA_PATH_NEEDLES with spaces,
// keeps newlines so line-based parsers still see the same line count.
function filterMapsBuffer(bufPtr, bytesRead) {
    if (bytesRead <= 0) return;
    let raw;
    try { raw = bufPtr.readByteArray(bytesRead); }
    catch (_) { return; }
    const u8 = new Uint8Array(raw);
    let lineStart = 0;
    let mutated = false;
    for (let i = 0; i <= bytesRead; i++) {
        if (i === bytesRead || u8[i] === 0x0A) {
            const lineLen = i - lineStart;
            if (lineLen > 0) {
                let lineStr = "";
                for (let j = lineStart; j < i; j++) lineStr += String.fromCharCode(u8[j]);
                if (strContainsAnyLower(lineStr, FRIDA_PATH_NEEDLES)) {
                    for (let j = lineStart; j < i; j++) u8[j] = 0x20; // space
                    mutated = true;
                }
            }
            lineStart = i + 1;
        }
    }
    if (mutated) {
        try { bufPtr.writeByteArray(u8.buffer); } catch (_) {}
    }
}

function isProcPathSensitive(path) {
    if (!path) return false;
    // /proc/self/maps, /proc/self/status, /proc/self/task/<tid>/maps, /proc/<pid>/maps, ...
    if (path.indexOf("/proc/") !== 0) return false;
    return path.indexOf("/maps") !== -1
        || path.indexOf("/status") !== -1
        || path.indexOf("/smaps") !== -1
        || path.indexOf("/cmdline") !== -1;
}

let evadeStats = { tried: 0, ok: 0, names: [] };

function installFridaEvade() {
    if (!CFG.EVADE) return;

    const libc = (() => {
        try { return Process.findModuleByName("libc.so") || Process.findModuleByName("libc.bionic"); }
        catch (_) { return null; }
    })();
    if (!libc) return;

    function exp(name) {
        try { return Module.findExportByName("libc.so", name) || Module.findExportByName(null, name); }
        catch (_) { return null; }
    }
    function safeAttach(label, ptr_, cbs) {
        if (!ptr_) return false;
        evadeStats.tried++;
        try {
            Interceptor.attach(ptr_, cbs);
            evadeStats.ok++;
            evadeStats.names.push(label);
            return true;
        } catch (_) { return false; }
    }

    // ---- open / openat: track sensitive FDs ----
    safeAttach("open", exp("open"), {
        onEnter(args) {
            try { this.path = args[0].readCString(); } catch (_) { this.path = null; }
        },
        onLeave(retval) {
            const fd = retval.toInt32();
            if (fd >= 0 && this.path && isProcPathSensitive(this.path)) {
                procFdSet.add(fd);
            }
        }
    });
    safeAttach("openat", exp("openat"), {
        onEnter(args) {
            try { this.path = args[1].readCString(); } catch (_) { this.path = null; }
        },
        onLeave(retval) {
            const fd = retval.toInt32();
            if (fd >= 0 && this.path && isProcPathSensitive(this.path)) {
                procFdSet.add(fd);
            }
        }
    });

    // ---- read / pread: filter buffers when fd is sensitive ----
    safeAttach("read", exp("read"), {
        onEnter(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
        },
        onLeave(retval) {
            if (!procFdSet.has(this.fd)) return;
            const n = retval.toInt32();
            if (n > 0) filterMapsBuffer(this.buf, n);
        }
    });
    safeAttach("pread", exp("pread") || exp("pread64"), {
        onEnter(args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
        },
        onLeave(retval) {
            if (!procFdSet.has(this.fd)) return;
            const n = retval.toInt32();
            if (n > 0) filterMapsBuffer(this.buf, n);
        }
    });

    // ---- close: drop tracked FDs ----
    safeAttach("close", exp("close"), {
        onEnter(args) {
            const fd = args[0].toInt32();
            if (procFdSet.has(fd)) procFdSet.delete(fd);
        }
    });

    // ---- fopen / fopen64: filter via stdio path too. We can't easily
    //      read FILE* internals, so we wrap fgets / getline / fread to
    //      detect when these were used. But the simplest reliable trick:
    //      if path is /proc/self/maps-like, redirect to a pre-filtered
    //      tmpfile. To keep this lightweight we just hook fgets/getline
    //      and post-filter. ----
    safeAttach("fgets", exp("fgets"), {
        onEnter(args) {
            this.buf = args[0];
        },
        onLeave(retval) {
            if (retval.isNull() || !this.buf) return;
            let line;
            try { line = this.buf.readCString(); } catch (_) { return; }
            if (line && strContainsAnyLower(line, FRIDA_PATH_NEEDLES)) {
                try { this.buf.writeUtf8String("\n"); } catch (_) {}
            }
        }
    });
    safeAttach("getline", exp("getline"), {
        onEnter(args) {
            this.lineptrPtr = args[0];
        },
        onLeave(retval) {
            if (retval.toInt32() <= 0) return;
            try {
                const linePtr = this.lineptrPtr.readPointer();
                if (linePtr.isNull()) return;
                const line = linePtr.readCString();
                if (line && strContainsAnyLower(line, FRIDA_PATH_NEEDLES)) {
                    linePtr.writeUtf8String("\n");
                }
            } catch (_) {}
        }
    });

    // ---- access / faccessat / stat / lstat / __xstat / __lxstat: hide files ----
    function isFridaFile(p) {
        if (!p) return false;
        for (let i = 0; i < FRIDA_FILE_PATHS.length; i++) {
            if (p === FRIDA_FILE_PATHS[i] || p.indexOf(FRIDA_FILE_PATHS[i]) === 0) return true;
        }
        // Also hide any /data/local/tmp/frida* and /data/local/tmp/re.frida*
        if (p.indexOf("/data/local/tmp/frida") === 0) return true;
        if (p.indexOf("/data/local/tmp/re.frida") === 0) return true;
        return false;
    }
    function denyHook(name, pathArgIndex) {
        safeAttach(name, exp(name), {
            onEnter(args) {
                let path = null;
                try { path = args[pathArgIndex].readCString(); } catch (_) {}
                this.deny = isFridaFile(path);
            },
            onLeave(retval) {
                if (this.deny) retval.replace(ptr(-1));
            }
        });
    }
    denyHook("access",   0);
    denyHook("faccessat",1);
    denyHook("stat",     0);
    denyHook("lstat",    0);
    denyHook("__xstat",  1);
    denyHook("__lxstat", 1);
    denyHook("stat64",   0);
    denyHook("lstat64",  0);

    // ---- pthread_getname_np: rewrite Frida thread names ----
    safeAttach("pthread_getname_np", exp("pthread_getname_np"), {
        onEnter(args) { this.buf = args[1]; },
        onLeave(retval) {
            if (retval.toInt32() !== 0 || !this.buf) return;
            try {
                const name = this.buf.readCString();
                if (name && strContainsAnyLower(name, FRIDA_THREAD_NEEDLES)) {
                    this.buf.writeUtf8String("Binder:0_0");
                }
            } catch (_) {}
        }
    });

    // ---- prctl(PR_GET_NAME=16, name): rewrite ----
    safeAttach("prctl", exp("prctl"), {
        onEnter(args) {
            this.op = args[0].toInt32();
            this.namePtr = args[1];
        },
        onLeave(retval) {
            if (this.op !== 16 /* PR_GET_NAME */ || retval.toInt32() !== 0) return;
            try {
                const name = this.namePtr.readCString();
                if (name && strContainsAnyLower(name, FRIDA_THREAD_NEEDLES)) {
                    this.namePtr.writeUtf8String("Binder:0_0");
                }
            } catch (_) {}
        }
    });

    // ---- ptrace: PTRACE_TRACEME (req=0) always succeeds ----
    safeAttach("ptrace", exp("ptrace"), {
        onEnter(args) { this.req = args[0].toInt32(); },
        onLeave(retval) {
            if (this.req === 0 /* PTRACE_TRACEME */) {
                retval.replace(ptr(0));
            }
        }
    });
}

// Install evasion synchronously, before anything else.
try { installFridaEvade(); } catch (_) {}

// ---------- STATE ----------
const seenAddr        = new Set();              // addresses processed at least once
const seenContentSha1 = new Set();              // sha1 hex of dumped buffers
const regionWatch     = new Map();              // addrStr -> { sizeHash, fullSize, source, lastDumpedSha }
const startMs         = Date.now();

let processName = "unknown_app";
let dexCounter  = 0;
let totalBytesDumped = 0;
let totalDumpsThisInterval = 0;

// ====================================================================
// Process name — read /proc/self/cmdline
// ====================================================================
function readProcessName() {
    try {
        const open  = new NativeFunction(Module.getExportByName('libc.so', 'open'),  'int', ['pointer','int']);
        const read_ = new NativeFunction(Module.getExportByName('libc.so', 'read'),  'int', ['int','pointer','int']);
        const close = new NativeFunction(Module.getExportByName('libc.so', 'close'), 'int', ['int']);
        const path = Memory.allocUtf8String('/proc/self/cmdline');
        const fd = open(path, 0);
        if (fd < 0) return "unknown_app";
        const buf = Memory.alloc(0x1000);
        read_(fd, buf, 0x1000);
        close(fd);
        const name = buf.readCString();
        return (name && name.length) ? name : "unknown_app";
    } catch (_) { return "unknown_app"; }
}

// ====================================================================
// /proc/self/maps cache for clamping reads
// ====================================================================
let readableRanges = [];
function refreshReadableRanges() {
    readableRanges = Process.enumerateRanges('r--').map(r => ({
        base: r.base, end: r.base.add(r.size), size: r.size
    }));
}
function clampToReadable(addr, size) {
    for (let i = 0; i < readableRanges.length; i++) {
        const r = readableRanges[i];
        if (addr.compare(r.base) >= 0 && addr.compare(r.end) < 0) {
            const remaining = r.end.sub(addr).toUInt32();
            return Math.min(size, remaining);
        }
    }
    return 0;
}

// ====================================================================
// Hashes
// ====================================================================
function adler32(u8, off, len) {
    const MOD = 65521;
    let a = 1, b = 0;
    for (let i = 0; i < len; i++) {
        a = (a + u8[off + i]) % MOD;
        b = (b + a)            % MOD;
    }
    return ((b * 0x10000) + a) >>> 0;
}
function sha1Bytes(u8, off, len) {
    function rol(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
    const ml = len * 8;
    const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
    padded.set(u8.subarray(off, off + len), 0);
    padded[len] = 0x80;
    const dv = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
    dv.setUint32(padded.length - 8, Math.floor(ml / 0x100000000), false);
    dv.setUint32(padded.length - 4, ml >>> 0, false);
    let h0=0x67452301, h1=0xEFCDAB89, h2=0x98BADCFE, h3=0x10325476, h4=0xC3D2E1F0;
    const w = new Uint32Array(80);
    for (let i = 0; i < padded.length; i += 64) {
        for (let j = 0; j < 16; j++) w[j] = dv.getUint32(i + j*4, false);
        for (let j = 16; j < 80; j++) w[j] = rol(w[j-3]^w[j-8]^w[j-14]^w[j-16], 1);
        let a=h0, b=h1, c=h2, d=h3, e=h4;
        for (let j = 0; j < 80; j++) {
            let f, k;
            if (j < 20)      { f = (b & c) | ((~b) & d);        k = 0x5A827999; }
            else if (j < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
            else if (j < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
            else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
            const t = (rol(a,5) + f + e + k + w[j]) >>> 0;
            e = d; d = c; c = rol(b, 30); b = a; a = t;
        }
        h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0; h4=(h4+e)>>>0;
    }
    const out = new Uint8Array(20);
    const ov = new DataView(out.buffer);
    ov.setUint32(0,  h0, false); ov.setUint32(4,  h1, false);
    ov.setUint32(8,  h2, false); ov.setUint32(12, h3, false);
    ov.setUint32(16, h4, false);
    return out;
}
function sha1Hex(u8, off, len) {
    const d = sha1Bytes(u8, off, len);
    let s = "";
    for (let i = 0; i < d.length; i++) s += (d[i] < 16 ? "0" : "") + d[i].toString(16);
    return s;
}

// ====================================================================
// DEX header utilities
// ====================================================================
const DEX_VERSIONS = ["035","036","037","038","039","040"];
function isDexMagic(u8, o) {
    if (o + 8 > u8.length) return false;
    return u8[o]===0x64 && u8[o+1]===0x65 && u8[o+2]===0x78 && u8[o+3]===0x0A
        && DEX_VERSIONS.indexOf(String.fromCharCode(u8[o+4],u8[o+5],u8[o+6])) !== -1
        && u8[o+7]===0x00;
}
function isCdexMagic(u8, o) {
    if (o + 4 > u8.length) return false;
    return u8[o]===0x63 && u8[o+1]===0x64 && u8[o+2]===0x65 && u8[o+3]===0x78;
}
function writeU32LE(u8, o, v) {
    u8[o]   = v & 0xFF;
    u8[o+1] = (v >>> 8)  & 0xFF;
    u8[o+2] = (v >>> 16) & 0xFF;
    u8[o+3] = (v >>> 24) & 0xFF;
}
function searchShiftedDexMagic(u8) {
    const limit = Math.min(u8.length - 8, CFG.MAX_HEADER_SEARCH);
    for (let off = 4; off < limit; off += 4) {
        if (isDexMagic(u8, off)) return off;
    }
    return -1;
}

// Build a clean DEX with valid file_size/checksum/signature.
function finalizeDex(arrayBuffer, kind, extra) {
    const u8 = new Uint8Array(arrayBuffer);
    if (u8.length < CFG.MIN_DEX_SIZE) {
        return { ok: false, kind: "broken", note: "post-slice too small" };
    }
    writeU32LE(u8, 0x20, u8.length);                         // file_size
    const sig = sha1Bytes(u8, 0x20, u8.length - 0x20);       // signature
    u8.set(sig, 0x0C);
    const adler = adler32(u8, 0x0C, u8.length - 0x0C);       // checksum
    writeU32LE(u8, 0x08, adler);
    return Object.assign({ ok: true, buffer: u8.buffer, kind: kind }, extra || {});
}

function repairDex(rawBuffer) {
    const u8 = new Uint8Array(rawBuffer);
    if (u8.length < CFG.MIN_DEX_SIZE) return { ok: false, kind: "broken", note: "too small" };

    if (isDexMagic(u8, 0))  return finalizeDex(u8.buffer, "dex");
    if (isCdexMagic(u8, 0)) return { ok: true, buffer: rawBuffer, kind: "cdex",
                                      note: "leave for offline conversion" };

    // Shifted DEX (DexProtector zero-header pattern)
    const off = searchShiftedDexMagic(u8);
    if (off > 0) {
        if (u8.length - off < CFG.MIN_DEX_SIZE) {
            return { ok: false, kind: "broken", note: "shifted region too small" };
        }
        const sliced = new Uint8Array(u8.buffer.slice(off));
        return finalizeDex(sliced.buffer, "shifted-dex", { offset: off });
    }

    // 'dex' but corrupted '\n' or version
    if (u8[0]===0x64 && u8[1]===0x65 && u8[2]===0x78 && u8[3]!==0x0A) {
        const copy = new Uint8Array(u8);
        copy[3] = 0x0A;
        if (DEX_VERSIONS.indexOf(String.fromCharCode(copy[4],copy[5],copy[6])) === -1) {
            copy[4]=0x30; copy[5]=0x33; copy[6]=0x35; copy[7]=0x00;
        }
        return finalizeDex(copy.buffer, "patched-magic");
    }

    return { ok: false, kind: "broken", note: "no DEX magic anywhere" };
}

// ====================================================================
// Read clamped to readable extent
// ====================================================================
function safeRead(base, size) {
    if (size < CFG.MIN_DEX_SIZE || size > CFG.MAX_DEX_SIZE) return null;
    if (readableRanges.length === 0) refreshReadableRanges();
    let usable = clampToReadable(base, size);
    if (usable < CFG.MIN_DEX_SIZE) {
        refreshReadableRanges();
        usable = clampToReadable(base, size);
        if (usable < CFG.MIN_DEX_SIZE) return null;
    }
    try { return base.readByteArray(usable); }
    catch (_) { return null; }
}

// ====================================================================
// Main dump entry. `kind` is just the source label (DefineClass/mmap/...).
// Returns true if anything was written.
// ====================================================================
function dumpBuffer(base, size, source, opts) {
    opts = opts || {};
    const baseStr = base.toString();
    const isReDump = !!opts.allowReDump;

    if (!isReDump && seenAddr.has(baseStr)) return false;
    seenAddr.add(baseStr);

    const raw = safeRead(base, size);
    if (!raw) return false;

    const result = repairDex(raw);
    if (!result.ok) {
        // Not a DEX (yet) — if the caller insists, save raw blob for offline analysis.
        if (opts.saveRawIfBroken) {
            const u8 = new Uint8Array(raw);
            const id = sha1Hex(u8, 0, Math.min(u8.length, 4096)).slice(0, 12);
            if (!seenContentSha1.has(id)) {
                seenContentSha1.add(id);
                const path = `${CFG.OUTPUT_DIR}/raw_${source}_${stamp()}_${id}.bin`;
                try {
                    const f = new File(path, "wb"); f.write(raw); f.flush(); f.close();
                    Yellow(`[~] Raw blob: ${path} (${result.note})`);
                } catch (e) { Red(`[!] Write failed: ${e}`); }
            }
        }
        return false;
    }

    const fixedU8 = new Uint8Array(result.buffer);
    const hash = sha1Hex(fixedU8, 0, fixedU8.length);
    if (seenContentSha1.has(hash)) return false;
    seenContentSha1.add(hash);

    dexCounter += 1;
    totalDumpsThisInterval += 1;
    totalBytesDumped += fixedU8.length;

    const tag = result.kind === "cdex" ? "cdex" : "dex";
    const idx = String(dexCounter).padStart(3, "0");
    const path = `${CFG.OUTPUT_DIR}/classes_${idx}_${source}_${stamp()}_${hash.slice(0,12)}.${tag}`;

    try {
        const f = new File(path, "wb");
        f.write(result.buffer);
        f.flush(); f.close();
    } catch (e) {
        Red(`[!] Write failed: ${path}: ${e}`);
        return false;
    }

    // Update region watcher so we can detect future content changes (lazy decrypt).
    try {
        const watchU8 = new Uint8Array(raw, 0, Math.min(CFG.REGION_WATCH_HEAD, raw.byteLength));
        regionWatch.set(baseStr, {
            base: base,
            fullSize: size,
            sizeHash: sha1Hex(watchU8, 0, watchU8.length),
            source: source,
            lastDumpedSha: hash
        });
    } catch (_) {}

    const sizeKb = (fixedU8.length / 1024).toFixed(1);
    if (result.kind === "shifted-dex") {
        Purple(`[+] DEX (shifted +0x${result.offset.toString(16)}): ${path} (${sizeKb} KB)`);
    } else if (result.kind === "cdex") {
        Yellow(`[+] CDEX: ${path} (${sizeKb} KB) — convert with vdex_extractor`);
    } else if (result.kind === "patched-magic") {
        Yellow(`[+] DEX (magic patched): ${path} (${sizeKb} KB)`);
    } else if (isReDump) {
        Cyan  (`[+] DEX re-dump (lazy decrypt detected): ${path} (${sizeKb} KB)`);
    } else {
        Green (`[+] DEX: ${path} (${sizeKb} KB)`);
    }
    return true;
}

function stamp() {
    const sec = Math.floor((Date.now() - startMs) / 1000);
    return "t" + String(sec).padStart(4, "0");
}

// ====================================================================
// Hook: art::ClassLinker::DefineClass
// Probe DexFile struct layout (varies across Android versions).
// ====================================================================
function hookDefineClass() {
    const libart = Process.findModuleByName("libart.so");
    if (!libart) { Red("[!] libart.so not found"); return; }

    let target = null;
    let targetName = null;
    libart.enumerateSymbols().some(sym => {
        if (sym.name.indexOf("ClassLinker") >= 0 &&
            sym.name.indexOf("DefineClass") >= 0 &&
            sym.name.indexOf("Thread") >= 0) {
            target = sym.address; targetName = sym.name;
            return true;
        }
        return false;
    });
    if (!target) { Red("[!] DefineClass symbol not found"); return; }

    const PS = Process.pointerSize;
    const offsetCandidates = [PS, PS * 2, 0x08, 0x10, 0x18];

    Interceptor.attach(target, {
        onEnter(args) {
            try {
                const dexFile = args[5];
                if (dexFile.isNull()) return;
                for (let i = 0; i < offsetCandidates.length; i++) {
                    const baseOff = offsetCandidates[i];
                    let beginPtr;
                    try { beginPtr = dexFile.add(baseOff).readPointer(); } catch (_) { continue; }
                    if (beginPtr.isNull()) continue;
                    let firstByte;
                    try { firstByte = beginPtr.readU8(); } catch (_) { continue; }
                    if (firstByte !== 0x64 /* 'd' */ && firstByte !== 0x63 /* 'c' for cdex */) continue;
                    let size;
                    try {
                        size = (PS === 8)
                            ? dexFile.add(baseOff + PS).readU64().toNumber()
                            : dexFile.add(baseOff + PS).readU32();
                    } catch (_) { continue; }
                    if (size < CFG.MIN_DEX_SIZE || size > CFG.MAX_DEX_SIZE) continue;
                    dumpBuffer(beginPtr, size, "DefineClass");
                    return;
                }
            } catch (_) { /* swallow */ }
        }
    });
    Cyan(`[+] Hook: ${targetName}`);
}

// ====================================================================
// Hook: many DexFile loaders inside libart
// (OpenCommon / OpenMemory / OpenAndReadMagic / DexFileLoader::Open)
// ====================================================================
function hookDexFileLoaders() {
    const libart = Process.findModuleByName("libart.so");
    if (!libart) return;

    const PS = Process.pointerSize;
    const NEEDLES = [
        ["DexFile", "OpenCommon"],
        ["DexFile", "OpenMemory"],
        ["DexFile", "OpenAndReadMagic"],
        ["DexFileLoader", "Open"],
        ["ArtDexFileLoader", "Open"]
    ];
    const installed = new Set();
    libart.enumerateSymbols().forEach(sym => {
        const n = sym.name;
        for (const [a, b] of NEEDLES) {
            if (n.indexOf(a) >= 0 && n.indexOf(b) >= 0 && !installed.has(n)) {
                installed.add(n);
                Interceptor.attach(sym.address, {
                    onEnter(args) {
                        try {
                            // Heuristic: arg[0]=base ptr, arg[1]=size (size_t)
                            const base = args[0];
                            if (!base || base.isNull()) return;
                            let firstByte;
                            try { firstByte = base.readU8(); } catch (_) { return; }
                            if (firstByte !== 0x64 && firstByte !== 0x63) return;
                            const size = (PS === 8) ? args[1].toUInt32() : args[1].toUInt32();
                            if (size < CFG.MIN_DEX_SIZE || size > CFG.MAX_DEX_SIZE) return;
                            dumpBuffer(base, size, "DexLoader");
                        } catch (_) {}
                    }
                });
                Cyan(`[+] Hook: ${n}`);
                break;
            }
        }
    });
}

// ====================================================================
// Hook: mmap / mmap64 — if newly-mapped page starts with DEX magic.
// ====================================================================
function hookMmap() {
    let attached = 0;
    ['mmap', 'mmap64'].forEach(name => {
        const ptr_ = Module.findExportByName(null, name);
        if (!ptr_) return;
        Interceptor.attach(ptr_, {
            onEnter(args) {
                this.size = args[1].toUInt32();
            },
            onLeave(retval) {
                if (retval.isNull()) return;
                const sz = this.size;          // capture before async dispatch
                if (sz < CFG.MIN_DEX_SIZE || sz > CFG.MAX_DEX_SIZE) return;
                const base = retval;
                setTimeout(() => {
                    try {
                        if (seenAddr.has(base.toString())) return;
                        const head = new Uint8Array(base.readByteArray(8));
                        if (isDexMagic(head, 0) || isCdexMagic(head, 0)) {
                            dumpBuffer(base, sz, "mmap");
                        }
                    } catch (_) {}
                }, 50);
            }
        });
        Cyan(`[+] Hook: ${name}`);
        attached++;
    });
    if (!attached) Red("[!] mmap/mmap64 not found");
}

// ====================================================================
// Hook: mprotect / mprotect64 — when a region transitions to PROT_EXEC
// it usually means freshly-decrypted code. Try to dump it.
// PROT_EXEC = 0x4. We wait briefly so the runtime finishes preparing.
// ====================================================================
const PROT_EXEC = 0x4;
function hookMprotect() {
    let attached = 0;
    ['mprotect', '__mprotect'].forEach(name => {
        const ptr_ = Module.findExportByName(null, name);
        if (!ptr_) return;
        Interceptor.attach(ptr_, {
            onEnter(args) {
                this.base = args[0];
                this.size = args[1].toUInt32();
                this.prot = args[2].toInt32();
            },
            onLeave(retval) {
                if (retval.toInt32() !== 0) return;
                if ((this.prot & PROT_EXEC) === 0) return;
                const base = this.base;
                const sz = this.size;
                if (sz < CFG.MIN_DEX_SIZE || sz > CFG.MAX_DEX_SIZE) return;
                setTimeout(() => {
                    try {
                        const head = new Uint8Array(base.readByteArray(8));
                        if (isDexMagic(head, 0) || isCdexMagic(head, 0)) {
                            // Allow re-dump even if we've seen this base — content
                            // likely changed (decryption window).
                            dumpBuffer(base, sz, "mprotect_x", { allowReDump: true });
                        }
                    } catch (_) {}
                }, 30);
            }
        });
        Cyan(`[+] Hook: ${name}`);
        attached++;
    });
    if (!attached) Yellow("[~] mprotect not found (skipping)");
}

// ====================================================================
// Hook: madvise — packers often call MADV_DONTNEED/MADV_FREE/MADV_REMOVE
// to wipe decrypted regions. Dump BEFORE the wipe goes through.
// ====================================================================
const MADV_DONTNEED = 4;
const MADV_FREE     = 8;
const MADV_REMOVE   = 9;
function hookMadvise() {
    const ptr_ = Module.findExportByName(null, 'madvise');
    if (!ptr_) { Yellow("[~] madvise not found (skipping)"); return; }
    Interceptor.attach(ptr_, {
        onEnter(args) {
            try {
                const advice = args[2].toInt32();
                if (advice !== MADV_DONTNEED && advice !== MADV_FREE && advice !== MADV_REMOVE) return;
                const base = args[0];
                const sz = args[1].toUInt32();
                if (sz < CFG.MIN_DEX_SIZE || sz > CFG.MAX_DEX_SIZE) return;
                const head = new Uint8Array(base.readByteArray(8));
                if (isDexMagic(head, 0) || isCdexMagic(head, 0)) {
                    Yellow(`[!] madvise(${advice}) about to wipe ${sz} bytes @ ${base} — dumping NOW`);
                    dumpBuffer(base, sz, "madv_rescue", { allowReDump: true });
                } else if (regionWatch.has(base.toString())) {
                    // Was a known DEX region (now possibly mid-wipe) — try anyway
                    const w = regionWatch.get(base.toString());
                    dumpBuffer(base, w.fullSize, "madv_rescue", { allowReDump: true });
                }
            } catch (_) {}
        }
    });
    Cyan("[+] Hook: madvise");
}

// ====================================================================
// Periodic re-scan:
//   1) Walk known DEX regions, re-hash first REGION_WATCH_HEAD bytes,
//      re-dump if the head changed (lazy decrypt landed bytes there).
//   2) Walk readable ranges, dump any new DEX magics.
// ====================================================================
function rescanAndCheckRegions() {
    let dumped = 0;
    refreshReadableRanges();

    // 1) Watched regions: did any change?
    regionWatch.forEach((info, addrStr) => {
        try {
            const head = new Uint8Array(info.base.readByteArray(
                Math.min(CFG.REGION_WATCH_HEAD, info.fullSize)));
            const headHash = sha1Hex(head, 0, head.length);
            if (headHash === info.sizeHash) return;
            // Content changed → re-dump full region
            const before = totalDumpsThisInterval;
            dumpBuffer(info.base, info.fullSize, info.source + "+rescan",
                { allowReDump: true });
            if (totalDumpsThisInterval > before) dumped++;
            // Update head hash either way
            info.sizeHash = headHash;
        } catch (_) {}
    });

    // 2) New regions
    Process.enumerateRanges('r--').forEach(r => {
        if (r.size < CFG.MIN_DEX_SIZE || r.size > CFG.MAX_DEX_SIZE) return;
        if (seenAddr.has(r.base.toString())) return;
        try {
            const head = new Uint8Array(r.base.readByteArray(8));
            if (isDexMagic(head, 0) || isCdexMagic(head, 0)) {
                if (dumpBuffer(r.base, r.size, "scan")) dumped++;
            }
        } catch (_) {}
    });

    return dumped;
}

// ====================================================================
// Hook: do_dlopen — re-scan after packer libs land in memory
// ====================================================================
function hookDlopen() {
    const linkerName = Process.pointerSize === 8 ? "linker64" : "linker";
    const linker = Process.findModuleByName(linkerName);
    if (!linker) return;
    const sym = linker.enumerateSymbols().find(s => s.name.indexOf("do_dlopen") >= 0);
    if (!sym) return;
    Interceptor.attach(sym.address, {
        onEnter(args) {
            try {
                const lib = args[0].readUtf8String();
                if (!lib) return;
                const lower = lib.toLowerCase();
                if (lower.indexOf("dexprotector") >= 0 ||
                    lower.indexOf("licel") >= 0 ||
                    /\/lib(dp|protector|virtualization)[^/]*\.so$/.test(lower)) {
                    Yellow(`[*] Packer lib loaded: ${lib} — rescheduling scan`);
                    setTimeout(() => {
                        const n = rescanAndCheckRegions();
                        if (n) Green(`[+] Post-load scan picked up ${n} new/changed DEX(es)`);
                    }, 1000);
                    setTimeout(() => {
                        const n = rescanAndCheckRegions();
                        if (n) Green(`[+] Post-load scan +5s picked up ${n} new/changed DEX(es)`);
                    }, 5000);
                }
            } catch (_) {}
        }
    });
    Cyan(`[+] Hook: ${sym.name}`);
}

// ====================================================================
// Bootstrap
// ====================================================================
setImmediate(() => {
    processName = readProcessName();
    CFG.OUTPUT_DIR = `/data/data/${processName}`;

    console.log("\n" + "=".repeat(64));
    Cyan(`DEX DUMP & FIX SCRIPT v5.2`);
    Cyan(`App:  ${processName}`);
    Cyan(`Arch: ${Process.arch}   PID: ${Process.id}   PtrSize: ${Process.pointerSize}`);
    Cyan(`Out:  ${CFG.OUTPUT_DIR}`);
    if (CFG.EVADE) {
        Cyan(`Evade: ${evadeStats.ok}/${evadeStats.tried} hooks (${evadeStats.names.join(",")})`);
    }
    console.log("=".repeat(64) + "\n");

    Blue("[*] Installing hooks…");
    try { hookDefineClass();    } catch (e) { Red(`hookDefineClass: ${e}`); }
    try { hookDexFileLoaders(); } catch (e) { Red(`hookDexFileLoaders: ${e}`); }
    try { hookMmap();           } catch (e) { Red(`hookMmap: ${e}`); }
    try { hookMprotect();       } catch (e) { Red(`hookMprotect: ${e}`); }
    try { hookMadvise();        } catch (e) { Red(`hookMadvise: ${e}`); }
    try { hookDlopen();         } catch (e) { Red(`hookDlopen: ${e}`); }

    setTimeout(() => {
        const n = rescanAndCheckRegions();
        if (n) Green(`[+] Initial scan: ${n} DEX(es) dumped`);
    }, CFG.INITIAL_SCAN_DELAY);

    setInterval(() => {
        totalDumpsThisInterval = 0;
        const n = rescanAndCheckRegions();
        if (n) Green(`[+] Periodic scan: ${n} new/changed DEX(es)  ` +
                     `(total ${dexCounter}, ${(totalBytesDumped/1024/1024).toFixed(1)} MB)`);
    }, CFG.SCAN_INTERVAL_MS);

    Yellow("\n[i] Active. Exercise app flows now to trigger lazy DEX decryption.");
    Yellow("[i] DEX dumps land in: " + CFG.OUTPUT_DIR + "/classes_*.dex");
    Yellow("[i] To stop and view summary, send Ctrl+C in your frida CLI.\n");
});
