'use strict';

const PACKAGE = 'com.nintendo.zaka';
const CHUNK_SIZE = 1024 * 1024;
const MAX_FILE_SIZE = 256 * 1024 * 1024;

let armed = false;
let nextDumpId = 1;
const fdPaths = new Map();
const seenPaths = new Set();
const dumpedPaths = new Set();

function safeReadCString(pointer) {
  if (pointer === null || pointer.isNull()) return null;
  try {
    return pointer.readUtf8String();
  } catch (_) {
    return null;
  }
}

function isMktPrivatePath(path) {
  if (path === null) return false;
  return path.includes(`/data/user/0/${PACKAGE}/`) ||
    path.includes(`/data/data/${PACKAGE}/`) ||
    path.includes(`/storage/emulated/0/Android/data/${PACKAGE}/`);
}

function isCandidate(path) {
  if (!isMktPrivatePath(path)) return false;
  const lower = path.toLowerCase();
  if (lower.includes('/shared_prefs/') ||
      lower.includes('/databases/') ||
      lower.includes('/code_cache/') ||
      lower.includes('/app_webview/') ||
      lower.endsWith('.so') ||
      lower.endsWith('.dex') ||
      lower.endsWith('.odex') ||
      lower.endsWith('.vdex') ||
      lower.endsWith('.prof') ||
      lower.endsWith('.lock')) return false;
  return true;
}

function reportPath(path, operation) {
  if (!armed || !isMktPrivatePath(path)) return;
  const key = `${operation}:${path}`;
  if (seenPaths.has(key)) return;
  seenPaths.add(key);
  send({ type: 'path', operation, path });
}

function dumpFile(path, reason) {
  if (!armed || !isCandidate(path) || dumpedPaths.has(path)) return;
  dumpedPaths.add(path);

  setImmediate(() => {
    const dumpId = nextDumpId++;
    let file = null;
    try {
      file = new File(path, 'rb');
      file.seek(0, File.SEEK_END);
      const size = Number(file.tell());
      file.seek(0, File.SEEK_SET);

      if (!Number.isFinite(size) || size < 0 || size > MAX_FILE_SIZE) {
        send({ type: 'file-skip', path, size, reason: `size-limit:${reason}` });
        file.close();
        return;
      }

      send({ type: 'file-start', id: dumpId, path, size, reason });
      let offset = 0;
      while (offset < size) {
        const wanted = Math.min(CHUNK_SIZE, size - offset);
        const bytes = file.readBytes(wanted);
        if (bytes.byteLength === 0) break;
        send({ type: 'file-chunk', id: dumpId, offset, length: bytes.byteLength }, bytes);
        offset += bytes.byteLength;
      }
      file.close();
      file = null;
      send({ type: 'file-end', id: dumpId, path, expected: size, written: offset });
    } catch (error) {
      try {
        if (file !== null) file.close();
      } catch (_) {}
      send({ type: 'file-error', id: dumpId, path, error: String(error) });
    }
  });
}

function hookOpen(name, pathIndex) {
  const address = Process.getModuleByName('libc.so').findExportByName(name);
  if (address === null) return;
  Interceptor.attach(address, {
    onEnter(args) {
      this.path = safeReadCString(args[pathIndex]);
      reportPath(this.path, name);
    },
    onLeave(result) {
      const fd = result.toInt32();
      if (fd >= 0 && this.path !== null && isMktPrivatePath(this.path)) {
        fdPaths.set(fd, this.path);
      }
    }
  });
}

function hookClose() {
  const address = Process.getModuleByName('libc.so').findExportByName('close');
  if (address === null) return;
  Interceptor.attach(address, {
    onEnter(args) {
      const fd = args[0].toInt32();
      this.path = fdPaths.get(fd) || null;
      if (this.path !== null) fdPaths.delete(fd);
    },
    onLeave(_) {
      if (this.path !== null) dumpFile(this.path, 'close');
    }
  });
}

function hookRename(name, oldIndex, newIndex) {
  const address = Process.getModuleByName('libc.so').findExportByName(name);
  if (address === null) return;
  Interceptor.attach(address, {
    onEnter(args) {
      this.oldPath = safeReadCString(args[oldIndex]);
      this.newPath = safeReadCString(args[newIndex]);
      reportPath(this.oldPath, `${name}:from`);
      reportPath(this.newPath, `${name}:to`);
    },
    onLeave(result) {
      if (result.toInt32() === 0 && this.newPath !== null) dumpFile(this.newPath, name);
    }
  });
}

hookOpen('open', 0);
hookOpen('open64', 0);
hookOpen('openat', 1);
hookOpen('openat64', 1);
hookClose();
hookRename('rename', 0, 1);
hookRename('renameat', 1, 3);

rpc.exports = {
  arm() {
    armed = true;
    seenPaths.clear();
    dumpedPaths.clear();
    send({ type: 'status', message: 'armed' });
    return true;
  },
  disarm() {
    armed = false;
    send({ type: 'status', message: 'disarmed' });
    return true;
  },
  dump(path) {
    dumpedPaths.delete(path);
    dumpFile(path, 'manual');
    return true;
  }
};

send({ type: 'status', message: 'course capture hooks installed' });
