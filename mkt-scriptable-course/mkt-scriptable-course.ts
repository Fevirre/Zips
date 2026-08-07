import "frida-il2cpp-bridge";

let armed = false;
let scanning = false;
const dumped = new Set<string>();
const MAX_DEPTH = 12;
const MAX_ARRAY = 50000;
const MAX_NODES = 50000;
const LAP_PATTERN = /(lap|round|race(rule|mode|setting|progress|director)?|goal|finish|checkpoint|section)/i;
const lapSnapshots = new Map<string, string>();
let lapCatalogSent = false;

function classDescription(klass: Il2Cpp.Class) {
  const hierarchy: Array<{ name: string; fields: Array<{ name: string; type: string; offset: number }> }> = [];
  for (const current of klass.hierarchy({ includeCurrent: true })) {
    hierarchy.push({
      name: current.fullName,
      fields: current.fields
        .filter(field => !field.isStatic)
        .map(field => ({ name: field.name, type: field.type.name, offset: field.offset }))
    });
  }
  return hierarchy;
}

function reflectObject(root: Il2Cpp.Object): unknown {
  const seen = new Set<string>();
  let nodes = 0;

  function visit(value: any, depth: number): any {
    nodes++;
    if (nodes > MAX_NODES) return "<node-limit>";
    if (value === null || value === undefined) return null;
    if (typeof value === "boolean" || typeof value === "number" || typeof value === "string") return value;
    if (value instanceof Int64 || value instanceof UInt64) return value.toString();
    if (value instanceof NativePointer) return value.toString();
    if (depth > MAX_DEPTH) return "<depth-limit>";

    if (value instanceof Il2Cpp.String) return value.content;

    if (value instanceof Il2Cpp.Array) {
      if (value.isNull()) return null;
      const length = Math.min(value.length, MAX_ARRAY);
      const items = [];
      for (let i = 0; i < length; i++) items.push(visit(value.get(i), depth + 1));
      if (value.length > length) items.push(`<${value.length - length} more elements>`);
      return items;
    }

    if (value instanceof Il2Cpp.ValueType) {
      const result: Record<string, unknown> = { "$type": value.type.name };
      for (const field of value.type.class.fields) {
        if (field.isStatic) continue;
        try {
          result[field.name] = visit(value.field(field.name).value, depth + 1);
        } catch (error) {
          result[field.name] = `<error:${String(error)}>`;
        }
      }
      return result;
    }

    if (value instanceof Il2Cpp.Object) {
      if (value.isNull()) return null;
      const handle = value.handle.toString();
      if (seen.has(handle)) return { "$ref": handle, "$type": value.class.fullName };
      seen.add(handle);

      const result: Record<string, unknown> = {
        "$type": value.class.fullName,
        "$handle": handle
      };
      for (const klass of value.class.hierarchy({ includeCurrent: true })) {
        for (const field of klass.fields) {
          if (field.isStatic || Object.prototype.hasOwnProperty.call(result, field.name)) continue;
          try {
            result[field.name] = visit(value.field(field.name).value, depth + 1);
          } catch (error) {
            result[field.name] = `<error:${String(error)}>`;
          }
        }
      }
      return result;
    }

    try {
      return value.toString();
    } catch (_) {
      return "<unprintable>";
    }
  }

  return visit(root, 0);
}

function findScriptableCourseClasses(): Il2Cpp.Class[] {
  const matches: Il2Cpp.Class[] = [];
  for (const assembly of Il2Cpp.domain.assemblies) {
    for (const klass of assembly.image.classes) {
      const lower = klass.name.toLowerCase();
      if (lower === "scriptablecourse" || lower.includes("scriptablecourse")) matches.push(klass);
    }
  }
  return matches;
}

function isLapRelated(value: string): boolean {
  return LAP_PATTERN.test(value);
}

function findLapCandidateClasses(): Il2Cpp.Class[] {
  const matches: Il2Cpp.Class[] = [];
  for (const assembly of Il2Cpp.domain.assemblies) {
    for (const klass of assembly.image.classes) {
      const classMatch = isLapRelated(klass.fullName);
      const fieldMatch = klass.fields.some(field => isLapRelated(`${field.name} ${field.type.name}`));
      if (classMatch || fieldMatch) matches.push(klass);
    }
  }
  return matches;
}

function simpleValue(value: any, depth = 0): any {
  if (value === null || value === undefined) return null;
  if (typeof value === "boolean" || typeof value === "number" || typeof value === "string") return value;
  if (value instanceof Int64 || value instanceof UInt64 || value instanceof NativePointer) return value.toString();
  if (value instanceof Il2Cpp.String) return value.isNull() ? null : value.content;
  if (depth >= 3) {
    try {
      return { "$type": value.class?.fullName || value.type?.name || "unknown", "$handle": value.handle?.toString() };
    } catch (_) {
      return "<depth-limit>";
    }
  }
  if (value instanceof Il2Cpp.Array) {
    if (value.isNull()) return null;
    const count = Math.min(value.length, 256);
    const result = [];
    for (let i = 0; i < count; i++) result.push(simpleValue(value.get(i), depth + 1));
    if (value.length > count) result.push(`<${value.length - count} more elements>`);
    return result;
  }
  if (value instanceof Il2Cpp.ValueType) {
    const result: Record<string, unknown> = { "$type": value.type.name };
    for (const field of value.type.class.fields) {
      if (field.isStatic) continue;
      try {
        result[field.name] = simpleValue(value.field(field.name).value, depth + 1);
      } catch (error) {
        result[field.name] = `<error:${String(error)}>`;
      }
    }
    return result;
  }
  if (value instanceof Il2Cpp.Object) {
    if (value.isNull()) return null;
    const result: Record<string, unknown> = {
      "$type": value.class.fullName,
      "$handle": value.handle.toString()
    };
    for (const klass of value.class.hierarchy({ includeCurrent: true })) {
      for (const field of klass.fields) {
        if (field.isStatic || !isLapRelated(`${field.name} ${field.type.name}`)) continue;
        try {
          result[field.name] = simpleValue(value.field(field.name).value, depth + 1);
        } catch (error) {
          result[field.name] = `<error:${String(error)}>`;
        }
      }
    }
    return result;
  }
  try {
    return value.toString();
  } catch (_) {
    return "<unprintable>";
  }
}

function lapObjectSnapshot(object: Il2Cpp.Object, klass: Il2Cpp.Class): Record<string, unknown> {
  const result: Record<string, unknown> = {
    "$type": klass.fullName,
    "$handle": object.handle.toString()
  };
  const includeAll = isLapRelated(klass.fullName);
  for (const current of klass.hierarchy({ includeCurrent: true })) {
    for (const field of current.fields) {
      if (field.isStatic) continue;
      if (!includeAll && !isLapRelated(`${field.name} ${field.type.name}`)) continue;
      try {
        result[field.name] = simpleValue(object.field(field.name).value);
      } catch (error) {
        result[field.name] = `<error:${String(error)}>`;
      }
    }
  }
  return result;
}

function scanLapRuntime(): void {
  const candidates = findLapCandidateClasses();
  if (!lapCatalogSent) {
    lapCatalogSent = true;
    send({
      type: "lap-class-catalog",
      classes: candidates.map(klass => ({
        className: klass.fullName,
        assembly: klass.assemblyName,
        fields: klass.fields.map(field => ({
          name: field.name,
          type: field.type.name,
          offset: field.offset,
          isStatic: field.isStatic
        }))
      }))
    });
  }

  for (const klass of candidates) {
    let objects: Il2Cpp.Object[];
    try {
      objects = Il2Cpp.gc.choose(klass).slice(0, 32);
    } catch (_) {
      continue;
    }
    for (const object of objects) {
      try {
        const snapshot = lapObjectSnapshot(object, klass);
        const encoded = JSON.stringify(snapshot);
        const key = `${klass.fullName}@${object.handle}`;
        if (lapSnapshots.get(key) === encoded) continue;
        lapSnapshots.set(key, encoded);
        send({
          type: "lap-runtime",
          className: klass.fullName,
          assembly: klass.assemblyName,
          handle: object.handle.toString(),
          snapshot
        });
      } catch (error) {
        send({ type: "scriptable-error", className: klass.fullName, error: `lap snapshot: ${String(error)}` });
      }
    }
  }
}

function getJsonUtility(): Il2Cpp.Method<Il2Cpp.String> | null {
  try {
    const assembly = Il2Cpp.domain.tryAssembly("UnityEngine.CoreModule");
    if (assembly === null) return null;
    const klass = assembly.image.tryClass("UnityEngine.JsonUtility");
    if (klass === null) return null;
    return klass.method<Il2Cpp.String>("ToJson", 2);
  } catch (_) {
    return null;
  }
}

async function scan(): Promise<void> {
  if (!armed || scanning) return;
  scanning = true;
  try {
    await Il2Cpp.perform(() => {
      const targets = findScriptableCourseClasses();
      if (targets.length === 0) {
        send({ type: "scriptable-status", message: "No ScriptableCourse class found yet" });
        return;
      }

      const jsonUtility = getJsonUtility();
      for (const klass of targets) {
        let objects: Il2Cpp.Object[] = [];
        try {
          objects = Il2Cpp.gc.choose(klass);
        } catch (error) {
          send({ type: "scriptable-error", className: klass.fullName, error: `gc.choose: ${String(error)}` });
          continue;
        }

        send({ type: "scriptable-status", message: `${klass.fullName}: ${objects.length} live instance(s)` });
        for (const object of objects) {
          const key = `${klass.fullName}@${object.handle}`;
          if (dumped.has(key)) continue;
          dumped.add(key);

          let unityJson: string | null = null;
          if (jsonUtility !== null) {
            try {
              const result = jsonUtility.invoke(object, true);
              unityJson = result === null || result.isNull() ? null : result.content;
            } catch (error) {
              send({ type: "scriptable-error", className: klass.fullName, error: `JsonUtility: ${String(error)}` });
            }
          }

          let reflected: unknown;
          try {
            reflected = reflectObject(object);
          } catch (error) {
            reflected = { "$error": String(error) };
          }

          send({
            type: "scriptable-course",
            className: klass.fullName,
            assembly: klass.assemblyName,
            handle: object.handle.toString(),
            unityJson,
            reflected,
            layout: classDescription(klass)
          });
        }
      }
      scanLapRuntime();
    });
  } catch (error) {
    send({ type: "scriptable-error", error: String(error) });
  } finally {
    scanning = false;
  }
}

setInterval(() => { void scan(); }, 750);

rpc.exports = {
  arm() {
    armed = true;
    dumped.clear();
    lapSnapshots.clear();
    lapCatalogSent = false;
    send({ type: "scriptable-status", message: "ScriptableCourse capture armed" });
    void scan();
    return true;
  },
  disarm() {
    armed = false;
    send({ type: "scriptable-status", message: "ScriptableCourse capture disarmed" });
    return true;
  },
  scan() {
    void scan();
    return true;
  }
};

send({ type: "scriptable-status", message: "IL2CPP ScriptableCourse probe loaded" });
