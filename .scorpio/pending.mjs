// Lists versions that still need the deep scan (state scanning/pending, not yet deep-scanned).
import fs from "node:fs";
const out = [];
for (const f of fs.existsSync("index") ? fs.readdirSync("index") : []) {
  if (!f.endsWith(".json")) continue;
  const m = JSON.parse(fs.readFileSync(`index/${f}`, "utf8"));
  for (const v of m.versions ?? []) {
    if ((v.state === "scanning" || v.state === "pending") && v.scan?.level !== "deep") {
      const path = `files/${m.name}/${v.version}/${v.file}`;
      if (fs.existsSync(path) && /^[A-Za-z0-9._-]+$/.test(v.file)) out.push({ name: m.name, version: v.version, file: v.file, path });
    }
  }
}
process.stdout.write(JSON.stringify(out.slice(0, 10)));
