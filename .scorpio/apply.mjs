// Applies verdicts to manifests. Quarantined files are removed from the CDN path.
import fs from "node:fs";
import { spawnSync } from "node:child_process";
const verdicts = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const releases = process.argv.includes("--releases");
const now = new Date().toISOString();
for (const v of verdicts) {
  const p = `index/${v.name}.json`;
  if (!fs.existsSync(p)) continue;
  const m = JSON.parse(fs.readFileSync(p, "utf8"));
  const e = m.versions.find((x) => x.version === v.version);
  if (!e) continue;
  if (releases) {
    if (e.state === "approved") spawnSync("gh", ["release", "create", `${m.name}@${e.version}`, "--title", `${m.name} ${e.version}`, "--notes", `${m.description}\n\nInstall: \`scorpio install ${m.name}@${e.version}\`\n\nsha256: \`${e.sha256}\`\nPublisher: ${m.publisherId ?? "legacy"}`], { stdio: "inherit" });
    continue;
  }
  if (e.state !== "scanning" && e.state !== "pending") continue;
  const deep = (v.findings ?? []).map((f) => ({ id: f.id, severity: f.severity, title: f.title, tool: f.tool }));
  e.findings = [...(e.findings ?? []).filter((f) => !f.tool), ...deep];
  e.scan = { level: "deep", at: now };
  if (v.verdict === "quarantined") {
    e.state = "quarantined";
    e.reason = deep.filter((f) => f.severity === "high").map((f) => f.title).join("; ").slice(0, 300) || "Failed the security scan";
    fs.rmSync(`files/${m.name}/${e.version}`, { recursive: true, force: true });
  } else {
    e.state = "approved";
    delete e.reason;
  }
  m.updatedAt = now;
  fs.writeFileSync(p, JSON.stringify(m, null, 2));
  const dir = `events/${now.slice(0, 7)}`;
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(`${dir}/${Date.now()}-${m.name}-${e.version}.json`, JSON.stringify({ at: now, event: e.state === "approved" ? "approved" : "quarantined", package: m.name, version: e.version, reason: e.reason, tools: [...new Set(deep.map((f) => f.tool))] }, null, 2));
  console.log(`${m.name}@${e.version}: ${e.state}`);
}
