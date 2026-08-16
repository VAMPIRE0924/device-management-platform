#!/bin/sh
set -eu

project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
docs_dir="$project_dir/docs"

node - "$docs_dir" <<'NODE'
const fs = require("node:fs");
const path = require("node:path");

const docs = path.resolve(process.argv[2]);
const requiredDirectories = ["部署运维", "开发维护"];
const errors = [];

for (const directory of requiredDirectories) {
  const target = path.join(docs, directory);
  if (!fs.existsSync(target) || !fs.statSync(target).isDirectory()) errors.push(`缺少目录：${directory}`);
  if (!fs.existsSync(path.join(target, "README.md"))) errors.push(`缺少目录索引：${directory}/README.md`);
}

for (const document of ["Docker部署.md", "构建部署与备份.md", "登录安全与双重认证.md"]) {
  if (!fs.existsSync(path.join(docs, "部署运维", document))) errors.push(`缺少部署资料：部署运维/${document}`);
}
if (!fs.existsSync(path.join(docs, "开发维护", "本地开发与发布.md"))) {
  errors.push("缺少开发资料：开发维护/本地开发与发布.md");
}

const rootFiles = fs.readdirSync(docs, { withFileTypes: true })
  .filter((entry) => entry.isFile())
  .map((entry) => entry.name)
  .filter((name) => name !== "README.md");
if (rootFiles.length) errors.push(`docs 根目录只允许 README.md，发现：${rootFiles.join(", ")}`);

function markdownFiles(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) return markdownFiles(absolute);
    return entry.isFile() && entry.name.endsWith(".md") ? [absolute] : [];
  });
}

const forbidden = [
  [/admin@66/i, "疑似历史测试凭据"],
  [/BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/, "私钥正文"],
  [/(?:public_vkey|web_password)\s*=/i, "节点秘密配置"],
];

for (const file of markdownFiles(docs)) {
  const content = fs.readFileSync(file, "utf8");
  const relative = path.relative(docs, file);
  for (const [pattern, message] of forbidden) {
    if (pattern.test(content)) errors.push(`${relative}：${message}`);
  }
  for (const match of content.matchAll(/\]\(([^)]+)\)/g)) {
    let target = match[1].trim().replace(/^<|>$/g, "").split("#", 1)[0];
    if (!target || /^(?:https?:|mailto:|data:)/i.test(target)) continue;
    try { target = decodeURIComponent(target); } catch {}
    const resolved = path.resolve(path.dirname(file), target);
    if (!resolved.startsWith(docs + path.sep) && resolved !== docs) {
      errors.push(`${relative}：链接越出 docs 目录：${match[1]}`);
    } else if (!fs.existsSync(resolved)) {
      errors.push(`${relative}：失效链接：${match[1]}`);
    }
  }
}

if (errors.length) {
  process.stderr.write(errors.map((error) => `- ${error}`).join("\n") + "\n");
  process.exit(1);
}
process.stdout.write("Documentation verification passed\n");
NODE
