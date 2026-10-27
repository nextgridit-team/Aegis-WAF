import { readFile, writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
const root = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);
const topics = JSON.parse(
  await readFile(path.join(root, "web/src/help-topics.json"), "utf8"),
);
const ids = new Set(),
  labels = new Set();
for (const t of topics) {
  if (
    !/^[a-z][a-z0-9-]*$/.test(t.id) ||
    ids.has(t.id) ||
    !t.title ||
    !t.summary ||
    !t.detail ||
    !t.labels?.length ||
    !/^[a-z0-9-]+\.md$/.test(t.guide)
  )
    throw Error("Invalid or duplicated help topic: " + t.id);
  ids.add(t.id);
  for (const label of t.labels) {
    const key = label.toLowerCase();
    if (labels.has(key)) throw Error("Duplicated help label: " + label);
    labels.add(key);
  }
  // The Docker dashboard build does not copy the repository docs.
  if (process.argv.includes("--docs") || process.argv.includes("--check"))
    await readFile(path.join(root, "docs", t.guide));
}
const esc = (s) =>
  s.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const html = `<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Help & glossary · Aegis WAF</title><link rel="stylesheet" href="help.css"></head><body><main><header><a href="/">← Aegis dashboard</a><p class="eyebrow">Aegis WAF · Help</p><h1>Security settings, explained simply.</h1><p>Choose a term for a short explanation and practical detail. This glossary is included with your installation and works without Internet access.</p></header><nav aria-label="Glossary topics">${topics.map((t) => `<a href="#${t.id}">${esc(t.title)}</a>`).join("")}</nav>${topics.map((t) => `<article id="${t.id}" tabindex="-1"><h2>${esc(t.title)}</h2><p class="summary">${esc(t.summary)}</p><p>${esc(t.detail)}</p><a href="https://github.com/nextgridit-team/Aegis-WAF/blob/main/docs/${t.guide}" target="_blank" rel="noopener noreferrer">Full configuration guide on GitHub ↗</a></article>`).join("")}<footer>Documentation describes the build containing this glossary. The GitHub guides may describe a newer release.</footer></main></body></html>\n`;
const markdown = `# Aegis glossary\n\nPlain-language explanations for settings shown in the dashboard. Click the **?** beside a setting for a short explanation, then **Read detailed explanation** for the built-in glossary. The same glossary is available at the management listener’s **/help.html** and works without Internet access. Full configuration-guide links open GitHub and require Internet access.\n\nThis file and the embedded glossary are generated from [the help catalogue](../web/src/help-topics.json). Update that source and run **node web/scripts/build-help.mjs --docs**; check consistency with **node web/scripts/build-help.mjs --check**.\n\n${topics.map((t) => `- [${t.title}](#${t.id})`).join("\n")}\n\n${topics.map((t) => `<a id="${t.id}"></a>\n\n## ${t.title}\n\n${t.summary}\n\n${t.detail}\n\n[Configuration guide](${t.guide})\n`).join("\n")}`;
const assets = path.join(root, "internal/app/assets");
if (process.argv.includes("--check")) {
  if (
    (await readFile(path.join(assets, "help.html"), "utf8")) !== html ||
    (await readFile(path.join(root, "docs/glossary.md"), "utf8")) !== markdown
  )
    throw Error(
      "Generated help is stale; rebuild the dashboard and run build-help.mjs --docs",
    );
  console.log(
    `PASS: ${topics.length} topics; unique labels, guide links and generated help/docs match.`,
  );
} else {
  await mkdir(assets, { recursive: true });
  await writeFile(path.join(assets, "help.html"), html);
  if (process.argv.includes("--docs"))
    await writeFile(path.join(root, "docs/glossary.md"), markdown);
}
