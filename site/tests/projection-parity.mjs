#!/usr/bin/env node
/**
 * Proposal C Phase C1 — Projection Parity Verification
 *
 * Independently reads raw Catalog inputs (index.json, packages/*.json,
 * identities/*, external/*, pinned postgresql.json, and
 * cli-v0.6.0 release snapshot) and verifies projection parity against the
 * statically generated site in --site.
 *
 * Writes evidence JSON to --output (default: <site>/../pages-projection-parity.json).
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { elements, hasClass, textContent } from "./html-contract.mjs";
import { verifyPublishedCli } from "./published-cli-contract.mjs";

const require = createRequire(import.meta.url);

function parseArgs(argv) {
  const args = {
    inputs: "site/inputs.json",
    site: "site/out/pages-preview",
    output: "site/out/pages-projection-parity.json",
  };
  for (let i = 2; i < argv.length; i += 1) {
    const key = argv[i];
    if (key === "--inputs" && argv[i + 1]) args.inputs = argv[++i];
    else if (key === "--site" && argv[i + 1]) args.site = argv[++i];
    else if (key === "--output" && argv[i + 1]) args.output = argv[++i];
    else throw new Error(`Unknown or incomplete argument: ${key}`);
  }
  return args;
}

function resolveRepoRoot(inputsPath) {
  let cur = dirname(resolve(inputsPath));
  while (true) {
    if (existsSync(join(cur, "index.json")) && existsSync(join(cur, "packages"))) return cur;
    const parent = dirname(cur);
    if (parent === cur) return process.cwd();
    cur = parent;
  }
}

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

function sha256Bytes(buf) {
  return createHash("sha256").update(buf).digest("hex");
}

function gitBlobSha256(text) {
  const buf = Buffer.from(text, "utf8");
  const header = Buffer.from(`blob ${buf.length}\0`, "ascii");
  return createHash("sha256").update(header).update(buf).digest("hex");
}

function decodeHtml(str) {
  return str
    .replaceAll("&amp;", "&")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&#x27;", "'")
    .replaceAll("&#39;", "'");
}

function extractTagSequence(html) {
  const voidTags = new Set(["meta", "link", "input", "br", "hr", "img"]);
  const cleaned = html
    .replace(/<!doctype[^>]*>/gi, "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "<script></script>");
  const tags = [];
  const re = /<\/?([a-zA-Z0-9-]+)\b[^>]*>/g;
  let m;
  while ((m = re.exec(cleaned)) !== null) {
    const raw = m[0];
    const name = m[1].toLowerCase();
    if (raw.startsWith("</")) {
      tags.push(`/${name}`);
    } else if (voidTags.has(name) || raw.endsWith("/>")) {
      tags.push(name);
    } else {
      tags.push(name);
    }
  }
  return tags;
}

function splitSectionsById(html, prefix, className) {
  // Extract each <article class="..."><details class="<className>" ... id="<prefix><name>">...</details></article>
  const map = new Map();
  const re = new RegExp(
    `<article\\b[^>]*>\\s*<details\\b[^>]*class="[^"]*\\b${className}\\b[^"]*"[^>]*id="${prefix}([^"]+)"[^>]*>([\\s\\S]*?)<\\/details>\\s*<\\/article>`,
    "g"
  );
  let m;
  while ((m = re.exec(html)) !== null) {
    map.set(m[1], m[0]);
  }
  return map;
}

function formatMajorRanges(values) {
  const majors = [...new Set(values.filter(Number.isInteger))].sort((a, b) => a - b);
  if (!majors.length) return "";
  const ranges = [];
  let start = majors[0];
  let prev = majors[0];
  for (let i = 1; i <= majors.length; i += 1) {
    const cur = majors[i];
    if (cur === prev + 1) {
      prev = cur;
      continue;
    }
    ranges.push(start === prev ? String(start) : `${start}–${prev}`);
    start = cur;
    prev = cur;
  }
  return ranges.join(", ");
}

function verifyHomeGuidance(html, locale) {
  const steps = elements(html, "ol").find((x) => hasClass(x, "quickstart-steps"));
  assert.ok(steps && elements(steps.content, "li").some((x) => textContent(x)), `Download steps missing (${locale})`);
  const topics =
    locale === "ja"
      ? [/検索/, /PostgreSQL/, /要件/, /ZIP/, /SHA-256/, /導入/]
      : [/search/i, /PostgreSQL/, /requirements/i, /ZIP/, /SHA-256/, /install/i];
  for (const topic of topics) {
    assert.match(textContent(steps), topic, `Download guidance omitted (${locale})`);
  }
  assert.ok(html.indexOf('id="quickstart-heading"') < html.indexOf('id="extensions-heading"'));
  const footer = elements(html, "footer")[0];
  assert.ok(footer, `Footer missing (${locale})`);
  const note = elements(footer.content, "section").find((x) => hasClass(x, "release-limitations"));
  assert.ok(note, `Installation limitations missing (${locale})`);
  assert.equal(note.attributes.role, "note");
  assert.ok(html.includes("Get-FileHash .\\downloaded-file.zip -Algorithm SHA256"));
  const limitations =
    locale === "ja"
      ? [/非公式/, /PostgreSQL/, /ライセンス/, /設定/, /インストールされません/, /提供元/]
      : [/unofficial/i, /PostgreSQL/, /licenses?/i, /configuration/i, /does not install/i, /provider/i];
  for (const lim of limitations) {
    assert.match(textContent(note), lim, `Installation caution omitted (${locale})`);
  }
}

function projectDistributionRecord(identity, pkg, packagesDir) {
  const name = identity.name;
  assert.equal(identity.schemaVersion, 1, `Unexpected identity schemaVersion on ${name}`);
  assert.equal(pkg.name, name, `Ledger name mismatch for ${name}`);
  assert.equal(identity.intake?.class, "distributed", `${name} must be distributed`);
  assert.equal(identity.intake?.distributionAllowed, true, `${name} must allow distribution`);
  assert.equal(
    identity.intake?.expectedUpstreamRepository,
    identity.upstreamRepository,
    `Expected upstream mismatch on ${name}`
  );
  assert.equal(identity.displayName ?? name, pkg.displayName, `displayName mismatch on ${name}`);
  assert.equal(identity.description, pkg.description, `description mismatch on ${name}`);
  assert.equal(identity.upstreamRepository, pkg.upstream.repository, `upstream mismatch on ${name}`);
  assert.equal(identity.distribution?.repository, pkg.repository, `repository mismatch on ${name}`);
  assert.equal(identity.distribution?.license, pkg.license, `license mismatch on ${name}`);
  assert.equal(identity.distribution?.ledgerPath, `${packagesDir}/${name}.json`, `ledgerPath mismatch on ${name}`);
  assert.equal(
    identity.distribution?.externalSourceRegistry,
    pkg.externalSourceRegistry,
    `externalSourceRegistry mismatch on ${name}`
  );

  const latest = pkg.releases.find((r) => r.releaseId === pkg.latestReleaseId);
  assert.ok(latest, `Missing latest release on ${name}`);
  const repo = identity.distribution.repository;
  const tag = latest.releaseTag;

  const upstream = { repository: identity.upstreamRepository };
  if (pkg.upstream.versionScheme === "perPostgresql") {
    const versions = { ...(pkg.upstream.unpublishedByMajor || {}) };
    for (const row of latest.packages) {
      const entry = { version: row.version };
      if (row.upstreamRef !== undefined) entry.ref = row.upstreamRef;
      versions[row.pgMajor] = entry;
    }
    upstream.perPostgresql = versions;
  } else {
    const versions = new Set(latest.packages.map((row) => row.version));
    assert.equal(versions.size, 1, `Shared upstream version differs on ${name}`);
    upstream.version = [...versions][0];
  }

  const postgresql = {};
  for (const major of pkg.unavailableMajors) {
    postgresql[major] = { available: false };
  }
  for (const row of latest.packages) {
    assert.ok(!(row.pgMajor in postgresql), `Conflicting availability for ${name} PG${row.pgMajor}`);
    postgresql[row.pgMajor] = {
      available: true,
      asset: row.asset,
      downloadUrl: `https://github.com/${repo}/releases/download/${tag}/${row.asset}`,
      sha256: row.sha256,
      evidence: row.evidence,
    };
  }

  return {
    schemaVersion: 2,
    name,
    displayName: identity.displayName ?? name,
    description: identity.description,
    upstream,
    repository: repo,
    license: identity.distribution.license,
    architecture: pkg.architecture,
    latest: {
      releaseTag: tag,
      publishedAt: latest.publishedAt,
      releaseUrl: `https://github.com/${repo}/releases/tag/${tag}`,
      checksumsAsset: latest.checksumsAsset,
    },
    postgresql,
    runtime: pkg.runtime,
    capabilities: pkg.capabilities,
    capabilitiesSource: pkg.capabilitiesSource,
    ...(identity.distribution.externalSourceRegistry
      ? { externalSourceRegistry: identity.distribution.externalSourceRegistry }
      : {}),
  };
}

function projectLandscapeRecord(identity) {
  const name = identity.name;
  const research = identity.research;
  const out = {
    schemaVersion: 1,
    name,
    displayName: identity.displayName ?? name,
    description: research.descriptionOverride ?? identity.description,
    upstreamRepository: identity.upstreamRepository,
  };
  if (identity.intake.class === "distributed") {
    out.status = "implemented";
    out.pgextwinCatalogName = name;
  } else {
    out.status = research.status;
  }
  for (const [key, value] of Object.entries(research)) {
    if (key === "status" || key === "descriptionOverride") continue;
    out[key] = value;
  }
  return out;
}

function main() {
  const args = parseArgs(process.argv);
  const inputsPath = resolve(args.inputs);
  const repoRoot = resolveRepoRoot(inputsPath);
  const siteDir = resolve(args.site);
  const outputPath = resolve(args.output);

  const inputs = readJson(inputsPath);
  const manifest = readJson(join(siteDir, "manifest.json"));
  const cliMeta = readJson(join(siteDir, "cli-release-metadata.json"));
  const filtersFilename = manifest.filtersFile;
  assert.match(filtersFilename, /^filters\.[0-9a-f]{12}\.json$/, "Unexpected filters filename");
  const filtersData = readJson(join(siteDir, filtersFilename));

  // Load raw Catalog sources
  const distIndex = readJson(join(repoRoot, inputs.catalogPaths.index));
  assert.equal(distIndex.schemaVersion, 3, "Expected schemaVersion 3 on index.json");
  assert.equal(distIndex.identitiesDir, inputs.catalogPaths.identitiesDir, "identitiesDir mismatch");
  assert.equal(distIndex.packagesDir, inputs.catalogPaths.packagesDir, "packagesDir mismatch");
  const distributedEntryNames = distIndex.identities
    .filter((entry) => entry.intakeClass === "distributed")
    .map((entry) => entry.name)
    .sort();
  assert.deepEqual([...distIndex.extensions].sort(), distributedEntryNames, "extensions roster disagrees with identities");
  const directRecords = readJson(join(repoRoot, inputs.catalogPaths.externalDirectGet)).records;
  const standaloneRecords = readJson(join(repoRoot, inputs.catalogPaths.externalStandaloneGet)).records;
  const pgSnapBytes = readFileSync(join(repoRoot, inputs.postgresqlLifecycle.snapshotPath));
  const pgSnap = JSON.parse(pgSnapBytes.toString("utf8"));
  const cliCfg = readJson(join(repoRoot, inputs.cliReleasePath));
  const cliSnapBytes = readFileSync(join(repoRoot, cliCfg.snapshotPath));
  const cliSnap = JSON.parse(cliSnapBytes.toString("utf8"));

  const ui = readJson(join(repoRoot, inputs.translationsDir, "ui.json"));
  const descI18n = readJson(join(repoRoot, inputs.translationsDir, "descriptions.json"));
  const scenI18n = readJson(join(repoRoot, inputs.translationsDir, "scenarios.json"));
  const decisionsCfg = readJson(join(repoRoot, inputs.landscapeDecisionsPath));

  const distRecords = distIndex.extensions.map((name) => {
    const identity = readJson(join(repoRoot, inputs.catalogPaths.identitiesDir, `${name}.json`));
    const pkg = readJson(join(repoRoot, inputs.catalogPaths.packagesDir, `${name}.json`));
    return {
      ext: projectDistributionRecord(identity, pkg, inputs.catalogPaths.packagesDir),
      pkg,
    };
  });
  const landscapeRegistry = distIndex.identities.map((entry) => {
    assert.equal(entry.path, `${inputs.catalogPaths.identitiesDir}/${entry.name}.json`);
    const identity = readJson(join(repoRoot, inputs.catalogPaths.identitiesDir, `${entry.name}.json`));
    assert.equal(identity.intake.class, entry.intakeClass);
    return projectLandscapeRecord(identity);
  });

  // Expected Landscape displayed IDs (46)
  const expectedLandscapeIds = new Set(distIndex.identities.map((entry) => entry.name));
  for (const [name, dec] of Object.entries(decisionsCfg.decisions)) {
    if (dec.displayName) expectedLandscapeIds.add(name);
  }
  for (const r of directRecords) {
    const item = r.extension || r.item;
    expectedLandscapeIds.add(item);
    if (item === "postgis") expectedLandscapeIds.add("pgrouting");
  }
  for (const r of standaloneRecords) {
    const item = r.extension || r.item;
    expectedLandscapeIds.add(item);
    if (item === "postgis") expectedLandscapeIds.add("pgrouting");
  }

  const rootHtml = readFileSync(join(siteDir, "index.html"), "utf8");
  const enHtml = readFileSync(join(siteDir, "en/index.html"), "utf8");
  const jaHtml = readFileSync(join(siteDir, "ja/index.html"), "utf8");
  const enCliHtml = readFileSync(join(siteDir, "en/cli.html"), "utf8");
  const jaCliHtml = readFileSync(join(siteDir, "ja/cli.html"), "utf8");
  const siteJsCode = readFileSync(join(siteDir, "site.js"), "utf8");

  const checks = [];
  function runCheck(name, fn) {
    const detail = fn();
    checks.push({ name, status: "PASS", ...(detail || {}) });
  }

  // 1. Pinned input & baseline counts parity
  runCheck("baseline_counts_and_pins", () => {
    assert.equal(sha256Bytes(pgSnapBytes), inputs.postgresqlLifecycle.snapshotSha256);
    assert.equal(sha256Bytes(cliSnapBytes), cliCfg.snapshotSha256);
    assert.equal(distRecords.length, 26);
    assert.equal(landscapeRegistry.length, 34);
    assert.equal(directRecords.length, 24);
    // Standalone record count tracks external/standalone-get.json: pgbouncer
    // plus the two psqlODBC 18.00.0006 architecture records (x64 + x86 MSI).
    assert.equal(standaloneRecords.length, 3);
    assert.equal(expectedLandscapeIds.size, 46);
    assert.equal(filtersData.extensions.length, 26);
    assert.equal(filtersData.landscape.length, 46);
    assert.equal(manifest.counts.distributedExtensions, 26);
    assert.equal(manifest.counts.landscapeRegistry, 34);
    assert.equal(manifest.counts.landscapeDisplayed, 46);
    return {
      distributed: 26,
      landscapeRegistry: 34,
      landscapeDisplayed: 46,
      externalDirect: 24,
      externalStandalone: standaloneRecords.length,
    };
  });

  // 2. Entrypoint, static structure, relative URLs, zero external runtime fetches
  runCheck("entrypoint_and_static_request_architecture", () => {
    assert.ok(rootHtml.includes("navigator.languages"));
    assert.ok(rootHtml.includes('href="./en/"') && rootHtml.includes('href="./ja/"'));
    assert.ok(rootHtml.includes('hreflang="x-default"'));
    for (const [lang, html] of [["en", enHtml], ["ja", jaHtml]]) {
      assert.ok(html.includes(`data-filters-url="../${filtersFilename}"`), `Missing single filters URL (${lang})`);
      assert.ok(html.includes('href="../styles.css"'), `Missing relative CSS (${lang})`);
      assert.ok(html.includes('src="../site.js"'), `Missing relative JS (${lang})`);
      assert.ok(!html.includes("raw.githubusercontent.com"), `Unexpected raw.githubusercontent.com fetch ref (${lang})`);
      const scripts = [...html.matchAll(/<script\b[^>]*>/gi)];
      assert.equal(scripts.length, 1, `Expected exactly 1 script tag on ${lang}/index.html`);
      verifyHomeGuidance(html, lang);
    }
    assert.ok(!siteJsCode.includes("raw.githubusercontent.com"), "site.js must not reference raw.githubusercontent.com");
    assert.ok(!siteJsCode.includes("api.github.com"), "site.js must not reference api.github.com");
    for (const [lang, cliHtml] of [["en", enCliHtml], ["ja", jaCliHtml]]) {
      assert.ok(!/<script\b/i.test(cliHtml), `CLI page must have 0 script tags (${lang})`);
      assert.ok(cliHtml.includes('href="../styles.css"'), `CLI page must use relative CSS (${lang})`);
    }
    const enCliTags = extractTagSequence(enCliHtml);
    const jaCliTags = extractTagSequence(jaCliHtml);
    assert.deepEqual(enCliTags, jaCliTags, "EN and JA CLI pages must have identical tag sequence");
    return { enCliTags: enCliTags.length, jaCliTags: jaCliTags.length, filtersFile: filtersFilename };
  });

  // 3. Distributed extensions (26): IDs, Release/ZIP/evidence links, PG versions/availability, Test Contract
  runCheck("distributed_extensions_26_parity", () => {
    const enCards = splitSectionsById(enHtml, "extension-", "extension-collapse");
    const jaCards = splitSectionsById(jaHtml, "extension-", "extension-collapse");
    const expectedOrder = [...distRecords]
      .sort((a, b) => a.ext.displayName.localeCompare(b.ext.displayName, "en", { sensitivity: "base" }))
      .map((x) => x.ext.name);
    assert.equal(enCards.size, 26);
    assert.equal(jaCards.size, 26);
    assert.deepEqual([...enCards.keys()].sort(), [...distIndex.extensions].sort());
    assert.deepEqual([...jaCards.keys()].sort(), [...distIndex.extensions].sort());
    assert.deepEqual([...enCards.keys()], [...jaCards.keys()], "EN and JA card orders differ");

    for (const { ext, pkg } of distRecords) {
      assert.equal(ext.latest.releaseTag, pkg.releases.find((r) => r.releaseId === pkg.latestReleaseId).releaseTag);
      for (const [lang, cards] of [["en", enCards], ["ja", jaCards]]) {
        const card = cards.get(ext.name);
        assert.ok(card, `Missing card for ${ext.name} (${lang})`);
        assert.ok(card.includes(ext.latest.releaseTag), `Missing releaseTag on ${ext.name}`);
        assert.ok(card.includes(ext.latest.releaseUrl), `Missing releaseUrl on ${ext.name}`);
        assert.ok(card.includes(`https://github.com/${ext.repository}`), `Missing repository URL on ${ext.name}`);
        assert.ok(card.includes(`https://github.com/${ext.upstream.repository}`), `Missing upstream URL on ${ext.name}`);
        assert.ok(card.includes(ext.capabilitiesSource.commit), `Missing capabilitiesSource commit on ${ext.name}`);

        // Check every PG major availability, ZIP URL, SHA-256, and evidence links
        const availMajors = [];
        const unavailMajors = [];
        for (const [major, info] of Object.entries(ext.postgresql)) {
          if (info.available) {
            availMajors.push(major);
            assert.ok(card.includes(info.asset), `Missing asset ${info.asset} on ${ext.name} PG${major}`);
            assert.ok(card.includes(info.downloadUrl), `Missing ZIP URL on ${ext.name} PG${major}`);
            assert.ok(card.includes(info.sha256), `Missing SHA-256 on ${ext.name} PG${major}`);
            if (info.evidence.sbom.available) {
              assert.ok(card.includes(info.evidence.sbom.downloadUrl), `Missing SBOM URL on ${ext.name} PG${major}`);
            }
            if (info.evidence.vulnerabilityReport.available) {
              assert.ok(
                card.includes(info.evidence.vulnerabilityReport.downloadUrl),
                `Missing vulnerability URL on ${ext.name} PG${major}`
              );
            }
          } else {
            unavailMajors.push(major);
            assert.ok(
              !new RegExp(`data-pg="${major}"`).test(card),
              `Unavailable PG${major} must not appear in binary list for ${ext.name}`
            );
          }
        }
        assert.ok(availMajors.length > 0);

        // Runtime requirements & Test Contract coverage + scenarios
        const req = ext.runtime.requirements;
        const u = ui[lang];
        assert.ok(card.includes(u.extensionCreationLabels[req.extensionCreation]));
        assert.ok(card.includes(u.preloadLabels[req.preload]));
        assert.ok(card.includes(req.backgroundWorker ? u.bgwUsed : u.bgwNotUsed));
        if (req.clientExecutable.required) {
          assert.ok(card.includes(u.clientExeRequired));
          for (const p of req.clientExecutable.packagePaths) {
            assert.ok(card.includes(p), `Missing client executable path ${p} on ${ext.name}`);
          }
        }
        for (const [covKey, covVal] of Object.entries(ext.capabilities.coverage)) {
          assert.ok(card.includes(u.coverageFields[covKey]));
          assert.ok(card.includes(u.coverageStatuses[covVal]));
        }
        for (const sc of ext.capabilities.functionalScenarios) {
          assert.ok(card.includes(`<code class="scenario-id">${sc.id}</code>`), `Missing scenario ${sc.id} on ${ext.name}`);
          if (Array.isArray(sc.postgresqlMajors) && sc.postgresqlMajors.length) {
            const scopeStr = `PostgreSQL ${formatMajorRanges(sc.postgresqlMajors)}${lang === "ja" ? "のみ" : " only"}`;
            assert.ok(card.includes(scopeStr), `Missing scenario scope '${scopeStr}' on ${ext.name}/${sc.id} (${lang})`);
          }
        }
      }
    }
    return { checkedExtensions: distRecords.length, expectedOrderSample: expectedOrder.slice(0, 5) };
  });

  // 4. Representative two extensions (pg_hint_plan, pg_repack) + pg_hint_plan PG15-16 scenario + translation policy
  runCheck("representative_two_and_translation_policy", () => {
    const enCards = splitSectionsById(enHtml, "extension-", "extension-collapse");
    const jaCards = splitSectionsById(jaHtml, "extension-", "extension-collapse");

    for (const [name, expectedUpstream, expectedRepo, expectedReleaseUrl] of [
      [
        "pg_hint_plan",
        "https://github.com/ossc-db/pg_hint_plan",
        "https://github.com/pgextwin/pg_hint_plan",
        "https://github.com/pgextwin/pg_hint_plan/releases/tag/v1.9.0-windows.1",
      ],
      [
        "pg_repack",
        "https://github.com/reorg/pg_repack",
        "https://github.com/pgextwin/pg_repack",
        "https://github.com/pgextwin/pg_repack/releases/tag/v1.5.3-windows.4",
      ],
    ]) {
      for (const [lang, cards] of [["en", enCards], ["ja", jaCards]]) {
        const card = cards.get(name);
        const navMatch = card.match(/<nav class="card-actions"[^>]*>([\s\S]*?)<\/nav>/);
        assert.ok(navMatch, `Missing card-actions nav on ${name} (${lang})`);
        const links = elements(navMatch[1], "a");
        const u = ui[lang];
        const byText = Object.fromEntries(links.map((a) => [decodeHtml(textContent(a)), a.attributes.href]));
        assert.equal(byText[u.releasePage], expectedReleaseUrl, `${name} Release page role mismatch (${lang})`);
        assert.equal(byText[u.repository], expectedRepo, `${name} Repository role mismatch (${lang})`);
        assert.equal(byText[u.upstream], expectedUpstream, `${name} Upstream role mismatch (${lang})`);
      }
    }

    // pg_hint_plan per-PG versions & PG15-16 scenario & no stale PG14-16 translation
    const hintEn = enCards.get("pg_hint_plan");
    const hintJa = jaCards.get("pg_hint_plan");
    for (const [major, ver] of [["15", "1.5.4"], ["16", "1.6.3"], ["17", "1.7.2"], ["18", "1.8.1"], ["19", "1.9.0"]]) {
      assert.ok(hintEn.includes(`Upstream version for PostgreSQL ${major}: ${ver}`));
      assert.ok(hintJa.includes(`PostgreSQL ${major}の上流バージョン：${ver}`));
    }
    assert.ok(hintEn.includes("PostgreSQL 15–16 only"));
    assert.ok(hintJa.includes("PostgreSQL 15–16のみ"));
    assert.ok(!hintJa.includes("PostgreSQL 14〜16"), "Stale PG14-16 translation leaked into pg_hint_plan JA");
    assert.ok(
      hintJa.includes("Exercises the PostgreSQL 15-16 query-jumble and hint-table compatibility path"),
      "Missing English original for untranslated pg_hint_plan PG15-16 scenario"
    );
    assert.ok(hintJa.includes("翻訳待ち"), "Missing translation-pending badge on pg_hint_plan JA");

    // odbc_fdw untranslated description & scenario must show English + 翻訳待ち (not 日本語の説明は準備中です)
    const odbcJa = jaCards.get("odbc_fdw");
    assert.ok(odbcJa.includes("A PostgreSQL extension that provides a Foreign Data Wrapper"));
    assert.ok(odbcJa.includes("Creates SQL extension version 0.5.2 and reads typed rows"));
    assert.ok(odbcJa.includes("翻訳待ち"));
    assert.ok(!odbcJa.includes("日本語の説明は準備中です"));

    // Exact migrated translations check (25 descriptions + 33 scenarios)
    let checkedDesc = 0;
    let checkedScen = 0;
    for (const { ext } of distRecords) {
      const card = jaCards.get(ext.name);
      const dEntry = descI18n[`${ext.name}.distribution`];
      if (dEntry && dEntry.sourceEn === ext.description) {
        assert.ok(card.includes(dEntry.ja), `Missing migrated JA description for ${ext.name}`);
        checkedDesc += 1;
      }
      for (const sc of ext.capabilities.functionalScenarios) {
        const key = `${ext.name}:${sc.id}:${gitBlobSha256(sc.description)}`;
        const sEntry = scenI18n[key];
        if (sEntry && sEntry.sourceEn === sc.description) {
          assert.ok(card.includes(sEntry.ja), `Missing migrated JA scenario for ${ext.name}:${sc.id}`);
          checkedScen += 1;
        }
      }
    }
    assert.equal(checkedDesc, 25);
    assert.equal(checkedScen, 33);
    return {
      pgHintPlanPg15_16EnScope: true,
      pgHintPlanPg15_16JaScope: true,
      pgHintPlanPendingFallback: true,
      migratedDescriptionsVerified: checkedDesc,
      migratedScenariosVerified: checkedScen,
    };
  });

  // 5. Landscape (46 displayed, 34 registry, external 24+3, bundle & license exclusions)
  runCheck("landscape_46_and_external_routes_parity", () => {
    const enLand = splitSectionsById(enHtml, "landscape-", "landscape-collapse");
    const jaLand = splitSectionsById(jaHtml, "landscape-", "landscape-collapse");
    assert.equal(enLand.size, 46);
    assert.equal(jaLand.size, 46);
    assert.deepEqual([...enLand.keys()].sort(), [...expectedLandscapeIds].sort());
    assert.deepEqual([...jaLand.keys()].sort(), [...expectedLandscapeIds].sort());
    assert.deepEqual([...enLand.keys()], [...jaLand.keys()], "EN and JA landscape orders differ");

    // Verify external direct (24) & standalone (3) assets appear in their respective cards (including pgrouting bundle)
    for (const pkg of [...directRecords, ...standaloneRecords]) {
      const targetNames = [pkg.extension || pkg.item];
      if (targetNames[0] === "postgis") targetNames.push("pgrouting");
      for (const target of targetNames) {
        assert.ok(enLand.get(target).includes(pkg.assetName), `Missing external asset ${pkg.assetName} in ${target} (en)`);
        assert.ok(jaLand.get(target).includes(pkg.assetName), `Missing external asset ${pkg.assetName} in ${target} (ja)`);
      }
    }
    assert.ok(enLand.get("pgrouting").includes("Available in the same package as PostGIS."));
    assert.ok(jaLand.get("pgrouting").includes("PostGISと同じパッケージに同梱されています。"));
    assert.ok(!enLand.get("postgis").includes("External Windows binary sources"));
    assert.ok(!enLand.get("pgrouting").includes("External Windows binary sources"));

    // Verify license-excluded entries clear packages and sources
    for (const exName of ["pgagent", "edb_language_pack", "asp_bluefin", "timescaledb"]) {
      assert.ok(enLand.get(exName).includes("landscape-status-label--license-excluded"));
      assert.ok(!enLand.get(exName).includes("External Windows binary sources"));
    }

    // Verify all registry source URLs and evidence URLs where not suppressed/license-excluded
    for (const rec of landscapeRegistry) {
      if (["timescaledb", "postgis", "pgrouting"].includes(rec.name)) continue;
      for (const src of rec.windowsBinarySources) {
        assert.ok(enLand.get(rec.name).includes(src.url), `Missing source URL on ${rec.name}`);
      }
      for (const evUrl of rec.evidenceUrls) {
        assert.ok(enLand.get(rec.name).includes(evUrl), `Missing evidence URL on ${rec.name}`);
      }
    }
    return { displayed: 46, registry: 34, externalDirect: directRecords.length, externalStandalone: standaloneRecords.length };
  });

  // 6. Filter JSON & site.js pure-logic parity (search, PG filter, landscape filters, UTC EOL boundary)
  runCheck("filters_and_utc_eol_boundary", () => {
    const siteJs = require(join(siteDir, "site.js"));

    // Search by name and upstream repository
    const hintByRepo = siteJs.filterExtensions(filtersData.extensions, { lang: "en", query: "ossc-db/pg_hint_plan" });
    assert.deepEqual(hintByRepo.map((x) => x.name), ["pg_hint_plan"]);
    const repackByRepo = siteJs.filterExtensions(filtersData.extensions, { lang: "ja", query: "reorg/pg_repack" });
    assert.deepEqual(repackByRepo.map((x) => x.name), ["pg_repack"]);

    // PG14 filter should include only extensions available on PG14 (pg_store_plans, pg_variables)
    const expectedPg14 = distRecords.filter((x) => x.ext.postgresql["14"]?.available).map((x) => x.ext.name).sort();
    const actualPg14 = siteJs.filterExtensions(filtersData.extensions, { lang: "en", major: "14" }).map((x) => x.name).sort();
    assert.deepEqual(actualPg14, expectedPg14);

    // Landscape filters
    const countByStatus = {};
    for (const status of ["implemented", "external-direct", "external-standalone", "candidate", "license-excluded", "not-planned"]) {
      countByStatus[status] = siteJs.filterLandscape(filtersData.landscape, { lang: "en", status }).length;
    }
    assert.deepEqual(countByStatus, {
      implemented: 26,
      "external-direct": 7,
      "external-standalone": 4,
      candidate: 4,
      "license-excluded": 4,
      "not-planned": 3,
    });
    const vendorMatches = siteJs.filterLandscape(filtersData.landscape, { lang: "en", sourceType: "vendor" }).map((x) => x.name).sort();
    assert.deepEqual(vendorMatches, ["pg_hint_plan", "pg_repack", "pgaudit"]);

    // UTC EOL boundary test: PG14 eol = 2026-11-12
    const pg14Eol = pgSnap.postgresql.find((p) => p.major === 14).eol;
    assert.equal(pg14Eol, "2026-11-12");
    // 2026-11-13T08:30:00+09:00 is 2026-11-12T23:30:00Z -> UTC date is 2026-11-12 -> maintained!
    const utcSameDay = siteJs.getUtcCalendarDate(new Date("2026-11-13T08:30:00+09:00"));
    assert.equal(utcSameDay, "2026-11-12");
    assert.equal(siteJs.getLifecycleStatus(pg14Eol, utcSameDay), "maintained");
    // 2026-11-13T09:00:00+09:00 is 2026-11-13T00:00:00Z -> UTC date is 2026-11-13 -> historical!
    const utcNextDay = siteJs.getUtcCalendarDate(new Date("2026-11-13T09:00:00+09:00"));
    assert.equal(utcNextDay, "2026-11-13");
    assert.equal(siteJs.getLifecycleStatus(pg14Eol, utcNextDay), "historical");
    // PG major availability in filters does NOT change across EOL boundary
    assert.deepEqual(actualPg14, ["pg_store_plans", "pg_variables"]);

    return { statusCounts: countByStatus, vendorMatches, pg14Available: actualPg14, utcBoundaryTested: ["2026-11-12", "2026-11-13"] };
  });

  // 7. CLI release metadata & published-cli-contract parity
  runCheck("cli_release_metadata_and_contract", () => {
    assert.equal(cliMeta.releaseId, cliSnap.id);
    assert.equal(cliMeta.tag, cliSnap.tag_name);
    assert.equal(cliMeta.tagCommit, cliSnap.target_commitish);
    assert.equal(cliMeta.prerelease, cliSnap.prerelease);
    const snapExe = cliSnap.assets.find((a) => a.name === "pgextwin.exe");
    const snapSums = cliSnap.assets.find((a) => a.name === "SHA256SUMS.txt");
    assert.equal(cliMeta.assets.exe.sizeBytes, snapExe.size);
    assert.equal(`sha256:${cliMeta.assets.exe.sha256}`, snapExe.digest);
    assert.equal(cliMeta.assets.exe.downloadUrl, snapExe.browser_download_url);
    assert.equal(`sha256:${cliMeta.assets.checksums.sha256}`, snapSums.digest);

    verifyPublishedCli(enCliHtml, enHtml, "en", cliMeta);
    verifyPublishedCli(jaCliHtml, jaHtml, "ja", cliMeta);
    return {
      cliTag: cliMeta.tag,
      releaseId: cliMeta.releaseId,
      exeBytes: cliMeta.assets.exe.sizeBytes,
      exeSha256: cliMeta.assets.exe.sha256,
    };
  });

  const report = {
    schemaVersion: 1,
    result: "PASS",
    generatedAtUtc: new Date().toISOString(),
    references: {
      catalogCommit: manifest.catalogCommit,
      inputsPath: args.inputs,
      inputsSha256: manifest.inputsSha256,
      postgresqlLifecyclePin: manifest.postgresqlLifecyclePin,
      cliRelease: manifest.cliRelease,
      siteDir: args.site,
    },
    counts: manifest.counts,
    checks,
  };

  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(report, null, 2) + "\n", "utf8");
  console.log(JSON.stringify({ result: report.result, checks: checks.length, counts: report.counts, output: args.output }));
}

main();
