import assert from 'node:assert/strict';
import { elements, hasClass, textContent } from './html-contract.mjs';

const prohibited = /\b(?:attestation|verify-external-all|DOWNLOAD_DENY|MIRROR_DENY|INTEGRITY_ONLY|UNVERIFIED|Sigstore|SBOM|Grype)\b|--external-(?:admission|bundle)|github\.com\/pgextwin\/(?:build|catalog)\/issues\/|cli-candidate\.yml|source-digest|証明情報|確認用台帳/i;

const commandPrefix = '.\\pgextwin.exe ';

function commandLines(html, usageOnly = false) {
  return elements(html, 'pre')
    .filter(block => !usageOnly || hasClass(block, 'cli-usage'))
    .flatMap(block => elements(block.content, 'code'))
    .flatMap(code => code.content.replaceAll('&lt;', '<').replaceAll('&gt;', '>').trim().split(/\r?\n/))
    .map(line => line.trim().replace(/\s+/g, ' '))
    .filter(line => line.startsWith(commandPrefix))
    .map(line => line.slice(commandPrefix.length));
}

function stripPrerenderedDataGrids(homeHtml) {
  // In C1, #extensions and #landscape-grid are statically pre-rendered in home HTML
  // (where extension cards legitimately show SPDX SBOM / Grype / attestation fields).
  // Strip only those two data grid containers before testing the surrounding page chrome
  // against the CLI prohibited-terminology regex.
  return homeHtml
    .replace(
      /<div id="extensions" class="extension-grid">[\s\S]*?(?=<section class="cli-home-teaser")/,
      '<div id="extensions" class="extension-grid"></div></section>'
    )
    .replace(
      /<div id="landscape-grid" class="extension-grid">[\s\S]*?(?=<section class="info" aria-labelledby="lifecycle-heading")/,
      '<div id="landscape-grid" class="extension-grid"></div></section>'
    );
}

export function verifyPublishedCli(page, home, locale, cliMeta) {
  const cliVersion = cliMeta.version;
  const cliExeSha = cliMeta.assets.exe.sha256;
  const cliExeBytes = cliMeta.assets.exe.sizeBytes;
  const cliExeSize = (Math.floor(cliExeBytes / 10_000) / 100).toFixed(2) + ' MB';

  const exe = cliMeta.assets.exe.downloadUrl;
  const sums = cliMeta.assets.checksums.downloadUrl;
  const release = cliMeta.releaseUrl;

  assert.ok(['en', 'ja'].includes(locale), 'Unknown CLI locale');
  assert.equal(elements(page, 'html')[0]?.attributes.lang, locale, 'Wrong CLI page language');
  assert.equal(elements(home, 'html')[0]?.attributes.lang, locale, 'Wrong home language');

  for (const [label, html, href] of [
    ['CLI download', page, exe], ['home CLI download', home, exe],
    ['CLI Release', page, release], ['checksum download', page, sums],
    ['back to catalog', page, './'], ['CLI instructions', home, './cli.html']
  ]) {
    assert.ok(elements(html, 'a').some(x => x.attributes.href === href), 'Missing ' + label + ' link (' + locale + ')');
  }

  for (const [label, value] of [
    ['CLI version', 'CLI v' + cliVersion],
    ['CLI executable SHA-256', cliExeSha],
    ['EXE exact bytes', cliExeBytes.toLocaleString('en-US')],
    ['EXE readable size', cliExeSize],
    ['diagnostics option', '--verbose'],
    ['Windows hash command', 'Get-FileHash .\\pgextwin.exe -Algorithm SHA256'],
    ['ZIP hash command', 'Get-FileHash .\\downloaded-file.zip -Algorithm SHA256']
  ]) {
    assert.ok(page.includes(value), 'Missing ' + label + ' (' + locale + ')');
  }

  const usage = commandLines(page, true);
  for (const command of [
    'list [--category <category>] [--pg <major|all>] [--format <text|json>]',
    'search <term> [--category <category>] [--pg <major|all>] [--format <text|json>]',
    'download <item> [--version <version>] [--pg <major|all>] [--category <category>] [--output <dir>]',
    'download <item> --source pgextwin --pg <major> [--version <version>] [--output <dir>]',
    'download-all --pg <major|all> [--output <dir>] [--latest|--fixed]',
    'download-all --source external [--pg <major|all>] [--category <category>] [--output <dir>]',
    'verify external --ledger <file> --input-dir <dir> --pg <major|all>',
    'verify report <item> --pg <major> --catalog-dir <dir> --policy <file> --policy-sha256 <hex> ' +
      '--trusted-root-sha256 <hex> --p1-verifier-sha256 <hex> --report <file> --signature <file> ' +
      '--authority-key <pem> --authority-key-sha256 <hex>',
    '--help', '--version'
  ]) {
    assert.ok(usage.includes(command), 'Missing generic usage for ' + command + ' (' + locale + ')');
  }

  const pageCommands = commandLines(page);
  const homeCommands = commandLines(home);
  for (const command of [
    'download pgvector --pg 18',
    'download pgvector --version 0.8.7 --pg 18',
    'download-all --source external --pg 18 --category extensions',
    'download-all --pg 18'
  ]) {
    assert.ok(pageCommands.includes(command), 'Missing CLI example ' + command + ' (' + locale + ')');
  }
  for (const command of ['download pgvector --pg 18', 'download-all --pg 18']) {
    assert.ok(homeCommands.includes(command), 'Missing home CLI example ' + command + ' (' + locale + ')');
  }
  assert.ok(home.includes('CLI v' + cliVersion) && home.includes('cli-home-teaser'), 'Missing CLI home content');
  for (const command of [...pageCommands, ...homeCommands]) {
    assert.doesNotMatch(command, /^download-all\b.*\s--(?:extension|version)(?:[=\s]|$)/,
      'Bulk syntax selects a single extension or version (' + locale + ')');
  }
  assert.ok(page.includes('oracle_fdw 2.9.0') && page.includes('pgvector 0.8.7') &&
    page.includes('pg_trickle 0.108.3'), 'External ZIP coverage omitted');

  assert.ok(!prohibited.test(page), 'CLI exposes internal terminology (' + locale + ')');
  assert.ok(!prohibited.test(stripPrerenderedDataGrids(home)), 'home chrome exposes internal terminology (' + locale + ')');

  const notes = elements(page, 'article').filter(x => hasClass(x, 'cli-note-block'));
  assert.ok(notes.length > 0, 'Release notes missing');
  assert.ok(notes.every(x => x.attributes.lang === locale), 'Release note language mismatch');

  const steps = elements(page, 'ol').find(x => hasClass(x, 'cli-flow-steps'));
  assert.ok(steps && elements(steps.content, 'li').some(x => textContent(x)), 'CLI usage steps missing');

  const caution = elements(page, 'section').find(x => hasClass(x, 'cli-caution'));
  assert.ok(caution, 'CLI limitations missing');
  const explanations = locale === 'ja'
    ? [/提供元/, /PostgreSQL/, /ライセンス/, /インストール.*行いません/, /設定変更.*行いません/]
    : [/providers?/i, /PostgreSQL/, /licenses?/i, /does not install/i, /change settings/i];
  for (const explanation of explanations) {
    assert.match(textContent(caution), explanation, 'CLI limitation omitted');
  }

  for (const id of ['extensions', 'search', 'pg-filter', 'landscape-grid',
    'landscape-filter', 'landscape-source-filter', 'lifecycle-notice']) {
    assert.ok(home.includes('id="' + id + '"'), 'Dynamic catalog DOM target lost: ' + id);
  }
}
