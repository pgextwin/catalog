(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.pgextwinSite = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const CALENDAR_DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/;
  const ENGLISH_MONTHS = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December"
  ];

  function isValidCalendarDate(value) {
    if (typeof value !== "string") return false;
    const match = CALENDAR_DATE_PATTERN.exec(value);
    if (!match) return false;
    const year = Number(match[1]);
    const month = Number(match[2]);
    const day = Number(match[3]);
    const date = new Date(Date.UTC(year, month - 1, day));
    return (
      date.getUTCFullYear() === year &&
      date.getUTCMonth() === month - 1 &&
      date.getUTCDate() === day
    );
  }

  function getUtcCalendarDate(date) {
    const target = date instanceof Date ? date : new Date();
    if (Number.isNaN(target.getTime())) return null;
    return target.toISOString().slice(0, 10);
  }

  function getLifecycleStatus(eolDate, effectiveDate) {
    if (!isValidCalendarDate(eolDate) || !isValidCalendarDate(effectiveDate)) {
      return "unknown";
    }
    return effectiveDate <= eolDate ? "maintained" : "historical";
  }

  function nextCalendarDate(value) {
    if (!isValidCalendarDate(value)) return null;
    const [year, month, day] = value.split("-").map(Number);
    const date = new Date(Date.UTC(year, month - 1, day + 1));
    return date.toISOString().slice(0, 10);
  }

  function formatCalendarDate(value, lang) {
    if (!isValidCalendarDate(value)) return value || "";
    const [year, month, day] = value.split("-").map(Number);
    if (lang === "ja") return `${year}年${month}月${day}日`;
    return `${ENGLISH_MONTHS[month - 1]} ${day}, ${year}`;
  }

  function filterExtensions(extensions, options) {
    const list = Array.isArray(extensions) ? extensions : [];
    const opts = options || {};
    const lang = opts.lang === "ja" ? "ja" : "en";
    const query = String(opts.query || "").trim().toLowerCase();
    const major = opts.major !== undefined && opts.major !== null && opts.major !== ""
      ? String(opts.major)
      : null;

    return list.filter((entry) => {
      if (major) {
        const majors = Array.isArray(entry.availableMajors) ? entry.availableMajors.map(String) : [];
        if (!majors.includes(major)) return false;
      }
      if (!query) return true;
      const haystack = (entry.searchText && (entry.searchText[lang] || entry.searchText.en)) || "";
      return haystack.toLowerCase().includes(query);
    });
  }

  function filterLandscape(entries, options) {
    const list = Array.isArray(entries) ? entries : [];
    const opts = options || {};
    const lang = opts.lang === "ja" ? "ja" : "en";
    const query = String(opts.query || "").trim().toLowerCase();
    const status = opts.status ? String(opts.status) : "";
    const sourceType = opts.sourceType ? String(opts.sourceType) : "";

    return list.filter((entry) => {
      if (status) {
        const distributions = Array.isArray(entry.distributions) ? entry.distributions : [];
        if (!distributions.includes(status)) return false;
      }
      if (sourceType) {
        const sourceTypes = Array.isArray(entry.sourceTypes) ? entry.sourceTypes : [];
        if (!sourceTypes.includes(sourceType)) return false;
      }
      if (!query) return true;
      const haystack = (entry.searchText && (entry.searchText[lang] || entry.searchText.en)) || "";
      return haystack.toLowerCase().includes(query);
    });
  }

  function buildLifecycleMessages(lang) {
    if (lang === "ja") {
      return {
        badge: {
          maintained: "サポート期間内",
          historical: "サポート終了／過去バージョン",
          unknown: "サポート期間不明"
        },
        detailMaintained: (major, eol) => `配布中のバイナリ · サポート終了日：${eol}`,
        detailHistorical: (major, eol) => `過去バージョンのバイナリ · PostgreSQL ${major}のサポート終了日：${eol}`,
        detailUnknown: "配布中のバイナリ · サポート情報が取得できません",
        noticeMaintained: (major, eol, nextDate) =>
          `PostgreSQL ${major}は${formatCalendarDate(eol, "ja")}まで保守対象です。サポート終了後も既存バイナリは保持しますが、${formatCalendarDate(nextDate, "ja")}以降の通常の新規ビルドではPG${major}を対象外とします。`,
        noticeHistorical: (major, eol, nextDate) =>
          `PostgreSQL ${major}は${formatCalendarDate(eol, "ja")}にサポートが終了しました（EOL）。既存バイナリは過去版のダウンロード用に保持しています。${formatCalendarDate(nextDate, "ja")}以降、通常の新規ビルドではPG${major}を対象外としています。`,
        noticeUnknown:
          "PostgreSQLのライフサイクル情報を取得できません。Catalogに登録された公開済みバイナリは引き続き表示しますが、現在の保守状況は判定できません。",
        statusSuffix: (date) => `サポート状況はUTCの${date}時点で判定しています。`,
        catalogStatus: (count, date) => `${count}件の拡張機能を読み込みました。 サポート状況はUTCの${date}時点で判定しています。`,
        resultsCount: (shown, total) => `${total}件中${shown}件の拡張機能を表示しています。`,
        landscapeCount: (shown, total) => `対応状況${total}件中${shown}件を表示しています。`,
        copyButton: "SHA-256をコピー",
        copied: "コピーしました",
        copyUnavailable: "コピーできません"
      };
    }
    return {
      badge: {
        maintained: "Maintained",
        historical: "EOL / Historical",
        unknown: "Lifecycle unknown"
      },
      detailMaintained: (major, eol) => `Available binary · Supported through ${eol}`,
      detailHistorical: (major, eol) => `Historical binary · PostgreSQL ${major} reached EOL on ${eol}`,
      detailUnknown: "Available binary · Lifecycle data unavailable",
      noticeMaintained: (major, eol, nextDate) =>
        `PostgreSQL ${major} is supported through ${formatCalendarDate(eol, "en")}. Existing binaries will remain available after EOL, but new normal builds will exclude PG${major} beginning ${formatCalendarDate(nextDate, "en")}.`,
      noticeHistorical: (major, eol, nextDate) =>
        `PostgreSQL ${major} reached EOL on ${formatCalendarDate(eol, "en")}. Existing binaries remain available as historical downloads; normal new builds have excluded PG${major} since ${formatCalendarDate(nextDate, "en")}.`,
      noticeUnknown:
        "PostgreSQL lifecycle data is unavailable. Published binary availability is still shown from the catalog, but current maintenance status cannot be determined.",
      statusSuffix: (date) => `Lifecycle status uses the ${date} UTC calendar date.`,
      catalogStatus: (count, date) => `${count} extension records loaded. Lifecycle status uses the ${date} UTC calendar date.`,
      resultsCount: (shown, total) => `${shown} of ${total} extensions shown.`,
      landscapeCount: (shown, total) => `${shown} of ${total} Landscape entries shown.`,
      copyButton: "Copy SHA-256",
      copied: "Copied",
      copyUnavailable: "Copy unavailable"
    };
  }

  function initDom() {
    if (typeof document === "undefined" || !document.getElementById) return;
    const filtersUrl = document.documentElement.dataset.filtersUrl;
    if (!filtersUrl) return;

    const lang = document.documentElement.lang === "ja" ? "ja" : "en";
    const msgs = buildLifecycleMessages(lang);

    const searchInput = document.getElementById("search");
    const pgFilter = document.getElementById("pg-filter");
    const extensionsGrid = document.getElementById("extensions");
    const statusElement = document.getElementById("status");
    const resultsCountElement = document.getElementById("results-count");
    const emptyStateElement = document.getElementById("empty-state");
    const lifecycleNoticeElement = document.getElementById("lifecycle-notice");

    const landscapeSearch = document.getElementById("landscape-search");
    const landscapeFilter = document.getElementById("landscape-filter");
    const landscapeSourceFilter = document.getElementById("landscape-source-filter");
    const landscapeGrid = document.getElementById("landscape-grid");
    const landscapeCountElement = document.getElementById("landscape-count");
    const landscapeEmptyElement = document.getElementById("landscape-empty");

    const extensionCards = new Map();
    if (extensionsGrid) {
      for (const card of extensionsGrid.querySelectorAll("article[data-extension]")) {
        extensionCards.set(card.dataset.extension, card);
      }
    }
    const landscapeCards = new Map();
    if (landscapeGrid) {
      for (const card of landscapeGrid.querySelectorAll("article[data-landscape]")) {
        landscapeCards.set(card.dataset.landscape, card);
      }
    }

    let filtersData = null;

    function updateLifecycleDom(effectiveDate, lifecycleMap) {
      if (!isValidCalendarDate(effectiveDate)) return;
      if (extensionsGrid) {
        for (const details of extensionsGrid.querySelectorAll(".pg-version[data-pg]")) {
          const major = details.dataset.pg;
          const eol = (lifecycleMap && lifecycleMap[major]) || details.dataset.eol || "";
          const status = getLifecycleStatus(eol, effectiveDate);
          const badge = details.querySelector(".lifecycle-badge");
          if (badge) {
            badge.className = `lifecycle-badge lifecycle-badge--${status}`;
            badge.textContent = msgs.badge[status];
          }
          const detail = details.querySelector(".pg-version-detail");
          if (detail) {
            if (status === "maintained") detail.textContent = msgs.detailMaintained(major, eol);
            else if (status === "historical") detail.textContent = msgs.detailHistorical(major, eol);
            else detail.textContent = msgs.detailUnknown;
          }
        }
      }
      if (lifecycleNoticeElement) {
        const pg14Eol = (lifecycleMap && lifecycleMap["14"]) || document.documentElement.dataset.pg14Eol || "";
        const status14 = getLifecycleStatus(pg14Eol, effectiveDate);
        const p = document.createElement("p");
        if (lang === "ja") p.lang = "ja";
        if (status14 === "maintained") {
          p.textContent = msgs.noticeMaintained(14, pg14Eol, nextCalendarDate(pg14Eol));
        } else if (status14 === "historical") {
          p.textContent = msgs.noticeHistorical(14, pg14Eol, nextCalendarDate(pg14Eol));
        } else {
          p.textContent = msgs.noticeUnknown;
        }
        lifecycleNoticeElement.replaceChildren(p);
      }
      if (statusElement && filtersData) {
        statusElement.textContent = msgs.catalogStatus(filtersData.extensions.length, effectiveDate);
      }
    }

    function applyExtensionFilters() {
      if (!filtersData || !extensionsGrid) return;
      const selectedMajor = pgFilter ? pgFilter.value : "";
      const query = searchInput ? searchInput.value : "";
      const matched = filterExtensions(filtersData.extensions, { lang, query, major: selectedMajor });
      const matchedIds = new Set(matched.map((e) => e.name));

      for (const [name, card] of extensionCards.entries()) {
        const visible = matchedIds.has(name);
        card.hidden = !visible;
        if (!visible) continue;

        for (const badge of card.querySelectorAll(".summary-pg[data-pg]")) {
          badge.hidden = Boolean(selectedMajor) && badge.dataset.pg !== selectedMajor;
        }
        for (const row of card.querySelectorAll(".binary-table tbody tr[data-pg]")) {
          row.hidden = Boolean(selectedMajor) && row.dataset.pg !== selectedMajor;
        }
        for (const li of card.querySelectorAll(".pg-list > li[data-pg]")) {
          li.hidden = Boolean(selectedMajor) && li.dataset.pg !== selectedMajor;
        }
        let shownScenarios = 0;
        for (const sc of card.querySelectorAll(".scenario-item[data-pg-majors]")) {
          const majorsAttr = sc.dataset.pgMajors;
          const applies = !selectedMajor || !majorsAttr || majorsAttr.split(",").includes(selectedMajor);
          sc.hidden = !applies;
          if (applies) shownScenarios += 1;
        }
        const emptyScenario = card.querySelector(".scenario-empty");
        if (emptyScenario) emptyScenario.hidden = shownScenarios !== 0;
      }

      if (resultsCountElement) {
        resultsCountElement.textContent = msgs.resultsCount(matched.length, filtersData.extensions.length);
      }
      if (emptyStateElement) {
        emptyStateElement.hidden = matched.length !== 0;
      }
    }

    function applyLandscapeFilters() {
      if (!filtersData || !landscapeGrid) return;
      const query = landscapeSearch ? landscapeSearch.value : "";
      const status = landscapeFilter ? landscapeFilter.value : "";
      const sourceType = landscapeSourceFilter ? landscapeSourceFilter.value : "";
      const matched = filterLandscape(filtersData.landscape, { lang, query, status, sourceType });
      const matchedIds = new Set(matched.map((e) => e.name));

      for (const [name, card] of landscapeCards.entries()) {
        card.hidden = !matchedIds.has(name);
      }
      if (landscapeCountElement) {
        landscapeCountElement.textContent = msgs.landscapeCount(matched.length, filtersData.landscape.length);
      }
      if (landscapeEmptyElement) {
        landscapeEmptyElement.hidden = matched.length !== 0;
      }
    }

    function wireInteractions() {
      for (const button of document.querySelectorAll(".copy-button[data-sha256]")) {
        button.addEventListener("click", async () => {
          const sha256 = button.dataset.sha256 || "";
          try {
            if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
              throw new Error("Clipboard API unavailable");
            }
            await navigator.clipboard.writeText(sha256);
            button.textContent = msgs.copied;
          } catch (err) {
            console.warn(err);
            button.textContent = msgs.copyUnavailable;
          } finally {
            window.setTimeout(() => {
              button.textContent = msgs.copyButton;
            }, 1800);
          }
        });
      }

      if (extensionsGrid) {
        for (const details of extensionsGrid.querySelectorAll(".extension-collapse")) {
          details.addEventListener("toggle", () => {
            const name = details.id.replace(/^extension-/, "");
            const url = new URL(window.location.href);
            if (details.open) {
              for (const other of extensionsGrid.querySelectorAll(".extension-collapse")) {
                if (other !== details && other.open) other.open = false;
              }
              url.searchParams.set("extension", name);
              window.history.replaceState(null, "", url);
            } else if (url.searchParams.get("extension") === name) {
              url.searchParams.delete("extension");
              window.history.replaceState(null, "", url);
            }
          });
        }
      }

      if (landscapeGrid) {
        for (const details of landscapeGrid.querySelectorAll(".landscape-collapse")) {
          details.addEventListener("toggle", () => {
            const name = details.id.replace(/^landscape-/, "");
            const url = new URL(window.location.href);
            if (details.open) {
              for (const other of landscapeGrid.querySelectorAll(".landscape-collapse")) {
                if (other !== details && other.open) other.open = false;
              }
              url.searchParams.set("landscape", name);
              window.history.replaceState(null, "", url);
            } else if (url.searchParams.get("landscape") === name) {
              url.searchParams.delete("landscape");
              window.history.replaceState(null, "", url);
            }
          });
        }

        for (const jump of landscapeGrid.querySelectorAll("a[data-catalog-target]")) {
          jump.addEventListener("click", () => {
            const targetName = jump.dataset.catalogTarget;
            if (searchInput) {
              searchInput.value = targetName;
              applyExtensionFilters();
            }
            const targetDetails = document.getElementById("extension-" + targetName);
            if (targetDetails) targetDetails.open = true;
          });
        }
      }

      const currentUrl = new URL(window.location.href);
      const extParam = currentUrl.searchParams.get("extension");
      const hashMatch = /^#extension-(.+)$/.exec(currentUrl.hash || "");
      const extToOpen = extParam || (hashMatch ? hashMatch[1] : null);
      if (extToOpen) {
        const el = document.getElementById("extension-" + extToOpen);
        if (el) el.open = true;
      }
      const landParam = currentUrl.searchParams.get("landscape");
      if (landParam) {
        const el = document.getElementById("landscape-" + landParam);
        if (el) el.open = true;
      }

      if (searchInput) searchInput.addEventListener("input", applyExtensionFilters);
      if (pgFilter) pgFilter.addEventListener("change", applyExtensionFilters);
      if (landscapeSearch) landscapeSearch.addEventListener("input", applyLandscapeFilters);
      if (landscapeFilter) landscapeFilter.addEventListener("change", applyLandscapeFilters);
      if (landscapeSourceFilter) landscapeSourceFilter.addEventListener("change", applyLandscapeFilters);
    }

    wireInteractions();

    fetch(filtersUrl)
      .then((response) => {
        if (!response.ok) throw new Error(`Filter index HTTP ${response.status}`);
        return response.json();
      })
      .then((payload) => {
        filtersData = payload;
        const effectiveDate = getUtcCalendarDate(new Date());
        if (effectiveDate) {
          updateLifecycleDom(effectiveDate, payload.postgresqlLifecycle || {});
        }
        applyExtensionFilters();
        applyLandscapeFilters();
      })
      .catch((error) => {
        console.warn("Filter payload unavailable; static HTML remains readable:", error);
      });
  }

  if (typeof document !== "undefined") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", initDom);
    } else {
      initDom();
    }
  }

  return {
    formatCalendarDate,
    getLifecycleStatus,
    getUtcCalendarDate,
    isValidCalendarDate,
    nextCalendarDate,
    filterExtensions,
    filterLandscape
  };
});
