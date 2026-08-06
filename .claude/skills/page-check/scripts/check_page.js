#!/usr/bin/env node
/**
 * HTML 페이지를 5가지 관점(title / 내부 링크 / img alt / viewport / UTF-8 인코딩)으로
 * 점검하고 사람이 읽기 좋은 한국어 리포트를 stdout에 출력한다.
 *
 * 사용법:
 *   node check_page.js <파일 또는 디렉터리> [<추가 경로> ...]
 *   node check_page.js                 // 인자 없으면 현재 디렉터리의 *.html을 재귀적으로 검사
 */
const fs = require("fs");
const path = require("path");

const SKIP_DIRS = new Set([".git", "node_modules", ".claude"]);

function findHtmlFiles(paths) {
  const files = [];
  const targets = paths.length ? paths : ["."];

  function walk(dir) {
    for (const name of fs.readdirSync(dir)) {
      const full = path.join(dir, name);
      const stat = fs.statSync(full);
      if (stat.isDirectory()) {
        if (!SKIP_DIRS.has(name)) walk(full);
      } else if (/\.(html?|HTML?)$/.test(name)) {
        files.push(full);
      }
    }
  }

  for (const p of targets) {
    if (!fs.existsSync(p)) continue;
    const stat = fs.statSync(p);
    if (stat.isDirectory()) walk(p);
    else files.push(p);
  }

  return [...new Set(files.map((f) => path.normalize(f)))].sort();
}

// attrs 문자열 "name=\"viewport\" content='x'" -> {name: 'viewport', content: 'x'}
function parseAttrs(attrStr) {
  const attrs = {};
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*("([^"]*)"|'([^']*)'|[^\s"'=<>`]+))?/g;
  let m;
  while ((m = re.exec(attrStr))) {
    const key = m[1].toLowerCase();
    const val = m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : m[2] !== undefined ? m[2] : "";
    attrs[key] = val;
  }
  return attrs;
}

function lineOf(text, index) {
  return text.slice(0, index).split("\n").length;
}

function checkFile(filePath) {
  const critical = [];
  const warning = [];
  const suggestion = [];

  const raw = fs.readFileSync(filePath);
  let text;
  let decodeOk = true;
  try {
    text = raw.toString("utf-8");
    if (raw.toString("utf-8") !== raw.toString("latin1") && raw.includes(0xef) === false) {
      // no-op, utf-8 decode in Node doesn't throw; validated below via byte check
    }
  } catch (e) {
    decodeOk = false;
    text = raw.toString("utf-8");
  }
  // Node's toString('utf-8') never throws; detect invalid sequences via replacement char.
  if (text.includes("�")) decodeOk = false;

  // <title>
  const titleMatch = text.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!titleMatch) {
    warning.push("<title> 태그가 아예 없습니다. 브라우저 탭/북마크/검색결과에 파일명이나 빈 제목이 노출됩니다.");
  } else if (!titleMatch[1].trim()) {
    warning.push("<title> 태그는 있지만 내용이 비어 있습니다.");
  }

  // <img> without alt
  const imgRe = /<img\b([^>]*)>/gi;
  const missingAltLines = [];
  let im;
  while ((im = imgRe.exec(text))) {
    const attrs = parseAttrs(im[1]);
    if (!("alt" in attrs)) missingAltLines.push(lineOf(text, im.index));
  }
  if (missingAltLines.length) {
    warning.push(
      `alt 속성이 없는 <img> 태그가 ${missingAltLines.length}개 있습니다 (줄: ${missingAltLines.join(", ")}). ` +
        "스크린 리더 사용자가 이미지 내용을 알 수 없습니다."
    );
  }

  // <meta> tags
  const metaRe = /<meta\b([^>]*)>/gi;
  const metas = [];
  let mm;
  while ((mm = metaRe.exec(text))) metas.push(parseAttrs(mm[1]));

  const hasViewport = metas.some((m) => (m.name || "").toLowerCase() === "viewport");
  if (!hasViewport) {
    critical.push(
      '<meta name="viewport" content="width=device-width, initial-scale=1.0"> 가 없습니다. ' +
        "모바일 브라우저에서 데스크톱 레이아웃으로 축소되어 보입니다."
    );
  }

  const hasUtf8Meta = metas.some((m) => {
    if (m.charset && m.charset.trim().toLowerCase() === "utf-8") return true;
    if ((m["http-equiv"] || "").toLowerCase() === "content-type" && /utf-8/i.test(m.content || "")) return true;
    return false;
  });
  const hasNonAscii = [...text].some((c) => c.codePointAt(0) > 127);

  if (!decodeOk) {
    critical.push("파일이 올바른 UTF-8로 저장되어 있지 않습니다. 한글이 깨질 수 있습니다.");
  } else if (!hasUtf8Meta && hasNonAscii) {
    critical.push(
      '<meta charset="UTF-8">가 없는데 한글 등 비-ASCII 문자가 포함되어 있습니다. ' +
        "다른 환경/서버에서 한글이 깨져 보일 수 있습니다."
    );
  } else if (!hasUtf8Meta) {
    suggestion.push(
      '<meta charset="UTF-8">를 <head> 맨 앞에 추가하는 것을 권장합니다 (지금은 비-ASCII 문자가 없어 당장 문제는 없습니다).'
    );
  }

  // ids on the page (for fragment link checks)
  const ids = new Set();
  const idRe = /\bid\s*=\s*("([^"]*)"|'([^']*)')/gi;
  let idm;
  while ((idm = idRe.exec(text))) ids.add(idm[2] !== undefined ? idm[2] : idm[3]);

  // <a href="..."> broken internal links
  const baseDir = path.dirname(path.resolve(filePath));
  const linkRe = /<a\b([^>]*)>/gi;
  const broken = [];
  let lm;
  while ((lm = linkRe.exec(text))) {
    const attrs = parseAttrs(lm[1]);
    const href = attrs.href;
    if (!href) continue;
    const h = href.trim();
    if (!h || /^(https?:|mailto:|tel:|javascript:|data:)/i.test(h)) continue;
    const line = lineOf(text, lm.index);
    if (h.startsWith("#")) {
      const frag = h.slice(1);
      if (frag && !ids.has(frag)) broken.push([line, href, `페이지 내 #${frag} 앵커를 찾을 수 없음`]);
      continue;
    }
    const target = h.split("#")[0].split("?")[0];
    if (!target) continue;
    const targetPath = path.normalize(path.join(baseDir, decodeURIComponent(target)));
    if (!fs.existsSync(targetPath)) broken.push([line, href, `파일을 찾을 수 없음: ${target}`]);
  }
  if (broken.length) {
    const detail = broken.map(([ln, h, why]) => `${ln}줄 href="${h}" (${why})`).join("; ");
    critical.push(`깨진 내부 링크 ${broken.length}개 발견: ${detail}`);
  }

  return { critical, warning, suggestion };
}

function formatReport(filePath, result) {
  const lines = [`## ${filePath}`];
  const total = result.critical.length + result.warning.length + result.suggestion.length;
  if (total === 0) {
    lines.push("문제 없음 — 5가지 항목 모두 통과했습니다. ✅");
    return lines.join("\n");
  }
  for (const item of result.critical) lines.push(`- 🔴 심각: ${item}`);
  for (const item of result.warning) lines.push(`- 🟡 주의: ${item}`);
  for (const item of result.suggestion) lines.push(`- 🟢 제안: ${item}`);
  return lines.join("\n");
}

function main() {
  const paths = process.argv.slice(2);
  const files = findHtmlFiles(paths);
  if (!files.length) {
    console.log("검사할 HTML 파일을 찾지 못했습니다.");
    process.exit(1);
  }
  for (const f of files) {
    const result = checkFile(f);
    console.log(formatReport(f, result));
    console.log("");
  }
}

main();
