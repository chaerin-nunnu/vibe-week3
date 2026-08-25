#!/usr/bin/env node
/**
 * HTML 페이지를 5가지 관점(시크릿 노출 / 위험한 동작 / 개인정보 평문 노출 /
 * 금융·결제 정보 / 안전하지 않은 외부 접근)으로 점검하고
 * 사람이 읽기 좋은 한국어 리포트를 stdout에 출력한다.
 *
 * 사용법:
 *   node check_security.js <파일 또는 디렉터리> [<추가 경로> ...]
 *   node check_security.js                 // 인자 없으면 현재 디렉터리의 *.html을 재귀적으로 검사
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

function lineOf(text, index) {
  return text.slice(0, index).split("\n").length;
}

// 한국어 주격 조사(이/가) 자동 선택: 마지막 글자에 받침이 있으면 "이", 없으면 "가"
function eunI(word) {
  const code = word.codePointAt(word.length - 1);
  if (code >= 0xac00 && code <= 0xd7a3) {
    return (code - 0xac00) % 28 === 0 ? "가" : "이";
  }
  return "가";
}

// 실제 값처럼 보이는지 대략 걸러내기 위한 최소 길이/패턴
const SECRET_PATTERNS = [
  { re: /\b(api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret)\s*[:=]\s*["'`]([A-Za-z0-9_\-\/+]{12,})["'`]/gi, label: "API 키/시크릿 키로 보이는 값" },
  { re: /\b(password|passwd|pwd)\s*[:=]\s*["'`]([^"'`\s]{4,})["'`]/gi, label: "비밀번호로 보이는 값" },
  { re: /\b(token|auth[_-]?token|bearer)\s*[:=]\s*["'`]([A-Za-z0-9_\-\.]{12,})["'`]/gi, label: "인증 토큰으로 보이는 값" },
  { re: /AKIA[0-9A-Z]{16}/g, label: "AWS Access Key ID 패턴" },
  { re: /AIza[0-9A-Za-z_\-]{35}/g, label: "Google API 키 패턴" },
  { re: /sk-[A-Za-z0-9]{20,}/g, label: "OpenAI/서비스 비밀 키(sk-...) 패턴" },
  { re: /ghp_[A-Za-z0-9]{30,}/g, label: "GitHub Personal Access Token 패턴" },
];

const DANGEROUS_JS_PATTERNS = [
  { re: /\beval\s*\(/g, label: "eval() 사용 — 문자열을 코드로 실행하여 인젝션에 취약" },
  { re: /new\s+Function\s*\(/g, label: "new Function() 사용 — eval과 동일한 코드 인젝션 위험" },
  { re: /document\.write\s*\(/g, label: "document.write() 사용 — XSS 및 렌더링 문제 위험" },
  { re: /\.innerHTML\s*=(?!=)/g, label: "innerHTML 직접 대입 — 값이 사용자 입력을 포함하면 XSS 위험" },
  { re: /\bon\w+\s*=\s*["'][^"']*(location\.href|document\.cookie)[^"']*["']/gi, label: "인라인 이벤트 핸들러에서 쿠키/URL을 직접 조작" },
];

const PII_PATTERNS = [
  { re: /\b01[016789]-?\d{3,4}-?\d{4}\b/g, label: "휴대전화번호로 보이는 패턴" },
  { re: /\b\d{6}-?[1-4]\d{6}\b/g, label: "주민등록번호로 보이는 패턴" },
  { re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, label: "이메일 주소" },
];

const FINANCE_PATTERNS = [
  { re: /\b(?:\d[ -]?){13,16}\b/g, label: "카드번호로 보이는 13~16자리 숫자 패턴" },
  { re: /\b\d{2,6}-\d{2,6}-\d{2,10}\b/g, label: "은행 계좌번호로 보이는 패턴" },
];

function checkFile(filePath) {
  const critical = [];
  const warning = [];
  const suggestion = [];

  const text = fs.readFileSync(filePath, "utf-8");

  // 1. 시크릿 노출
  for (const { re, label } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    let m;
    const lines = new Set();
    while ((m = re.exec(text))) lines.add(lineOf(text, m.index));
    if (lines.size) {
      critical.push(`${label}${eunI(label)} 코드에 하드코딩되어 있습니다 (줄: ${[...lines].join(", ")}). 즉시 제거하고 환경변수/서버 측 비밀 저장소로 옮기세요.`);
    }
  }

  // 2. 위험한 동작
  for (const { re, label } of DANGEROUS_JS_PATTERNS) {
    re.lastIndex = 0;
    let m;
    const lines = new Set();
    while ((m = re.exec(text))) lines.add(lineOf(text, m.index));
    if (lines.size) {
      critical.push(`${label} (줄: ${[...lines].join(", ")}).`);
    }
  }

  // 3. 개인정보 평문 노출
  for (const { re, label } of PII_PATTERNS) {
    re.lastIndex = 0;
    let m;
    const lines = new Set();
    while ((m = re.exec(text))) lines.add(lineOf(text, m.index));
    if (lines.size) {
      warning.push(`${label}${eunI(label)} 페이지에 그대로 노출되어 있습니다 (줄: ${[...lines].join(", ")}). 실제 개인정보라면 삭제하거나 마스킹하세요.`);
    }
  }

  // 4. 금융/결제 정보
  for (const { re, label } of FINANCE_PATTERNS) {
    re.lastIndex = 0;
    let m;
    const lines = new Set();
    while ((m = re.exec(text))) lines.add(lineOf(text, m.index));
    if (lines.size) {
      critical.push(`${label}${eunI(label)} 페이지에 노출되어 있습니다 (줄: ${[...lines].join(", ")}). 실제 결제/계좌 정보라면 즉시 제거하세요.`);
    }
  }

  // 5. 안전하지 않은 외부 접근
  // 5-1. http:// 로 불러오는 외부 리소스 (mixed content)
  const httpResRe = /\b(?:src|href|action)\s*=\s*["']http:\/\/[^"']+["']/gi;
  {
    let m;
    const lines = new Set();
    while ((m = httpResRe.exec(text))) lines.add(lineOf(text, m.index));
    if (lines.size) {
      warning.push(`암호화되지 않은 http:// 리소스를 불러오고 있습니다 (줄: ${[...lines].join(", ")}). https://로 바꾸세요 (mixed content 위험).`);
    }
  }
  // 5-2. integrity 없는 외부 CDN 스크립트
  const scriptRe = /<script\b([^>]*)>/gi;
  {
    let m;
    const lines = [];
    while ((m = scriptRe.exec(text))) {
      const attrs = m[1];
      const srcMatch = attrs.match(/\bsrc\s*=\s*["']([^"']+)["']/i);
      if (!srcMatch) continue;
      const src = srcMatch[1];
      if (/^https?:\/\//i.test(src) && !/\bintegrity\s*=/.test(attrs)) {
        lines.push(lineOf(text, m.index));
      }
    }
    if (lines.length) {
      suggestion.push(`외부 CDN에서 불러오는 <script>에 integrity(Subresource Integrity) 속성이 없습니다 (줄: ${lines.join(", ")}). CDN이 변조되면 그대로 실행될 수 있어 integrity/crossorigin 추가를 권장합니다.`);
    }
  }
  // 5-3. 폼이 외부/미상 도메인 또는 비-https 로 개인정보를 제출
  const formRe = /<form\b([^>]*)>/gi;
  {
    let m;
    const lines = [];
    while ((m = formRe.exec(text))) {
      const attrs = m[1];
      const actionMatch = attrs.match(/\baction\s*=\s*["']([^"']*)["']/i);
      const action = actionMatch ? actionMatch[1] : "";
      if (/^http:\/\//i.test(action)) lines.push(lineOf(text, m.index));
    }
    if (lines.length) {
      critical.push(`<form>이 암호화되지 않은 http:// 주소로 데이터를 전송합니다 (줄: ${lines.join(", ")}). 입력값이 평문으로 전송되어 도청될 수 있습니다.`);
    }
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
