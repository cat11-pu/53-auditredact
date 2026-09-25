// redact.js：脱敏（合并规则单次线性扫描，白名单优先，幂等，长度保持）
const DEFAULT_MASK = "#";
const TOKEN_CHAR = "[\\w#*]";
const MAIL_SOURCE = "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}";

export class RedactError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "RedactError";
    this.code = code;
  }
}

function badRule(detail) {
  throw new RedactError("E_BAD_RULE", "E_BAD_RULE: " + detail);
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// 已脱敏串或占位串（如 ####、9999）是统一字符序列，跳过以保证幂等。
function isUniform(text) {
  if (text.length < 2) return false;
  for (let index = 1; index < text.length; index += 1) {
    if (text[index] !== text[0]) return false;
  }
  return true;
}

function maskOf(rule) {
  const mask = typeof rule.mask === "string" && rule.mask.length > 0 ? rule.mask : DEFAULT_MASK;
  return mask[0];
}

function compileRule(rule, index) {
  if (!rule || typeof rule !== "object") badRule("第 " + index + " 条规则不是对象");
  const kind = rule.kind === undefined ? "prefix" : rule.kind;
  if (kind === "mail") {
    if (!Number.isInteger(rule.local) || rule.local < 0) badRule("邮箱规则缺 local 保留位数");
    return { kind: "mail", local: rule.local, mask: maskOf(rule), source: "(" + MAIL_SOURCE + ")" };
  }
  if (kind === "prefix") {
    if (typeof rule.prefix !== "string" || rule.prefix.length === 0) badRule("前缀规则缺 prefix");
    if (!Number.isInteger(rule.digits) || rule.digits <= 0) badRule("前缀规则缺 digits 位数");
    return { kind: "prefix", prefix: rule.prefix, digits: rule.digits, mask: maskOf(rule),
      source: "(" + escapeRegExp(rule.prefix) + TOKEN_CHAR + "{" + rule.digits + "}(?!" + TOKEN_CHAR + "))" };
  }
  badRule("未知规则类型 " + String(kind));
}

export function apply(text, rules, whitelist) {
  const source = String(text);
  const white = (Array.isArray(whitelist) ? whitelist : [])
    .filter((item) => typeof item === "string" && item.length > 0)
    .sort((a, b) => b.length - a.length);
  const compiled = (Array.isArray(rules) ? rules : []).map(compileRule);
  const hits = compiled.map(() => 0);

  // 第一遍：白名单整体定位，受保护区间任何规则都不得触碰。
  const protectedSpans = [];
  const kept = [];
  const seen = new Set();
  if (white.length > 0) {
    const whiteRe = new RegExp(white.map((item) => "(" + escapeRegExp(item) + ")").join("|"), "g");
    let match;
    while ((match = whiteRe.exec(source)) !== null) {
      protectedSpans.push([match.index, match.index + match[0].length]);
      for (let group = 0; group < white.length; group += 1) {
        if (match[group + 1] !== undefined && !seen.has(white[group])) {
          seen.add(white[group]);
          kept.push(white[group]);
        }
      }
    }
  }

  // 第二遍：所有规则合并成一个正则一次扫完，不逐条规则重扫全文。
  if (compiled.length === 0) return { text: source, hits: hits, kept: kept };
  const ruleRe = new RegExp(compiled.map((rule) => rule.source).join("|"), "g");
  const edits = [];
  let match;
  let spanIndex = 0;
  while ((match = ruleRe.exec(source)) !== null) {
    const start = match.index;
    const end = start + match[0].length;
    while (spanIndex < protectedSpans.length && protectedSpans[spanIndex][1] <= start) spanIndex += 1;
    if (spanIndex < protectedSpans.length && protectedSpans[spanIndex][0] < end) continue;
    let ruleIndex = -1;
    for (let group = 0; group < compiled.length; group += 1) {
      if (match[group + 1] !== undefined) { ruleIndex = group; break; }
    }
    const rule = compiled[ruleIndex];
    if (rule.kind === "prefix") {
      const region = match[0].slice(rule.prefix.length);
      if (isUniform(region)) continue;
      edits.push([start + rule.prefix.length, end, rule.mask.repeat(region.length)]);
      hits[ruleIndex] += 1;
    } else {
      const at = match[0].indexOf("@");
      if (at <= rule.local) continue;
      const rest = match[0].slice(rule.local, at);
      if (isUniform(rest)) continue;
      edits.push([start + rule.local, start + at, rule.mask.repeat(rest.length)]);
      hits[ruleIndex] += 1;
    }
  }

  if (edits.length === 0) return { text: source, hits: hits, kept: kept };
  let out = "";
  let cursor = 0;
  for (const edit of edits) {
    out += source.slice(cursor, edit[0]) + edit[2];
    cursor = edit[1];
  }
  out += source.slice(cursor);
  return { text: out, hits: hits, kept: kept };
}
