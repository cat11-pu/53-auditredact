// redact.js：脱敏核心。
// 语义约定：
// - 前缀规则 {prefix, digits}：前缀之后恰好 digits 个 token 字符（[0-9A-Za-z]）且后接非 token 边界时，
//   把这固定位数替换成等长掩码；占位值（各位全部相同，如 9999、####）跳过——
//   这既避免误掩测试占位值，也让已脱敏文本天然幂等（掩码字符不会成为下一轮命中）。
// - 邮箱规则 {kind:"mail", local}：保留 local 前 local 位，其余替换成等长掩码；local 不够长则不动、不计命中。
// - 白名单片段整体原样保留，与任何规则冲突时白名单优先（不做部分替换）。
// - 预算：白名单合并成一个正则扫一遍，所有规则合并成一个正则再扫一遍；
//   全程 O(文本长度)，十万字符不会对每条规则重扫全文。
// - 规则缺前缀或缺必要字段抛 E_BAD_RULE，绝不做整体替换。

const DEFAULT_MASK = "#";
const TOKEN_CLASS = "[0-9A-Za-z]";
const MAIL_SOURCE = "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}";

export class RedactError extends Error {
  constructor(detail) {
    super("E_BAD_RULE " + detail);
    this.code = "E_BAD_RULE";
  }
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function allSame(s) {
  for (let i = 1; i < s.length; i++) if (s[i] !== s[0]) return false;
  return true;
}

function normalizeRules(rules) {
  if (!Array.isArray(rules)) throw new RedactError("rules 必须是数组");
  return rules.map((rule, index) => {
    if (!rule || typeof rule !== "object") throw new RedactError("规则 " + index + " 不是对象");
    const mask = rule.mask === undefined ? DEFAULT_MASK : rule.mask;
    if (typeof mask !== "string" || mask.length !== 1) {
      throw new RedactError("规则 " + index + " 的 mask 必须是单字符");
    }
    const kind = rule.kind === undefined ? "prefix" : rule.kind;
    if (kind === "prefix") {
      if (typeof rule.prefix !== "string" || rule.prefix.length === 0) {
        throw new RedactError("规则 " + index + " 缺前缀 prefix");
      }
      if (!Number.isInteger(rule.digits) || rule.digits < 1) {
        throw new RedactError("规则 " + index + " 缺固定位数 digits");
      }
      return { kind, prefix: rule.prefix, digits: rule.digits, mask };
    }
    if (kind === "mail") {
      if (!Number.isInteger(rule.local) || rule.local < 0) {
        throw new RedactError("规则 " + index + " 缺 local 保留位数");
      }
      return { kind, local: rule.local, mask };
    }
    throw new RedactError("规则 " + index + " 未知类型 " + kind);
  });
}

function whitelistOf(whitelist) {
  if (!Array.isArray(whitelist)) return [];
  return whitelist.filter((w) => typeof w === "string" && w.length > 0);
}

// 第一遍：白名单合并成单个正则扫一次，产出保护区间（合并重叠）与 kept 列表。
function scanWhitelist(source, entries) {
  const intervals = [];
  const kept = [];
  if (entries.length === 0) return { intervals, kept };
  const re = new RegExp(entries.map(escapeRe).join("|"), "g");
  let m;
  while ((m = re.exec(source)) !== null) {
    const start = m.index;
    const end = start + m[0].length;
    kept.push(m[0]);
    const last = intervals[intervals.length - 1];
    if (last && start <= last[1]) last[1] = Math.max(last[1], end);
    else intervals.push([start, end]);
  }
  return { intervals, kept };
}

// 所有规则合并成一个正则：第 i 条规则对应第 i+1 个捕获组。
function buildRuleRegex(rules) {
  const parts = rules.map((rule) => {
    if (rule.kind === "prefix") {
      return "(" + escapeRe(rule.prefix) + TOKEN_CLASS + "{" + rule.digits + "}(?!" + TOKEN_CLASS + "))";
    }
    return "(" + MAIL_SOURCE + ")";
  });
  if (parts.length === 0) return null;
  return new RegExp(parts.join("|"), "g");
}

export function apply(text, rules, whitelist) {
  const normalized = normalizeRules(rules);
  const source = String(text);
  const entries = whitelistOf(whitelist);
  const { intervals, kept } = scanWhitelist(source, entries);

  const hits = normalized.map(() => 0);
  const edits = [];
  const re = buildRuleRegex(normalized);
  if (re) {
    let m;
    let guard = 0;
    while ((m = re.exec(source)) !== null) {
      let ruleIndex = -1;
      for (let g = 0; g < normalized.length; g++) {
        if (m[g + 1] !== undefined) { ruleIndex = g; break; }
      }
      if (ruleIndex < 0) continue;
      const start = m.index;
      const end = start + m[0].length;
      // 白名单优先：与保护区间有任何重叠就整体跳过，不做部分替换。
      while (guard < intervals.length && intervals[guard][1] <= start) guard++;
      if (guard < intervals.length && intervals[guard][0] < end) continue;

      const rule = normalized[ruleIndex];
      if (rule.kind === "prefix") {
        const body = m[0].slice(rule.prefix.length);
        if (body.indexOf(rule.mask) !== -1) continue; // 已脱敏
        if (body.length > 1 && allSame(body)) continue; // 占位值（如 9999）
        edits.push([start + rule.prefix.length, end, rule.mask.repeat(rule.digits)]);
        hits[ruleIndex]++;
      } else {
        const at = m[0].lastIndexOf("@");
        const local = m[0].slice(0, at);
        if (local.length <= rule.local) continue; // 不够长，无需掩
        if (local.indexOf(rule.mask) !== -1) continue; // 已脱敏
        const masked = local.slice(0, rule.local) + rule.mask.repeat(local.length - rule.local);
        edits.push([start, start + at, masked]);
        hits[ruleIndex]++;
      }
    }
  }

  let out = "";
  let cursor = 0;
  for (const [s, e, rep] of edits) {
    out += source.slice(cursor, s) + rep;
    cursor = e;
  }
  out += source.slice(cursor);
  return { text: out, hits, kept };
}
