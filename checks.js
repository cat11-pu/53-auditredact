// checks.js：白名单保留校验 + 幂等判定 + 长度模式判定。
import { apply } from "./redact.js";

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function verify(before, after, whitelist, rules) {
  const entries = (Array.isArray(whitelist) ? whitelist : [])
    .filter((w) => typeof w === "string" && w.length > 0);
  const kept = [];
  if (entries.length > 0) {
    const re = new RegExp(entries.map(escapeRe).join("|"), "g");
    let m;
    while ((m = re.exec(before)) !== null) {
      const frag = m[0];
      // 长度不变时按原偏移核对片段是否原样保留；否则退化为包含判断。
      const intact = after.length === before.length
        ? after.slice(m.index, m.index + frag.length) === frag
        : after.indexOf(frag) !== -1;
      if (intact) kept.push(frag);
    }
  }
  let idempotent = false;
  try {
    idempotent = apply(after, rules, whitelist).text === after;
  } catch (e) {
    idempotent = false;
  }
  return { kept, idempotent, length_preserved: before.length === after.length };
}
