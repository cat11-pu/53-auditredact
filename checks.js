// checks.js：白名单保留核对与幂等、长度判定
import { apply } from "./redact.js";

export function verify(before, after, whitelist, rules) {
  const prior = String(before);
  const later = String(after);
  const white = (Array.isArray(whitelist) ? whitelist : [])
    .filter((item) => typeof item === "string" && item.length > 0);
  const kept = [];
  const seen = new Set();
  for (const item of white) {
    if (!seen.has(item) && prior.includes(item) && later.includes(item)) {
      seen.add(item);
      kept.push(item);
    }
  }
  let idempotent = false;
  try {
    idempotent = apply(later, rules, white).text === later;
  } catch (error) {
    idempotent = false;
  }
  return { kept: kept, idempotent: idempotent, length_preserved: prior.length === later.length };
}
