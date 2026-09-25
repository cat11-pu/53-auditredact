// checks.js：白名单与幂等（基线：不校验、不判幂等）
export function verify(before, after, whitelist, rules) {
  return { kept: [], idempotent: false, length_preserved: false };
}
