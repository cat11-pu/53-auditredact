// redact.js：脱敏（基线：整段替换、不看规则）
export function apply(text, rules, whitelist) {
  return { text: text, hits: rules.map(() => 0), kept: [] };
}
