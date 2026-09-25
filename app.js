// app.js：渲染结果
import { apply } from "./redact.js";
import { verify } from "./checks.js";

export function render(spec) {
  const rules = (spec.rules || []).map((rule) =>
    rule && rule.mask === undefined && typeof spec.mask === "string" ? { ...rule, mask: spec.mask } : rule);
  const result = apply(spec.text, rules, spec.whitelist || []);
  const checked = verify(spec.text, result.text, spec.whitelist || [], rules);
  return { text: result.text, hits: result.hits, kept: result.kept,
           idempotent: checked.idempotent, length_preserved: checked.length_preserved,
           kept_count: checked.kept.length };
}
