// app.js：渲染结果
import { apply } from "./redact.js";
import { verify } from "./checks.js";

export function render(spec) {
  const result = apply(spec.text, spec.rules, spec.whitelist || []);
  const checked = verify(spec.text, result.text, spec.whitelist || [], spec.rules);
  return { text: result.text, hits: result.hits, kept: result.kept,
           idempotent: checked.idempotent, length_preserved: checked.length_preserved,
           kept_count: checked.kept.length };
}
