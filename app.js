// app.js：渲染结果（返回结构固定为 text/hits/kept/idempotent/length_preserved/kept_count 六键）
import { apply } from "./redact.js";
import { verify } from "./checks.js";

export function render(spec) {
  // 顶层 mask 作为各规则的默认掩码字符，规则自带 mask 优先。
  const rules = (spec.rules || []).map((rule) =>
    spec.mask !== undefined && rule && rule.mask === undefined
      ? Object.assign({}, rule, { mask: spec.mask })
      : rule);
  const result = apply(spec.text, rules, spec.whitelist || []);
  const checked = verify(spec.text, result.text, spec.whitelist || [], rules);
  return { text: result.text, hits: result.hits, kept: result.kept,
           idempotent: checked.idempotent, length_preserved: checked.length_preserved,
           kept_count: checked.kept.length };
}
