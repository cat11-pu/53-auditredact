import fs from "node:fs";
import { apply } from "./redact.js";
import { verify } from "./checks.js";
import { render } from "./app.js";

// 验收断言：上面每条值收进 emit，最后与期望值逐项比对，不符就非零退出。
const __lines = [];
function emit(label, value) { __lines.push([String(label).replace(/ =$/, ""), value]); }


const spec = JSON.parse(fs.readFileSync(process.argv[2] || "sample/redact.json", "utf8"));
const result = apply(spec.text, spec.rules, spec.whitelist || []);
const checked = verify(spec.text, result.text, spec.whitelist || [], spec.rules);
const view = render(spec);

emit("脱敏后的文本 =", result.text);
emit("每条规则的命中数 =", JSON.stringify(result.hits));
emit("白名单保留的片段 =", JSON.stringify(checked.kept));
emit("重复脱敏是否幂等 =", checked.idempotent);
emit("长度模式是否保留 =", checked.length_preserved);
emit("保留片段数 =", view.kept_count);
emit("规则非法的错误码 =", spec.bad_rule_code);


// ---- 期望值（参考模型算出，与题面给的验收数值一致）----
const EXPECTED = {
  "脱敏后的文本": "user=tok_#### mail=a@b.com tok_9999 keepme@corp.com",
  "每条规则的命中数": [
    1,
    0
  ],
  "白名单保留的片段": [
    "keepme@corp.com"
  ],
  "重复脱敏是否幂等": true,
  "长度模式是否保留": true,
  "保留片段数": 1,
  "规则非法的错误码": "E_BAD_RULE"
};
let __bad = 0;
for (const [label, want] of Object.entries(EXPECTED)) {
  const found = __lines.find((pair) => pair[0] === label);
  if (!found) { __bad += 1; console.log("缺失验收项 " + label); continue; }
  const got = found[1];
  if (JSON.stringify(got) === JSON.stringify(want)) { console.log("一致 " + label + " = " + JSON.stringify(got)); }
  else { __bad += 1; console.log("不一致 " + label + " 期望 " + JSON.stringify(want) + " 实际 " + JSON.stringify(got)); }
}
console.log("验收项 " + (Object.keys(EXPECTED).length - __bad) + "/" + Object.keys(EXPECTED).length + " 通过");
process.exit(__bad === 0 ? 0 : 1);
