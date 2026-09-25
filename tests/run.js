import assert from "node:assert";
import { apply } from "../redact.js";
import { verify } from "../checks.js";
import { render } from "../app.js";

let failed = 0;
function check(name, fn) {
  try { fn(); console.log("ok " + name); } catch (e) { failed += 1; console.log("FAIL " + name + " :: " + e.message); }
}

const rules = [{ id: "r0", prefix: "tok_", digits: 4 }];

check("apply returns text", () => {
  assert.strictEqual(typeof apply("tok_1234", rules, []).text, "string");
});

check("apply reports hits", () => {
  assert.ok(Array.isArray(apply("tok_1234", rules, []).hits));
});

check("verify reports idempotent", () => {
  assert.strictEqual(typeof verify("a", "a", [], rules).idempotent, "boolean");
});

check("verify reports kept", () => {
  assert.ok(Array.isArray(verify("a", "a", [], rules).kept));
});

check("render exposes kept_count", () => {
  assert.strictEqual(typeof render({ text: "a", rules: rules, whitelist: [] }).kept_count, "number");
});

console.log("5 cases, " + failed + " failed");
process.exit(failed === 0 ? 0 : 1);
