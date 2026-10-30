import test from "node:test";
import assert from "node:assert/strict";
import { isTotalGlob, matchesAny } from "./glob.js";

const m = (p: string, g: string) => matchesAny(p, [g]);

test("* stays within one segment, ** crosses them", () => {
  assert.equal(m("a.log", "*.log"), true);
  assert.equal(m("x/a.log", "*.log"), false, "anchored: * does not cross a slash");
  assert.equal(m("x/y/a.log", "**/*.log"), true);
  assert.equal(m("a.log", "**/*.log"), true, "** may match zero segments");
});

test("a trailing /** or / means the directory and everything under it", () => {
  assert.equal(m("wp-content/cache/a/b.html", "wp-content/cache/**"), true);
  assert.equal(m("wp-content/cache", "wp-content/cache/**"), true, "the directory itself, so it can be skipped");
  assert.equal(m("wp-content/cached/a", "wp-content/cache/**"), false, "a name that merely starts the same");
  assert.equal(m("uploads/a.php", "uploads/"), true);
});

test("regex metacharacters in a pattern are literal", () => {
  assert.equal(m("a.b", "a.b"), true);
  assert.equal(m("axb", "a.b"), false);
  assert.equal(m("a+b(1).txt", "a+b(1).txt"), true);
  assert.equal(m("ab", "a?"), true);
  assert.equal(m("a/b", "a?b"), false);
});

test("a pattern that would match every file is recognised", () => {
  for (const g of ["**", "**/*", "/", "", "**/**"]) assert.equal(isTotalGlob(g), true, JSON.stringify(g));
  for (const g of ["*.log", "cache/**", "**/*.log"]) assert.equal(isTotalGlob(g), false, g);
});

test("patterns that start with **/ match at the root and at any depth, as Django's defaults rely on", () => {
  assert.equal(m("__pycache__/x.pyc", "**/__pycache__/**"), true);
  assert.equal(m("app/__pycache__", "**/__pycache__/**"), true, "the directory itself, so it can be skipped");
  assert.equal(m("a/b/__pycache__/x.pyc", "**/__pycache__/**"), true);
  assert.equal(m("app/pycache/x.py", "**/__pycache__/**"), false);
  assert.equal(m("db.sqlite3", "**/*.sqlite3"), true);
  assert.equal(m("a/b/c.sqlite3", "**/*.sqlite3"), true);
  assert.equal(m("a/db.sqlite3.bak", "**/*.sqlite3"), false);
  assert.equal(m("x/.venv/lib/site.py", "**/.venv/**"), true);
});
