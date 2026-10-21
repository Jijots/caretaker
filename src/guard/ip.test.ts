import test from "node:test";
import assert from "node:assert/strict";
import { ipMatches, parseIp } from "./ip.js";

test("the same IPv6 address in different spellings is one address", () => {
  assert.equal(ipMatches("::1", "0:0:0:0:0:0:0:1"), true);
  assert.equal(ipMatches("2001:DB8::7", "2001:0db8:0000:0000:0000:0000:0000:0007"), true);
  assert.equal(ipMatches("[2001:db8::7]", "2001:db8::7"), true);
  assert.equal(ipMatches("2001:db8::7", "2001:db8::8"), false);
});

test("an IPv4 client seen through a dual-stack socket matches its IPv4 entry", () => {
  assert.equal(ipMatches("::ffff:203.0.113.7", "203.0.113.7"), true);
  assert.equal(ipMatches("::ffff:cb00:7107", "203.0.113.7"), true);
  assert.equal(ipMatches("203.0.113.7", "::ffff:203.0.113.7"), true);
  assert.equal(ipMatches("::ffff:203.0.113.8", "203.0.113.0/24"), true);
});

test("IPv6 ranges match by prefix", () => {
  assert.equal(ipMatches("2001:db8:1234::1", "2001:db8::/32"), true);
  assert.equal(ipMatches("2001:db9::1", "2001:db8::/32"), false);
  assert.equal(ipMatches("2001:db8::1", "2001:db8::1/128"), true);
  assert.equal(ipMatches("2001:db8::2", "2001:db8::1/128"), false);
  assert.equal(ipMatches("fe80::1", "::/0"), true);
  assert.equal(ipMatches("2001:db8:0:1::1", "2001:db8:0:2::/64"), false);
});

test("IPv4 ranges still work, including the edges", () => {
  assert.equal(ipMatches("10.200.1.1", "10.0.0.0/8"), true);
  assert.equal(ipMatches("11.0.0.1", "10.0.0.0/8"), false);
  assert.equal(ipMatches("1.2.3.4", "1.2.3.4/32"), true);
  assert.equal(ipMatches("1.2.3.5", "1.2.3.4/32"), false);
  assert.equal(ipMatches("8.8.8.8", "0.0.0.0/0"), true);
});

test("a family mismatch, a bad range and junk match nothing", () => {
  assert.equal(ipMatches("203.0.113.7", "2001:db8::/32"), false);
  assert.equal(ipMatches("2001:db8::1", "10.0.0.0/8"), false);
  for (const entry of ["10.0.0.0/33", "::/129", "10.0.0.0/", "10.0.0.0/8/8", "example.com", "10.0.0.0/-1", ""]) {
    assert.equal(ipMatches("10.0.0.1", entry), false, entry);
  }
  assert.equal(ipMatches("not-an-ip", "10.0.0.0/8"), false);
  assert.equal(parseIp("999.1.1.1"), null);
});
