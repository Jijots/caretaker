import test from "node:test";
import assert from "node:assert/strict";
import { DeployWindow } from "./config.js";
import { isInDeployWindow, localParts } from "./deploy-window.js";

const win = (w: unknown) => [DeployWindow.parse(w)];
const office = win({ days: ["mon", "tue", "wed", "thu", "fri"], start: "09:00", end: "17:00" });
const at = (iso: string) => new Date(iso);
const MNL = "Asia/Manila"; // UTC+8, no DST. 2026-10-05 is a Monday.

test("localParts reads the wall clock of the site's own zone", () => {
  assert.deepEqual(localParts(at("2026-10-05T02:00:00Z"), MNL), { day: 1, minutes: 10 * 60 });
  assert.deepEqual(localParts(at("2026-10-05T02:00:00Z"), "UTC"), { day: 1, minutes: 2 * 60 });
  assert.deepEqual(localParts(at("2026-10-05T17:00:00Z"), MNL), { day: 2, minutes: 60 }, "crosses midnight into Tuesday");
});

test("inside and outside an office-hours window", () => {
  assert.equal(isInDeployWindow(office, at("2026-10-05T02:00:00Z"), MNL), true, "Mon 10:00 Manila");
  assert.equal(isInDeployWindow(office, at("2026-10-05T10:00:00Z"), MNL), false, "Mon 18:00 Manila");
  assert.equal(isInDeployWindow(office, at("2026-10-10T02:00:00Z"), MNL), false, "Saturday");
});

test("start is inclusive and end is exclusive", () => {
  assert.equal(isInDeployWindow(office, at("2026-10-05T01:00:00Z"), MNL), true, "09:00 exactly");
  assert.equal(isInDeployWindow(office, at("2026-10-05T00:59:00Z"), MNL), false, "08:59");
  assert.equal(isInDeployWindow(office, at("2026-10-05T08:59:00Z"), MNL), true, "16:59");
  assert.equal(isInDeployWindow(office, at("2026-10-05T09:00:00Z"), MNL), false, "17:00 exactly");
});

test("the same instant is judged in the site's zone, not the server's", () => {
  const t = at("2026-10-05T02:00:00Z");
  assert.equal(isInDeployWindow(office, t, MNL), true);
  assert.equal(isInDeployWindow(office, t, "UTC"), false);
});

test("an overnight window belongs to the day it starts on", () => {
  const night = win({ days: ["mon"], start: "23:00", end: "02:00" });
  assert.equal(isInDeployWindow(night, at("2026-10-05T15:30:00Z"), MNL), true, "Mon 23:30");
  assert.equal(isInDeployWindow(night, at("2026-10-05T17:30:00Z"), MNL), true, "Tue 01:30 still belongs to Monday's window");
  assert.equal(isInDeployWindow(night, at("2026-10-05T18:00:00Z"), MNL), false, "Tue 02:00 exactly");
  assert.equal(isInDeployWindow(night, at("2026-10-06T15:30:00Z"), MNL), false, "Tue 23:30, Tuesday is not in days");
  assert.equal(isInDeployWindow(night, at("2026-10-04T17:30:00Z"), MNL), false, "Mon 01:30, the window has not started yet");
});

test("any of several windows counts", () => {
  const two = [...win({ days: ["sat"], start: "10:00", end: "11:00" }), ...office];
  assert.equal(isInDeployWindow(two, at("2026-10-10T02:30:00Z"), MNL), true, "Saturday 10:30");
  assert.equal(isInDeployWindow([], at("2026-10-05T02:00:00Z"), MNL), false, "no windows means never inside one");
});

test("daylight saving is handled by the zone rules, not by hand", () => {
  // US clocks jumped forward on Sunday 2026-03-08. 07:30Z is 03:30 EDT, a time that did not exist an hour earlier.
  const w = win({ days: ["sun"], start: "03:00", end: "04:00" });
  assert.equal(isInDeployWindow(w, at("2026-03-08T07:30:00Z"), "America/New_York"), true);
  assert.equal(isInDeployWindow(w, at("2026-03-08T06:30:00Z"), "America/New_York"), false, "06:30Z is 01:30 EST");
});

test("a window schema refuses start == end and malformed times", () => {
  assert.equal(DeployWindow.safeParse({ days: ["mon"], start: "09:00", end: "09:00" }).success, false);
  assert.equal(DeployWindow.safeParse({ days: ["mon"], start: "9:00", end: "17:00" }).success, false);
  assert.equal(DeployWindow.safeParse({ days: ["mon"], start: "09:00", end: "24:00" }).success, false);
  assert.equal(DeployWindow.safeParse({ days: [], start: "09:00", end: "17:00" }).success, false);
});
