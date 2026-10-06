import { DAYS, type DeployWindow } from "./config.js";

const hhmm = (s: string): number => Number(s.slice(0, 2)) * 60 + Number(s.slice(3, 5));

/** Day of week (0 = Sunday) and minutes since midnight, as seen on the wall clock of the given IANA zone. */
export function localParts(when: Date, timeZone: string): { day: number; minutes: number } {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone, weekday: "short", hour: "2-digit", minute: "2-digit", hourCycle: "h23",
  }).formatToParts(when);
  const get = (t: string) => parts.find((p) => p.type === t)?.value ?? "";
  const day = DAYS.indexOf(get("weekday").slice(0, 3).toLowerCase() as (typeof DAYS)[number]);
  return { day, minutes: Number(get("hour")) * 60 + Number(get("minute")) };
}

/**
 * Is this instant inside any deploy window, evaluated in the site's own time zone?
 * Start is inclusive, end is exclusive. A window whose end is earlier than its
 * start runs overnight, and belongs to the day it STARTS on: Mon 23:00 to 02:00
 * covers Tuesday 01:30 because Monday is in its days.
 *
 * A window is a statement about when deploys normally happen. It is not proof
 * that a given change was a deploy, and the orchestrator never treats it as such.
 */
export function isInDeployWindow(windows: DeployWindow[], when: Date, timeZone: string): boolean {
  const { day, minutes } = localParts(when, timeZone);
  const prevDay = (day + 6) % 7;
  return windows.some((w) => {
    const days = w.days.map((d) => DAYS.indexOf(d));
    const start = hhmm(w.start);
    const end = hhmm(w.end);
    if (start < end) return days.includes(day) && minutes >= start && minutes < end;
    return (days.includes(day) && minutes >= start) || (days.includes(prevDay) && minutes < end);
  });
}
