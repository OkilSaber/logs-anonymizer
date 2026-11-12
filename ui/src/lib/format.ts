export function bytes(n: number): string {
  if (n < 1024) return `${n} o`;
  const units = ["Ko", "Mo", "Go", "To"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)} ${units[i]}`;
}

/** Débit : « 3,4 Mo/s ». */
export function speed(bytesPerSecond: number): string {
  return `${bytes(Math.max(0, Math.round(bytesPerSecond)))}/s`;
}

/** Durée courte : « 8 s », « 2 min 05 s », « 1 h 12 min ». */
export function duration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${String(s % 60).padStart(2, "0")} s`;
  return `${Math.floor(s / 3600)} h ${String(Math.floor((s % 3600) / 60)).padStart(2, "0")} min`;
}

/**
 * Débit lissé d'une grandeur cumulée (octets, entrées). Un nouvel échantillon n'est pris
 * qu'après 250 ms, puis mélangé au débit précédent pour que l'affichage ne saute pas.
 */
export class Rate {
  private t = 0;
  private v = 0;
  private started = false;
  value = 0;

  reset() {
    this.started = false;
    this.value = 0;
  }

  push(total: number, now: number) {
    if (!this.started) {
      [this.t, this.v, this.started] = [now, total, true];
      return;
    }
    const dt = (now - this.t) / 1000;
    if (dt < 0.25) return;
    const instant = Math.max(0, total - this.v) / dt;
    this.value = this.value ? this.value * 0.6 + instant * 0.4 : instant;
    [this.t, this.v] = [now, total];
  }
}

export function count(n: number): string {
  return n.toLocaleString("fr-FR");
}

export function percent(part: number, total: number): string {
  return total > 0 ? `${((part / total) * 100).toFixed(part / total < 0.1 ? 1 : 0)} %` : "0 %";
}

export function isoDay(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

export type DayRange = { from: string; to: string };

/** Jours couverts par des plages, triés et sans doublon. Une plage à l'envers est remise à l'endroit. */
export function expandDays(ranges: DayRange[]): string[] {
  const days = new Set<string>();
  for (const r of ranges) {
    if (!r.from || !r.to) continue;
    const [a, b] = r.from <= r.to ? [r.from, r.to] : [r.to, r.from];
    const d = new Date(`${a}T12:00:00`);
    const end = new Date(`${b}T12:00:00`);
    for (let i = 0; d <= end && i < 400; i++) {
      days.add(isoDay(d));
      d.setDate(d.getDate() + 1);
    }
  }
  return [...days].sort();
}

/** Regroupe des jours triés en plages de jours consécutifs. */
export function toRanges(days: string[]): DayRange[] {
  const ranges: DayRange[] = [];
  for (const day of [...days].sort()) {
    const last = ranges[ranges.length - 1];
    const next = last && new Date(`${last.to}T12:00:00`);
    next?.setDate(next.getDate() + 1);
    if (last && next && isoDay(next) === day) last.to = day;
    else ranges.push({ from: day, to: day });
  }
  return ranges;
}

/** `2026-11-09` → `09/11/2026` */
export function frDay(day: string): string {
  const [y, m, d] = day.split("-");
  return `${d}/${m}/${y}`;
}

/** Résumé d'une liste de jours triés : « 09/11/2026 » ou « 7 jours, du 03/11/2026 au 09/11/2026 ». */
export function daysLabel(days: string[]): string {
  if (!days.length) return "aucun jour";
  if (days.length === 1) return frDay(days[0]);
  return `${days.length} jours, du ${frDay(days[0])} au ${frDay(days[days.length - 1])}`;
}

export function daysAgo(n: number): string {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return isoDay(d);
}
