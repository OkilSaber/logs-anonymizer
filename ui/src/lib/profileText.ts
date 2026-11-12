// Texte d'un profil, prêt à donner à une IA pour écrire ou améliorer un template.
// Il ne reprend que ce que l'écran affiche : formes masquées, noms de clés et comptes.
import type { Profile } from "./api";
import { bytes, count, frDay, percent } from "./format";

const MAX_SHAPES = 80;
const MAX_KEYS = 200;

export function profileText(p: Profile): string {
  const lines: string[] = [];
  lines.push(`Profil des logs de l'application ${p.app}, jour du ${frDay(p.day)}, anonymisés avec le template ${p.template}.`);
  lines.push("");
  lines.push("Ce profil ne contient aucune valeur réelle. Dans les formes d'entrées, les chaînes sont remplacées par \"…\" et les nombres par 0.");
  lines.push("Pour les clés, seule la forme des valeurs est donnée : a = minuscules, A = majuscules, 0 = chiffres, + = répétition, * = autre caractère.");
  lines.push("");
  lines.push(`${count(p.entries)} entrées, ${bytes(p.bytes)}, dont ${percent(p.filtered_bytes, p.bytes)} déjà retirés par les filtres du template.`);
  lines.push("");

  lines.push(`## Formes d'entrées les plus lourdes (${Math.min(MAX_SHAPES, p.shapes.length)} sur ${count(p.shapes_total)})`);
  lines.push("poids · nombre · niveau · forme · filtre qui la retire déjà");
  for (const s of p.shapes.slice(0, MAX_SHAPES)) {
    const shape = s.shape.replace(/\s+/g, " ").slice(0, 300);
    const filter = !s.filtered_by ? "" : s.filtered_count === s.count ? ` · déjà retirée par ${s.filtered_by}` : ` · retirée en partie par ${s.filtered_by} (${count(s.filtered_count)} sur ${count(s.count)})`;
    lines.push(`${percent(s.bytes, p.bytes)} · ${count(s.count)}× · [${s.level || "sans niveau"}] ${shape}${filter}`);
  }
  lines.push("");

  const clear = p.keys.filter((k) => k.count > k.replaced);
  lines.push(`## Clés qui gardent des valeurs en clair (${Math.min(MAX_KEYS, clear.length)} sur ${count(clear.length)})`);
  lines.push("clé · occurrences en clair / total · valeurs distinctes · formes des valeurs les plus fréquentes");
  for (const k of clear.slice(0, MAX_KEYS)) {
    const shapes = k.shapes.slice(0, 3).map((v) => `${v.shape} ×${count(v.count)}`).join(" | ");
    lines.push(`${k.path} · ${count(k.count - k.replaced)} / ${count(k.count)} · ${k.distinct_capped ? "plus de " : ""}${count(k.distinct)} distinctes · ${shapes}`);
  }
  if (!clear.length) lines.push("(aucune)");
  lines.push("");
  return lines.join("\n");
}
