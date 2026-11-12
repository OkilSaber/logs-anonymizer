<script lang="ts">
  import { api, ApiError, type KeyStat, type LocalAddition, type Profile, type ShapeStat } from "./api";
  import { bytes, count, frDay, percent } from "./format";
  import { profileText } from "./profileText";

  let { profile, onback }: { profile: Profile; onback: () => void } = $props();

  let tab = $state<"shapes" | "keys">("shapes");
  let search = $state("");
  let onlyClear = $state(true);
  let busy = $state("");
  let error = $state("");
  // Ce qui a été ajouté au template local pendant cette consultation : forme ou clé → identifiant.
  let added = $state<Record<string, string>>({});
  let localTemplate = $state("");

  const base = $derived(profile.template.split("@")[0]);
  const keptBytes = $derived(profile.bytes - profile.filtered_bytes);
  const needle = $derived(search.trim().toLowerCase());
  const shapes = $derived(profile.shapes.filter((s) => !needle || s.shape.toLowerCase().includes(needle)));
  const keys = $derived(profile.keys.filter((k) => (!onlyClear || k.count > k.replaced) && (!needle || k.path.includes(needle))));
  const clearKeys = $derived(profile.keys.filter((k) => k.count > k.replaced).length);
  const cumulative = $derived.by(() => {
    let sum = 0;
    return new Map(profile.shapes.map((s) => [s.shape, (sum += s.bytes)]));
  });
  const addedCount = $derived(Object.keys(added).length);

  async function add(id: string, addition: Omit<LocalAddition, "app" | "base_template">) {
    busy = id;
    error = "";
    try {
      const r = await api.localTemplateAdd({ app: profile.app, base_template: base, ...addition });
      added = { ...added, [id]: r.added_id };
      localTemplate = r.template_id;
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e);
    } finally {
      busy = "";
    }
  }

  // Copie du profil pour une IA : formes masquées, clés et comptes, sans aucune valeur.
  let copied = $state("");
  async function copyProfile() {
    error = "";
    try {
      const size = await api.copyProfile(profileText(profile));
      copied = `${bytes(size)} copiés`;
      setTimeout(() => (copied = ""), 2600);
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e);
    }
  }

  const filterShape = (s: ShapeStat) => add(`shape:${s.shape}`, { kind: "filter", description: s.shape.slice(0, 120), pattern: s.pattern, keys: [], strategy: null, label: null });

  // Jeton par défaut : le dernier segment de la clé, en majuscules.
  const labelOf = (k: KeyStat) => (k.path.split(".").pop() ?? "VALUE").replace(/[^a-z0-9]/gi, "").toUpperCase().slice(0, 14) || "VALUE";
  const ruleKey = (k: KeyStat, strategy: string) =>
    add(`key:${k.path}`, { kind: "rule", description: `Clé ${k.path}, vue dans le profil`, pattern: null, keys: [k.path], strategy, label: strategy === "keep" ? null : labelOf(k) });
</script>

<div class="flex h-full min-h-0 flex-col">
  <div class="flex items-center gap-3 border-b border-line px-4 py-2.5">
    <button class="btn btn-ghost h-7 px-2" onclick={onback}>← Résultats</button>
    <div class="min-w-0 flex-1 truncate text-[12px] text-muted">
      <span class="font-mono text-fg">{profile.app}</span> · {frDay(profile.day)} · {profile.template}
    </div>
    <span class="text-[12px] text-muted tabular-nums">
      {count(profile.entries)} entrées · {bytes(profile.bytes)} · <span class="text-fg">{percent(profile.filtered_bytes, profile.bytes)} déjà filtrés</span> · reste {bytes(keptBytes)}
    </span>
    <button class="btn h-7" title="Copie les formes et les clés du profil, sans aucune valeur, avec de quoi les lire : à donner à une IA pour écrire ou améliorer un template" onclick={copyProfile}>{copied || "Copier pour une IA"}</button>
  </div>

  <div class="flex items-center gap-2 border-b border-line px-4 py-2">
    <button class="chip {tab === 'shapes' ? 'chip-on' : ''}" onclick={() => (tab = "shapes")}>Formes · {count(profile.shapes_total)}</button>
    <button class="chip {tab === 'keys' ? 'chip-on' : ''}" onclick={() => (tab = "keys")}>
      Clés · {count(profile.keys_total)}{#if clearKeys}<span class="ml-1 text-warn">· {clearKeys} en clair</span>{/if}
    </button>
    <input class="field ml-2 h-7 w-64" placeholder={tab === "shapes" ? "Chercher dans les formes" : "Chercher une clé"} bind:value={search} />
    {#if tab === "keys"}
      <label class="ml-2 flex items-center gap-1.5 text-[12px] text-muted"><input type="checkbox" bind:checked={onlyClear} /> Seulement celles qui gardent des valeurs en clair</label>
    {/if}
    <span class="flex-1"></span>
    <span class="text-[11.5px] text-faint">Formes et comptes seulement : aucune valeur n'est lue ni affichée.</span>
  </div>

  {#if profile.warning}<div class="border-b border-line bg-warn-soft px-4 py-2 text-[12px] text-warn">{profile.warning}</div>{/if}
  {#if error}<div class="selectable border-b border-line bg-danger-soft px-4 py-2 text-[12.5px] text-danger">{error}</div>{/if}
  {#if addedCount}
    <div class="border-b border-line bg-accent-soft px-4 py-2 text-[12.5px]">
      {addedCount} ajout{addedCount > 1 ? "s" : ""} au template <span class="font-mono">{localTemplate}</span>, qui s'applique désormais à cette application. Relance le run pour en voir l'effet.
    </div>
  {/if}

  <div class="min-h-0 flex-1 overflow-y-auto">
    {#if tab === "shapes"}
      <table class="w-full border-collapse text-[12px]">
        <thead class="sticky top-0 z-10 bg-panel">
          <tr class="border-b border-line text-left text-[11px] tracking-wide text-muted uppercase">
            <th class="w-[150px] px-4 py-2 font-medium">Poids</th>
            <th class="w-[64px] px-2 py-2 text-right font-medium">Cumul</th>
            <th class="w-[96px] px-2 py-2 text-right font-medium">Entrées</th>
            <th class="w-[60px] px-2 py-2 font-medium">Niveau</th>
            <th class="px-2 py-2 font-medium">Forme</th>
            <th class="w-[230px] px-4 py-2 font-medium">Filtre</th>
          </tr>
        </thead>
        <tbody>
          {#each shapes as s (s.shape)}
            {@const mine = added[`shape:${s.shape}`]}
            {@const whole = s.filtered_count >= s.count && s.count > 0}
            <tr class="border-b border-line/60 {whole || mine ? 'text-faint' : ''}">
              <td class="px-4 py-1.5">
                <div class="flex items-center gap-2">
                  <div class="h-1 w-16 overflow-hidden rounded-full bg-raised"><div class="h-full rounded-full {whole || mine ? 'bg-faint' : 'bg-accent'}" style="width: {Math.max(2, (s.bytes / profile.bytes) * 100)}%"></div></div>
                  <span class="tabular-nums">{percent(s.bytes, profile.bytes)}</span>
                </div>
              </td>
              <td class="px-2 py-1.5 text-right text-muted tabular-nums">{percent(cumulative.get(s.shape) ?? 0, profile.bytes)}</td>
              <td class="px-2 py-1.5 text-right tabular-nums">{count(s.count)}</td>
              <td class="px-2 py-1.5 {s.level === 'error' ? 'text-danger' : s.level === 'warn' || s.level === 'warning' ? 'text-warn' : 'text-muted'}">{s.level || "—"}</td>
              <td class="selectable max-w-0 truncate px-2 py-1.5 font-mono text-[11.5px]" title={s.shape}>{s.shape}</td>
              <td class="px-4 py-1.5">
                {#if whole}
                  <span class="font-mono text-[11px]" title="Déjà retirée par ce filtre">{s.filtered_by}</span>
                {:else if mine}
                  <span class="text-ok">Filtre ajouté · {mine}</span>
                {:else}
                  <div class="flex items-center gap-2">
                    <button class="btn h-6 px-2 text-[12px]" disabled={!!busy} onclick={() => filterShape(s)}>{busy === `shape:${s.shape}` ? "Ajout…" : s.filtered_count ? "Filtrer le reste" : "Filtrer cette forme"}</button>
                    {#if s.filtered_count}<span class="text-[11px] text-muted" title="Une partie de ces entrées est déjà retirée par {s.filtered_by}">{percent(s.filtered_count, s.count)} déjà filtrées</span>{/if}
                  </div>
                {/if}
              </td>
            </tr>
          {:else}
            <tr><td colspan="6" class="p-8 text-center text-muted">Aucune forme ne correspond.</td></tr>
          {/each}
        </tbody>
      </table>
      {#if profile.shapes.length < profile.shapes_total}
        <div class="p-3 text-center text-[12px] text-faint">Les {count(profile.shapes.length)} formes les plus lourdes sur {count(profile.shapes_total)}.</div>
      {/if}
    {:else}
      <table class="w-full border-collapse text-[12px]">
        <thead class="sticky top-0 z-10 bg-panel">
          <tr class="border-b border-line text-left text-[11px] tracking-wide text-muted uppercase">
            <th class="px-4 py-2 font-medium">Chemin de clé</th>
            <th class="w-[96px] px-2 py-2 text-right font-medium">Valeurs</th>
            <th class="w-[120px] px-2 py-2 text-right font-medium">En clair</th>
            <th class="w-[90px] px-2 py-2 text-right font-medium">Distinctes</th>
            <th class="w-[230px] px-2 py-2 font-medium">Formes des valeurs en clair</th>
            <th class="w-[280px] px-4 py-2 font-medium">Règle</th>
          </tr>
        </thead>
        <tbody>
          {#each keys as k (k.path)}
            {@const clear = k.count - k.replaced}
            {@const mine = added[`key:${k.path}`]}
            <tr class="border-b border-line/60">
              <td class="selectable max-w-0 truncate px-4 py-1.5 font-mono text-[11.5px]" title={k.path}>{k.path}</td>
              <td class="px-2 py-1.5 text-right tabular-nums">{count(k.count)}</td>
              <td class="px-2 py-1.5 text-right tabular-nums {clear ? 'text-warn' : 'text-ok'}">{clear ? `${count(clear)} · ${percent(clear, k.count)}` : "aucune"}</td>
              <td class="px-2 py-1.5 text-right text-muted tabular-nums">{clear ? `${count(k.distinct)}${k.distinct_capped ? "+" : ""}` : ""}</td>
              <td class="px-2 py-1.5">
                <div class="flex flex-wrap gap-1">
                  {#each k.shapes.slice(0, 3) as sh}<span class="rounded bg-raised px-1.5 py-0.5 font-mono text-[11px] text-muted" title="{count(sh.count)} valeurs de cette forme">{sh.shape}</span>{/each}
                </div>
              </td>
              <td class="px-4 py-1.5">
                {#if mine}
                  <span class="text-ok">Règle ajoutée · {mine}</span>
                {:else if clear}
                  <div class="flex gap-1">
                    <button class="btn h-6 px-2 text-[12px]" disabled={!!busy} title="Remplace chaque valeur par un jeton stable : {labelOf(k)}_…" onclick={() => ruleKey(k, "pseudonymize")}>Pseudonymiser</button>
                    <button class="btn h-6 px-2 text-[12px]" disabled={!!busy} title="Remplace chaque valeur par [{labelOf(k)}]" onclick={() => ruleKey(k, "redact")}>Masquer</button>
                    <button class="btn btn-ghost h-6 px-2 text-[12px]" disabled={!!busy} title="Marque la clé comme non sensible : protégée des détecteurs à faux positifs" onclick={() => ruleKey(k, "keep")}>Garder</button>
                  </div>
                {:else}
                  <span class="text-faint">couverte</span>
                {/if}
              </td>
            </tr>
          {:else}
            <tr><td colspan="6" class="p-8 text-center text-muted">{onlyClear ? "Aucune clé ne garde de valeur en clair." : "Aucune clé ne correspond."}</td></tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</div>
