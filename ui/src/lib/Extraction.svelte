<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type AppInfoDto, type Config, type FileResult, type Plan, type PlanRequest, type Profile, type RunDone, type RunProgress, type SandboxResult, type TemplateInfo } from "./api";
  import { bytes, count, daysAgo, daysLabel, duration, expandDays, frDay, percent, Rate, speed, toRanges, type DayRange } from "./format";
  import ProfileView from "./Profile.svelte";
  import Secret from "./Secret.svelte";
  import SideBySide from "./SideBySide.svelte";

  let { config, templates, replay = null, onreplayed, onsettings }: { config: Config; templates: TemplateInfo[]; replay?: PlanRequest | null; onreplayed?: () => void; onsettings: () => void } = $props();

  let serverId = $state("");
  let ranges = $state<DayRange[]>([{ from: daysAgo(1), to: daysAgo(1) }]);
  let missingDays = $state<string[]>([]);
  let apps = $state<AppInfoDto[] | null>(null);
  let filter = $state("");
  let selected = $state<Record<string, string[]>>({});
  let kinds = $state<string[]>(["erlang"]);
  let template = $state("");
  let plan = $state<Plan | null>(null);
  let confirmed = $state(false);
  let busy = $state<"" | "discover" | "plan" | "run">("");
  let error = $state<ApiError | null>(null);
  let runId = $state<string | null>(null);
  // Téléchargement et anonymisation avancent en même temps, chacun sur plusieurs fichiers.
  type Phase = "download" | "anonymize";
  type FileStep = { p: RunProgress; fraction: number | null; bytes: number; entries: number; remaining: number | null };
  type Meter = { done: Rate; bytes: Rate; entries: Rate };
  let steps = $state<Record<Phase, FileStep[]>>({ download: [], anonymize: [] });
  const meters: Record<Phase, Map<number, Meter>> = { download: new Map(), anonymize: new Map() };

  function resetProgress() {
    steps = { download: [], anonymize: [] };
    meters.download.clear();
    meters.anonymize.clear();
  }

  function onProgress(p: RunProgress) {
    if (p.phase !== "download" && p.phase !== "anonymize") return;
    let m = meters[p.phase].get(p.file_index);
    if (!m) meters[p.phase].set(p.file_index, (m = { done: new Rate(), bytes: new Rate(), entries: new Rate() }));
    const now = performance.now();
    m.done.push(p.bytes_done, now);
    m.bytes.push(p.phase === "download" ? p.bytes_done : p.processed_bytes, now);
    m.entries.push(p.entries_in, now);
    const fraction = p.finished ? 1 : p.bytes_total > 0 ? Math.min(1, p.bytes_done / p.bytes_total) : null;
    const remaining = fraction !== null && fraction < 1 && m.done.value > 0 ? (p.bytes_total - p.bytes_done) / m.done.value : null;
    const step: FileStep = { p, fraction, bytes: m.bytes.value, entries: m.entries.value, remaining };
    const list = steps[p.phase];
    const at = list.findIndex((f) => f.p.file_index === p.file_index);
    if (at >= 0) list[at] = step;
    else list.push(step);
  }

  // Une étape vue d'ensemble : fichiers finis, fichiers en cours, débit cumulé.
  function summarize(list: FileStep[]) {
    const total = list[0]?.p.file_count ?? 0;
    const active = list.filter((f) => !f.p.finished);
    const finished = list.length - active.length;
    const sum = (pick: (f: FileStep) => number, of = list) => of.reduce((acc, f) => acc + pick(f), 0);
    return {
      total,
      finished,
      active,
      complete: total > 0 && finished === total,
      // Part des fichiers passés par l'étape, ceux en cours comptés pour leur avancement.
      fraction: total ? Math.min(1, (finished + sum((f) => f.fraction ?? 0, active)) / total) : 0,
      // Aucun total connaissable (fichiers compressés à la volée) : barre indéterminée.
      unknown: finished === 0 && active.length > 0 && active.every((f) => f.fraction === null),
      bytes: sum((f) => f.bytes, active),
      entriesRate: sum((f) => f.entries, active),
      processed: sum((f) => f.p.processed_bytes),
      entries: sum((f) => f.p.entries_in),
      dropped: sum((f) => f.p.dropped),
    };
  }
  type Summary = ReturnType<typeof summarize>;
  const downloadStep = $derived(summarize(steps.download));
  const anonymizeStep = $derived(summarize(steps.anonymize));
  const started = $derived(steps.download.length + steps.anonymize.length > 0);
  // Avancement du run entier : chaque étape compte pour moitié.
  const overall = $derived((downloadStep.fraction + anonymizeStep.fraction) / 2);
  let done = $state<RunDone | null>(null);
  let preview = $state<{ file: FileResult; result: SandboxResult } | null>(null);
  let profile = $state<Profile | null>(null);
  let profiling = $state("");
  let toast = $state("");
  let secret = $state<{ kind: "sudo" | "key"; target: string; retry: () => void } | null>(null);

  $effect(() => {
    if (!serverId && config.servers.length) serverId = config.servers[0].id;
  });

  const erlangTemplates = $derived(templates.filter((t) => t.available && !t.is_abstract && t.log_kind === "erlang"));
  const shown = $derived((apps ?? []).filter((a) => a.name.toLowerCase().includes(filter.trim().toLowerCase())));
  const selections = $derived(Object.entries(selected).filter(([, c]) => c.length).map(([app, clusters]) => ({ app, clusters })));
  const days = $derived(expandDays(ranges));
  const request = $derived<PlanRequest>({ server_id: serverId, days, selections, kinds, template: template || null });
  const usable = $derived(plan?.files.filter((f) => !f.problem) ?? []);
  const mustConfirm = $derived(!!plan && (plan.needs_confirmation || !!plan.disk_warning));

  function reset(level: "apps" | "plan") {
    if (level === "apps") {
      apps = null;
      selected = {};
      missingDays = [];
    }
    plan = null;
    confirmed = false;
    done = null;
    preview = null;
    profile = null;
    error = null;
  }

  // Une erreur de phrase de passe ou de sudo ouvre la saisie, puis relance l'action.
  function handle(e: unknown, retry: () => void) {
    const err = e instanceof ApiError ? e : new ApiError({ code: "internal", message: String(e), detail: null });
    if (err.code === "sudo_password_required" || err.code === "sudo_denied") {
      secret = { kind: "sudo", target: serverId, retry };
    } else if ((err.code === "key_passphrase_required" || err.code === "key_passphrase_invalid") && err.detail) {
      secret = { kind: "key", target: err.detail, retry };
    }
    error = err;
  }

  async function discover() {
    reset("apps");
    busy = "discover";
    try {
      const found = await api.discover(serverId, days);
      apps = found.apps;
      missingDays = found.missing_days;
    } catch (e) {
      handle(e, discover);
    } finally {
      busy = "";
    }
  }

  async function makePlan() {
    reset("plan");
    busy = "plan";
    try {
      plan = await api.planRun(request);
    } catch (e) {
      handle(e, makePlan);
    } finally {
      busy = "";
    }
  }

  async function start() {
    error = null;
    done = null;
    preview = null;
    resetProgress();
    busy = "run";
    try {
      runId = await api.startRun(request);
    } catch (e) {
      busy = "";
      handle(e, start);
    }
  }

  function toggle(app: AppInfoDto, cluster?: string) {
    const current = selected[app.name] ?? [];
    const next = cluster ? (current.includes(cluster) ? current.filter((c) => c !== cluster) : [...current, cluster]) : current.length ? [] : [...app.clusters];
    selected = { ...selected, [app.name]: next };
    plan = null;
  }

  function preset(from: number, to: number) {
    ranges = [{ from: daysAgo(from), to: daysAgo(to) }];
    reset("apps");
  }

  function toggleKind(k: string) {
    kinds = kinds.includes(k) ? kinds.filter((x) => x !== k) : [...kinds, k];
    plan = null;
  }

  async function act(label: string, fn: () => Promise<string | null>) {
    error = null;
    try {
      const msg = await fn();
      if (msg) {
        toast = msg;
        setTimeout(() => (toast = ""), 2600);
      }
    } catch (e) {
      handle(e, () => act(label, fn));
    }
  }

  // Une sortie par jour : les résultats sont regroupés par application, cluster et type,
  // et on choisit le jour affiché dans chaque groupe.
  type Group = { key: string; files: FileResult[] };
  const groups = $derived.by(() => {
    const byKey = new Map<string, FileResult[]>();
    for (const f of done?.files ?? []) {
      const key = `${f.app}/${f.cluster}/${f.kind}`;
      const list = byKey.get(key);
      if (list) list.push(f);
      else byKey.set(key, [f]);
    }
    return [...byKey].map(([key, files]): Group => ({ key, files }));
  });
  let chosen = $state<Record<string, string>>({});
  const current = (g: Group) => g.files.find((f) => f.output_id === chosen[g.key]) ?? g.files[0];
  const exportGroup = (g: Group) =>
    act("export", async () => {
      const filled = g.files.filter((f) => f.parts.length);
      return (await api.exportOutputs(filled.map((f) => f.output_id))) ? `${filled.length} jours exportés` : null;
    });

  const copy = (f: FileResult, part = 0) => act("copy", async () => `${bytes(await api.copyOutput(f.output_id, part))} copiés dans le presse-papier`);
  const openProfile = (f: FileResult) =>
    act("profile", async () => {
      profiling = f.output_id;
      try {
        profile = await api.profileOutput(f.output_id);
      } finally {
        profiling = "";
      }
      return null;
    });
  const exportFile = (f: FileResult) => act("export", async () => ((await api.exportOutput(f.output_id)) ? "Fichier exporté" : null));
  const openPreview = (f: FileResult) => act("preview", async () => ((preview = { file: f, result: await api.previewOutput(f.output_id, 200) }), null));

  // Clic sur un remplacement dans la vue côte à côte : la valeur n'est plus masquée pour
  // cette application. L'aperçu est recalculé tout de suite avec le template modifié.
  async function allowValue(value: string) {
    const file = preview!.file;
    await act("allow", async () => {
      const r = await api.localTemplateAdd({ app: file.app, base_template: file.template, kind: "allow_value", description: "", pattern: value, keys: [], strategy: null, label: null });
      preview = { file, result: await api.previewOutput(file.output_id, 200) };
      return `Valeur gardée dans ${r.template_id}`;
    });
  }
  const previewTemplate = $derived(preview?.result.template.split("@")[0] ?? "");

  async function submitSecret(value: string) {
    const s = secret!;
    secret = null;
    error = null;
    if (s.kind === "sudo") await api.provideSudoPassword(s.target, value);
    else await api.provideKeyPassphrase(s.target, value);
    s.retry();
  }

  // Rejouer un run de l'historique : mêmes serveur, jours et applications, puis le plan.
  $effect(() => {
    const r = replay;
    if (!r || busy) return;
    onreplayed?.();
    reset("apps");
    serverId = r.server_id;
    ranges = toRanges(r.days);
    apps = r.selections.map((s) => ({ name: s.app, clusters: s.clusters }));
    selected = Object.fromEntries(r.selections.map((s) => [s.app, s.clusters]));
    kinds = r.kinds;
    template = r.template ?? "";
    // Le plan part de la demande elle-même : les champs ci-dessus ne sont pas encore propagés.
    busy = "plan";
    api
      .planRun(r)
      .then((p) => (plan = p))
      .catch((e) => handle(e, makePlan))
      .finally(() => (busy = ""));
  });

  function primary() {
    if (busy) return;
    if (!apps) discover();
    else if (!plan && selections.length && kinds.length) makePlan();
    else if (plan && usable.length && (!mustConfirm || confirmed)) start();
  }

  onMount(() => {
    const offs = [
      api.onProgress((p) => p.run_id === runId && onProgress(p)),
      api.onDone((d) => {
        if (d.run_id !== runId) return;
        done = d;
        busy = "";
        resetProgress();
        if (d.error) error = new ApiError(d.error);
      }),
    ];
    const key = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        primary();
      }
    };
    window.addEventListener("keydown", key);
    return () => {
      window.removeEventListener("keydown", key);
      offs.forEach((o) => o.then((off) => off()));
    };
  });
</script>

{#snippet stepRow(title: string, phase: Phase, s: Summary)}
  <div>
    <div class="mb-1.5 flex items-baseline gap-3">
      <span class="text-[11px] font-medium tracking-wide text-muted uppercase">{title}</span>
      <span class="min-w-0 flex-1 truncate text-[12px] text-muted">{s.active.length > 1 ? `${s.active.length} fichiers en même temps` : ""}</span>
      {#if s.total}<span class="text-[12px] text-muted tabular-nums">{s.finished} / {s.total}</span>{/if}
      {#if s.total && !s.complete && !s.unknown}<span class="w-12 text-right text-[14px] font-semibold tabular-nums">{Math.floor(s.fraction * 100)} %</span>{/if}
    </div>
    <div class="h-1.5 overflow-hidden rounded-full bg-raised">
      {#if !s.total}
        <div class="h-full w-0"></div>
      {:else if s.complete}
        <div class="h-full w-full rounded-full bg-ok"></div>
      {:else if s.unknown}
        <div class="h-full w-1/3 animate-pulse rounded-full bg-accent"></div>
      {:else}
        <div class="h-full rounded-full bg-accent transition-[width] duration-150" style="width: {s.fraction * 100}%"></div>
      {/if}
    </div>
    <div class="mt-1.5 flex items-baseline gap-3 text-[12px] text-muted tabular-nums">
      {#if !s.total}
        <span class="flex-1 text-faint">En attente du premier fichier</span>
      {:else if s.complete}
        <span class="flex-1">{phase === "download" ? "Tous les fichiers sont dans le cache" : `Tous les fichiers sont anonymisés · ${count(s.entries)} entrées, ${count(s.dropped)} filtrées`}</span>
      {:else if phase === "download"}
        <span class="flex-1">{s.active.length ? "" : "En attente du fichier suivant"}</span>
        {#if s.bytes}<span class="text-fg">{speed(s.bytes)}</span>{/if}
      {:else}
        <span class="flex-1">{bytes(s.processed)} traités · {count(s.entries)} entrées, {count(s.dropped)} filtrées</span>
        {#if s.bytes}<span class="text-fg">{speed(s.bytes)}</span>{/if}
        {#if s.entriesRate}<span>{count(Math.round(s.entriesRate))} entrées/s</span>{/if}
      {/if}
    </div>
    <!-- Une ligne par fichier en cours. -->
    {#each s.active as f (f.p.file_index)}
      {@const [where, day] = f.p.label.split(" · ")}
      <div class="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11.5px] text-muted tabular-nums" title={phase === "download" ? `${f.p.label} — ${bytes(f.p.bytes_done)}${f.p.bytes_total ? ` sur ${bytes(f.p.bytes_total)}` : " reçus"}` : f.p.label}>
        <!-- Panneau étroit : le nom du fichier passe sur sa propre ligne. -->
        <span class="flex w-full min-w-0 gap-2 font-mono @lg:w-auto @lg:flex-1">
          <span class="min-w-0 truncate">{where}</span>
          {#if day}<span class="shrink-0 text-faint">{day}</span>{/if}
        </span>
        <div class="h-1 min-w-16 flex-1 overflow-hidden rounded-full bg-raised @lg:w-20 @lg:flex-none">
          {#if f.fraction !== null}
            <div class="h-full rounded-full bg-accent/70 transition-[width] duration-150" style="width: {f.fraction * 100}%"></div>
          {:else}
            <div class="h-full w-1/3 animate-pulse rounded-full bg-accent/70"></div>
          {/if}
        </div>
        <span class="w-9 shrink-0 text-right">{f.fraction !== null ? `${Math.floor(f.fraction * 100)} %` : ""}</span>
        <span class="w-[4.5rem] shrink-0 text-right">{f.bytes ? speed(f.bytes) : ""}</span>
        <span class="w-[4.5rem] shrink-0 text-right">{f.remaining !== null ? `reste ${duration(f.remaining)}` : ""}</span>
      </div>
    {/each}
  </div>
{/snippet}

{#if !config.bastion || !config.servers.length}
  <div class="flex h-full flex-col items-center justify-center gap-3 text-center">
    <div class="text-[15px] font-semibold">Aucun serveur configuré</div>
    <p class="m-0 max-w-sm text-muted">Renseigne le bastion et au moins un serveur syslog, ou importe-les depuis ta config SSH.</p>
    <button class="btn btn-primary" onclick={onsettings}>Ouvrir les réglages</button>
  </div>
{:else}
  <div class="flex h-full min-h-0">
    <!-- Colonne de sélection -->
    <div class="w-[340px] shrink-0 flex-col border-r border-line {profile ? 'hidden' : 'flex'}">
      <div class="space-y-3 border-b border-line p-4">
        <div>
          <label class="label" for="server">Serveur</label>
          <select id="server" class="field" bind:value={serverId} onchange={() => reset("apps")}>
            {#each config.servers as s}<option value={s.id}>{s.name}</option>{/each}
          </select>
        </div>
        <div>
          <div class="mb-1 flex items-baseline">
            <span class="label mb-0 flex-1">Jours</span>
            <span class="text-[11px] text-muted">{daysLabel(days)}</span>
          </div>
          <div class="space-y-1.5">
            {#each ranges as r, i}
              <div class="flex items-center gap-1.5">
                <input type="date" class="field px-1.5" aria-label="Du" bind:value={r.from} onchange={() => reset("apps")} />
                <span class="text-faint">→</span>
                <input type="date" class="field px-1.5" aria-label="Au" bind:value={r.to} onchange={() => reset("apps")} />
                {#if ranges.length > 1}
                  <button class="btn btn-ghost w-7 shrink-0 px-0" title="Retirer cette plage" onclick={() => (ranges.splice(i, 1), reset("apps"))}>×</button>
                {/if}
              </div>
            {/each}
          </div>
          <div class="mt-1.5 flex gap-1.5">
            <button class="btn h-7 px-2" onclick={() => preset(0, 0)}>Auj.</button>
            <button class="btn h-7 px-2" onclick={() => preset(1, 1)}>Hier</button>
            <button class="btn h-7 px-2" onclick={() => preset(6, 0)}>7 jours</button>
            <span class="flex-1"></span>
            <button class="btn btn-ghost h-7 px-2" onclick={() => (ranges.push({ from: daysAgo(1), to: daysAgo(1) }), reset("apps"))}>+ plage</button>
          </div>
        </div>
        <button class="btn w-full {apps ? '' : 'btn-primary'}" disabled={!!busy || !serverId || !days.length} onclick={discover}>
          {busy === "discover" ? "Connexion…" : apps ? "Redécouvrir" : "Découvrir les applications"}
        </button>
      </div>

      {#if apps}
        {#if missingDays.length}
          <div class="border-b border-line bg-warn-soft px-4 py-2 text-[12px] text-warn">Aucun dossier de logs pour : {missingDays.map(frDay).join(", ")}</div>
        {/if}
        <div class="border-b border-line p-3">
          <input class="field" placeholder="Filtrer les {apps.length} applications" bind:value={filter} />
        </div>
        <div class="min-h-0 flex-1 overflow-y-auto p-2">
          {#each shown as a (a.name)}
            {@const on = selected[a.name] ?? []}
            <div class="rounded-md px-2 py-1.5 transition-colors duration-100 {on.length ? 'bg-raised' : 'hover:bg-raised/60'}">
              <button class="flex w-full items-center gap-2 text-left" onclick={() => toggle(a)}>
                <span class="flex h-3.5 w-3.5 items-center justify-center rounded-[4px] border {on.length ? 'border-accent bg-accent' : 'border-faint'}">
                  {#if on.length}<svg viewBox="0 0 12 12" class="h-2.5 w-2.5 text-white"><path d="M2.5 6.2 5 8.6l4.5-5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" /></svg>{/if}
                </span>
                <span class="truncate font-mono text-[12px]">{a.name}</span>
              </button>
              {#if a.clusters.length > 1 || on.length}
                <div class="mt-1.5 ml-[22px] flex flex-wrap gap-1">
                  {#each a.clusters as c}
                    <button class="chip {on.includes(c) ? 'chip-on' : ''}" onclick={() => toggle(a, c)}>{c}</button>
                  {/each}
                </div>
              {/if}
            </div>
          {:else}
            <div class="p-4 text-center text-muted">Aucune application ne correspond.</div>
          {/each}
        </div>
        <div class="space-y-3 border-t border-line p-4">
          <div>
            <span class="label">Types de logs</span>
            <div class="flex gap-1.5">
              {#each ["erlang", "haproxy", "console"] as k}
                <button class="chip {kinds.includes(k) ? 'chip-on' : ''}" onclick={() => toggleKind(k)}>{k}</button>
              {/each}
            </div>
          </div>
          <div>
            <label class="label" for="tpl">Template (erlang)</label>
            <select id="tpl" class="field" bind:value={template} onchange={() => (plan = null)}>
              <option value="">Automatique, selon l'application</option>
              {#each erlangTemplates as t}<option value={t.id}>{t.id}</option>{/each}
            </select>
          </div>
          <button class="btn btn-primary w-full" disabled={!!busy || !selections.length || !kinds.length} onclick={makePlan}>
            {busy === "plan" ? "Préparation…" : "Préparer"}
            <span class="kbd ml-1 border-white/25 bg-white/10 text-white/80">⌘↵</span>
          </button>
        </div>
      {:else if !busy}
        <div class="flex flex-1 items-center justify-center p-6 text-center text-muted">Choisis un serveur et une période, puis découvre les applications présentes.</div>
      {/if}
    </div>

    <!-- Colonne de travail -->
    <div class="flex min-w-0 flex-1 flex-col">
      {#if error}
        <div class="m-4 mb-0 flex items-start gap-3 rounded-lg border border-danger/40 bg-danger-soft px-3.5 py-2.5">
          <div class="selectable min-w-0 flex-1 text-[12.5px] leading-relaxed">{error.message}</div>
          <button class="btn btn-ghost h-6 px-2" onclick={() => (error = null)}>Fermer</button>
        </div>
      {/if}

      {#if profile}
        <div class="min-h-0 flex-1"><ProfileView {profile} onback={() => (profile = null)} /></div>
      {:else if preview}
        <div class="flex items-center gap-3 border-b border-line px-4 py-2.5">
          <button class="btn btn-ghost h-7 px-2" onclick={() => (preview = null)}>← Résultats</button>
          <div class="min-w-0 flex-1 truncate font-mono text-[12px] text-muted">{preview.file.app}/{preview.file.cluster}/{preview.file.kind}</div>
          <span class="text-[12px] text-muted">{preview.result.entries.length} premières entrées</span>
          <button class="btn h-7" onclick={() => copy(preview!.file)}>Copier</button>
          <button class="btn btn-primary h-7" onclick={() => exportFile(preview!.file)}>Exporter</button>
        </div>
        <div class="grid grid-cols-2 border-b border-line bg-panel text-[11px] font-medium tracking-wide text-muted uppercase">
          <div class="border-r border-line px-3 py-1.5">Brut · reste sur ta machine</div>
          <div class="px-3 py-1.5">Anonymisé · ce que verra l'IA · clique sur un remplacement pour ne plus masquer sa valeur</div>
        </div>
        {#if previewTemplate && previewTemplate !== preview.file.template}
          <div class="border-b border-line bg-accent-soft px-4 py-2 text-[12.5px] leading-relaxed">
            Aperçu avec <span class="font-mono">{previewTemplate}</span>, modifié depuis ce run : c'est ce que donnerait un nouveau run. La sortie sur le disque n'a pas changé, « Copier » et « Exporter » prennent toujours l'ancienne. Relance le run pour la mettre à jour.
          </div>
        {/if}
        <div class="min-h-0 flex-1 overflow-y-auto"><SideBySide entries={preview.result.entries} onallow={allowValue} /></div>
      {:else if done}
        <div class="min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
          {#if done.cancelled}<div class="text-muted">Run annulé.</div>{/if}
          {#each groups as g (g.key)}
            {@const f = current(g)}
            <div class="card p-4">
              {#if g.files.length > 1}
                <!-- Un fichier par jour : le jour choisi est celui que montre la carte. -->
                <div class="mb-3.5 flex items-center gap-1.5 border-b border-line pb-3.5">
                  <div class="flex min-w-0 flex-1 flex-wrap gap-1.5">
                    {#each g.files as day (day.output_id)}
                      <button
                        class="chip tabular-nums {day.output_id === f.output_id ? 'chip-on' : ''} {day.quarantined ? 'text-danger' : ''}"
                        title="{bytes(day.bytes_out)} · {count(day.entries_out)} entrées{day.parts.length > 1 ? ` · ${day.parts.length} parties` : ''}"
                        onclick={() => (chosen[g.key] = day.output_id)}>{frDay(day.days[0] ?? "")}</button>
                    {/each}
                  </div>
                  <button class="btn shrink-0" disabled={g.files.some((d) => d.quarantined)} onclick={() => exportGroup(g)} title="Copie le fichier de chaque jour dans un dossier">Exporter les {g.files.length} jours</button>
                </div>
              {/if}
              <div class="flex items-center gap-3">
                <div class="min-w-0 flex-1">
                  <div class="truncate font-mono text-[13px]">{f.app}<span class="text-faint">/</span>{f.cluster}<span class="text-faint">/</span>{f.kind}</div>
                  <div class="mt-0.5 text-[12px] text-muted">{f.template}@{f.template_version} · {daysLabel(f.days)}</div>
                </div>
                <button class="btn" disabled={!!profiling} onclick={() => openProfile(f)} title="Formes d'entrées par poids et inventaire des clés, sur ce jour">
                  {profiling === f.output_id ? "Profilage…" : "Profil"}
                </button>
                <button class="btn" onclick={() => openPreview(f)}>Côte à côte</button>
                {#if f.parts.length <= 1}<button class="btn" disabled={f.quarantined} onclick={() => copy(f)}>Copier</button>{/if}
                <button class="btn btn-primary" disabled={f.quarantined} onclick={() => exportFile(f)}>{f.parts.length > 1 ? "Exporter tout" : "Exporter"}</button>
              </div>
              <div class="mt-3.5 grid grid-cols-5 gap-3">
                {#each [["Entrées lues", count(f.entries_in), ""], ["Filtrées", count(f.dropped), f.deduplicated ? `${percent(f.dropped, f.entries_in)} · ${count(f.deduplicated)} répétées` : percent(f.dropped, f.entries_in)], ["Modifiées", count(f.modified), percent(f.modified, f.entries_out)], ["Sortie", bytes(f.bytes_out), `${percent(f.bytes_out, f.bytes_in)} du brut`], ["Filet de sécurité", count(f.safety_total), f.safety_total ? "trous de couverture" : "rien à rattraper"]] as [label, value, sub], i}
                  <div>
                    <div class="text-[11px] text-muted">{label}</div>
                    <div class="mt-0.5 text-[17px] font-semibold tabular-nums {i === 4 && f.safety_total ? 'text-warn' : ''}">{value}</div>
                    <div class="text-[11px] text-faint">{sub}</div>
                  </div>
                {/each}
              </div>
              {#if f.parts.length > 1}
                <div class="mt-3.5 rounded-md border border-line">
                  {#each f.parts as part}
                    <div class="flex items-center gap-3 border-b border-line px-3 py-1.5 text-[12px] last:border-0">
                      <span class="w-16 text-muted">Partie {part.index + 1}</span>
                      <span class="w-20 text-right tabular-nums">{bytes(part.bytes)}</span>
                      <span class="flex-1 text-muted tabular-nums">≈ {count(part.tokens)} tokens</span>
                      <button class="btn h-6 px-2 text-[12px]" disabled={f.quarantined} onclick={() => copy(f, part.index)}>Copier</button>
                    </div>
                  {/each}
                </div>
              {/if}
              {#if f.quarantined}
                <div class="mt-3 rounded-md bg-danger-soft px-3 py-2 text-[12px] text-danger">Le filet de sécurité est en mode « signaler » : cette sortie contient des données non remplacées. Copie et export sont bloqués.</div>
              {/if}
              {#each f.warnings as w}<div class="mt-3 rounded-md bg-warn-soft px-3 py-2 text-[12px] text-warn">{w}</div>{/each}
              <div class="mt-4 grid grid-cols-2 gap-5">
                <div>
                  <div class="label">Règles</div>
                  {#each f.rules as r}
                    <div class="flex items-center gap-2 py-[3px] text-[12px]">
                      <span class="min-w-0 flex-1 truncate font-mono text-muted" title={r.id}>{r.id}</span>
                      {#if r.shadowed}<span class="text-faint" title="Candidats écartés par une règle prioritaire">{count(r.shadowed)} masqués</span>{/if}
                      <span class="tabular-nums">{count(r.hits)}</span>
                    </div>
                  {:else}<div class="text-[12px] text-faint">Aucune règle déclenchée.</div>{/each}
                </div>
                <div>
                  <div class="label">Filtres de bruit</div>
                  {#each f.filters as r}
                    <div class="flex items-center gap-2 py-[3px] text-[12px]">
                      <span class="min-w-0 flex-1 truncate font-mono text-muted">{r.id}</span>
                      <span class="tabular-nums">{count(r.hits)}</span>
                    </div>
                  {:else}<div class="text-[12px] text-faint">Aucune entrée filtrée.</div>{/each}
                  {#if f.findings.length}
                    <div class="label mt-4">Rattrapé par le filet</div>
                    {#each f.findings.slice(0, 6) as x}
                      <div class="selectable py-[3px] text-[12px]">
                        <span class="rounded bg-warn-soft px-1.5 py-0.5 font-mono text-[11px] text-warn">{x.detector}</span>
                        <span class="ml-1 text-faint">l. {x.line_no}</span>
                        <div class="mt-0.5 truncate font-mono text-[11px] text-muted" title={x.context}>{x.context}</div>
                      </div>
                    {/each}
                  {/if}
                </div>
              </div>
              <div class="selectable mt-3 truncate font-mono text-[11px] text-faint" title={f.output_path}>{f.output_path || "Sortie vide : toutes les entrées ont été filtrées."}</div>
            </div>
          {/each}
          {#if done.mapping_tokens}
            <div class="rounded-md border border-line px-3 py-2 text-[12px] text-muted">Table de correspondance enregistrée, chiffrée : {count(done.mapping_tokens)} jetons. Elle sert dans l'écran « Réponse IA ».</div>
          {/if}
          {#each done.skipped as s}<div class="rounded-md border border-line px-3 py-2 text-[12px] text-muted">Ignoré — {s}</div>{/each}
          {#if !done.files.length && !done.cancelled && !done.error}<div class="text-muted">Aucun fichier traité.</div>{/if}
        </div>
      {:else if busy === "run"}
        <div class="min-h-0 flex-1 overflow-y-auto">
         <div class="flex min-h-full flex-col items-center justify-center gap-5 p-8">
          <div class="@container w-full max-w-2xl space-y-5">
            {#if !started}
              <div>
                <div class="mb-2 text-[12px] text-muted">Connexion au serveur</div>
                <div class="h-1.5 overflow-hidden rounded-full bg-raised"><div class="h-full w-1/3 animate-pulse rounded-full bg-accent"></div></div>
              </div>
            {:else}
              {@render stepRow("Téléchargement", "download", downloadStep)}
              {@render stepRow("Anonymisation", "anonymize", anonymizeStep)}
              <div class="flex items-center gap-3 border-t border-line pt-4 text-[12px] text-muted tabular-nums">
                <span>Run entier</span>
                <div class="h-1 flex-1 overflow-hidden rounded-full bg-raised">
                  <div class="h-full rounded-full bg-faint transition-[width] duration-150" style="width: {overall * 100}%"></div>
                </div>
                <span>{Math.floor(overall * 100)} %</span>
              </div>
            {/if}
          </div>
          <button class="btn" onclick={() => runId && api.cancelRun(runId)}>Annuler</button>
         </div>
        </div>
      {:else if plan}
        <div class="min-h-0 flex-1 overflow-y-auto p-4">
          <div class="card overflow-hidden">
            <table class="w-full border-collapse text-[12px]">
              <thead>
                <tr class="border-b border-line text-left text-[11px] tracking-wide text-muted uppercase">
                  <th class="px-3 py-2 font-medium">Jour</th>
                  <th class="px-3 py-2 font-medium">Fichier</th>
                  <th class="px-3 py-2 font-medium">Template</th>
                  <th class="px-3 py-2 text-right font-medium">Taille</th>
                  <th class="px-3 py-2 font-medium">État</th>
                </tr>
              </thead>
              <tbody>
                {#each plan.files as f}
                  <tr class="border-b border-line last:border-0 {f.problem ? 'text-faint' : ''}">
                    <td class="px-3 py-2 tabular-nums text-muted">{frDay(f.day)}</td>
                    <td class="px-3 py-2 font-mono">{f.app}/{f.cluster}/{f.kind}{f.compressed ? ".log.gz" : ".log"}</td>
                    <td class="px-3 py-2 font-mono text-muted">{f.template ?? "—"}</td>
                    <td class="px-3 py-2 text-right tabular-nums">{bytes(f.size)}</td>
                    <td class="px-3 py-2">
                      {#if f.problem}<span title={f.problem}>Ignoré · {f.problem}</span>
                      {:else if f.cached}<span class="text-ok">En cache</span>
                      {:else}À télécharger{/if}
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          {#each plan.missing as m}<div class="mt-2 rounded-md border border-line px-3 py-2 text-[12px] text-muted">{m}</div>{/each}
          {#if plan.disk_warning}
            <div class="mt-3 rounded-md border border-warn/40 bg-warn-soft px-3 py-2.5 text-[12.5px] leading-relaxed text-warn">{plan.disk_warning}</div>
          {/if}
        </div>
        <div class="flex items-center gap-4 border-t border-line px-4 py-3">
          <div class="flex-1 text-[12px] text-muted">
            {usable.length} fichier{usable.length > 1 ? "s" : ""} · <span class="text-fg">{bytes(plan.download_bytes)} à télécharger</span> · sortie d'au plus {bytes(plan.estimated_output_bytes)} avant filtres · {bytes(Math.min(plan.output_free_bytes, plan.cache_free_bytes))} libres
          </div>
          {#if mustConfirm}
            <label class="flex items-center gap-2 text-[12px] text-warn">
              <input type="checkbox" bind:checked={confirmed} />
              {plan.disk_warning ? "Je lance quand même" : `Je confirme le téléchargement de ${bytes(plan.download_bytes)}`}
            </label>
          {/if}
          <button class="btn btn-primary" disabled={!usable.length || (mustConfirm && !confirmed)} onclick={start}>
            Lancer <span class="kbd ml-1 border-white/25 bg-white/10 text-white/80">⌘↵</span>
          </button>
        </div>
      {:else}
        <div class="flex flex-1 items-center justify-center p-8 text-center text-muted">
          {apps ? "Coche les applications à récupérer, puis prépare le run pour voir les fichiers et leur taille." : "Les fichiers à traiter apparaîtront ici."}
        </div>
      {/if}
    </div>
  </div>
{/if}

{#if toast}
  <div class="pointer-events-none fixed bottom-5 left-1/2 z-40 -translate-x-1/2 rounded-full border border-line bg-raised px-4 py-2 text-[12.5px] shadow-xl">{toast}</div>
{/if}

{#if secret}
  <Secret
    title={secret.kind === "sudo" ? "Mot de passe sudo" : "Phrase de passe de la clé SSH"}
    hint={secret.kind === "sudo"
      ? `Le serveur demande ton mot de passe pour « sudo chmod +r ». Il est gardé en mémoire le temps de la session, jamais écrit sur le disque.`
      : `La clé ${secret.target} est chiffrée. Sa phrase de passe est gardée en mémoire le temps de la session, jamais écrite sur le disque.`}
    onsubmit={submitSecret}
    oncancel={() => (secret = null)}
  />
{/if}
