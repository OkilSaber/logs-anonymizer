<script lang="ts">
  import { api, ApiError, type ImportReport, type TemplateCheck, type TemplateInfo } from "./api";

  let { templates, onchanged }: { templates: TemplateInfo[]; onchanged: () => void } = $props();

  // Texte en cours d'édition : celui d'un template de la bibliothèque, ou un nouveau.
  let current = $state<string | null>(null);
  let text = $state("");
  let saved = $state("");
  let builtin = $state(false);
  let check = $state<TemplateCheck | null>(null);
  let message = $state<{ ok: boolean; text: string } | null>(null);
  // Rapport du dernier import en lot, affiché tant qu'aucun template n'est ouvert.
  let report = $state<ImportReport | null>(null);
  let importing = $state(false);
  let seq = 0;

  const dirty = $derived(text !== saved);
  const selected = $derived(templates.find((t) => t.id === current) ?? null);
  const passed = $derived(check?.tests.filter((t) => t.passed).length ?? 0);
  // On n'écrase jamais un template fourni : il faut le dupliquer sous un autre identifiant.
  const canSave = $derived(!!check?.ok && !check.builtin && dirty);

  const SKELETON = `[template]
id = "local/mon-app"
name = "Mon application"
version = "0.1.0"
schema_version = 1
log_kind = "erlang"
format = "elixir_syslog"
extends = ["kbrw/elixir@^1"]
suggested_apps = ["mon_app"]

# [[filters]]
# id = "bruit"
# action = "drop_entry"
# header = '\\\\] +ligne périodique sans intérêt'

# [[rules]]
# id = "identifiant-client"
# keys = ["customer_ref"]
# strategy = "pseudonymize"
# token = "CUSTOMER"
`;

  function flash(ok: boolean, t: string) {
    message = { ok, text: t };
    if (ok) setTimeout(() => message?.text === t && (message = null), 2800);
  }

  const fail = (e: unknown) => flash(false, e instanceof ApiError ? e.message : String(e));

  function load(id: string | null, toml: string, isBuiltin: boolean, savedText = toml) {
    current = id;
    text = toml;
    saved = savedText;
    builtin = isBuiltin;
    check = null;
    message = null;
  }

  async function open(t: TemplateInfo) {
    try {
      const src = await api.templateSource(t.id);
      load(t.id, src.toml, src.builtin);
    } catch (e) {
      fail(e);
    }
  }

  // Validation en direct, 350 ms après la dernière frappe.
  $effect(() => {
    const t = text;
    if (!t.trim()) {
      check = null;
      return;
    }
    const mine = ++seq;
    const timer = setTimeout(async () => {
      const c = await api.templateCheck(t);
      if (mine === seq) check = c;
    }, 350);
    return () => clearTimeout(timer);
  });

  async function save() {
    try {
      const id = await api.templateSave(text);
      saved = text;
      current = id;
      builtin = false;
      onchanged();
      flash(true, `Template ${id} enregistré`);
    } catch (e) {
      fail(e);
    }
  }

  // Une copie modifiable d'un template fourni : même contenu, identifiant local.
  function duplicate() {
    const name = (current ?? "copie").split("/").pop();
    load(null, text.replace(/^(\s*id\s*=\s*)"[^"]*"/m, `$1"local/${name}-copie"`), false, "");
  }

  async function remove() {
    if (!current) return;
    try {
      await api.templateDelete(current);
      const id = current;
      load(null, "", false);
      onchanged();
      flash(true, `Template ${id} supprimé`);
    } catch (e) {
      fail(e);
    }
  }

  // Import en lot : des .toml et des .zip choisis, ou tous les .toml d'un dossier.
  async function importMany(folder: boolean) {
    if (importing) return;
    importing = true;
    try {
      const result = await api.templatesImport(folder);
      if (result) {
        load(null, "", false);
        report = result;
        onchanged();
      }
    } catch (e) {
      fail(e);
      report = { imported: [], rejected: [{ source: folder ? "Dossier" : "Fichiers", reason: e instanceof ApiError ? e.message : String(e) }] };
    } finally {
      importing = false;
    }
  }

  function openImported(id: string) {
    const t = templates.find((x) => x.id === id);
    if (t) open(t);
  }

  async function exportFile() {
    if (!current) return;
    try {
      const path = await api.templateExport(current);
      if (path) flash(true, "Template exporté");
    } catch (e) {
      fail(e);
    }
  }
</script>

<div class="flex h-full min-h-0">
  <div class="flex w-[300px] shrink-0 flex-col border-r border-line">
    <div class="flex gap-1.5 border-b border-line p-3">
      <button class="btn flex-1" onclick={() => load(null, SKELETON, false, "")}>Nouveau</button>
      <button class="btn flex-1" disabled={importing} title="Un ou plusieurs fichiers .toml, ou une archive .zip de templates" onclick={() => importMany(false)}>Importer…</button>
      <button class="btn flex-1" disabled={importing} title="Tous les .toml d'un dossier et de ses sous-dossiers" onclick={() => importMany(true)}>Dossier…</button>
    </div>
    <div class="min-h-0 flex-1 overflow-y-auto p-2">
      {#each templates as t (t.id)}
        <button class="block w-full rounded-md px-3 py-2 text-left transition-colors duration-100 {current === t.id ? 'bg-raised' : 'hover:bg-raised/60'}" onclick={() => open(t)}>
          <div class="flex items-center gap-2">
            <span class="truncate font-mono text-[12.5px]">{t.id}</span>
            <span class="text-[11px] text-faint">{t.version}</span>
            <span class="flex-1"></span>
            {#if !t.available}<span class="rounded bg-warn-soft px-1.5 py-0.5 text-[10.5px] text-warn">à venir</span>
            {:else if t.is_abstract}<span class="rounded bg-raised px-1.5 py-0.5 text-[10.5px] text-muted">socle</span>
            {:else if t.id.startsWith("local/")}<span class="rounded bg-accent-soft px-1.5 py-0.5 text-[10.5px] text-fg">local</span>{/if}
          </div>
          <div class="mt-0.5 truncate text-[12px] text-muted">{t.name}</div>
        </button>
      {:else}
        <div class="px-3 py-6 text-center text-[12.5px] leading-relaxed text-muted">Aucun template pour l'instant.</div>
      {/each}
    </div>
  </div>

  {#if !text && current === null}
    <div class="flex flex-1 items-center justify-center overflow-y-auto p-8">
      {#if report}
        {@const weak = report.imported.filter((t) => t.weakens > 0).length}
        <div class="w-full max-w-xl self-start">
          <div class="flex items-baseline gap-3">
            <h2 class="text-[15px] font-semibold">
              {report.imported.length} template{report.imported.length > 1 ? "s" : ""} importé{report.imported.length > 1 ? "s" : ""}{report.rejected.length ? `, ${report.rejected.length} refusé${report.rejected.length > 1 ? "s" : ""}` : ""}
            </h2>
            <span class="flex-1"></span>
            <button class="btn btn-ghost" onclick={() => (report = null)}>Fermer</button>
          </div>
          {#if weak}
            <p class="mt-2 rounded-md bg-warn-soft px-3 py-2 text-[12.5px] leading-relaxed text-warn">{weak} template{weak > 1 ? "s gardent" : " garde"} des valeurs en clair ou {weak > 1 ? "désactivent" : "désactive"} une protection héritée. Ouvre-{weak > 1 ? "les" : "le"} pour relire ce qui est concerné.</p>
          {/if}
          {#if report.imported.length}
            <div class="mt-3 divide-y divide-line rounded-md border border-line">
              {#each report.imported as t (t.id)}
                <button class="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-raised/60" onclick={() => openImported(t.id)}>
                  <span class="truncate font-mono text-[12.5px]">{t.id}</span>
                  <span class="flex-1"></span>
                  {#if t.replaced}<span class="rounded bg-raised px-1.5 py-0.5 text-[10.5px] text-muted">remplacé</span>{/if}
                  {#if t.weakens}<span class="rounded bg-warn-soft px-1.5 py-0.5 text-[10.5px] text-warn">{t.weakens} point{t.weakens > 1 ? "s" : ""} à relire</span>{/if}
                </button>
              {/each}
            </div>
          {/if}
          {#if report.rejected.length}
            <h3 class="mt-5 text-[12.5px] font-semibold text-danger">Refusés</h3>
            <div class="mt-2 space-y-2">
              {#each report.rejected as r}
                <div class="rounded-md bg-danger-soft px-3 py-2 text-[12px] leading-relaxed">
                  <div class="selectable font-mono text-danger">{r.source}</div>
                  <div class="selectable mt-0.5 text-fg">{r.reason}</div>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      {:else if !templates.length}
        <div class="max-w-md text-center">
          <div class="text-[15px] font-semibold">Aucun template</div>
          <p class="mt-2 text-[12.5px] leading-relaxed text-muted">L'app est livrée sans template : sans eux, aucun fichier ne peut être anonymisé. Importe l'archive .zip de ton équipe, un dossier, ou des fichiers .toml. Chaque template est validé et ses tests sont lancés avant d'être enregistré.</p>
          <div class="mt-4 flex justify-center gap-2">
            <button class="btn btn-primary" disabled={importing} onclick={() => importMany(false)}>Importer un .zip ou des .toml…</button>
            <button class="btn" disabled={importing} onclick={() => importMany(true)}>Importer un dossier…</button>
          </div>
        </div>
      {:else}
        <div class="text-center text-muted">Choisis un template pour le lire, crée le tien, ou importe-en plusieurs d'un coup (.toml, .zip, dossier).</div>
      {/if}
    </div>
  {:else}
    <div class="flex min-w-0 flex-1 flex-col">
      <div class="flex items-center gap-2 border-b border-line px-4 py-2.5">
        <div class="min-w-0 flex-1">
          <span class="font-mono text-[13px]">{check?.id ?? current ?? "nouveau template"}</span>
          {#if selected && current && !dirty}<span class="ml-2 text-[12px] text-muted">{selected.rules} règles · {selected.tests} tests{selected.format ? ` · ${selected.format}` : ""}</span>{/if}
          {#if dirty}<span class="ml-2 text-[12px] text-warn">modifié, non enregistré</span>{/if}
        </div>
        {#if message}<span class="selectable max-w-[40%] truncate text-[12px] {message.ok ? 'text-ok' : 'text-danger'}" title={message.text}>{message.text}</span>{/if}
        {#if builtin}<button class="btn" onclick={duplicate}>Dupliquer pour modifier</button>{/if}
        {#if current}<button class="btn" onclick={exportFile}>Exporter…</button>{/if}
        {#if current && !builtin}<button class="btn btn-ghost text-danger" onclick={remove}>Supprimer</button>{/if}
        <button class="btn btn-primary" disabled={!canSave} onclick={save}>Enregistrer</button>
      </div>

      <div class="flex min-h-0 flex-1">
        <textarea
          class="selectable min-w-0 flex-1 resize-none border-0 border-r border-line bg-bg p-4 font-mono text-[12px] leading-[1.6] text-fg outline-none"
          spellcheck="false"
          readonly={builtin}
          bind:value={text}
        ></textarea>

        <div class="w-[360px] shrink-0 overflow-y-auto p-4">
          {#if !check}
            <div class="text-[12px] text-muted">Validation…</div>
          {:else}
            <div class="flex items-center gap-2">
              <span class="h-2 w-2 rounded-full {check.ok ? 'bg-ok' : 'bg-danger'}"></span>
              <span class="text-[13px] font-medium">{check.ok ? "Template valide" : "Template invalide"}</span>
              {#if check.tests.length}<span class="text-[12px] text-muted">· {passed} / {check.tests.length} tests</span>{/if}
            </div>
            {#if check.error}<div class="selectable mt-2 rounded-md bg-danger-soft px-3 py-2 text-[12px] leading-relaxed text-danger">{check.error}</div>{/if}
            {#if check.builtin && !builtin}
              <div class="mt-2 rounded-md bg-warn-soft px-3 py-2 text-[12px] leading-relaxed text-warn">Cet identifiant est celui d'un template fourni avec l'app. Change-le pour pouvoir enregistrer.</div>
            {:else if check.exists && dirty && check.ok}
              <div class="mt-2 text-[12px] text-muted">Enregistrer remplacera le template {check.id} de ta bibliothèque.</div>
            {/if}
            {#each check.warnings as w}<div class="mt-2 rounded-md bg-warn-soft px-3 py-2 text-[12px] leading-relaxed text-warn">{w}</div>{/each}

            {#if check.weakens.length}
              <div class="label mt-4">Affaiblit la protection</div>
              <div class="rounded-md border border-warn/40 px-3 py-2 text-[12px] leading-relaxed">
                {#each check.weakens as w}<div class="selectable py-0.5">{w}</div>{/each}
              </div>
              <div class="mt-1 text-[11.5px] text-faint">À relire avant d'accepter un template reçu de quelqu'un d'autre.</div>
            {/if}

            {#if check.tests.length}
              <div class="label mt-4">Tests embarqués</div>
              <div class="space-y-1.5">
                {#each check.tests as o}
                  <details class="card">
                    <summary class="flex cursor-default items-center gap-2 px-3 py-1.5 text-[12px]">
                      <span class="h-1.5 w-1.5 shrink-0 rounded-full {o.passed ? 'bg-ok' : 'bg-danger'}"></span>
                      <span class="min-w-0 flex-1 truncate">{o.name}</span>
                    </summary>
                    <div class="border-t border-line p-3">
                      {#each o.failures as f}<div class="selectable mb-2 text-[12px] whitespace-pre-wrap text-danger">{f}</div>{/each}
                      <pre class="selectable m-0 font-mono text-[11px] leading-[1.55] break-all whitespace-pre-wrap text-muted">{o.output || "Aucune sortie : toutes les entrées sont filtrées."}</pre>
                    </div>
                  </details>
                {/each}
              </div>
            {/if}
          {/if}
        </div>
      </div>
    </div>
  {/if}
</div>
