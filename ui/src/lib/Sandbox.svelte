<script lang="ts">
  import { api, ApiError, type SandboxResult, type TemplateInfo } from "./api";
  import { count } from "./format";
  import { SANDBOX_SAMPLE } from "./sample";
  import SideBySide from "./SideBySide.svelte";

  let { templates }: { templates: TemplateInfo[] } = $props();
  const usable = $derived(templates.filter((t) => t.available));
  let template = $state("");
  let input = $state("");
  let result = $state<SandboxResult | null>(null);
  let error = $state("");
  let seq = 0;

  $effect(() => {
    if (!template && usable.length) template = (usable.find((t) => t.id === "kbrw/elixir") ?? usable[0]).id;
  });

  // Anonymisation en direct, 200 ms après la dernière frappe.
  $effect(() => {
    const [t, text] = [template, input];
    if (!t || !text.trim()) {
      result = null;
      error = "";
      return;
    }
    const mine = ++seq;
    const timer = setTimeout(async () => {
      try {
        const r = await api.sandboxRun(t, text);
        if (mine === seq) [result, error] = [r, ""];
      } catch (e) {
        if (mine === seq) error = e instanceof ApiError ? e.message : String(e);
      }
    }, 200);
    return () => clearTimeout(timer);
  });
</script>

<div class="flex h-full min-h-0 flex-col">
  <div class="flex items-center gap-3 border-b border-line px-4 py-2.5">
    <select class="field w-64" bind:value={template}>
      {#each usable as t}<option value={t.id}>{t.id}</option>{/each}
    </select>
    {#if result}
      <span class="text-[12px] text-muted tabular-nums">
        {count(result.entries_in)} entrées · {count(result.dropped)} filtrées · {count(result.modified)} modifiées
        {#if result.safety_total}· <span class="text-warn">{count(result.safety_total)} rattrapées par le filet</span>{/if}
      </span>
    {/if}
    <div class="flex-1"></div>
    <button class="btn btn-ghost" onclick={() => (input = SANDBOX_SAMPLE)}>Exemple</button>
    <button class="btn btn-ghost" disabled={!input} onclick={() => (input = "")}>Vider</button>
  </div>
  <textarea
    class="selectable h-40 shrink-0 resize-none border-0 border-b border-line bg-bg p-3 font-mono text-[12px] leading-[1.55] text-fg outline-none placeholder:text-faint"
    placeholder="Colle ici des lignes de log brutes (avec leur préfixe host). Elles restent sur ta machine."
    spellcheck="false"
    bind:value={input}
  ></textarea>
  {#if error}<div class="selectable border-b border-line bg-danger-soft px-4 py-2 text-[12.5px] text-danger">{error}</div>{/if}
  {#if result?.warnings.length}
    <div class="border-b border-line bg-warn-soft px-4 py-2 text-[12px] text-warn">{result.warnings.join(" · ")}</div>
  {/if}
  <div class="grid grid-cols-2 border-b border-line bg-panel text-[11px] font-medium tracking-wide text-muted uppercase">
    <div class="border-r border-line px-3 py-1.5">Brut</div>
    <div class="px-3 py-1.5">Anonymisé · survole un remplacement pour voir sa règle</div>
  </div>
  <div class="min-h-0 flex-1 overflow-y-auto">
    {#if result}<SideBySide entries={result.entries} />{:else}<div class="p-8 text-center text-muted">Le résultat apparaît ici au fil de la saisie.</div>{/if}
  </div>
</div>
