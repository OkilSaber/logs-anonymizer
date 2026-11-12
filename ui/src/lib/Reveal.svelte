<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type Deanonymized, type MappingInfo } from "./api";
  import { bytes, count } from "./format";

  let tables = $state<MappingInfo[] | null>(null);
  let runId = $state("");
  let input = $state("");
  let result = $state<Deanonymized | null>(null);
  let error = $state("");
  // « Tout supprimer » demande un second clic : les tables ne se récupèrent pas.
  let confirmAll = $state(false);
  let seq = 0;

  async function refresh() {
    tables = await api.mappingList();
    if (!tables.some((t) => t.run_id === runId)) runId = tables[0]?.run_id ?? "";
  }

  async function purge(id: string | null) {
    try {
      await api.mappingPurge(id);
      result = null;
      await refresh();
    } catch (e) {
      error = e instanceof ApiError ? e.message : String(e);
    }
  }

  // Les valeurs réelles reviennent 250 ms après la dernière frappe.
  $effect(() => {
    const [id, text] = [runId, input];
    if (!id || !text.trim()) {
      result = null;
      error = "";
      return;
    }
    const mine = ++seq;
    const timer = setTimeout(async () => {
      try {
        const r = await api.deanonymize(id, text);
        if (mine === seq) [result, error] = [r, ""];
      } catch (e) {
        if (mine === seq) [result, error] = [null, e instanceof ApiError ? e.message : String(e)];
      }
    }, 250);
    return () => clearTimeout(timer);
  });

  onMount(refresh);
</script>

<div class="flex h-full min-h-0 flex-col">
  {#if tables && !tables.length}
    <div class="flex flex-1 flex-col items-center justify-center gap-2 p-8 text-center">
      <div class="text-[15px] font-semibold">Aucune table de correspondance</div>
      <p class="m-0 max-w-md text-muted">Active « Garder la table de correspondance » dans les réglages, puis lance un run. Tu pourras ensuite coller ici la réponse de l'IA pour y remettre les vraies valeurs.</p>
    </div>
  {:else}
    <div class="flex items-center gap-3 border-b border-line px-4 py-2.5">
      <span class="text-[12px] text-muted">Run</span>
      <select class="field w-[420px] font-mono" bind:value={runId}>
        {#each tables ?? [] as t}<option value={t.run_id}>{t.run_id} · {bytes(t.bytes)}</option>{/each}
      </select>
      {#if result}
        <span class="text-[12px] text-muted tabular-nums">
          {count(result.replaced)} jeton{result.replaced > 1 ? "s" : ""} remplacé{result.replaced > 1 ? "s" : ""}
          {#if result.unknown}· <span class="text-warn">{count(result.unknown)} inconnu{result.unknown > 1 ? "s" : ""} de ce run</span>{/if}
        </span>
      {/if}
      <span class="flex-1"></span>
      <button class="btn btn-ghost" disabled={!runId} onclick={() => purge(runId)}>Supprimer cette table</button>
      {#if confirmAll}
        <button class="btn text-danger" onclick={() => ((confirmAll = false), purge(null))}>Confirmer : supprimer {tables?.length} table{(tables?.length ?? 0) > 1 ? "s" : ""}</button>
        <button class="btn btn-ghost" onclick={() => (confirmAll = false)}>Annuler</button>
      {:else}
        <button class="btn btn-ghost text-danger" onclick={() => (confirmAll = true)}>Tout supprimer</button>
      {/if}
    </div>
    {#if error}<div class="selectable border-b border-line bg-danger-soft px-4 py-2 text-[12.5px] text-danger">{error}</div>{/if}
    <div class="grid grid-cols-2 border-b border-line bg-panel text-[11px] font-medium tracking-wide text-muted uppercase">
      <div class="border-r border-line px-4 py-1.5">Réponse de l'IA, avec ses jetons</div>
      <div class="px-4 py-1.5 text-warn">Avec les vraies valeurs · à ne pas renvoyer à une IA</div>
    </div>
    <div class="grid min-h-0 flex-1 grid-cols-2">
      <textarea
        class="selectable resize-none border-0 border-r border-line bg-bg p-4 text-[13px] leading-relaxed text-fg outline-none placeholder:text-faint"
        placeholder="Colle ici la réponse de l'IA. Les jetons comme EMAIL_7f3a2c9d reprennent leur valeur à droite."
        spellcheck="false"
        bind:value={input}
      ></textarea>
      <div class="selectable overflow-y-auto p-4 text-[13px] leading-relaxed whitespace-pre-wrap">{result?.text ?? ""}</div>
    </div>
  {/if}
</div>
