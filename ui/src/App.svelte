<script lang="ts">
  import { onMount } from "svelte";
  import { api, inTauri, type Config, type PlanRequest, type TemplateInfo } from "./lib/api";
  import Extraction from "./lib/Extraction.svelte";
  import History from "./lib/History.svelte";
  import Reveal from "./lib/Reveal.svelte";
  import Sandbox from "./lib/Sandbox.svelte";
  import Settings from "./lib/Settings.svelte";
  import Templates from "./lib/Templates.svelte";

  type Tab = "extraction" | "sandbox" | "templates" | "reveal" | "history" | "settings";
  const tabs: { id: Tab; label: string; hint: string }[] = [
    { id: "extraction", label: "Extraction", hint: "⌘1" },
    { id: "sandbox", label: "Bac à sable", hint: "⌘2" },
    { id: "templates", label: "Templates", hint: "⌘3" },
    { id: "reveal", label: "Réponse IA", hint: "⌘4" },
    { id: "history", label: "Historique", hint: "⌘5" },
    { id: "settings", label: "Réglages", hint: "⌘6" },
  ];

  let tab = $state<Tab>("extraction");
  let config = $state<Config | null>(null);
  let templates = $state<TemplateInfo[]>([]);
  let fatal = $state("");
  // Run de l'historique à rejouer : repris par l'écran d'extraction.
  let replay = $state<PlanRequest | null>(null);

  onMount(() => {
    (async () => {
      try {
        [config, templates] = await Promise.all([api.getConfig(), api.listTemplates()]);
      } catch (e) {
        fatal = String(e);
      }
    })();
    const key = (e: KeyboardEvent) => {
      const i = Number(e.key) - 1;
      if ((e.metaKey || e.ctrlKey) && tabs[i]) {
        e.preventDefault();
        tab = tabs[i].id;
      }
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  });
</script>

<div class="flex h-full">
  <nav class="flex w-[200px] shrink-0 flex-col border-r border-line bg-panel">
    <div class="h-11 shrink-0" data-tauri-drag-region></div>
    <div class="px-4 pb-4">
      <div class="text-[13px] font-semibold tracking-tight">Logs Anonymizer</div>
      <div class="text-[11px] text-faint">Rien ne sort sans être anonymisé</div>
    </div>
    <div class="flex-1 space-y-0.5 px-2">
      {#each tabs as t}
        <button
          class="flex h-8 w-full items-center rounded-md px-2.5 text-left text-[13px] transition-colors duration-100 {tab === t.id ? 'bg-raised text-fg' : 'text-muted hover:bg-raised/60 hover:text-fg'}"
          onclick={() => (tab = t.id)}
        >
          <span class="flex-1">{t.label}</span>
          <span class="kbd">{t.hint}</span>
        </button>
      {/each}
    </div>
    {#if !inTauri}
      <div class="m-2 rounded-md bg-warn-soft px-2.5 py-2 text-[11px] leading-snug text-warn">Aperçu sans backend : données de démonstration.</div>
    {/if}
  </nav>
  <main class="flex min-w-0 flex-1 flex-col">
    <div class="h-7 shrink-0" data-tauri-drag-region></div>
    <div class="min-h-0 flex-1">
      {#if fatal}
        <div class="selectable p-8 text-danger">{fatal}</div>
      {:else if config}
        <!-- L'extraction reste montée : un run en cours survit à un changement d'onglet. -->
        <div class="h-full" class:hidden={tab !== "extraction"}>
          <Extraction {config} {templates} {replay} onreplayed={() => (replay = null)} onsettings={() => (tab = "settings")} />
        </div>
        {#if tab === "sandbox"}<Sandbox {templates} />{/if}
        {#if tab === "templates"}<Templates {templates} onchanged={async () => (templates = await api.listTemplates())} />{/if}
        {#if tab === "reveal"}<Reveal />{/if}
        {#if tab === "history"}<History {config} onreplay={(r) => ((replay = r), (tab = "extraction"))} />{/if}
        {#if tab === "settings"}<Settings {config} onsaved={(c) => (config = c)} />{/if}
      {/if}
    </div>
  </main>
</div>
