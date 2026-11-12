<script lang="ts">
  import { onMount } from "svelte";
  import { api, type Config, type HistoryEntry, type PlanRequest } from "./api";
  import { bytes, count, daysLabel } from "./format";

  let { config, onreplay }: { config: Config; onreplay: (r: PlanRequest) => void } = $props();
  let entries = $state<HistoryEntry[] | null>(null);

  const serverName = (id: string) => config.servers.find((s) => s.id === id)?.name ?? id;
  const when = (iso: string) => new Date(iso).toLocaleString("fr-FR", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
  const apps = (e: HistoryEntry) => e.request.selections.map((s) => s.app).join(", ");
  const outcome: Record<string, [string, string]> = { ok: ["Terminé", "text-ok"], cancelled: ["Annulé", "text-muted"], error: ["Échec", "text-danger"] };

  async function clear() {
    await api.historyClear();
    entries = [];
  }

  onMount(async () => {
    entries = await api.historyList();
  });
</script>

<div class="h-full overflow-y-auto">
  <div class="mx-auto max-w-4xl p-6">
    <div class="mb-4 flex items-center">
      <div class="flex-1">
        <h1 class="m-0 text-[15px] font-semibold">Historique</h1>
        <p class="m-0 mt-0.5 text-[12.5px] text-muted">Ce qui a été demandé et ce que ça a donné. Aucun contenu de log n'est gardé ici.</p>
      </div>
      <button class="btn" disabled={!entries?.length} onclick={clear}>Vider l'historique</button>
    </div>
    {#if entries && !entries.length}
      <div class="card p-8 text-center text-muted">Aucun run pour l'instant.</div>
    {/if}
    <div class="space-y-2">
      {#each entries ?? [] as e (e.run_id)}
        {@const [label, tone] = outcome[e.outcome] ?? [e.outcome, "text-muted"]}
        <div class="card px-4 py-3">
          <div class="flex items-center gap-3">
            <div class="min-w-0 flex-1">
              <div class="flex items-baseline gap-2">
                <span class="text-[13px] font-medium">{serverName(e.request.server_id)}</span>
                <span class="truncate font-mono text-[12px] text-muted">{apps(e)}</span>
              </div>
              <div class="mt-0.5 text-[12px] text-muted">
                {when(e.started_at)} · {daysLabel([...e.request.days].sort())} · {e.request.kinds.join(", ")}{e.request.template ? ` · ${e.request.template}` : ""}
              </div>
            </div>
            <span class="text-[12px] {tone}">{label}</span>
            <button class="btn" onclick={() => onreplay(e.request)} title="Reprend ce serveur, ces jours et ces applications, et prépare le run">Rejouer</button>
          </div>
          {#if e.error}<div class="selectable mt-2 text-[12px] text-danger">{e.error}</div>{/if}
          {#if e.files.length}
            <div class="mt-2.5 border-t border-line pt-2">
              {#each e.files as f}
                <div class="flex items-center gap-3 py-[2px] text-[12px] tabular-nums">
                  <span class="min-w-0 flex-1 truncate font-mono text-muted">{f.app}/{f.cluster}/{f.kind}</span>
                  <span class="text-faint">{f.template}</span>
                  <span class="w-40 text-right">{count(f.entries_out)} sur {count(f.entries_in)} entrées</span>
                  <span class="w-20 text-right">{bytes(f.bytes_out)}</span>
                  <span class="w-24 text-right {f.safety_total ? 'text-warn' : 'text-faint'}">filet {count(f.safety_total)}</span>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  </div>
</div>
