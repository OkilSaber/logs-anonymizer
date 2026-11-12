<script lang="ts">
  import type { SandboxEntry, Segment } from "./api";

  // `onallow` : si fourni, un clic sur un remplacement propose de ne plus masquer sa valeur.
  let { entries, onallow }: { entries: SandboxEntry[]; onallow?: (value: string, rule: string) => Promise<void> | void } = $props();
  let hovered = $state<string | null>(null);
  let picked = $state<{ x: number; y: number; value: string; rule: string; safety: boolean } | null>(null);
  let busy = $state(false);

  const cls = (s: Segment) =>
    s.safety
      ? "bg-danger-soft text-danger"
      : hovered !== null && s.rule === hovered
        ? "bg-accent text-white"
        : "bg-accent-soft text-fg";

  // Les remplacements sont dans le même ordre des deux côtés : le n-ième de la sortie
  // correspond au n-ième du brut, qui porte la valeur d'origine.
  function originals(e: SandboxEntry): string[] {
    const raw = e.raw.filter((s) => s.rule);
    let n = 0;
    return e.out.map((s) => (s.rule ? (raw[n++]?.text ?? s.text) : ""));
  }

  function pick(ev: MouseEvent, value: string, s: Segment) {
    if (!onallow || !s.rule) return;
    ev.stopPropagation();
    picked = { x: Math.min(ev.clientX, window.innerWidth - 380), y: Math.min(ev.clientY + 14, window.innerHeight - 190), value, rule: s.rule, safety: s.safety };
  }

  async function allow() {
    if (!picked || !onallow) return;
    busy = true;
    try {
      await onallow(picked.value, picked.rule);
      picked = null;
    } finally {
      busy = false;
    }
  }
</script>

<svelte:window onkeydown={(e) => e.key === "Escape" && (picked = null)} onclick={() => (picked = null)} />

{#snippet side(segs: Segment[], values: string[] | null)}
  {#each segs as s, i}{#if s.rule}{@const value = values ? values[i] : s.text}<mark
        class="rounded-[3px] px-[2px] transition-colors duration-100 {cls(s)} {onallow ? 'cursor-pointer' : ''}"
        title={(s.safety ? `Filet de sécurité · ${s.rule.replace("filet:", "")}` : s.rule) + (onallow ? " — clique pour ne plus masquer cette valeur" : "")}
        role={onallow ? "button" : undefined}
        onmouseenter={() => (hovered = s.rule)}
        onmouseleave={() => (hovered = null)}
        onclick={(ev) => pick(ev, value, s)}>{s.text}</mark
      >{:else}{s.text}{/if}{/each}
{/snippet}

<div class="selectable divide-y divide-line font-mono text-[12px] leading-[1.55]">
  {#each entries as e (e.line_no)}
    <div class="grid grid-cols-2">
      <div class="min-w-0 border-r border-line px-3 py-2">
        <div class="mb-0.5 flex items-center gap-2 font-sans text-[11px] text-faint">
          <span class="tabular-nums">l. {e.line_no}</span>
          <span class="truncate">{e.source}</span>
        </div>
        <pre class="m-0 break-all whitespace-pre-wrap {e.dropped_by ? 'text-faint' : ''}">{@render side(e.raw, null)}</pre>
      </div>
      <div class="min-w-0 px-3 py-2">
        {#if e.dropped_by}
          <div class="flex h-full items-center font-sans text-[12px] text-faint">
            Entrée filtrée par <span class="ml-1 rounded bg-raised px-1.5 py-0.5 font-mono text-[11px] text-muted">{e.dropped_by}</span>
          </div>
        {:else}
          <div class="mb-0.5 h-[17px]"></div>
          <pre class="m-0 break-all whitespace-pre-wrap">{@render side(e.out, originals(e))}</pre>
        {/if}
      </div>
    </div>
  {/each}
</div>

{#if picked}
  <div
    class="card fixed z-50 w-[360px] p-3.5 font-sans shadow-2xl"
    style="left: {picked.x}px; top: {picked.y}px"
    role="dialog"
    tabindex="-1"
    onclick={(e) => e.stopPropagation()}
    onkeydown={(e) => e.key === "Escape" && (picked = null)}
  >
    <div class="text-[11px] tracking-wide text-muted uppercase">{picked.safety ? "Rattrapé par le filet de sécurité" : "Remplacé par la règle"}</div>
    <div class="mt-0.5 truncate font-mono text-[12px]" title={picked.rule}>{picked.rule.replace("filet:", "")}</div>
    <div class="selectable mt-2.5 max-h-16 overflow-hidden rounded-md bg-raised px-2 py-1.5 font-mono text-[12px] break-all">{picked.value.length > 140 ? picked.value.slice(0, 140) + "…" : picked.value}</div>
    <p class="mt-2.5 mb-3 text-[12px] leading-relaxed text-muted">Cette valeur exacte ne sera plus masquée pour cette application, où qu'elle apparaisse. Les autres valeurs restent traitées comme avant.</p>
    <div class="flex justify-end gap-2">
      <button class="btn btn-ghost h-7" onclick={() => (picked = null)}>Annuler</button>
      <button class="btn btn-primary h-7" disabled={busy} onclick={allow}>{busy ? "Ajout…" : "Ne plus masquer cette valeur"}</button>
    </div>
  </div>
{/if}
