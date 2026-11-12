<script lang="ts">
  import type { Snippet } from "svelte";

  // Une section de réglages, repliable. L'état replié est retenu d'une ouverture de l'app à l'autre.
  let { id, title, summary = "", actions, children }: { id: string; title: string; summary?: string; actions?: Snippet; children: Snippet } = $props();

  const KEY = "settings.collapsed";
  function collapsed(): string[] {
    try {
      const list = JSON.parse(localStorage.getItem(KEY) ?? "[]");
      return Array.isArray(list) ? list : [];
    } catch {
      return [];
    }
  }

  let open = $state(true);
  $effect.pre(() => {
    open = !collapsed().includes(id);
  });

  function toggle() {
    open = !open;
    try {
      const others = collapsed().filter((x) => x !== id);
      localStorage.setItem(KEY, JSON.stringify(open ? others : [...others, id]));
    } catch {
      // Stockage indisponible : la section se replie quand même, sans être retenue.
    }
  }
</script>

<section class="card">
  <div class="flex items-center gap-3 px-5 py-3.5">
    <button class="flex min-w-0 flex-1 items-center gap-2.5 text-left" onclick={toggle} aria-expanded={open}>
      <svg class="size-3 shrink-0 text-faint transition-transform duration-150 {open ? 'rotate-90' : ''}" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4.5 2.5 8 6l-3.5 3.5" /></svg>
      <h2 class="m-0 shrink-0 text-[14px] font-semibold">{title}</h2>
      {#if !open && summary}<span class="min-w-0 truncate text-[12px] text-muted">{summary}</span>{/if}
    </button>
    {#if open && actions}{@render actions()}{/if}
  </div>
  {#if open}<div class="px-5 pb-5">{@render children()}</div>{/if}
</section>
