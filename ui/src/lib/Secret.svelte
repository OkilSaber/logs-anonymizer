<script lang="ts">
  let { title, hint, onsubmit, oncancel }: { title: string; hint: string; onsubmit: (v: string) => void; oncancel: () => void } = $props();
  let value = $state("");
  let input: HTMLInputElement | undefined = $state();
  $effect(() => input?.focus());
</script>

<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-[2px]" role="presentation" onkeydown={(e) => e.key === "Escape" && oncancel()}>
  <form
    class="card w-[420px] p-5 shadow-2xl"
    onsubmit={(e) => {
      e.preventDefault();
      if (value) onsubmit(value);
    }}
  >
    <h2 class="m-0 text-[15px] font-semibold">{title}</h2>
    <p class="mt-1.5 mb-4 text-[12.5px] leading-relaxed text-muted">{hint}</p>
    <input bind:this={input} bind:value class="field" type="password" autocomplete="off" />
    <div class="mt-4 flex justify-end gap-2">
      <button type="button" class="btn btn-ghost" onclick={oncancel}>Annuler</button>
      <button type="submit" class="btn btn-primary" disabled={!value}>Valider</button>
    </div>
  </form>
</div>
