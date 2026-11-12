<script lang="ts">
  import Section from "./Section.svelte";
  import { onMount } from "svelte";
  import { api, ApiError, type CacheInfo, type Config } from "./api";
  import { bytes } from "./format";

  let { config, onsaved }: { config: Config; onsaved: (c: Config) => void } = $props();

  const blankBastion = () => ({ host: "", user: "", port: 22, auth: "key", identity_file: "~/.ssh/id_rsa", mode: "nc", host_key_policy: "insecure" });
  const DEFAULT_PATTERN = "/srv/syslog/{YYYY}/{MM}/{DD}/APPS/{app_name}/{cluster}/";

  // Brouillon : copie de la config au moment de l'ouverture, modifiée librement jusqu'à l'enregistrement.
  const initial = () => structuredClone($state.snapshot(config)) as Config;
  let draft = $state<Config>(initial());
  let bastion = $state(initial().bastion ?? blankBastion());
  let cache = $state<CacheInfo | null>(null);
  let message = $state<{ ok: boolean; text: string } | null>(null);
  let saving = $state(false);

  const dirty = $derived(JSON.stringify({ ...draft, bastion: bastion.host ? bastion : null }) !== JSON.stringify(config));

  function flash(ok: boolean, text: string) {
    message = { ok, text };
    if (ok) setTimeout(() => message?.text === text && (message = null), 2600);
  }

  async function save() {
    saving = true;
    try {
      const saved = await api.saveConfig({ ...$state.snapshot(draft), bastion: bastion.host ? $state.snapshot(bastion) : null });
      draft = structuredClone(saved);
      bastion = saved.bastion ?? blankBastion();
      onsaved(saved);
      flash(true, "Réglages enregistrés");
    } catch (e) {
      flash(false, e instanceof ApiError ? e.message : String(e));
    } finally {
      saving = false;
    }
  }

  async function importSsh() {
    const found = await api.importSsh();
    let added = 0;
    if (found.bastion && !bastion.host) bastion = found.bastion;
    for (const s of found.servers) {
      if (!draft.servers.some((x) => x.id === s.id || x.host === s.host)) {
        draft.servers.push(s);
        added++;
      }
    }
    flash(true, found.servers.length || found.bastion ? `${added} serveur${added > 1 ? "s" : ""} ajouté${added > 1 ? "s" : ""} depuis ta config SSH, tes alias et l'historique du shell. Vérifie puis enregistre.` : "Rien trouvé dans ~/.ssh/config, ~/.zshrc ni l'historique du shell.");
  }

  async function purge() {
    try {
      cache = await api.cachePurge();
      flash(true, "Cache brut vidé");
    } catch (e) {
      flash(false, e instanceof ApiError ? e.message : String(e));
    }
  }

  onMount(async () => {
    cache = await api.cacheInfo().catch(() => null);
  });
</script>

<div class="h-full overflow-y-auto">
  <div class="mx-auto max-w-3xl space-y-6 p-6">
    <Section id="bastion" title="Bastion" summary={bastion.host ? `${bastion.user}@${bastion.host}` : "non configuré"}>
      {#snippet actions()}<button class="btn" onclick={importSsh}>Importer depuis ma config SSH</button>{/snippet}
      <div class="grid grid-cols-6 gap-3">
        <div class="col-span-3"><label class="label" for="bh">Hôte</label><input id="bh" class="field font-mono" bind:value={bastion.host} placeholder="access01.example.com" /></div>
        <div class="col-span-2"><label class="label" for="bu">Utilisateur</label><input id="bu" class="field font-mono" bind:value={bastion.user} /></div>
        <div><label class="label" for="bp">Port</label><input id="bp" class="field" type="number" bind:value={bastion.port} /></div>
        <div class="col-span-2">
          <label class="label" for="ba">Authentification</label>
          <select id="ba" class="field" bind:value={bastion.auth}><option value="key">Fichier de clé</option><option value="agent">ssh-agent</option></select>
        </div>
        <div class="col-span-4"><label class="label" for="bk">Clé privée</label><input id="bk" class="field font-mono" bind:value={bastion.identity_file} disabled={bastion.auth === "agent"} /></div>
        <div class="col-span-3">
          <label class="label" for="bm">Passage par le bastion</label>
          <select id="bm" class="field" bind:value={bastion.mode}><option value="nc">nc exécuté sur le bastion</option><option value="direct_tcpip">direct-tcpip</option></select>
        </div>
        <div class="col-span-3">
          <label class="label" for="bhk">Clés d'hôte</label>
          <select id="bhk" class="field" bind:value={bastion.host_key_policy}><option value="insecure">Non vérifiées, comme ma config SSH</option><option value="tofu">Confiance au premier contact</option></select>
        </div>
      </div>
    </Section>

    <Section id="servers" title="Serveurs syslog" summary={draft.servers.length ? draft.servers.map((s) => s.name || s.id).join(", ") : "aucun serveur"}>
      {#snippet actions()}<button class="btn" onclick={() => draft.servers.push({ id: "", name: "", host: "", path_pattern: DEFAULT_PATTERN })}>Ajouter</button>{/snippet}
      <div class="space-y-3">
        {#each draft.servers as s, i}
          <div class="rounded-md border border-line p-3">
            <div class="grid grid-cols-6 gap-3">
              <div><label class="label" for="si{i}">Identifiant</label><input id="si{i}" class="field font-mono" bind:value={s.id} placeholder="etam-sb" /></div>
              <div class="col-span-2"><label class="label" for="sn{i}">Nom affiché</label><input id="sn{i}" class="field" bind:value={s.name} /></div>
              <div class="col-span-3"><label class="label" for="sh{i}">Hôte</label><input id="sh{i}" class="field font-mono" bind:value={s.host} /></div>
              <div class="col-span-5"><label class="label" for="sp{i}">Motif de chemin</label><input id="sp{i}" class="field font-mono" bind:value={s.path_pattern} /></div>
              <div class="flex items-end"><button class="btn btn-ghost w-full text-danger" onclick={() => draft.servers.splice(i, 1)}>Retirer</button></div>
            </div>
          </div>
        {:else}
          <div class="text-muted">Aucun serveur. Ajoute-en un, ou importe ta config SSH.</div>
        {/each}
      </div>
    </Section>

    <Section
      id="outputs"
      title="Sorties anonymisées"
      summary="{draft.output_dir || draft.output_dir_effective} · {draft.parallel_downloads} téléchargements et {draft.parallel_processing} traitements en même temps">
      <div class="grid grid-cols-6 gap-3">
        <div class="col-span-6">
          <label class="label" for="od">Dossier</label>
          <input id="od" class="field font-mono" bind:value={draft.output_dir} placeholder={draft.output_dir_effective} />
        </div>
        <div class="col-span-3">
          <label class="label" for="ol">Disposition</label>
          <select id="ol" class="field" bind:value={draft.layout}><option value="compact">Compacte : host une fois par entrée</option><option value="faithful">Fidèle : host sur chaque ligne</option></select>
        </div>
        <div class="col-span-3">
          <label class="label" for="oc">Confirmer au-delà de (Mo à télécharger)</label>
          <input id="oc" class="field" type="number" min="0" bind:value={draft.confirm_above_mb} />
        </div>
        <div class="col-span-3">
          <label class="label" for="ot">Découper en parties de (tokens estimés, 0 = un fichier)</label>
          <input id="ot" class="field" type="number" min="0" step="50000" bind:value={draft.chunk_tokens} />
        </div>
        <div class="col-span-3 flex items-end text-[12px] leading-snug text-muted">
          {draft.chunk_tokens > 0 ? `Environ ${((draft.chunk_tokens * 3) / 1048576).toFixed(1)} Mo par partie, à raison de 3 octets par token. Une partie finit toujours sur une entrée entière.` : "La sortie tient dans un seul fichier, quelle que soit sa taille."}
        </div>
        <div class="col-span-3">
          <label class="label" for="pd">Téléchargements en même temps (1 à 8)</label>
          <input id="pd" class="field" type="number" min="1" max="8" bind:value={draft.parallel_downloads} />
        </div>
        <div class="col-span-3">
          <label class="label" for="pp">Fichiers anonymisés en même temps (1 à 8)</label>
          <input id="pp" class="field" type="number" min="1" max="8" bind:value={draft.parallel_processing} />
        </div>
        <div class="col-span-6 -mt-1 text-[12px] leading-snug text-muted">
          Les téléchargements passent tous par la même connexion SSH. Chaque fichier anonymisé en plus occupe des cœurs et de la mémoire : au-delà de 2 ou 3, le gain dépend de la machine. Chaque jour donne son propre fichier, identique quel que soit le réglage.
        </div>
        <label class="col-span-6 flex items-center gap-2 text-[12.5px]"><input type="checkbox" bind:checked={draft.header} /> En-tête en première ligne : app, type, jour, template et version</label>
      </div>
    </Section>

    <Section id="safety" title="Filet de sécurité" summary={draft.safety_action === "report" ? "signaler seulement" : "remplacer ce qui reste"}>
      <p class="-mt-2 mb-3 text-[12.5px] leading-relaxed text-muted">Après les règles du template, tous les détecteurs repassent sur la sortie. Ce qu'ils trouvent encore est un trou de couverture.</p>
      <select class="field w-80" bind:value={draft.safety_action}>
        <option value="replace">Remplacer ce qui reste (recommandé)</option>
        <option value="report">Signaler seulement</option>
      </select>
      {#if draft.safety_action === "report"}
        <div class="mt-3 rounded-md bg-danger-soft px-3 py-2 text-[12.5px] leading-relaxed text-danger">En mode « signaler », une sortie peut contenir des données non anonymisées. Tant qu'il reste des trouvailles, sa copie et son export sont bloqués.</div>
      {/if}
    </Section>

    <Section id="mapping" title="Table de correspondance" summary={draft.mapping_table ? "gardée pour chaque run, chiffrée" : "non gardée"}>
      <p class="-mt-2 mb-3 text-[12.5px] leading-relaxed text-muted">Pour chaque run, garde la liste jeton → valeur réelle, afin de remettre les vraies valeurs dans la réponse de l'IA. Elle contient des données réelles : elle est chiffrée, sa clé est dans le trousseau du système, et elle ne quitte jamais ta machine.</p>
      <label class="flex items-center gap-2 text-[12.5px]"><input type="checkbox" bind:checked={draft.mapping_table} /> Garder la table de correspondance de chaque run</label>
    </Section>

    <Section id="cache" title="Cache brut" summary="{cache ? bytes(cache.bytes) : '…'} · {draft.cache_max_gb > 0 ? `${draft.cache_max_gb} Go au plus` : 'sans limite'}">
      <p class="-mt-2 mb-3 text-[12.5px] leading-relaxed text-muted">Les fichiers téléchargés, non anonymisés. Ils restent ici pour relancer une anonymisation sans retélécharger, et ne sont jamais copiés ni exportés.</p>
      <div class="mb-3 flex items-center gap-3">
        <label class="text-[12.5px]" for="cm">Taille maximale (Go, 0 = sans limite)</label>
        <input id="cm" class="field w-24" type="number" min="0" bind:value={draft.cache_max_gb} />
        <span class="text-[12px] text-muted">Après chaque run, les fichiers les plus anciens sont supprimés pour repasser dessous ; ceux du run qui vient de finir sont gardés.</span>
      </div>
      <div class="flex items-center gap-3">
        <div class="selectable min-w-0 flex-1 truncate font-mono text-[12px] text-muted">{cache?.path ?? "…"}</div>
        <span class="tabular-nums">{cache ? bytes(cache.bytes) : ""}</span>
        <button class="btn" disabled={!cache?.bytes} onclick={purge}>Vider</button>
      </div>
    </Section>
    <div class="h-14"></div>
  </div>
</div>

<div class="pointer-events-none fixed right-0 bottom-0 left-[200px] flex items-center justify-end gap-3 border-t border-line bg-bg/90 px-6 py-3 backdrop-blur">
  {#if message}<span class="selectable text-[12.5px] {message.ok ? 'text-ok' : 'text-danger'}">{message.text}</span>{/if}
  <button class="btn btn-primary pointer-events-auto" disabled={!dirty || saving} onclick={save}>Enregistrer</button>
</div>
