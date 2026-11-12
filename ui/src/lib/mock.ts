// Backend de démonstration pour l'aperçu de l'interface dans un navigateur.
// Rien ici n'est utilisé dans l'app : aucune connexion, aucune anonymisation réelle.

import type { Api, Config, FileResult, Profile, RunDone, RunProgress, SandboxResult, Segment } from "./api";
import { SANDBOX_SAMPLE } from "./sample";

let config: Config = {
  bastion: { host: "bastion.example.net", user: "demo", port: 22, auth: "key", identity_file: "~/.ssh/id_rsa", mode: "nc", host_key_policy: "insecure" },
  servers: [
    { id: "etam-sb", name: "Etam — sandbox", host: "syslogserver01.priv.etamadm-sb.example.net", path_pattern: "/srv/syslog/{YYYY}/{MM}/{DD}/APPS/{app_name}/{cluster}/" },
    { id: "jar-sb", name: "Jar — sandbox", host: "syslogserver01.priv.jaradm-sb.example.net", path_pattern: "/srv/syslog/{YYYY}/{MM}/{DD}/APPS/{app_name}/{cluster}/" },
  ],
  associations: [],
  output_dir: "",
  output_dir_effective: "~/Documents/LogsAnonymizer",
  layout: "compact",
  header: true,
  chunk_tokens: 0,
  confirm_above_mb: 1024,
  parallel_downloads: 3,
  parallel_processing: 2,
  cache_max_gb: 50,
  mapping_table: true,
  safety_action: "replace",
};

let added = 0;

function fakeProfile(outputId: string): Profile {
  const shapes: [string, number, number, string, string | null][] = [
    ["in POST /api/gateway/order/delivery_modes", 4_160_859, 690_000_000, "info", "etam/services:delivery-modes-request"],
    ["The old stock value is the same as the new stock value for id \"…\"", 4_465_370, 616_000_000, "info", "etam/services:stock-unchanged"],
    ["Sent 0 in 0ms\tPOST /api/gateway/order/delivery_modes", 3_115_146, 557_000_000, "info", "etam/services:delivery-modes-fast-ok"],
    ["[EMAILS TRANSACS] properties sent successfully:", 17_442, 39_900_000, "debug", null],
    ["Execute action '…' (bypass state/transitions) for prepa_0-0 which goes from '…' to '…'", 109_164, 19_000_000, "info", null],
    ["in GET //api/v0/gateway/store/stock/item/availabilities", 29_763, 17_800_000, "info", null],
    ["Sent 0 in 0ms\tGET //api/gateway/store/0/preparation_list", 28_797, 5_400_000, "info", null],
    ["[process_store_delta]: ‹hex› not found on ETAM_0", 17_590, 1_950_000, "warn", null],
    ["[NODE_HEALTH] run_queue=0 riak_ping_ms=0 vnode_mq=0 port_count=0", 4_296, 1_200_000, "info", null],
    ["Error processing PREPROD/ECOM/ORDERS/sfcc_orders_0.xml in oms_puller_ecom_orders_etam:", 1_040, 890_000, "error", null],
  ];
  const keys: [string, number, number, number, [string, number][]][] = [
    ["properties.order_id", 22_691, 0, 15_399, [["0+", 22_691]]],
    ["ideshop", 17_893, 0, 11_301, [["0+", 17_893]]],
    ["properties.nickname", 9_120, 0, 4_410, [["Aa+", 7_300], ["Aa+0", 1_820]]],
    ["meta.qs.stores", 276_083, 0, 1_059, [["0+", 276_079], ["a+", 4]]],
    ["properties.firstname", 22_689, 22_689, 0, []],
    ["emailaddress", 22_691, 22_691, 0, []],
    ["properties.shippingaddress", 21_800, 21_800, 0, []],
  ];
  const total = shapes.reduce((a, s) => a + s[2], 0);
  return {
    app: outputId.split("/")[1] ?? "etam_services",
    day: "2026-10-08",
    template: "etam/services@1.0.0",
    entries: 13_731_767,
    bytes: total,
    filtered_entries: 11_741_375,
    filtered_bytes: 1_863_000_000,
    shapes_total: 1_835,
    shapes: shapes.map(([shape, count, bytes, level, filtered_by]) => ({ shape, pattern: "\\] +" + shape.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/0/g, "\\d+"), count, bytes, level, kind: "logger", filtered_count: filtered_by ? count : 0, filtered_by })),
    keys_total: 382,
    keys: keys.map(([path, count, replaced, distinct, sh]) => ({ path, count, replaced, distinct, distinct_capped: false, shapes: sh.map(([shape, c]) => ({ shape, count: c })) })),
    warning: null,
  };
}

// Valeurs que la démonstration ne masque plus, après un clic dans la vue côte à côte.
const allowedValues = new Set<string>();

const progressListeners = new Set<(p: RunProgress) => void>();
const doneListeners = new Set<(d: RunDone) => void>();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function fakeSegments(line: string): { raw: Segment[]; out: Segment[] } {
  const raw: Segment[] = [];
  const out: Segment[] = [];
  const re = /([\w.+-]+@[\w-]+\.[\w.]+)|(Basic )([A-Za-z0-9+/=]{8,})|(%7C[^\s;]+)/g;
  let pos = 0;
  let m: RegExpExecArray | null;
  const plain = (t: string) => {
    if (t) {
      raw.push({ text: t, rule: null, safety: false });
      out.push({ text: t, rule: null, safety: false });
    }
  };
  while ((m = re.exec(line))) {
    if (allowedValues.has(m[1] ?? m[3] ?? m[4])) continue;
    plain(line.slice(pos, m.index));
    if (m[1]) {
      raw.push({ text: m[1], rule: "kbrw/common:emails", safety: false });
      out.push({ text: "EMAIL_e3236363", rule: "kbrw/common:emails", safety: false });
    } else if (m[3]) {
      plain(m[2]);
      raw.push({ text: m[3], rule: "kbrw/common:auth-headers", safety: false });
      out.push({ text: "[CREDENTIALS]", rule: "kbrw/common:auth-headers", safety: false });
    } else {
      raw.push({ text: m[4], rule: "kbrw/common:cookies", safety: false });
      out.push({ text: "[SESSION]", rule: "kbrw/common:cookies", safety: false });
    }
    pos = m.index + m[0].length;
  }
  plain(line.slice(pos));
  return { raw, out };
}

function fakeSandbox(input: string): SandboxResult {
  const entries: SandboxResult["entries"] = [];
  let lineNo = 0;
  for (const line of input.split("\n")) {
    lineNo++;
    const [source, ...rest] = line.split("  ");
    const content = rest.join("  ");
    if (!content.trim()) continue;
    const start = /^\d\d:\d\d:\d\d\.\d{3} \[/.test(content);
    const last = entries[entries.length - 1];
    if (!start && last && last.source === source) {
      const s = fakeSegments("\n" + content);
      last.raw.push(...s.raw);
      last.out.push(...s.out);
      continue;
    }
    const dropped = /\/api\/ping/.test(content);
    const s = fakeSegments(content);
    entries.push({ source, line_no: lineNo, kind: "logger", dropped_by: dropped ? "kbrw/elixir:ping" : null, raw: s.raw, out: dropped ? [] : s.out });
  }
  const modified = entries.filter((e) => e.raw.some((x) => x.rule)).length;
  return { entries, entries_in: entries.length, dropped: entries.filter((e) => e.dropped_by).length, modified, safety_total: 0, warnings: [], template: allowedValues.size ? "local/etam_sb_gateway@0.1.0" : "etam/gateway@1.0.0" };
}

function fakeFile(runId: string, app: string, cluster: string, day: string): FileResult {
  return {
    output_id: `${runId}/${app}/${cluster}/erlang/${day}`,
    days: [day],
    app,
    cluster,
    kind: "erlang",
    template: app.includes("gateway") ? "etam/gateway" : "kbrw/elixir",
    template_version: "1.0.0",
    output_path: `~/Documents/LogsAnonymizer/${runId}/${app}/${cluster}/erlang.${day}.part001.log`,
    parts: [1, 2, 3].map((n, i) => ({ index: i, path: `~/Documents/LogsAnonymizer/${runId}/${app}/${cluster}/erlang.${day}.part00${n}.log`, bytes: n === 3 ? 1_240_000 : 2_990_000, tokens: n === 3 ? 413_000 : 996_000 })),
    deduplicated: 1840,
    entries_in: 184213,
    entries_out: 121877,
    dropped: 62336,
    modified: 48211,
    bytes_in: 61_300_000,
    bytes_out: 38_900_000,
    safety_total: 2,
    findings: [
      { detector: "high_entropy", source: "etam-gateway02.etam-sb.kbrw.fr", line_no: 48213, context: "signature => \"[SECRET]\", ts: 1794217138", replaced: true },
      { detector: "phone", source: "etam-gateway01.etam-sb.kbrw.fr", line_no: 90122, context: "rappel client au PHONE_bffe1622 demandé", replaced: true },
    ],
    rules: [
      { id: "kbrw/common:emails", hits: 31220, shadowed: 0 },
      { id: "kbrw/common:cookies", hits: 28841, shadowed: 0 },
      { id: "kbrw/common:auth-headers", hits: 9112, shadowed: 0 },
      { id: "kbrw/common:person-names", hits: 4210, shadowed: 0 },
      { id: "kbrw/common:basic-auth", hits: 0, shadowed: 9112 },
    ],
    filters: [
      { id: "kbrw/elixir:ping", hits: 51002, shadowed: 0 },
      { id: "kbrw/elixir:system-info", hits: 11334, shadowed: 0 },
    ],
    warnings: [],
    quarantined: false,
  };
}

export const mockApi: Api = {
  getConfig: async () => config,
  saveConfig: async (c) => {
    config = { ...config, ...c, output_dir_effective: c.output_dir || "~/Documents/LogsAnonymizer" } as Config;
    return config;
  },
  importSsh: async () => ({ bastion: config.bastion, servers: config.servers }),
  listTemplates: async () => [
    { id: "etam/gateway", name: "Etam — gateway", version: "1.0.0", description: "Gateway Etam : payloads de commandes et delivery modes.", log_kind: "erlang", format: "elixir_syslog", builtin: true, is_abstract: false, available: true, problem: null, warnings: ["filtre « kbrw/elixir:dedup » : la déduplication n'est pas encore exécutée par cette version"], suggested_apps: ["etam_*_gateway"], tests: 3, rules: 32 },
    { id: "local/etam_sb_gateway", name: "etam_sb_gateway (local)", version: "0.1.0", description: "", log_kind: "erlang", format: "elixir_syslog", builtin: false, is_abstract: false, available: true, problem: null, warnings: [], suggested_apps: ["etam_sb_gateway"], tests: 0, rules: 33 },
    { id: "kbrw/common", name: "KBRW — socle commun", version: "1.0.0", description: "Détecteurs, identifiants, jetons de session et PII génériques.", log_kind: null, format: null, builtin: true, is_abstract: true, available: true, problem: null, warnings: [], suggested_apps: [], tests: 6, rules: 27 },
    { id: "kbrw/elixir", name: "KBRW — Elixir (erlang.log)", version: "1.0.0", description: "Logs applicatifs Elixir/Erlang.", log_kind: "erlang", format: "elixir_syslog", builtin: true, is_abstract: false, available: true, problem: null, warnings: [], suggested_apps: ["*"], tests: 11, rules: 29 },
    { id: "kbrw/haproxy", name: "KBRW — HAProxy (haproxy.log)", version: "1.0.0", description: "Logs HAProxy du frontal.", log_kind: "haproxy", format: "haproxy_syslog", builtin: true, is_abstract: false, available: true, problem: null, warnings: [], suggested_apps: ["*"], tests: 9, rules: 30 },
  ],
  runTemplateTests: async () => [
    { name: "cookie d'auth contenant un email", passed: true, failures: [], output: "etam-admin01.etam-sb.kbrw.fr  09:39:05.203 [info]  in GET /api/banishment/planification\n  \tcookie : etam_admin-auth=EMAIL_e3236363[SESSION]\n" },
    { name: "bruit filtré : ping", passed: true, failures: [], output: "" },
  ],
  templateSource: async (id) => ({
    id,
    builtin: !id.startsWith("local/"),
    toml: `[template]\nid = "${id}"\nname = "Démo"\nversion = "1.0.0"\nschema_version = 1\nlog_kind = "erlang"\nformat = "elixir_syslog"\nextends = ["kbrw/elixir@^1"]\nsuggested_apps = ["etam_*_gateway"]\n\n[[filters]]\nid = "profil-1"\ndescription = "[EMAILS TRANSACS] properties sent successfully:"\naction = "drop_entry"\nheader = '\\] +\\[EMAILS TRANSACS\\] properties sent successfully:'\n\n[[rules]]\nid = "order-ids"\nkeys = ["orderid", "site"]\nstrategy = "keep"\npriority = 220\n`,
  }),
  templateCheck: async (toml) => {
    const id = /^id\s*=\s*"([^"]+)"/m.exec(toml)?.[1] ?? null;
    const broken = !id || /strategy\s*=\s*"teleport"/.test(toml);
    return {
      ok: !broken,
      id,
      error: broken ? (id ? `template « ${id} » : règle « order-ids » : strategy inconnue : « teleport »` : "TOML invalide : champ id manquant dans [template]") : null,
      warnings: [],
      tests: broken ? [] : [{ name: "cookie d'auth contenant un email", passed: true, failures: [], output: "h  09:39:05.203 [info]  in GET /x\n  \tcookie : etam_admin-auth=EMAIL_e3236363[SESSION]\n" }],
      weakens: /strategy\s*=\s*"keep"/.test(toml) ? ["Valeurs gardées en clair (règle order-ids) : orderid, site"] : [],
      exists: !!id,
      builtin: !!id && !id.startsWith("local/"),
    };
  },
  templateSave: async (toml) => /^id\s*=\s*"([^"]+)"/m.exec(toml)?.[1] ?? "local/demo",
  templateDelete: async () => {},
  templatesImport: async (folder) => ({
    imported: [
      { id: "kbrw/common", replaced: true, weakens: 1 },
      { id: "kbrw/elixir", replaced: true, weakens: 0 },
      { id: "etam/gateway", replaced: false, weakens: 2 },
    ],
    rejected: folder ? [{ source: "brouillon.toml", reason: "Des tests embarqués échouent. (payload de commande indenté)" }] : [],
  }),
  templateExport: async (id) => `~/Desktop/${id.replace("/", "-")}.toml`,
  sandboxRun: async (_t, input) => fakeSandbox(input),
  discover: async () => {
    await sleep(500);
    const apps = [
      { name: "etam_sb_admin", clusters: ["etam-sb"] },
      { name: "etam_sb_gateway", clusters: ["etam-sb"] },
      { name: "etam_sb_services", clusters: ["etam-sb"] },
      { name: "etam_sb_user", clusters: ["etam-sb"] },
      { name: "iam", clusters: ["etam-sb-atlas", "etam-sb-atlas02"] },
      { name: "riakn", clusters: ["etam-sb"] },
    ];
    return { apps, missing_days: [] };
  },
  planRun: async (req) => {
    await sleep(400);
    const files = [...req.days].sort().flatMap((day) => req.selections.flatMap((s) =>
      s.clusters.flatMap((c) =>
        req.kinds.map((kind, i) => ({
          day,
          app: s.app,
          cluster: c,
          kind,
          remote_path: `/srv/syslog/${day.replaceAll("-", "/")}/APPS/${s.app}/${c}/${kind}.log.gz`,
          size: kind === "erlang" ? 4_800_000 + s.app.length * 310_000 : 212_000_000,
          compressed: true,
          cached: i === 0 && s.app.endsWith("admin"),
          template: kind === "erlang" ? (s.app.includes("gateway") ? "etam/gateway" : "kbrw/elixir") : "kbrw/haproxy",
          problem: null,
        })),
      ),
    ));
    const usable = files.filter((f) => !f.problem);
    return {
      files,
      total_bytes: usable.reduce((a, f) => a + f.size, 0),
      download_bytes: usable.filter((f) => !f.cached).reduce((a, f) => a + f.size, 0),
      needs_confirmation: false,
      estimated_output_bytes: usable.reduce((a, f) => a + f.size * 17, 0),
      output_free_bytes: 69_000_000_000,
      cache_free_bytes: 69_000_000_000,
      disk_warning: null,
      missing: [],
    };
  },
  startRun: async (req) => {
    const days = [...req.days].sort();
    const runId = `demo-${req.server_id}-${days[0]}`;
    const targets = req.selections.flatMap((s) => s.clusters.map((c) => [s.app, c] as const));
    (async () => {
      // Un fichier par cible et par jour, traités à plusieurs comme dans l'app.
      const jobs = targets.flatMap(([a, c]) => days.map((d) => `${a}/${c}/erlang · ${d}`));
      const n = jobs.length;
      const emit = (p: RunProgress) => progressListeners.forEach((l) => l(p));
      const base = (i: number) => ({ run_id: runId, file_index: i, file_count: n, label: jobs[i], processed_bytes: 0, entries_in: 0, dropped: 0, modified: 0, finished: false });
      const ready: number[] = [];
      // `slots` tâches à la fois, chacune prenant le fichier suivant.
      const pool = (slots: number, next: () => Promise<number | null>, work: (i: number) => Promise<void>) =>
        Promise.all(
          Array.from({ length: slots }, async () => {
            for (let i = await next(); i !== null; i = await next()) await work(i);
          }),
        );
      let toFetch = 0;
      let fetched = 0;
      const downloads = pool(
        config.parallel_downloads,
        async () => (toFetch < n ? toFetch++ : null),
        async (i) => {
          const total = 4_000_000 + ((i * 7) % 5) * 1_100_000;
          for (let k = 1; k <= 20; k++) {
            await sleep(110 + (i % 3) * 25);
            emit({ ...base(i), phase: "download", bytes_done: (total / 20) * k, bytes_total: total });
          }
          emit({ ...base(i), phase: "download", bytes_done: total, bytes_total: total, finished: true });
          ready.push(i);
          fetched++;
        },
      );
      const processing = pool(
        config.parallel_processing,
        async () => {
          while (!ready.length && fetched < n) await sleep(50);
          return ready.shift() ?? null;
        },
        async (i) => {
          const stats = (k: number) => ({ processed_bytes: k * 1_800_000, entries_in: k * 5_400, dropped: k * 3_600, modified: k * 24 });
          for (let k = 1; k <= 30; k++) {
            await sleep(110 + (i % 2) * 30);
            emit({ ...base(i), phase: "anonymize", bytes_done: k * 175_000, bytes_total: 5_250_000, ...stats(k) });
          }
          emit({ ...base(i), phase: "anonymize", bytes_done: 1, bytes_total: 1, ...stats(30), finished: true });
        },
      );
      await Promise.all([downloads, processing]);
      doneListeners.forEach((l) => l({ run_id: runId, cancelled: false, error: null, files: targets.flatMap(([a, c]) => days.map((d) => fakeFile(runId, a, c, d))), skipped: [], mapping_tokens: 1284 }));
    })();
    return runId;
  },
  cancelRun: async () => {},
  provideSudoPassword: async () => {},
  provideKeyPassphrase: async () => {},
  previewOutput: async () => fakeSandbox(SANDBOX_SAMPLE),
  copyOutput: async () => 2_990_000,
  profileOutput: async (id) => fakeProfile(id),
  localTemplateAdd: async (a) => {
    await sleep(250);
    if (a.kind === "allow_value" && a.pattern) allowedValues.add(a.pattern);
    return { template_id: `local/${a.app}`, path: `~/Library/Application Support/fr.kbrw.logs-anonymizer/templates/local/${a.app}.toml`, added_id: `profil-${++added}` };
  },
  exportOutput: async () => "~/Desktop/etam_sb_gateway-etam-sb-erlang-2026-11-09.log",
  exportOutputs: async () => "~/Desktop/logs",
  mappingList: async () => [
    { run_id: "20261111-005749-etam-2026-10-01_2026-10-07", bytes: 184_200 },
    { run_id: "20261110-221200-jar-sb-2026-11-09", bytes: 12_400 },
  ],
  mappingPurge: async () => {},
  deanonymize: async (_id, text) => {
    let replaced = 0;
    const out = text.replace(/\b(EMAIL|NAME|IP)_[0-9a-f]{8,}\b/g, (_m, label) => (replaced++, label === "EMAIL" ? "jean.dupont@example.com" : label === "NAME" ? "Dupont" : "203.0.113.10"));
    return { text: out, replaced, unknown: (text.match(/\b[A-Z]{2,}_[0-9a-f]{8,}\b/g)?.length ?? 0) - replaced };
  },
  historyList: async () => [
    {
      run_id: "20261111-005749-etam-2026-10-01_2026-10-07",
      started_at: "2026-11-11T00:57:49+01:00",
      request: { server_id: "etam-sb", days: ["2026-10-01", "2026-10-02", "2026-10-03", "2026-10-06", "2026-10-07"], selections: [{ app: "etam_sb_services", clusters: ["etam-sb"] }], kinds: ["erlang"], template: null },
      outcome: "ok",
      error: null,
      files: [{ app: "etam_sb_services", cluster: "etam-sb", kind: "erlang", template: "etam/services@1.0.0", entries_in: 68_000_000, entries_out: 4_100_000, bytes_out: 955_000_000, safety_total: 12 }],
    },
    {
      run_id: "20261110-221200-jar-sb-2026-11-09",
      started_at: "2026-11-10T22:12:00+01:00",
      request: { server_id: "jar-sb", days: ["2026-11-09"], selections: [{ app: "jar_sb_admin", clusters: ["jar-sb-atlas", "jar-sb-atlas02"] }], kinds: ["erlang"], template: "kbrw/elixir" },
      outcome: "error",
      error: "Il reste moins de 2 Go libres sur le disque des sorties : le run est arrêté.",
      files: [],
    },
  ],
  historyClear: async () => {},
  cacheInfo: async () => ({ path: "~/Library/Caches/fr.kbrw.logs-anonymizer/raw", bytes: 412_000_000 }),
  cachePurge: async () => ({ path: "~/Library/Caches/fr.kbrw.logs-anonymizer/raw", bytes: 0 }),
  onProgress: async (cb) => {
    progressListeners.add(cb);
    return () => progressListeners.delete(cb);
  },
  onDone: async (cb) => {
    doneListeners.add(cb);
    return () => doneListeners.delete(cb);
  },
};

