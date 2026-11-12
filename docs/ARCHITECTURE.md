# Architecture — Logs Anonymizer

Statut : architecture validée ; le MVP (étape 2) est implémenté. Ce qui est fait et ce qui reste est dans le [README](../README.md).
Les templates complets sont dans [`templates/`](../templates) ; ce document décrit le reste.

Écart du MVP par rapport à ce document : le transfert passe pour l'instant par des canaux exec (`cat`, `head -c | gzip -c`), sans SFTP, sans segments ni reprise (§9). Ils viendront avec l'itération « cache brut ».

## 0. Décisions principales

| Sujet | Décision | Raison |
|---|---|---|
| Crates | `crates/core`, `crates/remote`, `crates/app` ; packages `logano-core`, `logano-remote`, `logano-app` | Un package nommé `core` masquerait la crate `core` de Rust |
| Texte | Tout le moteur travaille en **octets** (`&[u8]`, `regex::bytes`, `bstr`) | Les logs ne sont pas garantis UTF-8 ; pas de copie ni de validation |
| Concurrence moteur | Synchrone : threads + `rayon`, aucun `tokio` dans `core` | Charge CPU pure ; `remote` et `app` sont async et appellent le moteur en `spawn_blocking` |
| Transfert | Toujours **vers le cache brut**, puis anonymisation depuis le cache | Reprise, téléchargement par segments, relance sans retélécharger ; le réseau est le goulot, pas le moteur |
| SSH | `russh` + `russh-sftp` ; exec pour `sudo`, la compression à la volée et le repli sans SFTP | Conforme à la demande ; un seul trait `Transport`, deux implémentations |
| Filet de sécurité | Réglé dans la **config de l'app**, jamais dans un template | Un template importé ne doit pas pouvoir affaiblir la protection |
| Frontend | **Svelte 5** + TypeScript + Tailwind 4 + CodeMirror 6 | Voir §11 |
| Jetons | `EMAIL_7f3a2c9d` : 8 hex par défaut, extension en cas de collision | 6 hex (24 bits) donne des collisions dès quelques milliers de valeurs |

## 1. Workspace

```
logs_anonymyzer/
├─ Cargo.toml                  workspace
├─ crates/
│  ├─ core/      logano-core    moteur, zéro dépendance Tauri/tokio
│  ├─ remote/    logano-remote  SSH, bastion, sudo, découverte, transfert, cache brut
│  └─ app/       logano-app     Tauri 2 : commandes, events, orchestration des runs
├─ ui/                          Svelte 5
├─ templates/                   templates fournis, embarqués dans le binaire (include_dir)
├─ corpus/                      tests golden : <cas>.in.log / <cas>.out.log
└─ docs/
```

Modules de `logano-core` :

| Module | Rôle |
|---|---|
| `io` | décompression (gzip via `flate2`/zlib-ng, zstd), découpage en lignes (`memchr`), retrait du `\r` |
| `format` | trait `Format` + `elixir_syslog`, `haproxy_syslog`, `lager_syslog` |
| `assemble` | une entrée ouverte par source, tampon de réordonnancement borné |
| `extract` | `json`, `elixir_term`, `plug_metadata`, `http_request`, `cookie`, `haproxy`, `riak_key` + décodeurs (URL, Basic, JWT) |
| `detect` | `email`, `ipv4_public`, `ipv6_public`, `jwt`, `basic_auth`, `bearer_token`, `url_userinfo`, `high_entropy`, `phone`, `iban`, `card_luhn` |
| `rules` | template compilé : sélecteurs par clé / route / regex / détecteur |
| `resolve` | résolution des chevauchements, reconstruction en une passe |
| `strategy` | `pseudonymize`, `redact`, `mask_partial`, `hash`, `drop_field`, `drop_entry`, `keep` |
| `safety` | filet de sécurité final, type `Sanitized` |
| `template` | modèle serde + schemars, héritage, tests embarqués, import/export |
| `pipeline` | threads, lots, réassemblage ordonné, annulation |
| `output` | écriture, en-tête, découpage en chunks |
| `profile` | formes, inventaire des clés, couverture |
| `mapping` | table jeton → valeur, chiffrée |

## 2. Flux de données

```
            logano-remote (tokio)                         logano-core (threads)
┌────────┐  exec "nc host 22"  ┌────────┐
│bastion │◄────────────────────│ russh  │   1 session bastion, N sessions cibles réutilisées
└───┬────┘   canal = transport └────────┘
    ▼
┌────────┐ découverte (SFTP readdir/stat)
│ cible  │ sudo -n chmod +r
│        │ .gz → octets tels quels          ┌──────────────┐
│        │ .log → segments zstd/gzip ──────►│ cache brut   │  ~/Library/Caches/…/raw
└────────┘ (canaux bornés, backpressure)    └──────┬───────┘
                                                   ▼
   T1 décompression ─► T2 lignes → cadrage → assemblage par source ─► lots ≈ 4 Mo
                                                                        │ canal borné
                               ┌────────────────────────────────────────┘
                               ▼  rayon (un lot par tâche)
        filtres d'en-tête → préfiltre littéral → extracteurs → règles + détecteurs
        → résolution → reconstruction → filet de sécurité
                               │ lots numérotés
                               ▼
   T3 réassemblage ordonné → écriture `Sanitized` → chunks, stats, table de correspondance
                                                   ▼
                                          ┌──────────────┐
                                          │ sorties      │  dossier distinct du cache
                                          └──────────────┘
```

Mémoire bornée : les canaux entre étapes ont une capacité fixe (2 × nombre de threads), les lots font ≈ 4 Mo, les tampons sont recyclés. Ordre de grandeur : moins de 300 Mo quelle que soit la taille du fichier.

## 3. Cadrage et assemblage

Une **entrée** :

```rust
pub struct Entry<'b> {
    pub source: SourceId,      // host émetteur, interné
    pub line_no: u64,          // numéro de la première ligne physique
    pub kind: EntryKind,       // Logger, Alive, Statsd, IoTimestamped, Repeated, Orphan, Http, Tcp, TlsError…
    pub level: Option<Level>,
    pub text: &'b [u8],        // lignes jointes par \n, sans préfixe host, sans \r, sans ANSI
    pub header_len: u32,       // fin de la première ligne
}
```

Règles d'assemblage (`elixir_syslog`) :

- le cadrage coupe au **premier double espace** : `(source, contenu)` ;
- une ligne vide ou ne contenant que des codes ANSI est un **séparateur** ;
- un début `HH:MM:SS.mmm [level]` ouvre une entrée, même sans séparateur avant ;
- les lignes hors Logger (`=====…`, statsd, `ignore event …`, `[date UTC] …`, `message repeated …`) forment une entrée à elles seules et ferment celle de leur source ;
- tout le reste est une continuation de l'entrée ouverte **de la même source** ; sans entrée ouverte, c'est une entrée `Orphan` ;
- au-delà de `max_entry_lines` ou `max_entry_bytes`, l'entrée est coupée à une fin de ligne et la suite devient une entrée `Orphan`.

Ordre de sortie : par `line_no` de la première ligne. Une entrée n'est émise que quand toutes celles qui la précèdent sont fermées. Si une entrée ouverte bloque plus de `reorder_window` entrées (défaut 4096) ou 8 Mo, elle est fermée d'office. Une source muette ne retient donc jamais le flux.

`haproxy_syslog` : une ligne = une entrée, sans continuation. Le payload qui suit `<ISO8601> <host> haproxy[<pid>]: ` donne le type de l'entrée :

| Type | Payload |
|---|---|
| `http` | `<ip>:<port> [<date>] <frontend> <backend>/<server> tls[…] t[…] c[<status>] sz[…] <req_cookie> <resp_cookie> <état> <conns> <files> hds[…] req["…"]` |
| `tcp` | `<ip>:<port> [<date>] <frontend> <backend>/<server> <Tw/Tc/Tt> <octets> <état> <conns> <files>` |
| `tls_error` | `<ip>:<port> [<date>] <frontend>/<n>: <message contenant « SSL handshake »>` |
| `other` | tout le reste : message d'administration, ligne coupée avant `hds[`, ligne sans en-tête |

- Le port du client suit le **dernier** `:` (`2001:41d0:9a:aa0::2:65004`). Le `~` final du frontend (TLS) ne fait pas partie de son nom.
- `hds[…]` peut contenir des espaces : la requête commence au premier `] req["` et va jusqu'à la fin de la ligne. Une requête coupée par syslog (sans `"]` final) reste une entrée `http`.
- Une entrée `other` garde les champs lus avant l'écart (client, frontend…) et passe par les détecteurs comme les autres. Le parseur ne rejette jamais une ligne.
- L'option `compact_header` retire `<ISO8601> <host> haproxy[<pid>]: ` au cadrage : le contenu de l'entrée est le payload seul. Sans elle, cet en-tête reste en tête du contenu.

`lager_syslog` : une entrée (type `logger`) commence sur `YYYY-MM-DD HH:MM:SS.mmm [level]` ; les autres lignes de la même source sont ses continuations ; séparateurs et coupure des entrées trop longues comme en `elixir_syslog`. La déduplication (`ignore = ["timestamp", "pid"]`) reconnaît cet horodatage et les pids nus `<0.1166.0>`.

Un quatrième format interne, `plain` (une ligne = une entrée, sans préfixe), sert aux tests des templates abstraits et au bac à sable.

## 4. Traits

```rust
pub trait Format: Send + Sync {
    fn id(&self) -> &'static str;
    /// Ligne physique (sans \n ni \r) → (source, contenu).
    fn frame<'a>(&self, line: &'a [u8]) -> Framed<'a>;
    /// Ne lit que les premiers octets du contenu.
    fn classify(&self, content: &[u8]) -> LineClass;
    /// Champs de l'en-tête : niveau, URL (elixir), client_ip, frontend, status… (haproxy).
    fn header_fields(&self, entry: &Entry<'_>, sink: &mut SpanSink<'_>);
    /// Forme normalisée de l'en-tête, pour le profileur.
    fn shape(&self, entry: &Entry<'_>, out: &mut Vec<u8>);
    fn default_extractors(&self) -> &'static [ExtractorId];
}

pub enum LineClass {
    Start { kind: EntryKind, level: Option<Level> },
    Standalone(EntryKind),
    Separator,
    Continuation,
}

pub trait Extractor: Send + Sync {
    fn id(&self) -> ExtractorId;
    /// L'extracteur ne tourne que si l'un de ces littéraux est présent.
    fn triggers(&self) -> &'static [&'static [u8]];
    /// Types de contenu qu'il sait traiter quand il est appelé en cascade.
    fn accepts(&self, hint: ContentHint) -> bool;
    fn extract(&self, region: Region<'_>, sink: &mut SpanSink<'_>);
}

pub trait Detector: Send + Sync {
    fn id(&self) -> DetectorId;
    fn class(&self) -> DataClass;            // Email, IpV4, Jwt, Credentials, Secret, Phone, Iban, Card…
    fn prefilter(&self) -> Prefilter;        // littéraux ou classe d'octets à trouver avant de scanner
    fn scan(&self, hay: &[u8], cx: &DetectCx<'_>, out: &mut Vec<Finding>);
}

pub trait Strategy: Send + Sync {
    fn id(&self) -> StrategyId;
    fn apply(&self, value: &Value<'_>, cx: &mut StrategyCx<'_>, out: &mut Vec<u8>) -> Outcome;
}

pub enum Outcome { Replaced, Kept, DropField, DropEntry }
```

Les quatre traits sont implémentés **uniquement dans le moteur**. Un template ne fait que nommer et configurer ces briques.

Écart de l'implémentation pour `Format` : `header_fields` et `default_extractors` n'existent pas. À la place :

```rust
/// Requête HTTP de l'entrée dont `header` est la première ligne. Par défaut :
/// `MÉTHODE /chemin` cherché dans le message ; `haproxy_syslog` lit `req["…"]`.
fn request(&self, header: &[u8]) -> Option<Request>;
/// Champs d'en-tête lisibles par leur nom (conditions `where` des filtres).
fn field_names(&self) -> &'static [&'static str];
fn field<'a>(&self, header: &'a [u8], name: &str) -> Option<&'a [u8]>;
```

La requête sert aux routes (filtres et règles) et à l'extracteur `http_request`. Les spans `haproxy.*` viennent de l'extracteur `haproxy`, qui relit la ligne avec le parseur du format. Un template sans `[extractors] enabled` reçoit les extracteurs indépendants du format (`plug_metadata`, `cookie`, `json`, `elixir_term`, `http_request`) plus celui de son format (`haproxy` ou `riak_key`).

Un cinquième point d'extension interne, `Observer` (`on_entry`, `on_span`, `on_finding`, `on_replacement`), alimente les statistiques, le profileur et le surlignage du bac à sable sans toucher au chemin principal.

## 5. Spans et chevauchements

### Spans de valeur

```rust
pub struct ValueSpan {
    pub range: Range<u32>,           // contenu de la valeur dans le texte de l'entrée (guillemets exclus)
    pub field: Option<Range<u32>>,   // clé + valeur + séparateur, pour drop_field
    pub path: PathId,                // chemin de clé interné : "billingaddress.customername"
    pub extractor: ExtractorId,
    pub kind: ValueKind,             // String, Number, Atom, Bool, Null, Container, Raw
    pub quoting: Quoting,            // Json, ElixirString, Charlist, Binary, UrlEncoded, Bare
    pub view: Option<ViewId>,        // vue décodée, si la valeur a dû être décodée
}
```

Chemins produits :

| Extracteur | Exemples de chemins |
|---|---|
| `json` | `customername`, `billingaddress.customername`, `products.id` (indices de tableau omis) |
| `elixir_term` | `authorization`, `State.modstate.path`, `recipients`, `remote_ip` |
| `plug_metadata` | `meta.cookie`, `meta.authorization`, `meta.qs.brand` |
| `cookie` | `meta.cookie.etam_admin-auth` |
| `http_request` | `url.query.<paramètre>` : clé URL-décodée, valeur laissée telle quelle. Les segments de chemin sont visés par les règles `route`, pas par des chemins de clé |
| `haproxy` | `haproxy.client_ip`, `haproxy.client_port`, `haproxy.frontend`, `haproxy.frontend.ip`, `haproxy.backend`, `haproxy.backend.ip`, `haproxy.server`, `haproxy.status`, `haproxy.req_cookie`, `haproxy.resp_cookie` (rien si `-`), `haproxy.hds.<i>`, `haproxy.request` |
| `riak_key` | `riak.bucket`, `riak.key` : contenu entre guillemets de `<<"bucket">>/<<"clé">>` |

`haproxy.frontend.ip` et `haproxy.backend.ip` couvrent l'IP inscrite dans le nom : `51_75_10_28` dans `node-public_ipv4-51_75_10_28-443~`.

**Cascade** : un extracteur peut déclarer qu'une valeur a un contenu typé (`ContentHint`). Le moteur relance alors l'extracteur compétent sur cette valeur : `meta.cookie` → `cookie`, `"cookie" => "a=b"` dans un terme → `cookie`. Profondeur maximale : 3. La requête de `req["GET /x?y=z"]` ne passe pas par la cascade : `http_request` reçoit celle que rend `Format::request`.

**Vues décodées** : quand une valeur est encodée, le décodeur produit un tampon décodé et une table de correspondance des positions.

| Encodage | Correspondance | Effet d'une détection dans la vue |
|---|---|---|
| URL (`%7C`, `%40`) | par morceaux | remplacement précis dans le texte source |
| échappements JSON / Elixir | par morceaux | idem |
| `Basic <b64>` | opaque | tout le base64 est remplacé |
| JWT | opaque | tout le jeton est remplacé |

Les détecteurs tournent sur le texte de l'entrée **et** sur les vues décodées.

### Candidats et résolution

Chaque règle qui s'applique produit un candidat `(plage, règle, priorité, stratégie)`.

Priorité par défaut selon le sélecteur : clé et route = 200, regex = 150, détecteur = 100. Le champ `priority` d'une règle la remplace.

Algorithme :

1. trier les candidats par priorité décroissante, puis longueur décroissante (le plus englobant), puis position, puis ordre des règles ;
2. accepter un candidat s'il ne chevauche aucun candidat déjà accepté ;
3. s'il est **contenu** dans un candidat accepté, il est écarté, sauf si la règle englobante le liste dans `keep_inner` : il devient alors un trou dans le remplacement englobant ;
4. s'il chevauche **partiellement** un candidat accepté, les deux plages sont fusionnées et remplacées par `[REDACTED]` ;
5. s'il **englobe** des candidats acceptés de priorité supérieure et qu'il remplace sa plage (tout sauf `keep`), il les absorbe : la valeur entière est remplacée, rien ne reste en clair autour. Une valeur gardée (`keep`) à l'intérieur l'emporte sur lui ;
6. une stratégie `keep` acceptée bloque les candidats de priorité inférieure sur sa plage ;
7. `drop_entry` l'emporte sur tout ; `drop_field` remplace la plage `field`.

Puis reconstruction en une passe : copie des intervalles non touchés, écriture des remplacements.

Les candidats écartés sont comptés par règle (« masqué par la règle X ») et visibles dans le bac à sable.

Exemple, le cookie de session :

```
cookie : etam_admin-auth=jean.dupont@example.com%7C1794217138%7CAbCdEf…=
         └ règle cookies (redact SESSION, keep_inner = ["emails"]) ┘
                         └ détecteur email ┘
→ cookie : etam_admin-auth=EMAIL_7f3a2c9d[SESSION]
```

L'email reste corrélable avec le reste des logs, l'horodatage et le HMAC disparaissent.

### Préservation de la syntaxe

- la plage remplacée est le contenu **entre** les guillemets ;
- un nombre, un atome ou un tuple remplacé est mis entre guillemets (`"zipcode": "75***"`) ;
- `preserve = "scheme"` garde le premier mot : `Basic [CREDENTIALS]`, `Bearer [CREDENTIALS]` ;
- les jetons n'utilisent que `[A-Za-z0-9_\[\]]` : aucun échappement nécessaire en JSON, terme Elixir ou URL.

## 6. Pseudonymisation

```
jeton = <TOKEN>_<hex(HMAC-SHA256(clé_du_run, TOKEN | 0x1F | valeur_normalisée))[..8]>
```

- `normalize` : `none`, `trim` (défaut), `lower`, `email`, `casefold` (minuscules, sans accents, espaces réduits), `digits`, `ip` (accepte `1.2.3.4`, `1_2_3_4`, `{1, 2, 3, 4}`).
- Deux règles qui visent la même donnée doivent utiliser le **même `token`** pour que les jetons coïncident. `JEAN.DUPONT@EXAMPLE.COM` dans un JSON et `jean.dupont@example.com` dans une URL donnent le même `EMAIL_…`.
- **Collisions** : un registre concurrent `jeton → empreinte de la valeur` (`dashmap`). Si deux valeurs différentes tombent sur le même jeton, la seconde prend 2 hex de plus du même HMAC. Aucune coordination entre lots hors ce registre.
- **Clé du run** : aléatoire par défaut. Option « clé persistante », stockée dans le trousseau macOS (`keyring`), jamais dans la config.
- Le filet de sécurité reconnaît la grammaire des jetons et ne les re-détecte pas.

Limite connue : en cas de collision, le jeton étendu dépend de l'ordre d'arrivée. Avec la clé persistante, le registre est sauvegardé dans la table de correspondance pour que la résolution soit identique d'un run à l'autre.

## 7. Filet de sécurité et séparation brut / anonymisé

Le filet tourne sur les **octets de sortie**, dans un chemin de code indépendant de l'application des règles. Seules les implémentations des détecteurs sont partagées.

- Détecteurs : tous ceux de §1.
- Allowlists appliquées : `domains` (noms d'hôtes), `cidrs`, `emails`, `values`.
- Action par défaut `replace` : email → `EMAIL_…`, IP → `IP_…`, JWT → `[JWT]`, Basic → `[CREDENTIALS]`, secret → `[SECRET]`, téléphone → `PHONE_…`, IBAN → `[IBAN]`, carte → `[CARD]`.
- Chaque intervention du filet est un **trou de couverture** : elle est listée dans l'UI avec « créer une règle ».
- Action `report` : choisie dans la config de l'app, avec avertissement. Tant qu'il reste des trouvailles non traitées, la sortie reste dans `out/_quarantine/` et l'export comme la copie sont bloqués.

Garanties structurelles :

- le seul type que `output` sait écrire est `Sanitized`, que seul `safety` peut construire ;
- les commandes Tauri d'export et de presse-papier ne prennent qu'un identifiant de sortie, jamais un chemin ;
- le cache brut et les sorties ont deux racines différentes, et le code d'export refuse tout chemin situé sous la racine du cache ;
- une stratégie `keep` protège une valeur des détecteurs à faux positifs (`phone`, `high_entropy`, `card_luhn`), jamais des classes certaines (email, Basic, JWT, IBAN).

## 8. Templates

### Schéma TOML complet

```toml
[template]
id = "etam/gateway"              # <espace>/<nom>, unique dans la bibliothèque
name = "Etam — gateway"
version = "1.2.0"                # semver
schema_version = 1
author = "…"
description = "…"
log_kind = "erlang"              # erlang | haproxy | console
format = "elixir_syslog"         # elixir_syslog | haproxy_syslog | lager_syslog
abstract = false                 # true : socle sans format, non assignable à une app
extends = ["kbrw/elixir@^1"]     # parents, dans l'ordre ; contrainte semver
suggested_apps = ["etam_*_gateway"]

[format.options]                 # propres au format
strip_ansi = true
max_entry_lines = 2000
max_entry_bytes = "1MiB"
reorder_window = 4096
metadata_prefix = true           # elixir_syslog : [node][Module][#PID<…>]

[extractors]
enabled = ["plug_metadata", "http_request", "cookie", "json", "elixir_term"]

[extractors.options.elixir_term]
max_depth = 64

[detectors.high_entropy]         # réglage d'un détecteur
min_len = 24
min_entropy = 3.5

[[filters]]
id = "ping"
enabled = true
action = "drop_entry"            # drop_entry | dedup
# conditions, toutes requises quand elles sont présentes :
routes = ["GET /api/ping"]       # méthode optionnelle
header = '^regex sur la ligne d''en-tête'
kinds = ["statsd"]               # types d'entrée du format
levels = ["debug"]
where = { status = [400, 404], server = ["<NOSRV>"] }   # champs d'en-tête du format
# action = "dedup" seulement :
ignore = ["timestamp", "pid", "reference"]

[[rules]]
id = "customer-pii"
description = "…"
enabled = true
priority = 200
# sélecteur, un seul parmi :
keys = ["customername", "addressline*", "billingaddress.**"]
route = "/api/etam_admin/{v}"    # ou routes = [...]
regex = 'owner (?P<v>\S+) not found'
detector = "email"
# restrictions :
extractors = ["json", "elixir_term"]
kinds = ["logger"]
levels = ["error"]
targets = ["key"]                # route : segments nommés à remplacer
# action :
strategy = "pseudonymize"        # pseudonymize | redact | mask_partial | hash | drop_field | drop_entry | keep
token = "CUSTOMER"               # pseudonymize, hash
label = "CREDENTIALS"            # redact → [CREDENTIALS]
mask = "email"                   # mask_partial : email | ipv4 | keep_prefix:N | keep_suffix:N
normalize = "casefold"
preserve = "scheme"
keep_inner = ["emails"]          # ids de règles autorisées à percer ce remplacement

[allowlist]
domains = ["*.kbrw.fr"]          # noms d'hôtes uniquement, pas les emails
cidrs = ["2001:41d0:9a::/48"]
emails = ["*+mailer@kbrw.fr"]
values = ["hackney/*"]

[[tests]]
name = "payload commande"
input = '''…'''
expected = '''…'''               # sortie exacte (clé de test fixe, jetons stables)
expect_contains = ["CUSTOMER_"]
expect_not_contains = ["Dupont"]
expect_dropped = false
```

Le JSON Schema est généré depuis ces structs (`schemars`) et versionné dans `docs/template.schema.json`.

### Conditions `where`

- Chaque champ nommé doit valoir l'une des valeurs listées ; plusieurs champs = ET, y compris avec `routes`, `header`, `kinds` et `levels`. Entiers et chaînes sont comparés comme du texte à la valeur du champ.
- Champs de `haproxy_syslog` : `client_ip`, `client_port`, `frontend`, `backend`, `server`, `status`, `req_cookie`, `resp_cookie`, `termination`, `request` (le contenu de `req["…"]`, par exemple `<BADREQ>`). Un champ absent de l'entrée (le `status` d'une ligne TCP) ne satisfait aucune condition.
- `elixir_syslog`, `lager_syslog` et `plain` n'exposent aucun champ. Un champ inconnu du format, une liste vide ou une valeur qui n'est ni un entier ni une chaîne sont des erreurs à la compilation du template.

### Sémantique des clés

- Chemin = segments séparés par `.` ; indices de tableau omis ; comparaison insensible à la casse.
- Un motif correspond à un **suffixe** du chemin, sur des frontières de segments : `customername` attrape `billingaddress.customername`, `cookie.*` attrape `meta.cookie.etam_admin-auth`.
- `*` et `?` jouent dans un segment, `**` couvre zéro ou plusieurs segments, `$.` ancre à la racine.
- Si la valeur ciblée est un conteneur, la règle s'applique à toutes ses feuilles ; `drop_field` retire le champ entier.
- Le résultat de la correspondance est mis en cache par chemin interné : le glob n'est évalué qu'une fois par chemin distinct.

### Sémantique des routes

- `[MÉTHODE ]/seg/{nom}/*/**` ; les `/` doublés sont normalisés (`//api/x` ≡ `/api/x`).
- Correspondance exacte ; `**` final pour un préfixe.
- Dans une règle, les segments nommés sont les cibles (`targets` pour n'en garder que certains). Les segments sont comparés après URL-décodage.
- S'applique à la requête de l'entrée, celle que rend `Format::request` : en-tête Elixir (`in GET …`, `Sent 200 in 26ms\tGET …`, `GET //api/…`) et `req["…"]` HAProxy. La ligne `Request: POST /` d'un crash report est une continuation : elle n'est pas lue.

### Héritage

- `extends` est résolu dans la bibliothèque locale, avec contrainte semver. Parent manquant ou incompatible : erreur claire à la validation.
- Un template `abstract` n'a pas de format et peut être étendu par n'importe quel format (`kbrw/common`).
- Règles et filtres : fusion par `id`. Une entrée enfant avec l'id d'une règle héritée, écrit `kbrw/common:emails`, ne remplace que les champs qu'elle précise (`enabled = false` suffit à désactiver).
- `format.options`, `extractors`, `detectors` : l'enfant l'emporte champ par champ. `allowlist` : union.
- Les tests ne sont pas hérités : chaque template teste sa propre résolution.

### Garde-fous d'un template partagé

- Aucune exécution : regex du crate `regex` (temps linéaire, pas de retour arrière), taille de compilation plafonnée, nombre de règles plafonné.
- À l'import : validation du schéma, résolution des parents, exécution des tests, puis diff avec la version locale.
- L'écran d'import met en avant ce qui **affaiblit** la protection : allowlists ajoutées, règles héritées désactivées, stratégies `keep`.
- Fichiers annexes facultatifs à côté du `.toml`, inclus dans le bundle `.zip` : `<nom>.fixtures/` (corpus anonymisé) et `<nom>.shapes` (formes connues, calculées sur la sortie anonymisée).

### Distribution des templates

L'app n'embarque qu'un socle générique (`base/common`, `base/elixir`, `base/haproxy`, `base/riak-console`, dans `crates/core/templates/base/`) : détecteurs et clés courantes, sans rien de propre à une équipe. Il prend tout fichier qui n'a pas d'autre template, pour qu'une app vierge sache anonymiser ce qui se reconnaît à sa forme et profiler des logs ; à précision de motif égale, il passe après tous les autres. Les templates d'équipe ne sont ni dans le dépôt ni dans les binaires : l'app les charge depuis son dossier de données. Ils s'y importent en lot (plusieurs `.toml`, un dossier, une archive `.zip`) ; chaque template est validé et ses tests embarqués sont lancés avant d'être enregistré, et un lot peut contenir un template et ses parents dans n'importe quel ordre.

Organisation conseillée d'un lot :

| Template | Rôle |
|---|---|
| `<équipe>/common` | socle abstrait : détecteurs, identifiants, cookies, PII génériques, allowlist de l'infra |
| `<équipe>/elixir`, `<équipe>/haproxy`, `<équipe>/riak-console` | un socle par format de log, avec ses filtres de bruit |
| `<projet>/<app>` ou `<projet>/apps` | template d'application ou de projet : bruit mesuré sur des logs réels, clés propres au projet. `suggested_apps` désigne les applications ; le motif le plus précis l'emporte |

Pour le développement, `logano-core` peut embarquer les `.toml` d'un dossier `templates/` posé à la racine du dépôt (fonctionnalité `embedded-templates`, voir `crates/core/build.rs`) : c'est ce qu'utilisent ses tests et ses outils. L'app ne l'active jamais.

## 9. Accès distant (`logano-remote`)

### Connexion

- **Bastion** : une session `russh`, ouverte une fois, partagée.
- **Mode `nc`** (défaut) : canal exec `nc <host> 22` sur le bastion ; `channel.into_stream()` donne un flux `AsyncRead + AsyncWrite` passé à `russh::client::connect_stream`. La commande est configurable (`nc {host} {port}`).
- **Mode `direct-tcpip`** : `channel_open_direct_tcpip`, même suite.
- **Auth** : clé (`~/.ssh/id_rsa` par défaut, signatures `rsa-sha2-256/512`) ou ssh-agent (`SSH_AUTH_SOCK`). Phrase de passe d'une clé chiffrée : demandée une fois, gardée en mémoire.
- **Host key** : `insecure` par défaut (comme ta config), `tofu` en option avec un fichier `known_hosts` propre à l'app.
- **Keepalive** 60 s sur les deux sessions. Fenêtre de canal élargie pour le débit.
- **Pool** : une session par serveur cible, gardée pendant toute l'extraction ; plusieurs canaux par session pour les téléchargements parallèles.

### sudo

1. `sudo -n chmod +r -- <fichiers>` avant chaque lecture, par lot de fichiers d'un même dossier ; chemins protégés par quotage shell.
2. Si sudo demande un mot de passe : demande unique par session et par serveur, `SecretString` en mémoire, passé sur stdin à `sudo -S -p ''`. Jamais écrit ni journalisé.
3. Échec : erreur typée avec le stderr de sudo.

### Découverte

- Le motif `/srv/syslog/{YYYY}/{MM}/{DD}/APPS/{app_name}/{cluster}/` est découpé en segments ; la découverte liste le niveau `{app_name}` puis `{cluster}`, puis `stat` les fichiers attendus.
- Résultat mis en cache par serveur et par jour. Jours ou fichiers absents : signalés, sans échec.

### Transfert

| Fichier distant | Méthode | Reprise |
|---|---|---|
| `*.log.gz` | SFTP, lectures par plages en parallèle ; repli exec `tail -c +N \| head -c L` | par plage |
| `*.log` (jour en cours) | exec `tail -c +A f \| head -c L \| zstd -3 -c` par segment de 256 Mo ; `gzip -c` si zstd absent | par segment |

- La taille est figée au `stat` : un fichier qui grossit pendant la lecture ne pose pas de problème, la suite est récupérée au rafraîchissement suivant.
- Chaque segment est une trame zstd (ou un membre gzip) indépendante ; les trames se concatènent. Le jour en cours se **rafraîchit par delta** : seuls les octets ajoutés depuis la dernière fois sont téléchargés.
- Tailles affichées avant téléchargement ; confirmation au-delà du seuil (`confirm_above`, 1 Gio par défaut).
- Progression (octets, débit, ETA) par events ; annulation par `CancellationToken`.

### Cache brut

```
~/Library/Caches/<bundle>/raw/<serveur>/<YYYY>/<MM>/<DD>/<app>/<cluster>/<type>.log.{gz,zst}
                                                                        + .meta.json
```

`.meta.json` : taille et mtime distants, octets bruts couverts, complet ou non. Taille maximale avec purge LRU, purge manuelle, invalidation du jour en cours.

## 10. Orchestration d'un run (`logano-app`)

1. **Plan** : serveur + apps/clusters + types + jours → liste de fichiers avec tailles et templates associés. Affiché avant de lancer.
2. **Récupération** : fichiers manquants ou périmés vers le cache, `transfer.parallel_downloads` à la fois (3 par défaut, 8 au plus : un canal SSH par fichier, sous le `MaxSessions` d'OpenSSH).
3. **Anonymisation** : dès qu'un fichier est complet, pipeline du moteur ; `transfer.parallel_processing` fichiers à la fois (2 par défaut, 8 au plus). Chaque fichier donne sa propre sortie : rien n'est regroupé entre les jours. Sur une erreur ou une annulation, les traitements en cours s'arrêtent et leurs sorties incomplètes sont supprimées ; les sorties déjà terminées restent.
4. **Résultat** : `out/<run>/<app>/<cluster>/<type>.<jour>[.partNNN].log`, stats, trouvailles du filet, formes inconnues. L'interface regroupe les jours d'une même app, et peut les exporter ensemble dans un dossier.
5. **Historique** : métadonnées seulement (serveur, apps, jours, templates et versions, stats) ; rejouable.

Commandes Tauri typées (`tauri-specta`) : `config_*`, `ssh_import`, `discover`, `plan_run`, `start_run`, `cancel_run`, `template_*` (lister, lire, valider, tester, importer, exporter), `sandbox_run`, `profile_*`, `output_*` (copier, exporter), `cache_*`, `mapping_*`. Events : `run://progress`, `run://file`, `run://finding`, `run://done`.

## 11. Frontend

**Svelte 5**, parce que :

- la progression arrive par events à haute fréquence ; les runes (`$state`, `$derived`) mettent à jour le DOM sans diff d'arbre ni mémoïsation manuelle ;
- le bundle est petit et l'app démarre vite, ce qui compte dans une webview ;
- les pièces lourdes (CodeMirror 6 pour le TOML, liste virtualisée du bac à sable) sont indépendantes du framework ;
- SolidJS aurait les mêmes qualités avec un écosystème de composants plus mince ; React apporterait son écosystème, inutile ici, au prix d'un runtime plus lourd.

Écrans : Extraction (serveur → apps → types → jours → plan → run), Résultat (stats, trouvailles, sorties), Templates (bibliothèque, éditeur TOML + formulaire, bac à sable côte à côte), Profileur, Historique, Réglages. Palette de commandes `⌘K`, thème sombre par défaut.

Tauri : capabilities réduites à `core`, `dialog` et écriture du presse-papier ; pas de plugin `fs`, `shell` ni `http` (tout passe par des commandes typées). CSP `default-src 'self'`. Polices embarquées. Aucun updater, aucune télémétrie.

## 12. Config de l'app

`~/Library/Application Support/<bundle>/config.toml`, versionné (`config_version`), migré au chargement.

```toml
config_version = 1

[bastion]
host = "access01.cloud.kbrwadventure.com"
user = "jdupont"
port = 22
auth = "key"                      # key | agent
identity_file = "~/.ssh/id_rsa"
mode = "nc"                       # nc | direct_tcpip
nc_command = "nc {host} {port}"
host_key_policy = "insecure"      # insecure | tofu
keepalive_secs = 60

[[servers]]
id = "etam-sb"
name = "Etam — sandbox"
host = "syslogserver01.priv.etamadm-sb.kbrw.fr"
user = "jdupont"
path_pattern = "/srv/syslog/{YYYY}/{MM}/{DD}/APPS/{app_name}/{cluster}/"
# identity_file, [servers.bastion] : facultatifs, sinon ceux du bastion global

[[associations]]
app = "etam_*_gateway"
log_kind = "erlang"
template = "etam/gateway"

[transfer]
parallel = 3
confirm_above = "1GiB"
remote_compression = "auto"       # auto | zstd | gzip

[cache]
max_size = "50GiB"

[output]
dir = "~/Documents/LogsAnonymizer"
layout = "compact"                # compact | faithful
header = true
chunk_tokens = 0                  # 0 = pas de découpage

[safety_net]
action = "replace"                # replace | report

[pseudonyms]
persistent_key = false
mapping_table = false
```

Import : lecture de `~/.ssh/config` (blocs `Host`, `ProxyCommand`, `User`, `IdentityFile`), de `~/.zshrc` (alias `*logs`) et de l'historique du shell (seulement les commandes `ssh … syslogserver…`, pour les serveurs joints à la main sans alias), détection des hosts `syslogserver*`, proposition à cocher.

Rendu de sortie `compact` : le host apparaît une fois, sur la première ligne de l'entrée ; les continuations suivent sans préfixe ; les entrées sont désentrelacées. `faithful` remet le préfixe sur chaque ligne.

## 13. Performance et tests

Performance :

- un seul passage Aho-Corasick par entrée donne le jeu de déclencheurs présents (`@`, `Basic `, `eyJ`, `{`, `%{`, `\t`, `?`, `=`…) ; une entrée sans aucun déclencheur ne passe que par le filet ;
- extracteurs et regex ne tournent que sur déclencheur ;
- décompression, assemblage et écriture sur trois threads dédiés, le reste sur `rayon` ;
- cible ≥ 300 Mo/s ; bancs `criterion` sur un corpus synthétique généré depuis les formes observées (`cargo run --example gen_corpus`).

Tests :

- unitaires par extracteur, détecteur, stratégie, avec les cas pièges listés dans le prompt ;
- golden sur `corpus/`, construit depuis les exemples du prompt ;
- `proptest` : aucune valeur injectée ne survit ; la sortie ne déclenche jamais plus de détecteurs que l'entrée ;
- tests embarqués des templates, lancés par `cargo test` ;
- intégration SSH : deux conteneurs `sshd` (bastion avec `nc`, cible avec l'arborescence, fichiers `-rw-r-----`, sudo avec et sans mot de passe), derrière `--features docker-tests` ;
- erreurs typées (`thiserror`) : bastion ou cible injoignable, clé refusée, sudo refusé, jour absent, `.gz` tronqué.

## 14. Écarts par rapport au prompt

1. **Noms de packages** `logano-*` au lieu de `core` / `remote` / `app` (les dossiers gardent ces noms).
2. **Un quatrième template de base**, `kbrw/common`, abstrait, dont héritent les trois autres : évite de tripler les règles de détection et l'allowlist.
3. **`allowlist.domains` ne s'applique pas aux emails.** L'inventaire classe les emails du staff comme sensibles ; `jean.dupont@kbrw.fr` est donc pseudonymisé. Les exceptions passent par `allowlist.emails`.
4. **Le filet de sécurité n'est pas réglable par template** (voir §7).
5. **Jetons de 8 hex** au lieu de 6.
6. **Pas de streaming direct SSH → moteur** : le cache est toujours entre les deux. Le moteur lit n'importe quel `Read`, le mode direct reste possible plus tard.
7. **Cookie de session** : `etam_admin-auth=EMAIL_…[SESSION]` au lieu de `[SESSION]` seul, pour garder la corrélation par email. Choix validé.
8. **`customeremail` porte le jeton `EMAIL`**, pas `CUSTOMER`, pour coïncider avec le même email vu ailleurs.
