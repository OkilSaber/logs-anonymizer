//! Types échangés avec l'interface. Les types TypeScript sont générés depuis ceux-ci.

use crate::error::AppError;
use serde::{Deserialize, Serialize};
use specta::Type;
use tauri_specta::Event;

#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub struct BastionDto {
    pub host: String,
    pub user: String,
    pub port: u16,
    /// `key` ou `agent`.
    pub auth: String,
    pub identity_file: String,
    /// `nc` ou `direct_tcpip`.
    pub mode: String,
    /// `insecure` ou `tofu`.
    pub host_key_policy: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub struct ServerDto {
    pub id: String,
    pub name: String,
    pub host: String,
    pub path_pattern: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub struct AssociationDto {
    pub app: String,
    pub log_kind: String,
    pub template: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub struct ConfigDto {
    pub bastion: Option<BastionDto>,
    pub servers: Vec<ServerDto>,
    pub associations: Vec<AssociationDto>,
    pub output_dir: String,
    /// Dossier effectif des sorties (lecture seule).
    pub output_dir_effective: String,
    pub layout: String,
    pub header: bool,
    /// Taille visée d'une partie de sortie, en tokens estimés ; 0 = un seul fichier.
    pub chunk_tokens: u32,
    pub confirm_above_mb: u32,
    /// Fichiers téléchargés en même temps (1 à 8).
    pub parallel_downloads: u32,
    /// Fichiers anonymisés en même temps (1 à 8).
    pub parallel_processing: u32,
    /// Taille maximale du cache brut, en Go ; 0 = pas de limite.
    pub cache_max_gb: u32,
    /// Garder, chiffrée, la table jeton → valeur réelle de chaque run.
    pub mapping_table: bool,
    pub safety_action: String,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct ImportDto {
    pub bastion: Option<BastionDto>,
    pub servers: Vec<ServerDto>,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct TemplateInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub log_kind: Option<String>,
    pub format: Option<String>,
    pub builtin: bool,
    pub is_abstract: bool,
    /// Utilisable par cette version du moteur.
    pub available: bool,
    pub problem: Option<String>,
    pub warnings: Vec<String>,
    pub suggested_apps: Vec<String>,
    pub tests: u32,
    pub rules: u32,
}

/// Texte TOML d'un template.
#[derive(Clone, Debug, Serialize, Type)]
pub struct TemplateSource {
    pub id: String,
    pub toml: String,
    pub builtin: bool,
}

/// Un template enregistré par un import en lot.
#[derive(Clone, Debug, Serialize, Type)]
pub struct ImportedTemplate {
    pub id: String,
    /// Un template de ce nom existait déjà : il est remplacé.
    pub replaced: bool,
    /// Nombre de points qui affaiblissent la protection (allowlist, règle héritée désactivée,
    /// valeurs gardées) : à relire dans l'éditeur.
    pub weakens: u32,
}

/// Un fichier écarté par un import en lot, et pourquoi.
#[derive(Clone, Debug, Serialize, Type)]
pub struct RejectedTemplate {
    pub source: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct ImportReport {
    pub imported: Vec<ImportedTemplate>,
    pub rejected: Vec<RejectedTemplate>,
}

/// Résultat de la validation d'un texte de template : jamais une erreur, toujours un état.
#[derive(Clone, Debug, Serialize, Type)]
pub struct TemplateCheck {
    pub ok: bool,
    pub id: Option<String>,
    pub error: Option<String>,
    pub warnings: Vec<String>,
    pub tests: Vec<TestOutcomeDto>,
    /// Ce qui affaiblit la protection par rapport aux parents : allowlists, règles
    /// héritées désactivées, valeurs gardées. À relire avant d'accepter un template reçu.
    pub weakens: Vec<String>,
    /// Un template de ce nom existe déjà dans la bibliothèque.
    pub exists: bool,
    pub builtin: bool,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct TestOutcomeDto {
    pub name: String,
    pub passed: bool,
    pub failures: Vec<String>,
    pub output: String,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct SegmentDto {
    pub text: String,
    pub rule: Option<String>,
    pub safety: bool,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct SandboxEntryDto {
    pub source: String,
    pub line_no: u64,
    pub kind: String,
    pub dropped_by: Option<String>,
    pub raw: Vec<SegmentDto>,
    pub out: Vec<SegmentDto>,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct SandboxResult {
    pub entries: Vec<SandboxEntryDto>,
    pub entries_in: u64,
    pub dropped: u64,
    pub modified: u64,
    pub safety_total: u64,
    pub warnings: Vec<String>,
    /// Template utilisé pour ce résultat, `id@version`.
    pub template: String,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct AppInfoDto {
    pub name: String,
    pub clusters: Vec<String>,
}

/// Apps et clusters vus sur au moins un des jours demandés.
#[derive(Clone, Debug, Serialize, Type)]
pub struct DiscoverResult {
    pub apps: Vec<AppInfoDto>,
    /// Jours sans dossier de logs sur le serveur.
    pub missing_days: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub struct Selection {
    pub app: String,
    pub clusters: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub struct PlanRequest {
    pub server_id: String,
    /// Jours à récupérer, `YYYY-MM-DD`. L'ordre et les doublons n'ont pas d'importance.
    pub days: Vec<String>,
    pub selections: Vec<Selection>,
    /// `erlang`, `haproxy`, `console`.
    pub kinds: Vec<String>,
    /// Template imposé pour les fichiers `erlang` ; sinon association ou suggestion.
    pub template: Option<String>,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct PlanFile {
    /// `YYYY-MM-DD`
    pub day: String,
    pub app: String,
    pub cluster: String,
    pub kind: String,
    pub remote_path: String,
    pub size: u64,
    pub compressed: bool,
    pub cached: bool,
    pub template: Option<String>,
    /// Pourquoi ce fichier ne sera pas traité (format pas encore disponible…).
    pub problem: Option<String>,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct Plan {
    pub files: Vec<PlanFile>,
    pub total_bytes: u64,
    pub download_bytes: u64,
    /// La taille à télécharger dépasse le seuil de confirmation.
    pub needs_confirmation: bool,
    /// Estimation haute de la taille des sorties (logs décompressés, avant filtres).
    pub estimated_output_bytes: u64,
    /// Espace libre sur le volume des sorties et sur celui du cache brut.
    pub output_free_bytes: u64,
    pub cache_free_bytes: u64,
    /// Le run risque de remplir le disque : à confirmer explicitement.
    pub disk_warning: Option<String>,
    /// Sélections sans dossier ou sans fichier pour ce jour.
    pub missing: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Type, Event)]
pub struct RunProgress {
    pub run_id: String,
    pub file_index: u32,
    pub file_count: u32,
    pub label: String,
    /// `connect`, `download` ou `anonymize`.
    pub phase: String,
    /// Avancement de l'étape : octets reçus (téléchargement) ou octets lus du cache (anonymisation).
    pub bytes_done: u64,
    /// Total de l'étape ; 0 s'il n'est pas connaissable (fichier compressé à la volée).
    pub bytes_total: u64,
    /// Octets de log traités, décompressés (anonymisation).
    pub processed_bytes: u64,
    pub entries_in: u64,
    pub dropped: u64,
    pub modified: u64,
    /// Ce fichier a fini cette étape. Plusieurs fichiers peuvent être dans la même étape.
    pub finished: bool,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct FindingDto {
    pub detector: String,
    pub source: String,
    pub line_no: u64,
    pub context: String,
    pub replaced: bool,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct PartInfo {
    pub index: u32,
    pub path: String,
    pub bytes: u64,
    /// Estimation, à raison de 3 octets par token.
    pub tokens: u64,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct ShapeDto {
    pub shape: String,
    pub pattern: String,
    pub count: u64,
    pub bytes: u64,
    pub level: String,
    pub kind: String,
    /// Entrées de cette forme déjà retirées par un filtre (la forme peut n'être filtrée qu'en partie).
    pub filtered_count: u64,
    pub filtered_by: Option<String>,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct ValueShape {
    pub shape: String,
    pub count: u64,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct KeyDto {
    pub path: String,
    pub count: u64,
    pub replaced: u64,
    pub distinct: u64,
    pub distinct_capped: bool,
    pub shapes: Vec<ValueShape>,
}

/// Profil d'un jour de logs : formes d'entrées par poids, et inventaire des clés.
/// Calculé sur la sortie anonymisée : il ne contient aucune valeur.
#[derive(Clone, Debug, Serialize, Type)]
pub struct ProfileDto {
    pub app: String,
    pub day: String,
    pub template: String,
    pub entries: u64,
    pub bytes: u64,
    pub filtered_entries: u64,
    pub filtered_bytes: u64,
    pub shapes_total: u64,
    pub shapes: Vec<ShapeDto>,
    pub keys_total: u64,
    pub keys: Vec<KeyDto>,
    pub warning: Option<String>,
}

/// Ajout au template local d'une application, depuis le profileur.
#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub struct LocalAddition {
    pub app: String,
    /// Template que le template local étend s'il n'existe pas encore.
    pub base_template: String,
    /// `filter` : retire les entrées dont l'en-tête correspond à `pattern`.
    /// `rule` : applique `strategy` aux valeurs des clés `keys`.
    /// `allow_value` : la valeur exacte `pattern` n'est plus masquée.
    pub kind: String,
    pub description: String,
    pub pattern: Option<String>,
    pub keys: Vec<String>,
    /// `pseudonymize`, `redact` ou `keep`.
    pub strategy: Option<String>,
    /// Jeton (`pseudonymize`) ou libellé (`redact`), en majuscules.
    pub label: Option<String>,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct LocalTemplate {
    pub template_id: String,
    pub path: String,
    /// Identifiant du filtre ou de la règle ajouté.
    pub added_id: String,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct Counter {
    pub id: String,
    pub hits: u64,
    pub shadowed: u64,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct FileResult {
    pub output_id: String,
    /// Jours présents dans cette sortie, dans l'ordre.
    pub days: Vec<String>,
    pub app: String,
    pub cluster: String,
    pub kind: String,
    pub template: String,
    pub template_version: String,
    pub output_path: String,
    /// Fichiers de la sortie : un seul, ou plusieurs parties.
    pub parts: Vec<PartInfo>,
    /// Entrées identiques à la précédente, remplacées par un compteur.
    pub deduplicated: u64,
    pub entries_in: u64,
    pub entries_out: u64,
    pub dropped: u64,
    pub modified: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub safety_total: u64,
    pub findings: Vec<FindingDto>,
    pub rules: Vec<Counter>,
    pub filters: Vec<Counter>,
    pub warnings: Vec<String>,
    /// La sortie contient des trouvailles non remplacées : copie et export refusés.
    pub quarantined: bool,
}

#[derive(Clone, Debug, Serialize, Type, Event)]
pub struct RunDone {
    pub run_id: String,
    pub cancelled: bool,
    pub error: Option<AppError>,
    pub files: Vec<FileResult>,
    /// Fichiers ignorés, avec la raison.
    pub skipped: Vec<String>,
    /// Jetons enregistrés dans la table de correspondance de ce run (0 si elle n'est pas gardée).
    pub mapping_tokens: u64,
}

/// Un fichier d'un run passé : compteurs seulement.
#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub struct HistoryFile {
    pub app: String,
    pub cluster: String,
    pub kind: String,
    pub template: String,
    pub entries_in: u64,
    pub entries_out: u64,
    pub bytes_out: u64,
    pub safety_total: u64,
}

/// Un run passé : ce qui a été demandé et ce qu'il a donné. Aucun contenu de log.
#[derive(Clone, Debug, Serialize, Deserialize, Type)]
pub struct HistoryEntry {
    pub run_id: String,
    /// Date et heure locales de lancement, ISO 8601.
    pub started_at: String,
    pub request: PlanRequest,
    /// `ok`, `cancelled` ou `error`.
    pub outcome: String,
    pub error: Option<String>,
    pub files: Vec<HistoryFile>,
}

/// Table de correspondance d'un run, sans son contenu.
#[derive(Clone, Debug, Serialize, Type)]
pub struct MappingInfo {
    pub run_id: String,
    pub bytes: u64,
}

/// Texte où les jetons ont repris leur valeur réelle. À ne pas renvoyer à une IA.
#[derive(Clone, Debug, Serialize, Type)]
pub struct Deanonymized {
    pub text: String,
    pub replaced: u64,
    /// Jetons absents de cette table (autre run, ou table purgée).
    pub unknown: u64,
}

#[derive(Clone, Debug, Serialize, Type)]
pub struct CacheInfo {
    pub path: String,
    pub bytes: u64,
}
