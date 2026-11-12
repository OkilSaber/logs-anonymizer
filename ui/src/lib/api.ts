// Accès au backend. Dans l'app, ce sont les commandes Tauri typées ; dans un navigateur
// (aperçu de l'interface sans backend), des données de démonstration.

import {
  commands,
  events,
  type AppError_Serialize,
  type AppInfoDto,
  type CacheInfo,
  type ConfigDto_Deserialize,
  type ConfigDto_Serialize,
  type DiscoverResult,
  type HistoryEntry,
  type ImportDto_Serialize,
  type ImportReport,
  type LocalAddition,
  type Deanonymized,
  type LocalTemplate,
  type MappingInfo,
  type ProfileDto,
  type Plan_Serialize,
  type PlanRequest_Deserialize,
  type RunDone_Serialize,
  type TemplateCheck,
  type TemplateSource,
  type RunProgress,
  type SandboxResult_Serialize,
  type TemplateInfo_Serialize,
  type TestOutcomeDto,
  type UpdateInfo_Serialize,
  type UpdateProgress_Serialize,
} from "./bindings";
import { mockApi } from "./mock";

export type Config = ConfigDto_Serialize;
export type ConfigInput = ConfigDto_Deserialize;
export type Plan = Plan_Serialize;
export type PlanRequest = PlanRequest_Deserialize;
export type RunDone = RunDone_Serialize;
export type SandboxResult = SandboxResult_Serialize;
export type TemplateInfo = TemplateInfo_Serialize;
export type Import = ImportDto_Serialize;
export type UpdateInfo = UpdateInfo_Serialize;
export type UpdateProgress = UpdateProgress_Serialize;
export type { AppInfoDto, CacheInfo, ImportReport, Deanonymized, DiscoverResult, HistoryEntry, MappingInfo, LocalAddition, TemplateCheck, TemplateSource, LocalTemplate, RunProgress, TestOutcomeDto };
export type Profile = ProfileDto;
export type ShapeStat = ProfileDto["shapes"][number];
export type KeyStat = ProfileDto["keys"][number];
export type FileResult = RunDone["files"][number];
export type SandboxEntry = SandboxResult["entries"][number];
export type Segment = SandboxEntry["raw"][number];

export class ApiError extends Error {
  code: string;
  detail: string | null;
  constructor(e: AppError_Serialize) {
    super(e.message);
    this.code = e.code;
    this.detail = e.detail;
  }
}

type Outcome<T> = { status: "ok"; data: T } | { status: "error"; error: AppError_Serialize };

async function unwrap<T>(p: Promise<Outcome<T>>): Promise<T> {
  const r = await p;
  if (r.status === "error") throw new ApiError(r.error);
  return r.data;
}

export interface Api {
  getConfig(): Promise<Config>;
  saveConfig(c: ConfigInput): Promise<Config>;
  importSsh(): Promise<Import>;
  listTemplates(): Promise<TemplateInfo[]>;
  runTemplateTests(id: string): Promise<TestOutcomeDto[]>;
  templateSource(id: string): Promise<TemplateSource>;
  templateCheck(toml: string): Promise<TemplateCheck>;
  templateSave(toml: string): Promise<string>;
  templateDelete(id: string): Promise<void>;
  /** Import en lot : des .toml et des .zip choisis, ou tous les .toml d'un dossier. */
  templatesImport(folder: boolean): Promise<ImportReport | null>;
  templateExport(id: string): Promise<string | null>;
  sandboxRun(templateId: string, input: string): Promise<SandboxResult>;
  discover(serverId: string, days: string[]): Promise<DiscoverResult>;
  planRun(req: PlanRequest): Promise<Plan>;
  startRun(req: PlanRequest): Promise<string>;
  cancelRun(runId: string): Promise<void>;
  provideSudoPassword(serverId: string, password: string): Promise<void>;
  provideKeyPassphrase(identityFile: string, passphrase: string): Promise<void>;
  previewOutput(outputId: string, limit: number): Promise<SandboxResult>;
  copyOutput(outputId: string, part: number): Promise<number>;
  profileOutput(outputId: string): Promise<Profile>;
  localTemplateAdd(addition: LocalAddition): Promise<LocalTemplate>;
  exportOutput(outputId: string): Promise<string | null>;
  exportOutputs(outputIds: string[]): Promise<string | null>;
  mappingList(): Promise<MappingInfo[]>;
  mappingPurge(runId: string | null): Promise<void>;
  deanonymize(runId: string, text: string): Promise<Deanonymized>;
  historyList(): Promise<HistoryEntry[]>;
  historyClear(): Promise<void>;
  cacheInfo(): Promise<CacheInfo>;
  cachePurge(): Promise<CacheInfo>;
  /** Copie le texte d'un profil (formes et clés, aucune valeur). Rend le nombre d'octets copiés. */
  copyProfile(text: string): Promise<number>;
  /** Cherche une version plus récente ; `null` si l'app est à jour. */
  updateCheck(): Promise<UpdateInfo | null>;
  /** Télécharge, vérifie et installe la dernière version, puis relance l'app. */
  updateInstall(): Promise<void>;
  onUpdateProgress(cb: (p: UpdateProgress) => void): Promise<() => void>;
  onProgress(cb: (p: RunProgress) => void): Promise<() => void>;
  onDone(cb: (d: RunDone) => void): Promise<() => void>;
}

const tauriApi: Api = {
  getConfig: () => commands.getConfig(),
  saveConfig: (c) => unwrap(commands.saveConfig(c)),
  importSsh: () => commands.importSsh(),
  listTemplates: () => commands.listTemplates(),
  runTemplateTests: (id) => unwrap(commands.runTemplateTests(id)),
  templateSource: (id) => unwrap(commands.templateSource(id)),
  templateCheck: (toml) => commands.templateCheck(toml),
  templateSave: (toml) => unwrap(commands.templateSave(toml)),
  templateDelete: async (id) => {
    await unwrap(commands.templateDelete(id));
  },
  templatesImport: (folder) => unwrap(commands.templatesImport(folder)),
  templateExport: (id) => unwrap(commands.templateExport(id)),
  sandboxRun: (t, i) => unwrap(commands.sandboxRun(t, i)),
  discover: (s, d) => unwrap(commands.discover(s, d)),
  planRun: (r) => unwrap(commands.planRun(r)),
  startRun: (r) => unwrap(commands.startRun(r)),
  cancelRun: (id) => commands.cancelRun(id),
  provideSudoPassword: (s, p) => commands.provideSudoPassword(s, p),
  provideKeyPassphrase: async (f, p) => {
    await unwrap(commands.provideKeyPassphrase(f, p));
  },
  previewOutput: (o, l) => unwrap(commands.previewOutput(o, l)),
  copyOutput: (o, p) => unwrap(commands.copyOutput(o, p)),
  profileOutput: (o) => unwrap(commands.profileOutput(o)),
  localTemplateAdd: (a) => unwrap(commands.localTemplateAdd(a)),
  exportOutput: (o) => unwrap(commands.exportOutput(o)),
  exportOutputs: (ids) => unwrap(commands.exportOutputs(ids)),
  mappingList: () => commands.mappingList(),
  mappingPurge: async (id) => {
    await unwrap(commands.mappingPurge(id));
  },
  deanonymize: (id, text) => unwrap(commands.deanonymize(id, text)),
  historyList: () => commands.historyList(),
  historyClear: async () => {
    await unwrap(commands.historyClear());
  },
  cacheInfo: () => unwrap(commands.cacheInfo()),
  cachePurge: () => unwrap(commands.cachePurge()),
  copyProfile: (t) => unwrap(commands.copyProfile(t)),
  updateCheck: () => unwrap(commands.updateCheck()),
  updateInstall: async () => {
    await unwrap(commands.updateInstall());
  },
  onUpdateProgress: (cb) => events.updateProgress.listen((e) => cb(e.payload)),
  onProgress: (cb) => events.runProgress.listen((e) => cb(e.payload)),
  onDone: (cb) => events.runDone.listen((e) => cb(e.payload)),
};

export const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
export const api: Api = inTauri ? tauriApi : mockApi;
