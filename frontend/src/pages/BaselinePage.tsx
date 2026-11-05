import React, { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { BaselinePrefixSettings, FolderItem } from "../types";

const VARIABLES: { tag: string; label: string }[] = [
  { tag: "{{tenant}}", label: "Tenant" },
  { tag: "{{technology_name}}", label: "Tecnologia" },
  { tag: "{{tactic}}", label: "Tática" },
  { tag: "{{severity}}", label: "Severidade" },
];

const PRESETS: { name: string; value: string }[] = [
  { name: "Baseline - ", value: "Baseline - " },
  { name: "[Tenant] [Tecnologia] - ", value: "[{{tenant}}] [{{technology_name}}] - " },
  { name: "[Tecnologia] ", value: "[{{technology_name}}] " },
  { name: "Sem prefixo", value: "" },
];

const SAMPLE = {
  title: "Tentativa de Força Bruta contra RDP",
  technology: "AD/Windows",
  tactic: "credential_access",
  severity: "high",
  tenant: "Financeiro",
};

export const BaselinePage: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Pasta global
  const [folders, setFolders] = useState<FolderItem[]>([]);
  const [currentFolderUid, setCurrentFolderUid] = useState("");
  const [currentFolderTitle, setCurrentFolderTitle] = useState("");
  const [selectedFolderUid, setSelectedFolderUid] = useState("");
  const [savingFolder, setSavingFolder] = useState(false);

  // Padrão de nomenclatura
  const [settings, setSettings] = useState<BaselinePrefixSettings>({ enabled: true, template: "Baseline - " });
  const [savingNaming, setSavingNaming] = useState(false);
  const [previewBaseline, setPreviewBaseline] = useState(SAMPLE.title);
  const [previewClient, setPreviewClient] = useState(SAMPLE.title);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let mounted = true;
    Promise.all([
      api.getBaselineFolder(),
      api.getFolders().catch(() => [] as FolderItem[]),
      api.getBaselinePrefixSettings(),
    ])
      .then(([folder, folderList, prefix]) => {
        if (!mounted) return;
        setCurrentFolderUid(folder.baseline_folder_uid);
        setCurrentFolderTitle(folder.baseline_folder_title || folder.baseline_folder_uid);
        setSelectedFolderUid(folder.baseline_folder_uid);
        setFolders(folderList);
        setSettings(prefix);
      })
      .catch((err) => mounted && setError(err instanceof Error ? err.message : "Erro ao carregar o Baseline."))
      .finally(() => mounted && setLoading(false));
    return () => {
      mounted = false;
    };
  }, []);

  // Preview ao vivo (debounce curto)
  useEffect(() => {
    if (!settings.enabled) {
      setPreviewBaseline(SAMPLE.title);
      setPreviewClient(SAMPLE.title);
      return;
    }
    let cancelled = false;
    const handle = setTimeout(() => {
      const base = {
        template: settings.template || "",
        title: SAMPLE.title,
        technology: SAMPLE.technology,
        technology_name: SAMPLE.technology,
        tactic: SAMPLE.tactic,
        severity: SAMPLE.severity,
      };
      api
        .previewBaselinePrefix({ ...base, tenant: null })
        .then((r) => !cancelled && setPreviewBaseline(r.preview_title))
        .catch(() => {});
      if (/\{\{?tenant\}?\}/i.test(settings.template || "")) {
        api
          .previewBaselinePrefix({ ...base, tenant: SAMPLE.tenant })
          .then((r) => !cancelled && setPreviewClient(r.preview_title))
          .catch(() => {});
      } else {
        setPreviewClient(SAMPLE.title);
      }
    }, 250);
    return () => {
      cancelled = true;
      clearTimeout(handle);
    };
  }, [settings]);

  const flash = (msg: string) => {
    setSuccess(msg);
    setTimeout(() => setSuccess(null), 3500);
  };

  const handleSaveFolder = async () => {
    setSavingFolder(true);
    setError(null);
    try {
      const res = await api.setBaselineFolder(selectedFolderUid);
      setCurrentFolderUid(res.baseline_folder_uid);
      setCurrentFolderTitle(res.baseline_folder_title || res.baseline_folder_uid);
      flash("Pasta global atualizada.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erro ao definir a pasta global.");
    } finally {
      setSavingFolder(false);
    }
  };

  const handleSaveNaming = async () => {
    setSavingNaming(true);
    setError(null);
    try {
      setSettings(await api.setBaselinePrefixSettings(settings));
      flash("Padrão de nomenclatura salvo.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Erro ao salvar o padrão de nomenclatura.");
    } finally {
      setSavingNaming(false);
    }
  };

  const insertVariable = (tag: string) => {
    const input = inputRef.current;
    const start = input?.selectionStart ?? settings.template.length;
    const end = input?.selectionEnd ?? settings.template.length;
    const next = settings.template.slice(0, start) + tag + settings.template.slice(end);
    setSettings((prev) => ({ ...prev, template: next }));
    setTimeout(() => {
      input?.focus();
      input?.setSelectionRange(start + tag.length, start + tag.length);
    }, 0);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-16 text-on-surface-variant font-body-sm">
        Carregando Baseline...
      </div>
    );
  }

  const folderDirty = selectedFolderUid !== currentFolderUid;
  const cardCls = "bg-surface-container-low rounded-xl border border-outline-variant/30 p-6 space-y-4";

  return (
    <div className="flex flex-col w-full max-w-3xl space-y-6 pb-16">
      <header>
        <h1 className="font-headline-xl text-headline-xl text-on-surface font-semibold tracking-tight">Baseline</h1>
        <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">
          Defina a pasta global do Grafana que guarda as regras de referência e o padrão de nome das regras de detecção.
        </p>
      </header>

      {success && (
        <div className="px-4 py-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-body-sm">
          {success}
        </div>
      )}
      {error && (
        <div className="px-4 py-3 rounded-lg bg-error/10 border border-error/30 text-error font-body-sm">{error}</div>
      )}

      {/* Pasta global */}
      <section className={cardCls}>
        <div>
          <h2 className="font-title-md text-title-md text-on-surface font-medium">Pasta global</h2>
          <p className="font-body-xs text-body-xs text-on-surface-variant">
            Atual: <strong className="text-on-surface">{currentFolderTitle}</strong>{" "}
            <code className="text-secondary font-mono">{currentFolderUid}</code>
          </p>
        </div>
        <div className="flex flex-col sm:flex-row gap-3">
          <select
            value={selectedFolderUid}
            onChange={(e) => setSelectedFolderUid(e.target.value)}
            className="flex-1 px-3 py-2 bg-surface-container-highest/60 border border-outline-variant/40 rounded-lg text-on-surface font-body-sm focus:outline-none focus:border-primary/60"
          >
            {folders.map((f) => (
              <option key={f.uid} value={f.uid}>
                {f.title} ({f.uid})
              </option>
            ))}
          </select>
          <button
            type="button"
            onClick={handleSaveFolder}
            disabled={!folderDirty || savingFolder}
            className="px-5 py-2 rounded-lg bg-primary text-on-primary font-body-sm font-medium hover:bg-primary/90 disabled:opacity-40 transition-colors"
          >
            {savingFolder ? "Salvando..." : "Definir pasta"}
          </button>
        </div>
      </section>

      {/* Nomenclatura */}
      <section className={cardCls}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="font-title-md text-title-md text-on-surface font-medium">Nomenclatura das regras</h2>
            <p className="font-body-xs text-body-xs text-on-surface-variant">
              Prefixo aplicado ao título das regras no baseline. Regras replicadas só recebem o nome do cliente se o
              padrão usar <code className="text-primary font-mono">{"{{tenant}}"}</code>.
            </p>
          </div>
          <label className="flex items-center gap-2 cursor-pointer shrink-0">
            <span className="font-body-xs text-on-surface-variant">{settings.enabled ? "Ativo" : "Desativado"}</span>
            <input
              type="checkbox"
              checked={settings.enabled}
              onChange={(e) => setSettings((p) => ({ ...p, enabled: e.target.checked }))}
              className="accent-primary w-4 h-4"
            />
          </label>
        </div>

        <input
          ref={inputRef}
          type="text"
          disabled={!settings.enabled}
          value={settings.template}
          onChange={(e) => setSettings((p) => ({ ...p, template: e.target.value }))}
          placeholder="Ex: Baseline - "
          className="w-full px-4 py-2.5 bg-surface-container-highest/60 border border-outline-variant/40 rounded-lg font-mono text-on-surface placeholder:text-on-surface-variant/40 focus:outline-none focus:border-primary/60 disabled:opacity-50"
        />

        <div className="flex flex-wrap gap-2">
          {VARIABLES.map((v) => (
            <button
              key={v.tag}
              type="button"
              disabled={!settings.enabled}
              onClick={() => insertVariable(v.tag)}
              className="px-2.5 py-1 rounded-md bg-surface-container-high hover:bg-surface-container-highest text-primary border border-primary/20 font-mono text-xs disabled:opacity-50"
              title={`Inserir ${v.label}`}
            >
              {v.tag}
            </button>
          ))}
          <span className="mx-1 w-px bg-outline-variant/40" />
          {PRESETS.map((p) => (
            <button
              key={p.name}
              type="button"
              disabled={!settings.enabled && p.value !== ""}
              onClick={() => setSettings({ enabled: p.value !== "" ? true : settings.enabled, template: p.value })}
              className={`px-2.5 py-1 rounded-md border text-xs transition-colors ${
                settings.template === p.value
                  ? "bg-primary/10 border-primary text-on-surface"
                  : "bg-transparent border-outline-variant/40 text-on-surface-variant hover:text-on-surface"
              }`}
            >
              {p.name}
            </button>
          ))}
        </div>

        <div className="rounded-lg bg-surface-container-highest/40 border border-outline-variant/30 divide-y divide-outline-variant/20">
          <div className="px-4 py-2.5">
            <span className="block text-[11px] uppercase tracking-wide text-outline">No baseline</span>
            <span className="font-body-sm text-on-surface break-words">{previewBaseline}</span>
          </div>
          <div className="px-4 py-2.5">
            <span className="block text-[11px] uppercase tracking-wide text-outline">No cliente ({SAMPLE.tenant})</span>
            <span className="font-body-sm text-on-surface break-words">{previewClient}</span>
          </div>
        </div>

        <div className="flex justify-end">
          <button
            type="button"
            onClick={handleSaveNaming}
            disabled={savingNaming}
            className="px-5 py-2 rounded-lg bg-primary text-on-primary font-body-sm font-medium hover:bg-primary/90 disabled:opacity-40 transition-colors"
          >
            {savingNaming ? "Salvando..." : "Salvar nomenclatura"}
          </button>
        </div>
      </section>
    </div>
  );
};
