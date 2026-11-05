import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { Modal } from "../components/Modal";
import { ConfirmModal } from "../components/ConfirmModal";
import { TenantSummary, TenantTechnologiesResult } from "../types";

export const TenantsPage: React.FC = () => {
  const [tenants, setTenants] = useState<TenantSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Filtros
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  // Estado de ações em andamento
  const [actionLoadingUid, setActionLoadingUid] = useState<string | null>(null);

  // Modal Criar Tenant
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [createTitle, setCreateTitle] = useState("");
  const [createUid, setCreateUid] = useState("");
  const [createLokiUrl, setCreateLokiUrl] = useState("");
  const [creatingTenant, setCreatingTenant] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  // Data source Loki
  const [datasourceLoadingUid, setDatasourceLoadingUid] = useState<string | null>(null);
  const [datasourceModalTenant, setDatasourceModalTenant] = useState<TenantSummary | null>(null);
  const [datasourceUrlInput, setDatasourceUrlInput] = useState("");
  const [datasourceError, setDatasourceError] = useState<string | null>(null);

  // Modal Confirmação de Exclusão
  const [deleteModalOpen, setDeleteModalOpen] = useState(false);
  const [tenantToDelete, setTenantToDelete] = useState<TenantSummary | null>(null);
  const [deletingTenant, setDeletingTenant] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  // Modal Confirmação de Sandbox (Ativar/Desativar)
  const [sandboxModalOpen, setSandboxModalOpen] = useState(false);
  const [sandboxModalTarget, setSandboxModalTarget] = useState<{
    tenant: TenantSummary;
    enable: boolean;
  } | null>(null);
  const [sandboxActionLoadingUid, setSandboxActionLoadingUid] = useState<string | null>(null);

  // Modal Confirmação de Pausa/Reativação de Tenant
  const [confirmPauseModalOpen, setConfirmPauseModalOpen] = useState(false);
  const [tenantToToggle, setTenantToToggle] = useState<{
    tenant: TenantSummary;
    pause: boolean;
  } | null>(null);

  // Modal Confirmação de Ocultar/Reexibir Tenant
  const [tenantToHide, setTenantToHide] = useState<{
    tenant: TenantSummary;
    hide: boolean;
  } | null>(null);
  const [hideLoading, setHideLoading] = useState(false);

  // Pop-up de baseline e tecnologias do tenant
  const [techModalTenant, setTechModalTenant] = useState<TenantSummary | null>(null);
  const [techData, setTechData] = useState<TenantTechnologiesResult | null>(null);
  const [techLoading, setTechLoading] = useState(false);
  const [techError, setTechError] = useState<string | null>(null);

  const loadTenants = async () => {
    try {
      setError(null);
      const data = await api.getTenants();
      setTenants(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Erro ao carregar lista de tenants.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadTenants();
  }, []);

  const metrics = useMemo(() => {
    // Tenants Ocultos ficam fora de todas as métricas.
    const visible = tenants.filter((t) => !t.hidden);
    const totalTenants = visible.length;
    const totalRules = visible.reduce((acc, t) => acc + t.rules_count, 0);
    const activeTenants = visible.filter((t) => t.active_rules_count > 0).length;
    const emptyTenants = visible.filter((t) => t.rules_count === 0).length;
    const withDatasource = visible.filter((t) => t.loki_datasource_present).length;
    const withGroup = visible.filter((t) => t.evaluation_group_present).length;

    return {
      totalTenants,
      totalRules,
      activeTenants,
      emptyTenants,
      withDatasource,
      withoutDatasource: totalTenants - withDatasource,
      withGroup,
      withoutGroup: totalTenants - withGroup,
      tenantsWithoutGroup: visible.filter((t) => !t.evaluation_group_present),
      hiddenTenants: tenants.length - visible.length,
    };
  }, [tenants]);

  const filteredTenants = useMemo(() => {
    return tenants.filter((t) => {
      const matchSearch =
        t.title.toLowerCase().includes(search.toLowerCase()) ||
        t.uid.toLowerCase().includes(search.toLowerCase()) ||
        (t.loki_datasource_name || "").toLowerCase().includes(search.toLowerCase());

      let matchStatus = true;
      if (statusFilter === "active") {
        matchStatus = t.active_rules_count > 0;
      } else if (statusFilter === "paused") {
        matchStatus = t.rules_count > 0 && t.active_rules_count === 0;
      } else if (statusFilter === "empty") {
        matchStatus = t.rules_count === 0;
      }

      return matchSearch && matchStatus;
    });
  }, [tenants, search, statusFilter]);

  const handleOpenCreateModal = () => {
    setCreateTitle("");
    setCreateUid("");
    setCreateLokiUrl("");
    setCreateError(null);
    setCreateModalOpen(true);
  };

  const handleCreateTenantSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanTitle = createTitle.trim();
    if (!cleanTitle) {
      setCreateError("O nome do tenant é obrigatório.");
      return;
    }
    if (cleanTitle.toLowerCase() === "global") {
      setCreateError("O nome 'Global' é reservado pelo sistema.");
      return;
    }
    const cleanLokiUrl = createLokiUrl.trim();
    if (cleanLokiUrl && !/^https?:\/\//i.test(cleanLokiUrl)) {
      setCreateError("A URL da Telemetria deve começar com http:// ou https://.");
      return;
    }

    setCreatingTenant(true);
    setCreateError(null);

    try {
      await api.createTenant({
        title: cleanTitle,
        uid: createUid.trim() || undefined,
        loki_url: cleanLokiUrl || undefined,
      });
      setActionSuccess(
        `Tenant "${cleanTitle}" criado com pasta, telemetria dedicada e grupo de avaliação (5m).`
      );
      setCreateModalOpen(false);
      await loadTenants();
      setTimeout(() => setActionSuccess(null), 4000);
    } catch (err: unknown) {
      setCreateError(err instanceof Error ? err.message : "Erro ao criar tenant.");
    } finally {
      setCreatingTenant(false);
    }
  };

  const handleOpenDatasourceModal = (tenant: TenantSummary) => {
    setDatasourceModalTenant(tenant);
    setDatasourceUrlInput("");
    setDatasourceError(null);
  };

  const handleCreateTenantDatasource = async () => {
    if (!datasourceModalTenant) return;
    const tenant = datasourceModalTenant;
    const cleanUrl = datasourceUrlInput.trim();
    if (cleanUrl && !/^https?:\/\//i.test(cleanUrl)) {
      setDatasourceError("A URL da telemetria deve começar com http:// ou https://.");
      return;
    }

    setDatasourceLoadingUid(tenant.uid);
    setDatasourceError(null);
    try {
      const res = await api.createTenantDatasource(tenant.uid, cleanUrl || undefined);
      setActionSuccess(res.message);
      setDatasourceModalTenant(null);
      await loadTenants();
      setTimeout(() => setActionSuccess(null), 4000);
    } catch (err: unknown) {
      setDatasourceError(
        err instanceof Error ? err.message : "Erro ao criar o data source de telemetria."
      );
    } finally {
      setDatasourceLoadingUid(null);
    }
  };

  const handleRequestToggleSandbox = (tenant: TenantSummary) => {
    const isCurrentlyPresent = Boolean(tenant.sandbox_datasource_present);
    setSandboxModalTarget({
      tenant,
      enable: !isCurrentlyPresent,
    });
    setSandboxModalOpen(true);
  };

  const handleConfirmToggleSandbox = async () => {
    if (!sandboxModalTarget) return;
    const { tenant, enable } = sandboxModalTarget;
    setSandboxActionLoadingUid(tenant.uid);
    setActionSuccess(null);
    setError(null);
    try {
      if (enable) {
        const res = await api.enableTenantSandbox(tenant.uid);
        setActionSuccess(res.message);
      } else {
        const res = await api.disableTenantSandbox(tenant.uid);
        setActionSuccess(res.message);
      }
      setSandboxModalOpen(false);
      setSandboxModalTarget(null);
      await loadTenants();
      setTimeout(() => setActionSuccess(null), 4000);
    } catch (err: unknown) {
      setError(
        err instanceof Error
          ? err.message
          : `Erro ao ${enable ? "ativar" : "desativar"} sandbox do tenant.`
      );
    } finally {
      setSandboxActionLoadingUid(null);
    }
  };

  const handleRequestToggleTenantPause = (tenant: TenantSummary, pause: boolean) => {
    if (tenant.rules_count === 0) {
      alert("Este tenant não possui regras de detecção para alterar o status.");
      return;
    }
    setTenantToToggle({ tenant, pause });
    setConfirmPauseModalOpen(true);
  };

  const handleConfirmHideTenant = async () => {
    if (!tenantToHide) return;
    setHideLoading(true);
    setError(null);
    try {
      const res = await api.setTenantHidden(tenantToHide.tenant.uid, tenantToHide.hide);
      setActionSuccess(res.message);
      setTenantToHide(null);
      await loadTenants();
      setTimeout(() => setActionSuccess(null), 4000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Erro ao alterar a visibilidade do tenant.");
      setTenantToHide(null);
    } finally {
      setHideLoading(false);
    }
  };

  const handleToggleTenantPause = async (tenant: TenantSummary, pause: boolean) => {
    setActionLoadingUid(tenant.uid);
    setActionSuccess(null);
    setError(null);
    try {
      const res = await api.toggleTenantPause(tenant.uid, pause);
      setActionSuccess(res.message);
      await loadTenants();
      setTimeout(() => setActionSuccess(null), 4000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Erro ao alternar status do tenant.");
    } finally {
      setActionLoadingUid(null);
      setConfirmPauseModalOpen(false);
      setTenantToToggle(null);
    }
  };

  const handleRequestDelete = (tenant: TenantSummary) => {
    setTenantToDelete(tenant);
    setDeleteError(null);
    setDeleteModalOpen(true);
  };

  const handleConfirmDelete = async () => {
    if (!tenantToDelete) return;
    setDeletingTenant(true);
    setDeleteError(null);
    try {
      const res = await api.deleteTenant(tenantToDelete.uid);
      setActionSuccess(res.message);
      setDeleteModalOpen(false);
      setTenantToDelete(null);
      await loadTenants();
      setTimeout(() => setActionSuccess(null), 4000);
    } catch (err: unknown) {
      setDeleteError(err instanceof Error ? err.message : "Erro ao excluir tenant.");
    } finally {
      setDeletingTenant(false);
    }
  };

  const openTechModal = async (tenant: TenantSummary) => {
    setTechModalTenant(tenant);
    setTechLoading(true);
    setTechError(null);
    setTechData(null);
    try {
      const data = await api.getTenantTechnologies(tenant.uid);
      setTechData(data);
    } catch (err: unknown) {
      setTechError(err instanceof Error ? err.message : "Erro ao carregar tecnologias do tenant.");
    } finally {
      setTechLoading(false);
    }
  };

  return (
    <div className="flex flex-col w-full pb-space-xl text-on-surface">
      {/* Header Section */}
      <section className="flex flex-col md:flex-row md:items-start justify-between gap-space-lg mb-space-lg relative z-10 pt-2">
        <div className="space-y-space-xs max-w-4xl">
          <div className="flex items-center gap-space-xs">
            <span className="w-1.5 h-1.5 rounded-full bg-primary-container"></span>
            <span className="font-code-sm text-code-sm text-outline tracking-wider uppercase">Provisionamento Multi-Tenant Core</span>
          </div>
          <h1 className="font-headline-xl text-headline-xl text-on-surface tracking-tight font-bold">Tenants</h1>
          <p className="font-body-md text-body-md text-outline leading-relaxed max-w-3xl">
            Cada tenant é um conjunto segregado: repositório de regras (<span className="font-code-sm text-code-sm text-secondary bg-surface-container-high px-1.5 py-0.5 rounded">tenant_scope</span>), base de telemetria dedicada e grupo de avaliação com o próprio nome, segregando clientes SIEM por telemetria, regras e intervalo de avaliação.
          </p>
        </div>

        {/* Header Actions */}
        <div className="flex items-center gap-space-sm self-start shrink-0 pt-1">
          <button
            onClick={loadTenants}
            disabled={loading}
            className="flex items-center gap-1.5 px-space-md py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface transition-all active:scale-95 shadow-sm disabled:opacity-50"
            type="button"
          >
            <span className="material-symbols-outlined text-[16px] text-outline">sync</span>
            <span className="font-body-sm text-body-sm font-semibold">Atualizar</span>
          </button>
          <button
            onClick={handleOpenCreateModal}
            className="flex items-center gap-1.5 px-space-md py-1.5 rounded-lg bg-primary-container hover:bg-primary text-on-primary transition-all active:scale-95 shadow-[0_0_16px_rgba(225,29,72,0.35)] font-semibold"
            type="button"
          >
            <span className="material-symbols-outlined text-[18px]">add</span>
            <span className="font-body-sm text-body-sm">Criar Tenant</span>
          </button>
        </div>
      </section>

      {actionSuccess && (
        <div className="mb-space-md p-space-sm rounded-lg bg-tertiary/15 border border-tertiary/30 text-tertiary text-sm flex justify-between items-center">
          <span>{actionSuccess}</span>
          <button onClick={() => setActionSuccess(null)} className="text-xs text-on-surface underline">Fechar</button>
        </div>
      )}

      {error && (
        <div className="mb-space-md p-space-sm rounded-lg bg-error-container text-on-error-container text-sm">
          {error}
        </div>
      )}

      {/* Metric KPI Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-space-sm mb-space-lg">
        {/* Card 1 */}
        <div className="bg-surface-container-low rounded-xl p-space-md flex flex-col justify-between shadow-sm relative overflow-hidden group hover:bg-surface-container transition-colors">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase">Total de Tenants</span>
            <span className="material-symbols-outlined text-[16px] text-outline/60">domain</span>
          </div>
          <div className="my-space-xs flex items-baseline gap-2">
            <span className="font-metric-display text-metric-display text-on-surface font-bold">{metrics.totalTenants}</span>
            <span className="font-code-sm text-code-sm text-tertiary font-semibold flex items-center gap-0.5">
              <span className="material-symbols-outlined text-[12px]">trending_flat</span> 100%
            </span>
          </div>
          <span className="font-body-sm text-body-sm text-outline">Clientes SIEM cadastrados{metrics.hiddenTenants > 0 ? ` · ${metrics.hiddenTenants} oculto(s) fora das métricas` : ""}</span>
        </div>

        {/* Card 2 */}
        <div className="bg-surface-container-low rounded-xl p-space-md flex flex-col justify-between shadow-sm relative overflow-hidden group hover:bg-surface-container transition-colors">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase">Regras de Detecção</span>
            <span className="material-symbols-outlined text-[16px] text-outline/60">code_blocks</span>
          </div>
          <div className="my-space-xs flex items-baseline gap-2">
            <span className="font-metric-display text-metric-display text-on-surface font-bold">{metrics.totalRules}</span>
            <span className="font-code-sm text-code-sm text-outline">em execução</span>
          </div>
          <span className="font-body-sm text-body-sm text-outline">Total de regras em tenants</span>
        </div>

        {/* Card 3 */}
        <div className="bg-surface-container-low rounded-xl p-space-md flex flex-col justify-between shadow-sm relative overflow-hidden group hover:bg-surface-container transition-colors">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase">Tenants Ativos</span>
            <div className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-tertiary opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-tertiary"></span>
            </div>
          </div>
          <div className="my-space-xs flex items-baseline gap-2">
            <span className="font-metric-display text-metric-display text-tertiary font-bold">{metrics.activeTenants}</span>
            <span className="px-1.5 py-0.5 rounded font-code-sm text-code-sm bg-tertiary-container/30 text-tertiary font-semibold">Saudável</span>
          </div>
          <span className="font-body-sm text-body-sm text-outline">Com detecções avaliando</span>
        </div>

        {/* Card 4 */}
        <div className="bg-surface-container-low rounded-xl p-space-md flex flex-col justify-between shadow-sm relative overflow-hidden group hover:bg-surface-container transition-colors">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase">Tenants Vazios</span>
            <span className="material-symbols-outlined text-[16px] text-outline/60">check_circle</span>
          </div>
          <div className="my-space-xs flex items-baseline gap-2">
            <span className="font-metric-display text-metric-display text-on-surface font-bold">{metrics.emptyTenants}</span>
            <span className="font-code-sm text-code-sm text-outline">órfãos</span>
          </div>
          <span className="font-body-sm text-body-sm text-outline">Aptos para exclusão segura</span>
        </div>

        {/* Card 5 */}
        <div className="bg-surface-container-low rounded-xl p-space-md flex flex-col justify-between shadow-sm relative overflow-hidden group hover:bg-surface-container transition-colors">
          <div className="flex items-center justify-between">
            <span className="font-label-uppercase text-label-uppercase text-outline tracking-wider uppercase">Bases de Telemetria</span>
            <span className="material-symbols-outlined text-[16px] text-secondary">database</span>
          </div>
          <div className="my-space-xs flex items-baseline gap-2">
            <span className="font-metric-display text-metric-display text-secondary font-bold">{metrics.withDatasource}/{metrics.totalTenants}</span>
            <span className="px-1.5 py-0.5 rounded font-code-sm text-code-sm bg-secondary-container/20 text-secondary font-semibold">
              {metrics.totalTenants > 0 ? Math.round((metrics.withDatasource / metrics.totalTenants) * 100) : 100}% OK
            </span>
          </div>
          <span className="font-body-sm text-body-sm text-outline">Todos os tenants com telemetria dedicada</span>
        </div>
      </section>

      {/* Filter & Search Controls Bar */}
      <div className="bg-surface-container-low rounded-xl p-space-sm mb-space-sm flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-space-sm shadow-sm">
        <div className="flex flex-1 items-center gap-space-sm max-w-xl">
          <div className="relative w-full flex items-center">
            <span className="material-symbols-outlined absolute left-2.5 text-[18px] text-outline">search</span>
            <input
              className="w-full bg-surface-container-lowest text-on-surface placeholder:text-outline font-body-sm text-body-sm rounded-lg pl-9 pr-8 py-1.5 focus:outline-none focus:ring-1 focus:ring-secondary transition-all"
              placeholder="Buscar tenant por nome ou UID..."
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            <span className="absolute right-2 px-1.5 py-0.5 rounded bg-surface-container text-outline font-code-sm text-code-sm uppercase select-none">/</span>
          </div>
          <div className="relative shrink-0">
            <select
              className="appearance-none bg-surface-container-lowest text-on-surface font-body-sm text-body-sm rounded-lg pl-3 pr-8 py-1.5 focus:outline-none focus:ring-1 focus:ring-secondary cursor-pointer"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
            >
              <option value="all">Todos os Status</option>
              <option value="active">Apenas Ativos</option>
              <option value="paused">Pausados</option>
              <option value="empty">Sem Regras (Vazios)</option>
            </select>
            <span className="material-symbols-outlined pointer-events-none absolute right-2 top-2 text-[16px] text-outline">expand_more</span>
          </div>
        </div>

        <div className="flex items-center gap-2 px-space-sm py-1 rounded bg-surface-container self-end sm:self-center shrink-0">
          <span className="w-1.5 h-1.5 rounded-full bg-tertiary"></span>
          <span className="font-code-sm text-code-sm text-on-surface">{filteredTenants.length} de {tenants.length} tenants</span>
        </div>
      </div>

      {/* Table Container */}
      <div className="bg-surface-container-low rounded-xl overflow-hidden shadow-md">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-surface-container-lowest text-outline font-code-sm text-code-sm uppercase tracking-wider">
                <th className="py-2.5 px-space-md font-semibold">Tenant</th>
                <th className="py-2.5 px-space-md font-semibold">UID</th>
                <th className="py-2.5 px-space-md font-semibold">Telemetria</th>
                <th className="py-2.5 px-space-md font-semibold">Sandbox</th>
                <th className="py-2.5 px-space-md font-semibold">Regras</th>
                <th className="py-2.5 px-space-md font-semibold">Tecnologias</th>
                <th className="py-2.5 px-space-md font-semibold">Estado</th>
                <th className="py-2.5 px-space-md font-semibold text-right">Ações</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-container font-body-sm text-body-sm">
              {filteredTenants.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-outline">
                    Nenhum tenant encontrado com os filtros selecionados.
                  </td>
                </tr>
              ) : (
                filteredTenants.map((t) => {
                  const isActionLoading = actionLoadingUid === t.uid;
                  const isPaused = t.rules_count > 0 && t.active_rules_count === 0;

                  return (
                    <tr key={t.uid} className={`hover:bg-surface-container transition-colors group ${t.hidden ? "opacity-60" : ""}`}>
                      <td className="py-3 px-space-md align-top">
                        <div className="flex flex-col gap-1.5">
                          <span className="font-headline-md text-headline-md text-on-surface font-semibold tracking-tight">
                            {t.title}
                            {t.hidden && (
                              <span className="ml-2 inline-flex items-center gap-1 align-middle px-2 py-0.5 rounded bg-surface-container-highest text-outline font-code-sm text-xs border border-outline-variant/40">
                                <span className="material-symbols-outlined text-[13px]">visibility_off</span>
                                Oculto
                              </span>
                            )}
                          </span>
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="inline-flex items-center gap-1 bg-surface-container-highest px-2 py-0.5 rounded text-outline font-code-sm text-code-sm">
                              {t.evaluation_group || "5m"} [{t.rules_count} regras]
                            </span>
                          </div>
                        </div>
                      </td>

                      <td className="py-3 px-space-md align-top">
                        <span className="font-code-sm text-code-sm bg-surface-container-lowest text-secondary px-2 py-1 rounded inline-block select-all font-mono">
                          {t.uid}
                        </span>
                      </td>

                      <td className="py-3 px-space-md align-top">
                        {t.loki_datasource_present ? (
                          <div className="flex flex-col gap-0.5">
                            <span className="font-body-sm text-body-sm font-semibold text-on-surface">{t.loki_datasource_name}</span>
                            <span className="font-code-sm text-code-sm text-secondary font-mono">{t.loki_datasource_url || "http://loki:3100"}</span>
                            <span className="font-code-sm text-code-sm text-outline font-mono">uid: {t.loki_datasource_uid}</span>
                          </div>
                        ) : (
                          <button
                            onClick={() => handleOpenDatasourceModal(t)}
                            className="px-2 py-1 rounded bg-amber-500/15 text-amber-300 font-code-sm text-xs border border-amber-500/30 hover:bg-amber-500/25"
                          >
                            + Criar Telemetria DS
                          </button>
                        )}
                      </td>

                      <td className="py-3 px-space-md align-top">
                        <div className="flex flex-col gap-1">
                          <div className="flex items-center gap-2">
                            <button
                              type="button"
                              role="switch"
                              aria-checked={Boolean(t.sandbox_datasource_present)}
                              disabled={isActionLoading || sandboxActionLoadingUid === t.uid}
                              onClick={() => handleRequestToggleSandbox(t)}
                              className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-1 focus:ring-secondary ${
                                t.sandbox_datasource_present
                                  ? "bg-tertiary"
                                  : "bg-surface-container-highest"
                              } disabled:opacity-50 disabled:cursor-not-allowed`}
                              title={
                                t.sandbox_datasource_present
                                  ? `Sandbox ativo (${t.sandbox_datasource_name || `sandbox-${t.title.toLowerCase()}`}). Clique para desativar.`
                                  : `Sandbox inativo. Clique para criar data source sandbox.`
                              }
                            >
                              <span
                                aria-hidden="true"
                                className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
                                  t.sandbox_datasource_present ? "translate-x-4" : "translate-x-0"
                                }`}
                              />
                            </button>
                            <span className={`font-code-sm text-xs ${t.sandbox_datasource_present ? "text-tertiary font-semibold" : "text-outline"}`}>
                              {t.sandbox_datasource_present ? "Ativo" : "Inativo"}
                            </span>
                          </div>
                          {t.sandbox_datasource_present && (
                            <span className="font-code-sm text-[11px] text-outline font-mono truncate max-w-[130px]" title={t.sandbox_datasource_name || `sandbox-${t.title.toLowerCase()}`}>
                              {t.sandbox_datasource_name || `sandbox-${t.title.toLowerCase()}`}
                            </span>
                          )}
                        </div>
                      </td>

                      <td className="py-3 px-space-md align-top">
                        <div className="flex flex-col gap-1">
                          <div className="flex items-center gap-1.5">
                            <span className="font-headline-md text-headline-md font-bold text-on-surface">{t.rules_count}</span>
                            <span className="bg-tertiary-container/30 text-tertiary font-code-sm text-code-sm px-1.5 py-0.5 rounded font-semibold">
                              {t.active_rules_count} ativas
                            </span>
                          </div>
                          <Link
                            to={`/rules?tenant=${encodeURIComponent(t.title)}`}
                            className="inline-flex items-center gap-0.5 font-code-sm text-code-sm text-secondary hover:underline"
                          >
                            Ver regras <span className="material-symbols-outlined text-[13px]">north_east</span>
                          </Link>
                        </div>
                      </td>

                      <td className="py-3 px-space-md align-top">
                        <button
                          onClick={() => openTechModal(t)}
                          className="inline-flex items-center gap-1.5 text-secondary hover:underline font-code-sm text-xs"
                        >
                          <span className="material-symbols-outlined text-[14px]">tune</span>
                          <span>Ver Baseline</span>
                        </button>
                      </td>

                      <td className="py-3 px-space-md align-top">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded font-code-sm text-code-sm font-semibold ${
                          isPaused
                            ? "bg-surface-container-highest text-outline"
                            : "bg-tertiary-container/30 text-tertiary"
                        }`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${isPaused ? "bg-outline" : "bg-tertiary"}`}></span>
                          {isPaused ? "Pausado" : "Ativo"}
                        </span>
                      </td>

                      <td className="py-3 px-space-md align-top text-right">
                        <div className="inline-flex items-center gap-1.5">
                          {t.rules_count > 0 && (
                            <button
                              onClick={() => handleRequestToggleTenantPause(t, !isPaused)}
                              disabled={isActionLoading}
                              className="px-2.5 py-1 rounded bg-surface-container hover:bg-surface-bright text-on-surface font-body-sm text-body-sm transition-colors disabled:opacity-50"
                              type="button"
                            >
                              {isPaused ? "Reativar" : "Pausar"}
                            </button>
                          )}
                          <button
                            onClick={() => setTenantToHide({ tenant: t, hide: !t.hidden })}
                            disabled={isActionLoading}
                            className="px-2.5 py-1 rounded bg-surface-container hover:bg-surface-bright text-on-surface font-body-sm text-body-sm transition-colors disabled:opacity-50"
                            type="button"
                            title={t.hidden ? "Voltar a considerar este tenant nas métricas" : "Remover este tenant de conformidade e métricas"}
                          >
                            {t.hidden ? "Reexibir" : "Ocultar"}
                          </button>
                          <button
                            onClick={() => handleRequestDelete(t)}
                            className="px-2.5 py-1 rounded bg-surface-container hover:bg-error-container hover:text-on-error-container text-on-surface font-body-sm text-body-sm transition-colors"
                            type="button"
                          >
                            Excluir
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal Criar Tenant */}
      <Modal
        isOpen={createModalOpen}
        onClose={() => setCreateModalOpen(false)}
        maxWidth="520px"
        title="Novo Tenant SIEM"
      >
        <form onSubmit={handleCreateTenantSubmit} className="flex flex-col gap-space-md text-on-surface">
          {createError && (
            <div className="p-2 rounded bg-error-container text-on-error-container text-xs">{createError}</div>
          )}

          <div>
            <label className="text-xs text-outline uppercase block mb-1">Nome do Cliente / Tenant *</label>
            <input
              type="text"
              required
              placeholder="ex.: Acme Corp, FinTech Global, Retail Ops"
              className="w-full h-9 px-3 rounded bg-surface-container-lowest text-on-surface text-sm focus:outline-none"
              value={createTitle}
              onChange={(e) => setCreateTitle(e.target.value)}
            />
          </div>

          <div>
            <label className="text-xs text-outline uppercase block mb-1">UID Opcional (deixe vazio para automático)</label>
            <input
              type="text"
              placeholder="ex.: acme-corp"
              className="w-full h-9 px-3 rounded bg-surface-container-lowest text-on-surface text-sm font-mono focus:outline-none"
              value={createUid}
              onChange={(e) => setCreateUid(e.target.value)}
            />
          </div>

          <div>
            <label className="text-xs text-outline uppercase block mb-1">URL da Telemetria (opcional)</label>
            <input
              type="text"
              placeholder="http://loki:3100"
              className="w-full h-9 px-3 rounded bg-surface-container-lowest text-on-surface text-sm font-mono focus:outline-none"
              value={createLokiUrl}
              onChange={(e) => setCreateLokiUrl(e.target.value)}
            />
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-outline-variant/20">
            <button
              type="button"
              className="px-4 py-1.5 rounded bg-surface-container-high text-on-surface text-sm"
              onClick={() => setCreateModalOpen(false)}
              disabled={creatingTenant}
            >
              Cancelar
            </button>
            <button
              type="submit"
              disabled={creatingTenant}
              className="px-4 py-1.5 rounded bg-primary-container text-on-primary text-sm font-semibold disabled:opacity-50"
            >
              {creatingTenant ? "Criando..." : "Criar Tenant"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Modal Criar Loki DS */}
      <Modal
        isOpen={Boolean(datasourceModalTenant)}
        onClose={() => setDatasourceModalTenant(null)}
        maxWidth="480px"
        title="Criar Data Source de Telemetria"
      >
        <div className="flex flex-col gap-space-md text-on-surface">
          <p className="text-xs text-outline">
            Provisione o data source de telemetria homônimo para o tenant <strong>{datasourceModalTenant?.title}</strong>.
          </p>

          {datasourceError && (
            <div className="p-2 rounded bg-error-container text-on-error-container text-xs">{datasourceError}</div>
          )}

          <div>
            <label className="text-xs text-outline uppercase block mb-1">URL da Telemetria</label>
            <input
              type="text"
              placeholder="http://loki:3100"
              className="w-full h-9 px-3 rounded bg-surface-container-lowest text-on-surface text-sm font-mono focus:outline-none"
              value={datasourceUrlInput}
              onChange={(e) => setDatasourceUrlInput(e.target.value)}
            />
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-outline-variant/20">
            <button
              type="button"
              className="px-4 py-1.5 rounded bg-surface-container-high text-on-surface text-sm"
              onClick={() => setDatasourceModalTenant(null)}
            >
              Cancelar
            </button>
            <button
              type="button"
              disabled={Boolean(datasourceLoadingUid)}
              onClick={handleCreateTenantDatasource}
              className="px-4 py-1.5 rounded bg-primary-container hover:bg-primary text-on-primary text-sm font-semibold transition-colors disabled:opacity-50"
            >
              {datasourceLoadingUid ? "Provisionando..." : "Provisionar Data Source"}
            </button>
          </div>
        </div>
      </Modal>

      {/* ConfirmModal Excluir Tenant */}
      <ConfirmModal
        isOpen={deleteModalOpen}
        onClose={() => setDeleteModalOpen(false)}
        onConfirm={handleConfirmDelete}
        title="Excluir Tenant SIEM"
        confirmLabel="Confirmar Exclusão"
        cancelLabel="Cancelar"
        variant="danger"
        isLoading={deletingTenant}
        message={
          tenantToDelete ? (
            <div className="space-y-2 text-sm">
              <p>
                Tem certeza que deseja excluir o tenant <strong>{tenantToDelete.title}</strong> (UID: <code>{tenantToDelete.uid}</code>)?
              </p>
              <p className="text-xs text-error">
                {tenantToDelete.rules_count > 0
                  ? `ATENÇÃO: Este tenant possui ${tenantToDelete.rules_count} regra(s) de detecção que serão excluídas permanentemente da plataforma.`
                  : "O repositório de regras e o data source de telemetria homônimo serão removidos."}
              </p>
              {deleteError && (
                <div className="p-2 rounded bg-error-container/30 text-error text-xs font-semibold">
                  {deleteError}
                </div>
              )}
            </div>
          ) : null
        }
      />

      {/* ConfirmModal Ativar / Desativar Sandbox */}
      <ConfirmModal
        isOpen={sandboxModalOpen}
        onClose={() => {
          if (!sandboxActionLoadingUid) {
            setSandboxModalOpen(false);
            setSandboxModalTarget(null);
          }
        }}
        onConfirm={handleConfirmToggleSandbox}
        title={
          sandboxModalTarget?.enable
            ? "Ativar Data Source Sandbox"
            : "Desativar Data Source Sandbox"
        }
        confirmLabel={
          sandboxModalTarget?.enable
            ? "Ativar Sandbox"
            : "Desativar e Excluir"
        }
        cancelLabel="Cancelar"
        variant={sandboxModalTarget?.enable ? "primary" : "danger"}
        isLoading={Boolean(sandboxActionLoadingUid)}
        message={
          sandboxModalTarget ? (
            <div className="space-y-2 text-sm">
              <p>
                {sandboxModalTarget.enable
                  ? `Deseja ativar o ambiente sandbox para o cliente "${sandboxModalTarget.tenant.title}"?`
                  : `Tem certeza que deseja desativar o ambiente sandbox para o cliente "${sandboxModalTarget.tenant.title}"?`}
              </p>
              <div className="text-xs text-outline space-y-1">
                {sandboxModalTarget.enable ? (
                  <>
                    <p>
                      Esta ação criará na engine o data source dedicado{" "}
                      <span className="font-mono text-tertiary font-semibold">
                        {sandboxModalTarget.tenant.sandbox_datasource_name ||
                          `sandbox-${sandboxModalTarget.tenant.title.toLowerCase()}`}
                      </span>.
                    </p>
                    <p>
                      Permitirá injetar logs sintéticos isolados e validar consultas LogQL sem poluir nem expor a telemetria de produção do cliente.
                    </p>
                  </>
                ) : (
                  <>
                    <p className="text-error font-semibold">
                      Atenção: O data source{" "}
                      <span className="font-mono">
                        {sandboxModalTarget.tenant.sandbox_datasource_name ||
                          `sandbox-${sandboxModalTarget.tenant.title.toLowerCase()}`}
                      </span>{" "}
                      será excluído permanentemente da plataforma.
                    </p>
                    <p>
                      Validações de regras que utilizam este sandbox passarão a reportar que o ambiente de testes do cliente está inativo.
                    </p>
                  </>
                )}
              </div>
            </div>
          ) : null
        }
      />

      {/* ConfirmModal Ocultar / Reexibir Tenant */}
      <ConfirmModal
        isOpen={tenantToHide !== null}
        onClose={() => setTenantToHide(null)}
        onConfirm={handleConfirmHideTenant}
        title={tenantToHide?.hide ? "Ocultar Tenant" : "Reexibir Tenant"}
        confirmLabel={tenantToHide?.hide ? "Ocultar Tenant" : "Reexibir Tenant"}
        variant={tenantToHide?.hide ? "warning" : "primary"}
        isLoading={hideLoading}
        message={
          tenantToHide ? (
            <div className="space-y-2">
              <p>
                {tenantToHide.hide
                  ? `Deseja ocultar o tenant "${tenantToHide.tenant.title}" (${tenantToHide.tenant.uid})?`
                  : `Deseja voltar a considerar o tenant "${tenantToHide.tenant.title}"?`}
              </p>
              <p className="text-xs opacity-80">
                {tenantToHide.hide
                  ? `Enquanto oculto, ele NÃO contabiliza no Mapa de Adesão ao baseline, não aparece no controle de tecnologias por cliente nem em nenhuma outra métrica do D.A.N.T.E. (${tenantToHide.tenant.rules_count} regra(s) deixam de ser contadas). Nenhum dado no Grafana é alterado e a ação é reversível.`
                  : "Ele voltará a contar na conformidade ao baseline, no controle de tecnologias por cliente e nas demais métricas."}
              </p>
            </div>
          ) : undefined
        }
      />

      {/* ConfirmModal Pausar / Reativar Tenant */}
      <ConfirmModal
        isOpen={confirmPauseModalOpen}
        onClose={() => setConfirmPauseModalOpen(false)}
        onConfirm={() => {
          if (tenantToToggle) {
            handleToggleTenantPause(tenantToToggle.tenant, tenantToToggle.pause);
          }
        }}
        title={tenantToToggle?.pause ? "Pausar Regras do Tenant" : "Reativar Regras do Tenant"}
        confirmLabel={tenantToToggle?.pause ? "Pausar Todas as Regras" : "Reativar Todas as Regras"}
        cancelLabel="Cancelar"
        variant={tenantToToggle?.pause ? "warning" : "primary"}
        isLoading={Boolean(actionLoadingUid)}
        message={
          tenantToToggle ? (
            <div className="space-y-2 text-sm">
              <p>
                {tenantToToggle.pause
                  ? `Deseja pausar todas as ${tenantToToggle.tenant.rules_count} regras do tenant "${tenantToToggle.tenant.title}"?`
                  : `Deseja reativar todas as regras do tenant "${tenantToToggle.tenant.title}"?`}
              </p>
              <p className="text-xs text-outline">
                {tenantToToggle.pause
                  ? "As regras pausadas cessarão a avaliação na telemetria até serem reativadas."
                  : "As regras voltarão a avaliar telemetria normalmente."}
              </p>
            </div>
          ) : null
        }
      />

      {/* Modal Tecnologias / Baseline do Tenant */}
      <Modal
        isOpen={Boolean(techModalTenant)}
        onClose={() => setTechModalTenant(null)}
        maxWidth="680px"
        title={techModalTenant ? `Tecnologias & Baseline — ${techModalTenant.title}` : "Baseline"}
      >
        <div className="flex flex-col gap-space-md text-on-surface">
          {techLoading ? (
            <div className="py-8 text-center text-outline text-sm">Carregando tecnologias do tenant...</div>
          ) : techError ? (
            <div className="p-2 rounded bg-error-container text-on-error-container text-xs">{techError}</div>
          ) : techData ? (
            <div className="space-y-3">
              <p className="text-xs text-outline">
                Tecnologias identificadas no tenant e conformidade com o baseline global.
              </p>
              <div className="space-y-2 max-h-72 overflow-y-auto">
                {techData.technologies.map((t) => (
                  <div key={t.slug} className="p-3 rounded-lg bg-surface-container-low flex justify-between items-center text-xs">
                    <div>
                      <span className="font-semibold text-on-surface">{t.name}</span>
                      <span className="text-outline block font-mono">{t.description || t.slug}</span>
                    </div>
                    <div className="text-right">
                      <span className="font-bold text-on-surface">{t.implemented_rules}</span>
                      <span className="text-outline">/{t.baseline_rules} baseline</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          <div className="flex justify-end pt-2 border-t border-outline-variant/20">
            <button
              type="button"
              className="px-4 py-1.5 rounded bg-surface-container-high text-on-surface text-sm"
              onClick={() => setTechModalTenant(null)}
            >
              Fechar
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
