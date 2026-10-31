import React from "react";
import { Link, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { PortalConfig } from "../types";

interface TopHeaderProps {
  config: PortalConfig | null;
  alertCount?: number;
  sidebarCollapsed?: boolean;
}

export const TopHeader: React.FC<TopHeaderProps> = ({
  config,
  alertCount,
  sidebarCollapsed = false,
}) => {
  const { user, logout } = useAuth();
  const location = useLocation();

  const getBreadcrumb = () => {
    const p = location.pathname;
    if (p === "/") return { section: "MONITORAMENTO", current: "VISÃO GERAL" };
    if (p.startsWith("/alerts")) return { section: "MONITORAMENTO", current: "ALERTAS" };
    if (p.startsWith("/silences")) return { section: "MONITORAMENTO", current: "SILENCES & EXCEÇÕES" };
    if (p.startsWith("/rules")) return { section: "ENGENHARIA", current: "REGRAS DE DETECÇÃO" };
    if (p.startsWith("/curadoria")) return { section: "ENGENHARIA", current: "CURADORIA DE REGRAS" };
    if (p.startsWith("/homologacao")) return { section: "ENGENHARIA", current: "HOMOLOGAÇÃO" };
    if (p.startsWith("/baseline") || p.startsWith("/global-rules")) return { section: "ENGENHARIA", current: "CONTROLE DE BASELINE" };
    if (p.startsWith("/technologies")) return { section: "TELEMETRIA", current: "TECNOLOGIAS" };
    if (p.startsWith("/loki")) return { section: "TELEMETRIA", current: "LOGS SINTÉTICOS" };
    if (p.startsWith("/tenants")) return { section: "ADMIN", current: "TENANTS" };
    if (p.startsWith("/api-keys")) return { section: "ADMIN", current: "API KEYS" };
    if (p.startsWith("/users")) return { section: "ADMIN", current: "USUÁRIOS & PERMISSÕES" };
    if (p.startsWith("/system")) return { section: "ADMIN", current: "SISTEMA & UPDATES" };
    return { section: "DANTE", current: "OPERATIONS" };
  };

  const breadcrumb = getBreadcrumb();

  return (
    <header
      className={`fixed top-0 ${
        sidebarCollapsed ? "left-16" : "left-64"
      } right-0 h-14 bg-surface/90 backdrop-blur-xl z-40 flex items-center justify-between px-margin border-b border-outline-variant/30 shadow-[0_1px_8px_rgba(0,0,0,0.4)] transition-all duration-200`}
    >
      {/* Left: Context Breadcrumb */}
      <div className="flex items-center gap-space-md">
        <div className="flex items-center gap-2 text-on-surface-variant font-code-sm text-code-sm">
          <span className="text-outline">DANTE</span>
          <span className="text-surface-container-highest">/</span>
          <span className="text-outline">{breadcrumb.section}</span>
          <span className="text-surface-container-highest">/</span>
          <span className="text-on-surface font-semibold">{breadcrumb.current}</span>
        </div>
        <div className="h-4 w-px bg-surface-variant hidden sm:block" />
        <div className="hidden md:flex items-center gap-2 px-space-sm py-1 rounded bg-surface-container-low border border-outline-variant/20">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-tertiary opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-tertiary"></span>
          </span>
          <span className="font-code-sm text-code-sm text-on-surface">
            Loki &amp; Grafana Ruler Conectados
          </span>
        </div>
      </div>

      {/* Right: Actions, Alerts, User Profile */}
      <div className="flex items-center gap-space-md">
        {config?.grafana_public_url && (
          <a
            className="hidden lg:flex items-center gap-1.5 px-space-sm py-1 rounded bg-surface-container-low text-on-surface hover:bg-surface-container-high hover:text-on-surface transition-colors font-body-sm text-body-sm border border-outline-variant/20"
            href={config.grafana_public_url}
            rel="noreferrer"
            target="_blank"
            title="Abrir o console oficial do Grafana"
          >
            <span className="font-code-sm text-code-sm">Abrir Grafana</span>
            <span className="material-symbols-outlined text-[16px]">north_east</span>
          </a>
        )}

        <Link
          to="/alerts"
          className="relative p-1.5 rounded-lg text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface transition-colors"
          title="Ver alertas ativos"
        >
          <span className="material-symbols-outlined text-[20px]">notifications</span>
          {typeof alertCount === "number" && alertCount > 0 && (
            <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-primary-container ring-2 ring-surface"></span>
          )}
        </Link>

        <div className="h-4 w-px bg-surface-variant" />

        <div className="flex items-center gap-space-sm pl-space-xs">
          <div className="flex flex-col text-right hidden sm:flex">
            <span className="font-body-sm text-body-sm font-semibold text-on-surface leading-tight">
              {user?.username || "hunter"}
            </span>
            <span className="font-code-sm text-code-sm text-outline leading-tight">
              SecOps L3
            </span>
          </div>
          <div className="w-8 h-8 rounded-full bg-primary-container flex items-center justify-center text-on-primary-container shadow-sm font-semibold text-body-sm">
            {user?.username ? user.username.charAt(0).toUpperCase() : "H"}
          </div>
          <button
            onClick={logout}
            className="p-1.5 rounded-lg text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface transition-colors"
            title="Encerrar sessão"
            type="button"
          >
            <span className="material-symbols-outlined text-[18px]">logout</span>
          </button>
        </div>
      </div>
    </header>
  );
};