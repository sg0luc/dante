import React, { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { PortalConfig } from "../types";
import { DanteLogo } from "./DanteLogo";

interface SidebarProps {
  config: PortalConfig | null;
  alertCount?: number;
  silenceCount?: number;
  version?: string;
  onOpenUpdateModal?: () => void;
  updateAvailable?: boolean;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  config,
  alertCount,
  silenceCount,
  version = "v1.0.0",
  onOpenUpdateModal,
  updateAvailable = false,
  collapsed: controlledCollapsed,
  onToggleCollapse,
}) => {
  const location = useLocation();
  const [internalCollapsed, setInternalCollapsed] = useState(false);
  const collapsed = controlledCollapsed !== undefined ? controlledCollapsed : internalCollapsed;

  const handleToggle = () => {
    if (onToggleCollapse) {
      onToggleCollapse();
    } else {
      setInternalCollapsed(!internalCollapsed);
    }
  };

  const isActive = (path: string, exact = false) => {
    if (exact) {
      return location.pathname === path;
    }
    return location.pathname === path || location.pathname.startsWith(path + "/");
  };

  const navItemClass = (active: boolean) =>
    `flex items-center ${
      collapsed ? "justify-center px-0 py-2" : "justify-between px-space-sm py-1.5"
    } rounded-lg transition-colors group ${
      active
        ? "bg-primary-container text-on-primary-container font-semibold shadow-[0_0_12px_rgba(225,29,72,0.25)]"
        : "text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface"
    }`;

  return (
    <aside
      className={`fixed left-0 top-0 h-screen bg-surface-container-lowest flex flex-col z-50 shadow-[0_1px_8px_rgba(0,0,0,0.6)] border-r border-outline-variant/30 transition-all duration-200 ${
        collapsed ? "w-16" : "w-64"
      }`}
    >
      {/* Brand Header */}
      <div
        className={`h-14 flex items-center ${
          collapsed ? "justify-center px-2" : "justify-between px-margin"
        } bg-surface-container-low border-b border-outline-variant/30`}
      >
        {!collapsed && (
          <Link
            to="/"
            className="flex items-center gap-space-sm overflow-hidden group"
            title="D.A.N.T.E. - Detection & Alerting Navigator for Threat Engineering"
          >
            <div className="w-8 h-8 rounded-lg bg-surface-container-high border border-outline-variant/50 flex items-center justify-center shadow-[0_0_12px_rgba(225,29,72,0.35)] shrink-0 group-hover:border-primary-container transition-colors">
              <DanteLogo size={20} glow={false} />
            </div>
            <div className="flex flex-col whitespace-nowrap">
              <span className="font-headline-md text-headline-md tracking-wider text-on-surface leading-tight font-bold">
                D.A.N.T.E.
              </span>
              <span className="font-code-sm text-code-sm uppercase text-outline tracking-widest">
                Threat Eng.
              </span>
            </div>
          </Link>
        )}
        <button
          onClick={handleToggle}
          className={`${
            collapsed ? "w-9 h-9" : "w-7 h-7"
          } flex items-center justify-center rounded-lg text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface transition-colors`}
          title={collapsed ? "Expandir barra lateral" : "Recolher barra lateral"}
          type="button"
        >
          <span className="material-symbols-outlined text-[20px]">
            {collapsed ? "menu" : "menu_open"}
          </span>
        </button>
      </div>

      {/* Navigation Sections */}
      <div className="flex-1 overflow-y-auto px-space-sm py-space-md space-y-space-md">
        {/* Section: Monitoramento & Operação */}
        <div className="space-y-space-xs">
          {!collapsed && (
            <div className="px-space-sm py-space-xs font-label-uppercase text-label-uppercase tracking-wider text-outline uppercase">
              Monitoramento &amp; Operação
            </div>
          )}
          <nav className="space-y-space-xs">
            <Link
              to="/"
              className={navItemClass(isActive("/", true))}
              title="Visão Geral"
            >
              <div className="flex items-center gap-space-sm">
                <span className="material-symbols-outlined text-[18px]">dashboard</span>
                {!collapsed && <span className="font-body-sm text-body-sm">Visão Geral</span>}
              </div>
            </Link>

            <Link
              to="/alerts"
              className={navItemClass(isActive("/alerts"))}
              title={`Alertas${alertCount ? ` (${alertCount})` : ""}`}
            >
              <div className="flex items-center gap-space-sm relative">
                <span className="material-symbols-outlined text-[18px]">
                  notification_important
                </span>
                {collapsed && typeof alertCount === "number" && alertCount > 0 && (
                  <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-error ring-2 ring-surface"></span>
                )}
                {!collapsed && <span className="font-body-sm text-body-sm">Alertas</span>}
              </div>
              {!collapsed && typeof alertCount === "number" && alertCount > 0 && (
                <span className="px-1.5 py-0.5 rounded font-code-sm text-code-sm bg-error-container text-on-error-container font-semibold">
                  {alertCount}
                </span>
              )}
            </Link>

            <Link
              to="/silences"
              className={navItemClass(isActive("/silences"))}
              title={`Silences & Exceções${silenceCount ? ` (${silenceCount})` : ""}`}
            >
              <div className="flex items-center gap-space-sm relative">
                <span className="material-symbols-outlined text-[18px]">
                  notifications_off
                </span>
                {collapsed && typeof silenceCount === "number" && silenceCount > 0 && (
                  <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-surface-container-highest ring-2 ring-surface"></span>
                )}
                {!collapsed && (
                  <span className="font-body-sm text-body-sm">Silences &amp; Exceções</span>
                )}
              </div>
              {!collapsed && typeof silenceCount === "number" && silenceCount > 0 && (
                <span className="px-1.5 py-0.5 rounded font-code-sm text-code-sm bg-surface-container-highest text-on-surface font-semibold">
                  {silenceCount}
                </span>
              )}
            </Link>
          </nav>
        </div>

        {/* Section: Engenharia de Detecção */}
        <div className="space-y-space-xs">
          {!collapsed && (
            <div className="px-space-sm py-space-xs font-label-uppercase text-label-uppercase tracking-wider text-outline uppercase">
              Engenharia de Detecção
            </div>
          )}
          <nav className="space-y-space-xs">
            <Link
              to="/rules"
              className={navItemClass(isActive("/rules"))}
              title="Regras de Detecção"
            >
              <div className="flex items-center gap-space-sm">
                <span className="material-symbols-outlined text-[18px]">code_blocks</span>
                {!collapsed && (
                  <span className="font-body-sm text-body-sm">Regras de Detecção</span>
                )}
              </div>
            </Link>

            <Link
              to="/curadoria"
              className={navItemClass(isActive("/curadoria"))}
              title="Curadoria de Regras"
            >
              <div className="flex items-center gap-space-sm">
                <span className="material-symbols-outlined text-[18px]">auto_awesome</span>
                {!collapsed && (
                  <span className="font-body-sm text-body-sm">Curadoria de Regras</span>
                )}
              </div>
              {!collapsed && (
                <span className="px-1.5 py-0.5 rounded font-code-sm text-code-sm bg-tertiary-container text-on-tertiary-container font-semibold">
                  Auto
                </span>
              )}
            </Link>

            <Link
              to="/homologacao"
              className={navItemClass(isActive("/homologacao"))}
              title="Homologação"
            >
              <div className="flex items-center gap-space-sm">
                <span className="material-symbols-outlined text-[18px]">rule_folder</span>
                {!collapsed && (
                  <span className="font-body-sm text-body-sm">Homologação</span>
                )}
              </div>
            </Link>

            <Link
              to="/baseline"
              className={navItemClass(isActive("/baseline") || isActive("/global-rules"))}
              title="Controle de Baseline"
            >
              <div className="flex items-center gap-space-sm">
                <span className="material-symbols-outlined text-[18px]">tune</span>
                {!collapsed && (
                  <span className="font-body-sm text-body-sm">Controle de Baseline</span>
                )}
              </div>
            </Link>
          </nav>
        </div>

        {/* Section: Telemetria & Validação */}
        <div className="space-y-space-xs">
          {!collapsed && (
            <div className="px-space-sm py-space-xs font-label-uppercase text-label-uppercase tracking-wider text-outline uppercase">
              Telemetria &amp; Validação
            </div>
          )}
          <nav className="space-y-space-xs">
            <Link
              to="/technologies"
              className={navItemClass(isActive("/technologies"))}
              title="Tecnologias"
            >
              <div className="flex items-center gap-space-sm">
                <span className="material-symbols-outlined text-[18px]">dns</span>
                {!collapsed && <span className="font-body-sm text-body-sm">Tecnologias</span>}
              </div>
            </Link>

            <Link
              to="/loki"
              className={navItemClass(isActive("/loki"))}
              title="Logs Sintéticos"
            >
              <div className="flex items-center gap-space-sm">
                <span className="material-symbols-outlined text-[18px]">terminal</span>
                {!collapsed && (
                  <span className="font-body-sm text-body-sm">Logs Sintéticos</span>
                )}
              </div>
            </Link>
          </nav>
        </div>

        {/* Section: Configurações & Admin */}
        <div className="space-y-space-xs">
          {!collapsed && (
            <div className="px-space-sm py-space-xs font-label-uppercase text-label-uppercase tracking-wider text-outline uppercase">
              Configurações &amp; Admin
            </div>
          )}
          <nav className="space-y-space-xs">
            <Link
              to="/tenants"
              className={navItemClass(isActive("/tenants"))}
              title="Tenants"
            >
              <div className="flex items-center gap-space-sm">
                <span className="material-symbols-outlined text-[18px]">domain</span>
                {!collapsed && <span className="font-body-sm text-body-sm">Tenants</span>}
              </div>
            </Link>

            <Link
              to="/api-keys"
              className={navItemClass(isActive("/api-keys"))}
              title="API Keys"
            >
              <div className="flex items-center gap-space-sm">
                <span className="material-symbols-outlined text-[18px]">auto_awesome</span>
                {!collapsed && <span className="font-body-sm text-body-sm">API Keys</span>}
              </div>
            </Link>

            <Link
              to="/baseline-prefix"
              className={navItemClass(isActive("/baseline-prefix"))}
              title="Prefixo Baseline"
            >
              <div className="flex items-center gap-space-sm">
                <span className="material-symbols-outlined text-[18px]">title</span>
                {!collapsed && <span className="font-body-sm text-body-sm">Prefixo Baseline</span>}
              </div>
            </Link>

            <Link
              to="/users"
              className={navItemClass(isActive("/users"))}
              title="Usuários & Permissões"
            >
              <div className="flex items-center gap-space-sm">
                <span className="material-symbols-outlined text-[18px]">manage_accounts</span>
                {!collapsed && <span className="font-body-sm text-body-sm">Usuários</span>}
              </div>
            </Link>

            {config?.grafana_public_url && (
              <a
                href={`${config.grafana_public_url}/datasources`}
                target="_blank"
                rel="noreferrer"
                className={navItemClass(false)}
                title="Data Sources no Grafana"
              >
                <div className="flex items-center gap-space-sm">
                  <span className="material-symbols-outlined text-[18px]">database</span>
                  {!collapsed && (
                    <span className="font-body-sm text-body-sm">Data Sources ↗</span>
                  )}
                </div>
              </a>
            )}

            <button
              type="button"
              onClick={onOpenUpdateModal}
              className={`w-full ${navItemClass(false)}`}
              title={`Atualizações do Sistema (${version})`}
            >
              <div className="flex items-center gap-space-sm relative">
                <span className="material-symbols-outlined text-[18px]">deployed_code</span>
                {collapsed && updateAvailable && (
                  <span className="absolute -top-1 -right-1 flex h-2 w-2">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary-container opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-primary-container"></span>
                  </span>
                )}
                {!collapsed && (
                  <span className="font-body-sm text-body-sm">Atualizações</span>
                )}
              </div>
              {!collapsed && (
                <div className="flex items-center gap-1.5">
                  {updateAvailable && (
                    <span className="relative flex h-2 w-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary-container opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-primary-container"></span>
                    </span>
                  )}
                  <span className="px-1.5 py-0.5 rounded font-code-sm text-code-sm bg-surface-container-high text-outline font-semibold">
                    {version}
                  </span>
                </div>
              )}
            </button>
          </nav>
        </div>
      </div>

      {/* Footer Status & Docs */}
      <div className="p-space-sm bg-surface-container-low mt-auto flex flex-col gap-space-xs border-t border-outline-variant/30">
        <a
          className={`flex items-center ${
            collapsed ? "justify-center px-0 py-1.5" : "gap-space-sm px-space-sm py-1.5"
          } rounded-lg text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface transition-colors`}
          href="https://github.com/sg0luc/dante"
          target="_blank"
          rel="noreferrer"
          title="Documentação e Repositório"
        >
          <span className="material-symbols-outlined text-[18px]">menu_book</span>
          {!collapsed && (
            <span className="font-body-sm text-body-sm">Documentação &amp; Docs</span>
          )}
        </a>
      </div>
    </aside>
  );
};